import json
import queue as stdlib_queue
import subprocess
import threading
import time

import pytest
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient

from ouroboros.task_results import (
    STATUS_CANCELLED,
    STATUS_FAILED,
    STATUS_REQUESTED,
    STATUS_SCHEDULED,
    load_task_result,
)
from supervisor import queue
from supervisor.task_lifecycle import (
    REMOTE_ADMISSIONS,
    _live_project_task_ids,
    complete_requested_admission,
    list_requested_admissions,
    register_requested_admission,
)


@pytest.fixture()
def isolated_queue(tmp_path):
    drive = tmp_path / "data"
    (drive / "state").mkdir(parents=True)
    queue.init(drive, 600, 1800)
    queue.init_queue_refs([], {}, {"value": 0})
    queue.ACCEPTANCE_FENCES.clear()
    queue.BUDGET_ROOT_FENCES.clear()
    REMOTE_ADMISSIONS.clear()
    from ouroboros.gateway import tasks as gateway_tasks

    gateway_tasks._REMOTE_SUBMISSIONS.clear()
    yield drive
    queue.ACCEPTANCE_FENCES.clear()
    queue.BUDGET_ROOT_FENCES.clear()
    REMOTE_ADMISSIONS.clear()
    gateway_tasks._REMOTE_SUBMISSIONS.clear()


def _task(task_id: str, drive, **extra):
    return {
        "id": task_id,
        "type": "task",
        "chat_id": 1,
        "text": "remote work",
        "root_task_id": task_id,
        "budget_drive_root": str(drive),
        **extra,
    }


def test_requested_admission_is_not_runnable_until_atomic_completion(isolated_queue):
    task = _task("remote-1", isolated_queue)

    registered = register_requested_admission(task)

    assert registered["ok"] is True
    assert registered["status"] == "requested"
    assert registered["task_id"] == "remote-1"
    assert registered["admission_id"]
    assert queue.PENDING == []
    requested_task = list_requested_admissions()[0]["task"]
    assert requested_task["id"] == task["id"]
    assert requested_task["text"] == task["text"]
    assert requested_task["budget_drive_root"] == task["budget_drive_root"]
    assert isinstance(requested_task["task_contract"], dict)
    assert load_task_result(isolated_queue, "remote-1")["status"] == STATUS_REQUESTED

    completed = complete_requested_admission(
        "remote-1",
        admission_id=registered["admission_id"],
        admitted_task={
            "metadata": {
                "_sealed_workspace_ref": {
                    "kind": "ssh",
                    "connection_id": "connection-1",
                    "remote_root": "/srv/project",
                    "workspace_id": "workspace-1",
                }
            }
        },
    )

    assert completed["status"] == "scheduled"
    assert [item["id"] for item in queue.PENDING] == ["remote-1"]
    assert list_requested_admissions() == []
    assert load_task_result(isolated_queue, "remote-1")["status"] == STATUS_SCHEDULED


def test_cancel_owns_inflight_admission_and_late_completion_cannot_enqueue(isolated_queue):
    cancelled = threading.Event()
    task = _task("remote-2", isolated_queue)
    registered = register_requested_admission(task, cancel=cancelled.set)

    assert queue.cancel_task_by_id("remote-2") is True
    assert cancelled.wait(1)
    assert queue.PENDING == []
    assert load_task_result(isolated_queue, "remote-2")["status"] == STATUS_CANCELLED

    late = complete_requested_admission(
        "remote-2",
        admission_id=registered["admission_id"],
        admitted_task={"metadata": {"_remote_admission_evidence": {"late": True}}},
    )
    assert late["status"] == "stale"
    assert queue.PENDING == []
    assert load_task_result(isolated_queue, "remote-2")["status"] == STATUS_CANCELLED


def test_project_quiescence_and_cascade_include_requested_admissions(isolated_queue):
    register_requested_admission(
        _task("remote-parent", isolated_queue, project_id="project-1")
    )
    register_requested_admission(
        _task(
            "remote-child",
            isolated_queue,
            project_id="project-1",
            parent_task_id="remote-parent",
            root_task_id="remote-parent",
        )
    )

    assert _live_project_task_ids(isolated_queue, "project-1") == [
        "remote-child",
        "remote-parent",
    ]
    assert queue.cancel_task_by_id("remote-parent", cascade=True) is True
    assert list_requested_admissions() == []
    assert load_task_result(isolated_queue, "remote-parent")["status"] == STATUS_CANCELLED
    assert load_task_result(isolated_queue, "remote-child")["status"] == STATUS_CANCELLED


def test_acceptance_fence_is_rechecked_before_requested_task_becomes_pending(isolated_queue):
    registered = register_requested_admission(
        _task(
            "remote-child",
            isolated_queue,
            root_task_id="root-1",
            parent_task_id="root-1",
        )
    )
    queue.ACCEPTANCE_FENCES["root-1"] = {
        "token": "fence-1",
        "root_task_id": "root-1",
        "task_id": "root-1",
        "status": "active",
    }

    completed = complete_requested_admission(
        "remote-child",
        admission_id=registered["admission_id"],
    )

    assert completed["status"] == "failed"
    assert completed["reason_code"] == "task_acceptance_fence"
    assert queue.PENDING == []
    result = load_task_result(isolated_queue, "remote-child")
    assert result["status"] == STATUS_FAILED
    assert result["reason_code"] == "task_acceptance_fence"


def test_restart_restores_requested_state_for_broker_rebind_without_enqueuing(isolated_queue):
    register_requested_admission(_task("remote-restore", isolated_queue))
    snapshot = json.loads(queue.QUEUE_SNAPSHOT_PATH.read_text(encoding="utf-8"))
    assert snapshot["requested_count"] == 1
    assert snapshot["requested_admissions"][0]["id"] == "remote-restore"

    REMOTE_ADMISSIONS.clear()
    assert queue.restore_pending_from_snapshot() == 0

    recovered = list_requested_admissions(recovery_required_only=True)
    assert [row["task_id"] for row in recovered] == ["remote-restore"]
    assert queue.PENDING == []
    assert load_task_result(isolated_queue, "remote-restore")["status"] == STATUS_REQUESTED


def test_completion_cannot_rewrite_lineage_or_escape_project_and_acceptance_fences(
    isolated_queue,
):
    from ouroboros.projects_registry import begin_project_deletion, create_project

    create_project(isolated_queue, "project-locked", name="Locked")
    registered = register_requested_admission(
        _task(
            "remote-locked",
            isolated_queue,
            project_id="project-locked",
            root_task_id="root-locked",
            parent_task_id="root-locked",
        )
    )
    begin_project_deletion(isolated_queue, "project-locked")
    queue.ACCEPTANCE_FENCES["root-locked"] = {
        "token": "fence-locked",
        "root_task_id": "root-locked",
        "task_id": "root-locked",
        "status": "active",
    }

    for authority_override in (
        {"root_task_id": "other-root"},
        {"project_id": ""},
        {"budget_drive_root": "/tmp/other"},
    ):
        rejected = complete_requested_admission(
            "remote-locked",
            admission_id=registered["admission_id"],
            admitted_task=authority_override,
        )
        assert rejected["status"] == "error"
        assert list_requested_admissions()[0]["task_id"] == "remote-locked"

    fenced = complete_requested_admission(
        "remote-locked",
        admission_id=registered["admission_id"],
        admitted_task={
            "metadata": {
                "_remote_admission_evidence": {"host_id": "host-1"},
            }
        },
    )
    assert fenced["status"] == "failed"
    assert fenced["reason_code"] == "project_routing_fence"
    assert queue.PENDING == []


def test_requested_task_and_public_snapshots_are_deeply_immutable(isolated_queue):
    task = _task(
        "remote-copy",
        isolated_queue,
        metadata={
            "_sealed_workspace_ref": {
                "kind": "ssh",
                "connection_id": "connection-1",
                "remote_root": "/srv/original",
                "workspace_id": "workspace-1",
            }
        },
    )
    register_requested_admission(task)
    task["metadata"]["_sealed_workspace_ref"]["remote_root"] = "/srv/caller-mutated"
    public = list_requested_admissions()
    public[0]["task"]["metadata"]["_sealed_workspace_ref"]["remote_root"] = "/srv/list-mutated"

    live = list_requested_admissions()[0]["task"]
    assert live["metadata"]["_sealed_workspace_ref"]["remote_root"] == "/srv/original"
    snapshot = json.loads(queue.QUEUE_SNAPSHOT_PATH.read_text(encoding="utf-8"))
    assert (
        snapshot["requested_admissions"][0]["task"]["metadata"]
        ["_sealed_workspace_ref"]["remote_root"]
        == "/srv/original"
    )


def test_admission_id_rejects_stale_completion_and_terminal_task_id_reuse(isolated_queue):
    registered = register_requested_admission(_task("remote-generation", isolated_queue))
    stale = complete_requested_admission(
        "remote-generation",
        admission_id="stale-admission",
    )
    assert stale["status"] == "stale"
    assert list_requested_admissions()[0]["admission_id"] == registered["admission_id"]

    assert queue.cancel_task_by_id("remote-generation")
    reused = register_requested_admission(_task("remote-generation", isolated_queue))
    assert reused["status"] == "conflict"
    assert reused["error"] == "task_id_is_terminal"
    late = complete_requested_admission(
        "remote-generation",
        admission_id=registered["admission_id"],
    )
    assert late["status"] == "stale"
    assert queue.PENDING == []


def test_snapshot_writers_are_linearized_with_admission_completion(
    isolated_queue,
    monkeypatch,
):
    registered = register_requested_admission(_task("remote-linear", isolated_queue))
    original_write = queue.atomic_write_text
    old_writer_entered = threading.Event()
    release_old_writer = threading.Event()

    def delayed_write(path, text):
        payload = json.loads(text)
        if payload.get("reason") == "delayed-old":
            old_writer_entered.set()
            assert release_old_writer.wait(2)
        return original_write(path, text)

    monkeypatch.setattr(queue, "atomic_write_text", delayed_write)
    old_writer = threading.Thread(
        target=queue.persist_queue_snapshot,
        kwargs={"reason": "delayed-old"},
    )
    old_writer.start()
    assert old_writer_entered.wait(1)
    completion_result = {}

    def finish():
        completion_result.update(
            complete_requested_admission(
                "remote-linear",
                admission_id=registered["admission_id"],
            )
        )

    completion = threading.Thread(target=finish)
    completion.start()
    time.sleep(0.05)
    assert completion.is_alive()
    release_old_writer.set()
    old_writer.join(2)
    completion.join(2)

    assert completion_result["status"] == "scheduled"
    snapshot = json.loads(queue.QUEUE_SNAPSHOT_PATH.read_text(encoding="utf-8"))
    assert snapshot["requested_count"] == 0
    assert snapshot["pending_count"] == 1


def test_cancel_is_durable_and_nonblocking_before_external_callback_finishes(
    isolated_queue,
):
    callback_entered = threading.Event()
    callback_release = threading.Event()

    def blocking_cancel():
        callback_entered.set()
        callback_release.wait(2)

    register_requested_admission(
        _task("remote-cancel-durable", isolated_queue),
        cancel=blocking_cancel,
    )
    started = time.monotonic()
    assert queue.cancel_task_by_id("remote-cancel-durable")
    elapsed = time.monotonic() - started

    assert elapsed < 0.5
    assert callback_entered.wait(1)
    snapshot = json.loads(queue.QUEUE_SNAPSHOT_PATH.read_text(encoding="utf-8"))
    assert snapshot["requested_count"] == 0
    assert load_task_result(isolated_queue, "remote-cancel-durable")["status"] == STATUS_CANCELLED
    callback_release.set()


def test_old_or_corrupt_snapshot_recovers_marked_request_despite_pending_queue(
    isolated_queue,
):
    register_requested_admission(_task("remote-old", isolated_queue))
    snapshot = json.loads(queue.QUEUE_SNAPSHOT_PATH.read_text(encoding="utf-8"))
    snapshot["ts"] = "2000-01-01T00:00:00+00:00"
    queue.QUEUE_SNAPSHOT_PATH.write_text(json.dumps(snapshot), encoding="utf-8")
    REMOTE_ADMISSIONS.clear()
    queue.PENDING.append(_task("already-pending", isolated_queue))

    assert queue.restore_pending_from_snapshot(max_age_sec=1) == 0
    assert [row["task_id"] for row in list_requested_admissions()] == ["remote-old"]
    REMOTE_ADMISSIONS.clear()
    queue.QUEUE_SNAPSHOT_PATH.write_text("{corrupt", encoding="utf-8")
    assert queue.restore_pending_from_snapshot() == 0
    assert [row["task_id"] for row in list_requested_admissions()] == ["remote-old"]


def test_project_registry_migrates_local_refs_and_guards_remote_rebind(tmp_path):
    from ouroboros.projects_registry import (
        create_project,
        get_project,
        rebind_project_workspace,
        workspace_identity_key,
    )

    local = tmp_path / "repo"
    local.mkdir()
    project = create_project(
        tmp_path,
        "typed-project",
        working_dir=str(local),
    )
    assert project["workspace_ref"] == {
        "kind": "local",
        "local_root": str(local.resolve()),
    }
    assert workspace_identity_key(project).startswith("local:")
    generation = project["routing_generation"]
    remote = rebind_project_workspace(
        tmp_path,
        "typed-project",
        {
            "kind": "ssh",
            "connection_id": "connection-1",
            "remote_root": "/srv/repo",
            "workspace_id": "workspace-1",
        },
        expected_routing_generation=generation,
    )
    assert remote["working_dir"] == ""
    assert remote["routing_generation"] == generation + 1
    assert workspace_identity_key(remote) == "ssh:connection-1:workspace-1"
    with pytest.raises(ValueError, match="generation"):
        rebind_project_workspace(
            tmp_path,
            "typed-project",
            None,
            expected_routing_generation=generation,
        )
    assert get_project(tmp_path, "typed-project")["workspace_ref"]["kind"] == "ssh"


def test_background_admission_uses_project_identity_and_durable_cancel(
    isolated_queue,
    monkeypatch,
):
    from ouroboros.gateway.tasks import submit_remote_task_admission

    events = stdlib_queue.Queue()
    monkeypatch.setattr("supervisor.workers.get_event_q", lambda: events)
    entered = threading.Event()
    released = threading.Event()

    class Service:
        def __init__(self):
            self.cancelled = []
            self.call = None

        def admit_workspace(self, connection, **kwargs):
            self.call = (connection, kwargs)
            entered.set()
            released.wait(2)
            return {
                "ok": False,
                "task_id": "broker-must-not-rebind-task",
                "project_id": "broker-must-not-rebind-project",
                "error": "cancelled",
                "error_code": "cancelled",
                "diagnostic": {
                    "domain": "transport",
                    "code": "cancelled",
                    "message": "admission cancelled",
                    "phase": "connect",
                },
                "log_refs": [
                    {"stream": "stderr", "blob_id": "admission-log"},
                ],
            }

        def cancel_admission(self, task_id):
            self.cancelled.append(task_id)
            released.set()
            return True

    service = Service()
    task = _task(
        "remote-background",
        isolated_queue,
        project_id="project-1",
        metadata={
            "_sealed_workspace_ref": {
                "kind": "ssh",
                "connection_id": "connection-1",
                "remote_root": "/srv/repo",
                "workspace_id": "workspace-1",
            },
            "executor_ref": {
                "type": "ssh_exec",
                "id": "connection-1",
                "network": "host",
                "workspace_id": "workspace-1",
            },
        },
    )
    submitted = submit_remote_task_admission(
        task,
        connection={"id": "connection-1", "ssh_alias": "build"},
        service=service,
    )
    assert submitted["ok"] and submitted["submitted"]
    assert entered.wait(1)
    assert service.call[1]["remote_root"] == "/srv/repo"
    assert service.call[1]["project_id"] == "project-1"
    assert service.call[1]["workspace_id"] == "workspace-1"
    assert service.call[1]["task_id"] == "remote-background"
    assert isinstance(service.call[1]["cancel_event"], threading.Event)

    assert queue.cancel_task_by_id("remote-background")
    deadline = time.time() + 1
    while time.time() < deadline and not service.cancelled:
        time.sleep(0.01)
    assert service.cancelled == ["remote-background"]
    event = events.get(timeout=1)
    assert event["type"] == "remote_admission_result"
    assert event["task_id"] == "remote-background"
    assert event["project_id"] == "project-1"
    assert event["admission_id"] == submitted["admission_id"]
    assert event["diagnostic"]["code"] == "cancelled"
    assert event["log_refs"][0]["blob_id"] == "admission-log"


def test_cron_ssh_project_stays_requested_until_broker_admission(
    isolated_queue,
    monkeypatch,
):
    from ouroboros.projects_registry import create_project

    create_project(
        isolated_queue,
        "scheduled-remote",
        workspace_ref={
            "kind": "ssh",
            "connection_id": "connection-cron",
            "remote_root": "/srv/cron",
            "workspace_id": "workspace-cron",
        },
    )
    events = stdlib_queue.Queue()
    entered = threading.Event()
    released = threading.Event()

    class Service:
        def admit_workspace(self, connection, **kwargs):
            entered.set()
            released.wait(2)
            return {
                "ok": True,
                "workspace_ref": {
                    "kind": "ssh",
                    "connection_id": connection["id"],
                    "remote_root": kwargs["remote_root"],
                    "workspace_id": kwargs["workspace_id"],
                },
            }

        def cancel_admission(self, _task_id):
            released.set()
            return True

    monkeypatch.setattr("supervisor.workers.get_event_q", lambda: events)
    monkeypatch.setattr(
        "ouroboros.gateway.connections.get_connection",
        lambda connection_id, *_args, **_kwargs: {
            "id": connection_id,
            "ssh_alias": "cron-host",
            "lifecycle": "active",
        },
    )
    monkeypatch.setattr(
        "ouroboros.remote_workspace.get_remote_workspace_service",
        lambda: Service(),
    )
    monkeypatch.setattr(
        queue,
        "enqueue_task",
        lambda *_args, **_kwargs: pytest.fail(
            "remote cron became runnable before broker admission"
        ),
    )
    queue.upsert_scheduled_task({
        "id": "remote-cron",
        "name": "Remote cron",
        "enabled": True,
        "trigger": {"type": "cron", "expr": "* * * * *"},
        "next_run_at": "2000-01-01T00:00:00+00:00",
        "task": {
            "type": "task",
            "text": "remote scheduled work",
            "project_id": "scheduled-remote",
        },
    })

    queue.check_scheduled_tasks()
    assert entered.wait(1)
    requested = list_requested_admissions()
    assert len(requested) == 1
    task = requested[0]["task"]
    assert task["project_id"] == "scheduled-remote"
    assert task["workspace_mode"] == "external"
    assert task["memory_mode"] == "forked"
    assert task["metadata"]["_sealed_workspace_ref"]["remote_root"] == "/srv/cron"
    assert queue.PENDING == []
    assert load_task_result(isolated_queue, task["id"])["status"] == STATUS_REQUESTED

    queue.check_scheduled_tasks()
    assert len(list_requested_admissions()) == 1
    released.set()
    assert events.get(timeout=1)["task_id"] == task["id"]


def test_cron_missing_project_fails_closed_without_local_enqueue(
    isolated_queue,
    monkeypatch,
):
    called = []
    monkeypatch.setattr(
        queue,
        "enqueue_task",
        lambda task, **_kwargs: called.append(task) or task,
    )
    queue.upsert_scheduled_task({
        "id": "missing-project-cron",
        "name": "Missing project cron",
        "enabled": True,
        "trigger": {"type": "cron", "expr": "* * * * *"},
        "next_run_at": "2000-01-01T00:00:00+00:00",
        "task": {
            "type": "task",
            "text": "must not run locally",
            "project_id": "missing-project",
        },
    })

    queue.check_scheduled_tasks()

    assert called == []
    schedule = queue.list_scheduled_tasks()["tasks"][0]
    result = load_task_result(isolated_queue, schedule["last_task_id"])
    assert result["status"] == STATUS_FAILED
    assert result["reason_code"] == "project_not_found"


def test_cron_local_project_uses_registered_workspace_and_child_drive(
    isolated_queue,
    tmp_path,
    monkeypatch,
):
    from ouroboros.projects_registry import create_project

    workspace = tmp_path / "local-cron-workspace"
    workspace.mkdir()
    subprocess.run(
        ["git", "init", "-q"],
        cwd=workspace,
        check=True,
        capture_output=True,
    )
    create_project(
        isolated_queue,
        "scheduled-local",
        working_dir=str(workspace),
    )
    monkeypatch.setattr(
        "ouroboros.workspace_admission.bounded_workspace_preflight",
        lambda root: {"schema_version": 1, "workspace_root": str(root)},
    )
    queue.upsert_scheduled_task({
        "id": "local-project-cron",
        "name": "Local Project cron",
        "enabled": True,
        "trigger": {"type": "cron", "expr": "* * * * *"},
        "next_run_at": "2000-01-01T00:00:00+00:00",
        "task": {
            "type": "task",
            "text": "work in the registered project",
            "project_id": "scheduled-local",
        },
    })

    queue.check_scheduled_tasks()

    assert len(queue.PENDING) == 1
    task = queue.PENDING[0]
    child = isolated_queue / "state" / "headless_tasks" / task["id"] / "data"
    assert task["workspace_root"] == str(workspace.resolve())
    assert task["workspace_mode"] == "external"
    assert task["memory_mode"] == "forked"
    assert task["drive_root"] == str(child)
    assert task["child_drive_root"] == str(child)
    assert task["budget_drive_root"] == str(isolated_queue)
    assert task["metadata"]["workspace_root"] == str(workspace.resolve())
    assert "[HEADLESS_WORKSPACE]" in task["text"]
    assert child.is_dir()


def test_cron_legacy_project_id_is_validated_exactly_at_fire_time(
    isolated_queue,
    monkeypatch,
):
    from ouroboros.projects_registry import create_project

    create_project(isolated_queue, "prod")
    monkeypatch.setattr(
        queue,
        "enqueue_task",
        lambda *_args, **_kwargs: pytest.fail(
            "malformed legacy project id was normalized into a live Project"
        ),
    )
    queue.upsert_scheduled_task({
        "id": "legacy-project-id",
        "name": "Legacy malformed Project id",
        "enabled": True,
        "trigger": {"type": "cron", "expr": "* * * * *"},
        "next_run_at": "2000-01-01T00:00:00+00:00",
        "task": {
            "type": "task",
            "text": "must fail closed",
            "project_id": "PROD",
        },
    })

    queue.check_scheduled_tasks()

    schedule = queue.list_scheduled_tasks()["tasks"][0]
    result = load_task_result(isolated_queue, schedule["last_task_id"])
    assert result["status"] == STATUS_FAILED
    assert result["reason_code"] == "invalid_project_id"
    assert result["project_id"] == "PROD"


def test_cron_remote_preflight_failure_preserves_identity_without_child_drive(
    isolated_queue,
    monkeypatch,
):
    from ouroboros.projects_registry import create_project

    create_project(
        isolated_queue,
        "offline-remote",
        workspace_ref={
            "kind": "ssh",
            "connection_id": "offline-connection",
            "remote_root": "/srv/offline",
            "workspace_id": "offline-workspace",
        },
    )
    monkeypatch.setattr(
        "ouroboros.gateway.connections.get_connection",
        lambda *_args, **_kwargs: None,
    )
    queue.upsert_scheduled_task({
        "id": "offline-remote-cron",
        "name": "Offline remote cron",
        "enabled": True,
        "trigger": {"type": "cron", "expr": "* * * * *"},
        "next_run_at": "2000-01-01T00:00:00+00:00",
        "task": {
            "type": "task",
            "text": "remote scheduled work",
            "project_id": "offline-remote",
        },
    })

    queue.check_scheduled_tasks()

    schedule = queue.list_scheduled_tasks()["tasks"][0]
    task_id = schedule["last_task_id"]
    result = load_task_result(isolated_queue, task_id)
    assert result["status"] == STATUS_FAILED
    assert result["reason_code"] == "remote_connection_unavailable"
    assert result["project_id"] == "offline-remote"
    assert result["description"] == "remote scheduled work"
    assert result["metadata"]["schedule_id"] == "offline-remote-cron"
    assert (
        result["metadata"]["_sealed_workspace_ref"]["connection_id"]
        == "offline-connection"
    )
    assert not (
        isolated_queue / "state" / "headless_tasks" / task_id
    ).exists()


def test_cron_remote_registration_refusal_removes_prepared_child_drive(
    isolated_queue,
    monkeypatch,
):
    from ouroboros.projects_registry import create_project

    create_project(
        isolated_queue,
        "rejected-remote",
        workspace_ref={
            "kind": "ssh",
            "connection_id": "rejected-connection",
            "remote_root": "/srv/rejected",
            "workspace_id": "rejected-workspace",
        },
    )
    monkeypatch.setattr(
        "ouroboros.gateway.connections.get_connection",
        lambda connection_id, *_args, **_kwargs: {
            "id": connection_id,
            "lifecycle": "active",
        },
    )
    monkeypatch.setattr(
        "ouroboros.remote_workspace.get_remote_workspace_service",
        lambda: object(),
    )
    monkeypatch.setattr(
        "ouroboros.gateway.tasks.submit_remote_task_admission",
        lambda *_args, **_kwargs: {
            "ok": False,
            "status": "blocked",
            "reason_code": "synthetic_registration_refusal",
        },
    )
    queue.upsert_scheduled_task({
        "id": "rejected-remote-cron",
        "name": "Rejected remote cron",
        "enabled": True,
        "trigger": {"type": "cron", "expr": "* * * * *"},
        "next_run_at": "2000-01-01T00:00:00+00:00",
        "task": {
            "type": "task",
            "text": "remote scheduled work",
            "project_id": "rejected-remote",
        },
    })

    queue.check_scheduled_tasks()

    schedule = queue.list_scheduled_tasks()["tasks"][0]
    task_id = schedule["last_task_id"]
    result = load_task_result(isolated_queue, task_id)
    assert result["reason_code"] == "synthetic_registration_refusal"
    assert not (
        isolated_queue / "state" / "headless_tasks" / task_id
    ).exists()


def test_cron_broker_denial_updates_schedule_failure_state(
    isolated_queue,
    monkeypatch,
):
    from ouroboros.projects_registry import create_project

    create_project(
        isolated_queue,
        "denied-remote",
        workspace_ref={
            "kind": "ssh",
            "connection_id": "denied-connection",
            "remote_root": "/srv/denied",
            "workspace_id": "denied-workspace",
        },
    )
    events = stdlib_queue.Queue()

    class Service:
        def admit_workspace(self, _connection, **_kwargs):
            return {
                "ok": False,
                "error": "broker denied admission",
                "error_code": "broker_denied",
            }

    monkeypatch.setattr("supervisor.workers.get_event_q", lambda: events)
    monkeypatch.setattr(
        "ouroboros.gateway.connections.get_connection",
        lambda connection_id, *_args, **_kwargs: {
            "id": connection_id,
            "lifecycle": "active",
        },
    )
    monkeypatch.setattr(
        "ouroboros.remote_workspace.get_remote_workspace_service",
        lambda: Service(),
    )
    queue.upsert_scheduled_task({
        "id": "denied-remote-cron",
        "name": "Denied remote cron",
        "enabled": True,
        "trigger": {"type": "cron", "expr": "* * * * *"},
        "next_run_at": "2000-01-01T00:00:00+00:00",
        "task": {
            "type": "task",
            "text": "remote scheduled work",
            "project_id": "denied-remote",
        },
    })

    queue.check_scheduled_tasks()
    event = events.get(timeout=1)
    outcome = complete_requested_admission(
        event["task_id"],
        admission_id=event["admission_id"],
        admitted_task=event.get("admitted_task"),
        error=event["error"],
        reason_code=event["reason_code"],
    )

    assert outcome["status"] == "failed"
    schedule = queue.list_scheduled_tasks()["tasks"][0]
    assert schedule["failure_count"] == 1
    assert "broker_denied" in schedule["last_error"]


def test_remote_schedule_completion_does_not_overwrite_newer_fire(
    isolated_queue,
):
    from supervisor.task_lifecycle import _record_completed_scheduled_admission

    queue.upsert_scheduled_task({
        "id": "guarded-remote-cron",
        "name": "Guarded remote cron",
        "enabled": True,
        "trigger": {"type": "cron", "expr": "* * * * *"},
        "next_run_at": "2099-01-01T00:00:00+00:00",
        "last_task_id": "newer-task",
        "failure_count": 2,
        "last_error": "newer outcome",
        "task": {"type": "task", "text": "remote scheduled work"},
    })

    _record_completed_scheduled_admission(
        queue,
        {
            "id": "older-task",
            "metadata": {"schedule_id": "guarded-remote-cron"},
        },
        succeeded=False,
        reason_code="late_broker_denial",
    )

    schedule = queue.list_scheduled_tasks()["tasks"][0]
    assert schedule["failure_count"] == 2
    assert schedule["last_error"] == "newer outcome"


def test_admission_completion_broadcast_preserves_bounded_evidence(monkeypatch):
    from supervisor.events import _handle_remote_admission_result

    broadcasts = []
    monkeypatch.setattr(
        "supervisor.task_lifecycle.complete_requested_admission",
        lambda *args, **kwargs: {
            "ok": False,
            "status": "failed",
            "reason_code": "permission_denied",
        },
    )
    monkeypatch.setattr(
        "ouroboros.gateway.tasks.finish_remote_task_admission",
        lambda *args: None,
    )
    monkeypatch.setattr(
        "ouroboros.gateway.connections._broadcast_connection_state",
        lambda connection_id, payload: broadcasts.append(
            (connection_id, payload)
        ),
    )

    _handle_remote_admission_result({
        "task_id": "task-1",
        "admission_id": "admission-1",
        "connection_id": "connection-1",
        "project_id": "project-1",
        "reason_code": "permission_denied",
        "diagnostic": {
            "domain": "filesystem",
            "code": "permission_denied",
            "details": {"stderr": "Permission denied."},
        },
        "log_refs": [{"stream": "stderr", "blob_id": "log-1"}],
    }, object())

    connection_id, payload = broadcasts[0]
    assert connection_id == "connection-1"
    assert payload["status"] == "degraded"
    assert payload["diagnostic"]["code"] == "permission_denied"
    assert payload["log_refs"][0]["blob_id"] == "log-1"


def test_task_api_inherits_remote_placement_only_from_project(
    isolated_queue,
    tmp_path,
    monkeypatch,
):
    from ouroboros.gateway.connections import add_connection
    from ouroboros.gateway.tasks import api_tasks_create
    from ouroboros.projects_registry import create_project

    connection_path = tmp_path / "connections.json"
    connection = add_connection(
        name="Build", ssh_alias="build", path=connection_path
    )
    create_project(
        isolated_queue,
        "remote-project",
        workspace_ref={
            "kind": "ssh",
            "connection_id": connection["id"],
            "remote_root": "/srv/repo",
            "workspace_id": "workspace-1",
        },
    )
    events = stdlib_queue.Queue()
    monkeypatch.setattr("supervisor.workers.get_event_q", lambda: events)

    class Service:
        def admit_workspace(self, connection, **kwargs):
            return {
                "ok": True,
                "workspace_ref": {
                    "kind": "ssh",
                    "connection_id": connection["id"],
                    "remote_root": kwargs["remote_root"],
                    "workspace_id": kwargs["workspace_id"],
                },
            }

        def cancel_admission(self, task_id):
            return True

    app = Starlette(routes=[
        Route("/api/tasks", api_tasks_create, methods=["POST"]),
    ])
    app.state.drive_root = isolated_queue
    app.state.repo_dir = tmp_path / "system-repo"
    app.state.repo_dir.mkdir()
    app.state.remote_connections_path = connection_path
    app.state.remote_workspace_service = Service()
    response = TestClient(app).post(
        "/api/tasks",
        json={
            "description": "work remotely",
            "task_id": "remote-api",
            "project_id": "remote-project",
        },
    )
    assert response.status_code == 202
    assert response.json()["status"] == "requested"
    assert queue.PENDING == []
    requested = list_requested_admissions()[0]["task"]
    assert requested["metadata"]["_sealed_workspace_ref"]["connection_id"] == connection["id"]
    assert requested["metadata"]["executor_ref"] == {
        "type": "ssh_exec",
        "id": connection["id"],
        "network": "host",
        "workspace_id": "workspace-1",
    }
    event = events.get(timeout=1)
    assert event["project_id"] == "remote-project"

    rejected = TestClient(app).post(
        "/api/tasks",
        json={
            "description": "try to override",
            "project_id": "remote-project",
            "connection_id": "other",
        },
    )
    assert rejected.status_code == 400
    assert "inherited from project_id" in rejected.json()["error"]


def test_remote_broker_forces_spawn_instead_of_inheriting_fork_state(monkeypatch):
    import supervisor.workers as workers

    monkeypatch.setattr(workers, "_WORKER_START_METHOD", "fork")
    assert workers._effective_worker_start_method(lambda: object()) == "spawn"
    assert workers._effective_worker_start_method(None) == "fork"


def test_remote_broker_respawn_fails_closed_with_inherited_fork_context(
    monkeypatch,
):
    import supervisor.workers as workers

    class ForkContext:
        @staticmethod
        def get_start_method():
            return "fork"

        def Queue(self):
            raise AssertionError("respawn must fail before allocating a queue")

    monkeypatch.setattr(
        workers,
        "_remote_worker_proxy_factory",
        lambda: lambda: object(),
    )
    monkeypatch.setattr(workers, "_get_ctx", lambda: ForkContext())

    with pytest.raises(RuntimeError, match="spawn context"):
        workers.respawn_worker(7)


def test_project_create_admits_ssh_ref_and_rebind_refuses_live_tasks(
    isolated_queue,
    tmp_path,
):
    from ouroboros.gateway.connections import add_connection, get_connection
    from ouroboros.gateway.projects import api_project_update, api_projects_create
    from ouroboros.projects_registry import get_project

    connection_path = tmp_path / "project-connections.json"
    connection = add_connection(
        name="Remote", ssh_alias="remote", path=connection_path
    )

    class Service:
        def __init__(self):
            self.calls = []
            self.closed = []
            self.host_id = "host-continuity-1"

        def admit_workspace(self, conn, **kwargs):
            self.calls.append((conn, kwargs))
            return {
                "ok": True,
                "workspace_ref": {
                    "kind": "ssh",
                    "connection_id": conn["id"],
                    "remote_root": kwargs["remote_root"],
                    "workspace_id": kwargs["workspace_id"] or "allocated-workspace",
                },
                "admission_evidence": {"host_id": self.host_id},
            }

        def close_project_session(self, workspace_ref, *, project_id):
            self.closed.append((dict(workspace_ref), project_id))
            return True

    service = Service()
    app = Starlette(routes=[
        Route("/api/projects", api_projects_create, methods=["POST"]),
        Route(
            "/api/projects/{project_id}/update",
            api_project_update,
            methods=["POST"],
        ),
    ])
    app.state.drive_root = isolated_queue
    app.state.repo_dir = tmp_path / "system"
    app.state.repo_dir.mkdir()
    app.state.remote_connections_path = connection_path
    app.state.remote_workspace_service = service
    client = TestClient(app)
    created = client.post(
        "/api/projects",
        json={
            "name": "Remote project",
            "workspace_ref": {
                "kind": "ssh",
                "connection_id": connection["id"],
                "remote_root": "/srv/project",
            },
        },
    )
    assert created.status_code == 200, created.text
    project = created.json()["project"]
    assert project["working_dir"] == ""
    assert project["workspace_ref"]["workspace_id"] == "allocated-workspace"
    assert service.calls[0][1]["project_id"] == project["id"]
    assert service.calls[0][1]["task_id"] == f"project:{project['id']}"
    assert get_connection(connection["id"], connection_path)["expected_host_id"] == (
        "host-continuity-1"
    )
    service.host_id = "host-continuity-changed"
    changed = client.post(
        "/api/projects",
        json={
            "name": "Changed host project",
            "workspace_ref": {
                "kind": "ssh",
                "connection_id": connection["id"],
                "remote_root": "/srv/other-project",
            },
        },
    )
    assert changed.status_code == 409
    assert changed.json()["error_code"] == "host_identity_changed"
    assert changed.json()["action"] == "retrust"
    assert len(service.closed) == 1
    assert service.closed[0][0]["remote_root"] == "/srv/other-project"

    register_requested_admission(
        _task(
            "live-project-task",
            isolated_queue,
            project_id=project["id"],
        )
    )
    blocked = client.post(
        f"/api/projects/{project['id']}/update",
        json={"workspace_ref": None},
    )
    assert blocked.status_code == 409
    assert blocked.json()["error_code"] == "project_has_live_tasks"
    assert get_project(isolated_queue, project["id"])["workspace_ref"]["kind"] == "ssh"
    calls_before = len(service.calls)
    blocked_remote = client.post(
        f"/api/projects/{project['id']}/update",
        json={
            "workspace_ref": {
                "kind": "ssh",
                "connection_id": connection["id"],
                "remote_root": "/srv/rejected-before-admission",
            }
        },
    )
    assert blocked_remote.status_code == 409
    assert blocked_remote.json()["error_code"] == "project_has_live_tasks"
    assert len(service.calls) == calls_before


def test_remote_rebind_late_task_race_closes_only_provisional_session(
    isolated_queue,
    tmp_path,
    monkeypatch,
):
    from ouroboros.gateway import projects as projects_gateway
    from ouroboros.gateway.connections import add_connection
    from ouroboros.projects_registry import create_project, get_project

    connection_path = tmp_path / "race-connections.json"
    connection = add_connection(
        name="Remote", ssh_alias="remote", path=connection_path
    )
    project = create_project(
        isolated_queue,
        "race-project",
        workspace_ref={
            "kind": "ssh",
            "connection_id": connection["id"],
            "remote_root": "/srv/old",
            "workspace_id": "workspace-old",
        },
    )

    class Service:
        def __init__(self):
            self.calls = []

        def admit_workspace(self, conn, **kwargs):
            self.calls.append(("admit", conn["id"], dict(kwargs)))
            return {
                "ok": True,
                "workspace_ref": {
                    "kind": "ssh",
                    "connection_id": conn["id"],
                    "remote_root": kwargs["remote_root"],
                    "workspace_id": "workspace-new",
                },
                "admission_evidence": {"host_id": "host-race"},
            }

        def close_project_session(self, workspace_ref, *, project_id):
            self.calls.append(("close", dict(workspace_ref), project_id))
            return {"ok": True}

    service = Service()
    checks = iter((False, True))
    monkeypatch.setattr(
        projects_gateway,
        "_project_has_live_tasks",
        lambda _drive, _project: next(checks),
    )
    app = Starlette(
        routes=[
            Route(
                "/api/projects/{project_id}/update",
                projects_gateway.api_project_update,
                methods=["POST"],
            )
        ]
    )
    app.state.drive_root = isolated_queue
    app.state.remote_connections_path = connection_path
    app.state.remote_workspace_service = service

    response = TestClient(app).post(
        f"/api/projects/{project['id']}/update",
        json={
            "workspace_ref": {
                "kind": "ssh",
                "connection_id": connection["id"],
                "remote_root": "/srv/new",
            }
        },
    )

    assert response.status_code == 409
    assert response.json()["error_code"] == "project_has_live_tasks"
    assert [call[0] for call in service.calls] == ["admit", "close"]
    assert service.calls[1][1]["workspace_id"] == "workspace-new"
    assert service.calls[1][2] == project["id"]
    assert get_project(isolated_queue, project["id"])["workspace_ref"]["workspace_id"] == (
        "workspace-old"
    )


def test_successful_project_rebind_closes_only_the_superseded_session(
    isolated_queue,
    tmp_path,
):
    from ouroboros.gateway import projects as projects_gateway
    from ouroboros.gateway.connections import add_connection
    from ouroboros.projects_registry import create_project

    connection_path = tmp_path / "rebind-connections.json"
    connection = add_connection(
        name="Remote",
        ssh_alias="remote",
        path=connection_path,
    )
    project = create_project(
        isolated_queue,
        "rebind-project",
        workspace_ref={
            "kind": "ssh",
            "connection_id": connection["id"],
            "remote_root": "/srv/old",
            "workspace_id": "workspace-old",
        },
    )

    class Service:
        def __init__(self):
            self.closed = []

        def admit_workspace(self, conn, **kwargs):
            return {
                "ok": True,
                "workspace_ref": {
                    "kind": "ssh",
                    "connection_id": conn["id"],
                    "remote_root": kwargs["remote_root"],
                    "workspace_id": "workspace-new",
                },
                "admission_evidence": {"host_id": "host-rebind"},
            }

        def close_project_session(self, workspace_ref, *, project_id):
            self.closed.append((dict(workspace_ref), project_id))
            return True

    service = Service()
    app = Starlette(
        routes=[
            Route(
                "/api/projects/{project_id}/update",
                projects_gateway.api_project_update,
                methods=["POST"],
            )
        ]
    )
    app.state.drive_root = isolated_queue
    app.state.remote_connections_path = connection_path
    app.state.remote_workspace_service = service
    client = TestClient(app)

    rebound = client.post(
        f"/api/projects/{project['id']}/update",
        json={
            "workspace_ref": {
                "kind": "ssh",
                "connection_id": connection["id"],
                "remote_root": "/srv/new",
            }
        },
    )
    localized = client.post(
        f"/api/projects/{project['id']}/update",
        json={"workspace_ref": None},
    )

    assert rebound.status_code == 200, rebound.text
    assert localized.status_code == 200, localized.text
    assert [
        row[0]["workspace_id"] for row in service.closed
    ] == ["workspace-old", "workspace-new"]
    assert all(row[1] == project["id"] for row in service.closed)


def test_concurrent_remote_rebinds_serialize_admission_commit_and_cleanup(
    isolated_queue,
    tmp_path,
):
    import concurrent.futures

    from ouroboros.gateway import projects as projects_gateway
    from ouroboros.gateway.connections import add_connection
    from ouroboros.projects_registry import create_project, get_project

    connection_path = tmp_path / "serialized-rebind-connections.json"
    connection = add_connection(
        name="Remote",
        ssh_alias="remote",
        path=connection_path,
    )
    project = create_project(
        isolated_queue,
        "serialized-rebind-project",
        workspace_ref={
            "kind": "ssh",
            "connection_id": connection["id"],
            "remote_root": "/srv/old",
            "workspace_id": "workspace-old",
        },
    )
    first_started = threading.Event()
    release_first = threading.Event()

    class Service:
        def __init__(self):
            self.calls = []
            self.closed = []
            self.active = 0
            self.max_active = 0
            self.lock = threading.Lock()

        def admit_workspace(self, conn, **kwargs):
            with self.lock:
                self.calls.append(kwargs["remote_root"])
                call_number = len(self.calls)
                self.active += 1
                self.max_active = max(self.max_active, self.active)
            try:
                if call_number == 1:
                    first_started.set()
                    assert release_first.wait(5)
                suffix = kwargs["remote_root"].rsplit("/", 1)[-1]
                return {
                    "ok": True,
                    "workspace_ref": {
                        "kind": "ssh",
                        "connection_id": conn["id"],
                        "remote_root": kwargs["remote_root"],
                        "workspace_id": f"workspace-{suffix}",
                    },
                    "admission_evidence": {"host_id": "host-serialized"},
                }
            finally:
                with self.lock:
                    self.active -= 1

        def close_project_session(self, workspace_ref, *, project_id):
            self.closed.append((dict(workspace_ref), project_id))
            return True

    service = Service()
    app = Starlette(
        routes=[
            Route(
                "/api/projects/{project_id}/update",
                projects_gateway.api_project_update,
                methods=["POST"],
            )
        ]
    )
    app.state.drive_root = isolated_queue
    app.state.remote_connections_path = connection_path
    app.state.remote_workspace_service = service

    with TestClient(app) as client, concurrent.futures.ThreadPoolExecutor(
        max_workers=2
    ) as pool:
        first = pool.submit(
            client.post,
            f"/api/projects/{project['id']}/update",
            json={
                "workspace_ref": {
                    "kind": "ssh",
                    "connection_id": connection["id"],
                    "remote_root": "/srv/first",
                }
            },
        )
        assert first_started.wait(2)
        second = pool.submit(
            client.post,
            f"/api/projects/{project['id']}/update",
            json={
                "workspace_ref": {
                    "kind": "ssh",
                    "connection_id": connection["id"],
                    "remote_root": "/srv/second",
                }
            },
        )
        time.sleep(0.05)
        assert service.calls == ["/srv/first"]
        release_first.set()
        first_response = first.result(timeout=5)
        second_response = second.result(timeout=5)

    assert first_response.status_code == 200, first_response.text
    assert second_response.status_code == 200, second_response.text
    assert service.max_active == 1
    assert get_project(
        isolated_queue, project["id"]
    )["workspace_ref"]["workspace_id"] == "workspace-second"
    assert [row[0]["workspace_id"] for row in service.closed] == [
        "workspace-old",
        "workspace-first",
    ]


def test_project_admission_timeout_cancels_and_closes_late_transport(
    tmp_path,
    monkeypatch,
):
    import ouroboros.remote_workspace as remote_workspace
    from ouroboros.workspace_native import MANDATORY_REMOTE_NATIVE_OPERATIONS

    entered = threading.Event()
    released = threading.Event()
    closed = threading.Event()

    class Transport:
        def __init__(self, request):
            self.request = request

        def handshake(self):
            entered.set()
            assert released.wait(5)
            return {}

        def close(self):
            closed.set()

        panic = close

    manifest = {
        "schema_version": 1,
        "manifest_sha256": "a" * 64,
        "public_schema_sha256": "b" * 64,
        "native_operations": [
            {"name": name}
            for name in sorted(MANDATORY_REMOTE_NATIVE_OPERATIONS)
        ],
        "native_kernel_modules": [],
        "native_import_modules": [],
        "native_import_edges": {},
    }
    monkeypatch.setattr(
        remote_workspace,
        "get_ssh_timeout_sec",
        lambda kind: 0.05 if kind == "admission" else 5,
    )
    broker = remote_workspace.RemoteSessionBroker(
        tmp_path,
        "generation-timeout",
        manifest,
        transport_factory=Transport,
    )
    try:
        with pytest.raises(
            remote_workspace.RemoteWorkspaceError,
            match="Home deadline",
        ) as timeout:
            broker.admit_workspace(
                {"id": "connection-timeout", "ssh_alias": "timeout"},
                remote_root="/srv/timeout",
                project_id="project-timeout",
                task_id="project:project-timeout",
            )
        assert timeout.value.code == "remote_request_timeout"
        assert entered.is_set()
        released.set()
        assert closed.wait(2)
        assert broker.status()["connections"] == []
    finally:
        released.set()
        broker.close(timeout_sec=2)


def test_direct_project_room_gets_private_remote_lens_not_executor_authority(
    isolated_queue,
    monkeypatch,
):
    import supervisor.workers as workers
    from ouroboros.projects_registry import create_project

    project = create_project(
        isolated_queue,
        "room-project",
        workspace_ref={
            "kind": "ssh",
            "connection_id": "connection-1",
            "remote_root": "/srv/room",
            "workspace_id": "workspace-room",
        },
    )
    captured = []

    class Agent:
        def handle_task(self, task):
            captured.append(task)
            return []

    monkeypatch.setattr(workers, "DRIVE_ROOT", isolated_queue)
    monkeypatch.setattr(workers, "get_event_q", lambda: stdlib_queue.Queue())
    workers._run_chat_task(
        Agent(),
        int(project["chat_id"]),
        "inspect the project",
        task_metadata={"project_id": "room-project"},
    )
    metadata = captured[0]["metadata"]
    assert metadata["_project_room_workspace_ref"]["remote_root"] == "/srv/room"
    assert "_sealed_workspace_ref" not in metadata
    assert "executor_ref" not in metadata

def test_registration_fails_closed_when_required_snapshot_commit_fails(
    isolated_queue,
    monkeypatch,
):
    def fail_required_snapshot(reason="", *, required=False):
        if required:
            raise OSError("disk full")
        return False

    monkeypatch.setattr(queue, "persist_queue_snapshot", fail_required_snapshot)
    registered = register_requested_admission(
        _task("remote-persist-fail", isolated_queue)
    )

    assert registered["ok"] is False
    assert registered["error"] == "remote_admission_persistence_failed"
    assert list_requested_admissions() == []
    result = load_task_result(isolated_queue, "remote-persist-fail")
    assert result["status"] == STATUS_FAILED
    assert result["reason_code"] == "remote_admission_persistence_failed"


def test_stale_requested_snapshot_cannot_cancel_same_id_already_in_pending(
    isolated_queue,
):
    registered = register_requested_admission(_task("remote-cross-state", isolated_queue))
    stale_snapshot = json.loads(queue.QUEUE_SNAPSHOT_PATH.read_text(encoding="utf-8"))
    completed = complete_requested_admission(
        "remote-cross-state",
        admission_id=registered["admission_id"],
    )
    assert completed["status"] == "scheduled"
    queue.QUEUE_SNAPSHOT_PATH.write_text(json.dumps(stale_snapshot), encoding="utf-8")

    assert queue.restore_pending_from_snapshot() == 0
    assert [task["id"] for task in queue.PENDING] == ["remote-cross-state"]
    assert list_requested_admissions() == []
    assert load_task_result(isolated_queue, "remote-cross-state")["status"] == STATUS_SCHEDULED


def test_restore_drops_pending_duplicate_of_requested_admission(isolated_queue):
    registered = register_requested_admission(_task("remote-duplicate", isolated_queue))
    snapshot = json.loads(queue.QUEUE_SNAPSHOT_PATH.read_text(encoding="utf-8"))
    snapshot["pending"] = [
        {
            "id": "remote-duplicate",
            "task": _task("remote-duplicate", isolated_queue),
        }
    ]
    snapshot["pending_count"] = 1
    queue.QUEUE_SNAPSHOT_PATH.write_text(json.dumps(snapshot), encoding="utf-8")
    REMOTE_ADMISSIONS.clear()

    assert queue.restore_pending_from_snapshot() == 0
    assert queue.PENDING == []
    recovered = list_requested_admissions()
    assert [row["task_id"] for row in recovered] == ["remote-duplicate"]

    completed = complete_requested_admission(
        "remote-duplicate",
        admission_id=registered["admission_id"],
    )
    assert completed["status"] == "scheduled"
    assert [task["id"] for task in queue.PENDING] == ["remote-duplicate"]


@pytest.mark.parametrize("fence_field", ["acceptance_fences", "budget_root_fences"])
def test_parseable_malformed_fences_still_recover_nonrunnable_requested_state(
    isolated_queue,
    fence_field,
):
    register_requested_admission(_task(f"remote-{fence_field}", isolated_queue))
    snapshot = json.loads(queue.QUEUE_SNAPSHOT_PATH.read_text(encoding="utf-8"))
    snapshot[fence_field] = {}
    queue.QUEUE_SNAPSHOT_PATH.write_text(json.dumps(snapshot), encoding="utf-8")
    REMOTE_ADMISSIONS.clear()

    assert queue.restore_pending_from_snapshot() == 0
    assert [row["task_id"] for row in list_requested_admissions()] == [
        f"remote-{fence_field}"
    ]
    assert queue.PENDING == []


@pytest.mark.parametrize(
    ("failing_status", "completion_kwargs"),
    [
        (STATUS_SCHEDULED, {}),
        (STATUS_FAILED, {"error": "handshake failed"}),
    ],
)
def test_completion_result_write_failure_rolls_back_to_requested(
    isolated_queue,
    monkeypatch,
    failing_status,
    completion_kwargs,
):
    from ouroboros import task_results

    registered = register_requested_admission(_task("remote-write-fail", isolated_queue))
    original_write = task_results.write_task_result

    def fail_transition(drive_root, task_id, status, **fields):
        if status == failing_status:
            raise OSError("injected result write failure")
        return original_write(drive_root, task_id, status, **fields)

    monkeypatch.setattr(task_results, "write_task_result", fail_transition)
    completed = complete_requested_admission(
        "remote-write-fail",
        admission_id=registered["admission_id"],
        **completion_kwargs,
    )

    assert completed["status"] == "error"
    assert completed["reason_code"] == "remote_admission_persistence_failed"
    assert queue.PENDING == []
    assert [row["task_id"] for row in list_requested_admissions()] == [
        "remote-write-fail"
    ]
    assert load_task_result(isolated_queue, "remote-write-fail")["status"] == STATUS_REQUESTED
    snapshot = json.loads(queue.QUEUE_SNAPSHOT_PATH.read_text(encoding="utf-8"))
    assert snapshot["requested_count"] == 1
    assert snapshot["pending_count"] == 0


def test_terminal_failure_survives_required_snapshot_failure_without_live_admission(
    isolated_queue,
    monkeypatch,
):
    registered = register_requested_admission(_task("remote-terminal-snapshot", isolated_queue))
    original_persist = queue.persist_queue_snapshot

    def fail_terminal_snapshot(reason="", *, required=False):
        if reason == "remote_admission_failed" and required:
            raise OSError("injected snapshot failure")
        return original_persist(reason=reason, required=required)

    monkeypatch.setattr(queue, "persist_queue_snapshot", fail_terminal_snapshot)
    completed = complete_requested_admission(
        "remote-terminal-snapshot",
        admission_id=registered["admission_id"],
        error="handshake failed",
    )

    assert completed["status"] == "failed"
    assert completed["snapshot_persistence_degraded"] is True
    assert list_requested_admissions() == []
    assert queue.PENDING == []
    assert load_task_result(isolated_queue, "remote-terminal-snapshot")["status"] == STATUS_FAILED

    REMOTE_ADMISSIONS.clear()
    assert queue.restore_pending_from_snapshot() == 0
    assert list_requested_admissions() == []


def test_malformed_acceptance_fence_does_not_terminalize_recovered_requested_duplicate(
    isolated_queue,
):
    register_requested_admission(_task("remote-malformed-duplicate", isolated_queue))
    snapshot = json.loads(queue.QUEUE_SNAPSHOT_PATH.read_text(encoding="utf-8"))
    snapshot["acceptance_fences"] = {}
    snapshot["pending"] = [
        {
            "id": "remote-malformed-duplicate",
            "task": _task("remote-malformed-duplicate", isolated_queue),
        }
    ]
    snapshot["pending_count"] = 1
    queue.QUEUE_SNAPSHOT_PATH.write_text(json.dumps(snapshot), encoding="utf-8")
    REMOTE_ADMISSIONS.clear()

    assert queue.restore_pending_from_snapshot() == 0
    assert queue.PENDING == []
    assert [row["task_id"] for row in list_requested_admissions()] == [
        "remote-malformed-duplicate"
    ]
    assert (
        load_task_result(isolated_queue, "remote-malformed-duplicate")["status"]
        == STATUS_REQUESTED
    )
