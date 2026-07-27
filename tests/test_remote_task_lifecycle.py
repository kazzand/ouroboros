"""Remote task lease cleanup at supervisor lifecycle boundaries."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from ouroboros.remote_workspace import set_remote_workspace_service
from ouroboros.task_results import STATUS_COMPLETED, write_task_result

_REMOTE_REF = {
    "kind": "ssh",
    "connection_id": "connection-1",
    "remote_root": "/srv/project",
    "workspace_id": "workspace-1",
}


@pytest.fixture(autouse=True)
def _reset_remote_workspace_service():
    set_remote_workspace_service(None)
    yield
    set_remote_workspace_service(None)


def _task(task_id: str, *, remote: bool) -> dict:
    metadata = {"_sealed_workspace_ref": dict(_REMOTE_REF)} if remote else {}
    return {
        "id": task_id,
        "type": "task",
        "chat_id": 1,
        "root_task_id": task_id,
        "text": "test task",
        "metadata": metadata,
    }


def _terminal_cost() -> dict:
    return {
        "cost_usd": 0.0,
        "total_rounds": 0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "cost_accounting_status": "available",
        "cost_final": True,
    }


def _task_done_context(drive_root, task: dict):
    return SimpleNamespace(
        DRIVE_ROOT=drive_root,
        RUNNING={task["id"]: {"task": task}},
        WORKERS={},
        bridge=SimpleNamespace(push_log=lambda _payload: None),
        persist_queue_snapshot=lambda reason="": None,
    )


def _patch_task_done_dependencies(monkeypatch, *, order: list[str]) -> None:
    from ouroboros import headless
    from supervisor import events

    monkeypatch.setattr(
        "supervisor.update_merge.abort_orphaned_assisted_tx",
        lambda _task_id: None,
    )
    monkeypatch.setattr(headless, "copy_child_task_result", lambda *_args: None)
    monkeypatch.setattr(headless, "task_is_readonly_subagent", lambda _task: False)

    def finalize(drive_root, task):
        order.append("finalize")
        write_task_result(
            drive_root,
            task["id"],
            STATUS_COMPLETED,
            result="done",
            artifact_status="ready_no_changes",
        )

    monkeypatch.setattr(headless, "finalize_task_artifacts", finalize)
    monkeypatch.setattr(
        events,
        "_checkpoint_coop_roots_on_root_done",
        lambda *_args: None,
    )
    monkeypatch.setattr(
        events,
        "_authoritative_terminal_cost",
        lambda *_args, **_kwargs: _terminal_cost(),
    )


def test_task_done_finishes_remote_lease_after_artifact_finalization(
    tmp_path,
    monkeypatch,
):
    from supervisor import events

    order: list[str] = []
    task = _task("remote-done", remote=True)
    ctx = _task_done_context(tmp_path, task)
    (tmp_path / "logs").mkdir()
    _patch_task_done_dependencies(monkeypatch, order=order)

    class Service:
        def finish_task(self, workspace_ref, *, task_id):
            assert workspace_ref == _REMOTE_REF
            assert task_id == task["id"]
            order.append("finish")
            return True

    set_remote_workspace_service(Service())

    events._handle_task_done(
        {
            "type": "task_done",
            "task_id": task["id"],
            "task_type": "task",
            "status": STATUS_COMPLETED,
        },
        ctx,
    )

    assert order == ["finalize", "finish"]
    assert task["id"] not in ctx.RUNNING


def test_local_task_done_does_not_call_remote_service(tmp_path, monkeypatch):
    from supervisor import events

    order: list[str] = []
    task = _task("local-done", remote=False)
    ctx = _task_done_context(tmp_path, task)
    (tmp_path / "logs").mkdir()
    _patch_task_done_dependencies(monkeypatch, order=order)

    class Service:
        def finish_task(self, workspace_ref, *, task_id):
            raise AssertionError(
                f"local task unexpectedly reached remote service: {workspace_ref}, {task_id}"
            )

    set_remote_workspace_service(Service())

    events._handle_task_done(
        {
            "type": "task_done",
            "task_id": task["id"],
            "task_type": "task",
            "status": STATUS_COMPLETED,
        },
        ctx,
    )

    assert order == ["finalize"]
    assert task["id"] not in ctx.RUNNING


def test_task_done_remote_cleanup_failure_is_logged_and_fail_soft(
    tmp_path,
    monkeypatch,
    caplog,
):
    from supervisor import events

    order: list[str] = []
    task = _task("remote-finish-failure", remote=True)
    ctx = _task_done_context(tmp_path, task)
    (tmp_path / "logs").mkdir()
    _patch_task_done_dependencies(monkeypatch, order=order)

    class Service:
        def finish_task(self, workspace_ref, *, task_id):
            order.append("finish")
            raise RuntimeError("injected remote cleanup failure")

    set_remote_workspace_service(Service())

    with caplog.at_level("WARNING", logger="supervisor.events"):
        events._handle_task_done(
            {
                "type": "task_done",
                "task_id": task["id"],
                "task_type": "task",
                "status": STATUS_COMPLETED,
            },
            ctx,
        )

    assert order == ["finalize", "finish"]
    assert task["id"] not in ctx.RUNNING
    assert "Failed to release remote task lease" in caplog.text


def test_running_cancel_finishes_remote_lease_before_worker_tree_kill(
    tmp_path,
    monkeypatch,
):
    from ouroboros import platform_layer
    from ouroboros.tools import services
    from supervisor import queue, workers

    drive_root = tmp_path / "data"
    (drive_root / "state").mkdir(parents=True)
    task = _task("remote-cancel", remote=True)
    running = {task["id"]: {"task": task}}
    queue.init(drive_root, 600, 1800)
    queue.init_queue_refs([], running, {"value": 0})

    order: list[str] = []

    class Process:
        pid = 4242

        def __init__(self):
            self.alive = True

        def is_alive(self):
            return self.alive

        def terminate(self):
            order.append("terminate")
            self.alive = False

        def join(self, timeout=None):
            return None

    proc = Process()
    worker = SimpleNamespace(wid=7, busy_task_id=task["id"], proc=proc)
    monkeypatch.setattr(workers, "WORKERS", {worker.wid: worker})

    class Service:
        def finish_task(self, workspace_ref, *, task_id):
            assert workspace_ref == _REMOTE_REF
            assert task_id == task["id"]
            order.append("finish")
            return True

    set_remote_workspace_service(Service())

    def kill_pid_tree(pid, *, exclude_pids=None):
        assert pid == proc.pid
        order.append("kill")
        proc.alive = False

    monkeypatch.setattr(platform_layer, "kill_pid_tree", kill_pid_tree)
    monkeypatch.setattr(queue, "_kept_service_pids", lambda: set())
    monkeypatch.setattr(queue, "_emit_cancel_task_done", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(queue, "persist_queue_snapshot", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        queue,
        "reconstruct_task_cost",
        lambda *_args, **_kwargs: _terminal_cost(),
    )
    monkeypatch.setattr(
        services,
        "archive_task_service_logs",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        workers,
        "respawn_worker",
        lambda _wid: order.append("respawn"),
    )

    assert queue._cancel_task_by_id_single(task["id"]) is True
    assert order == ["finish", "kill", "respawn"]
    assert task["id"] not in running
