from __future__ import annotations

import pathlib
from types import MethodType, SimpleNamespace

import pytest
import threading

from ouroboros.remote_finalization import reconcile_remote_operations
from ouroboros.remote_pending_operations import (
    load_pending_operations,
    restore_transport_tracking,
    write_pending_operation,
)
from ouroboros.remote_ssh import OpenSSHExecdTransport


def _request(tmp_path):
    return SimpleNamespace(
        connection={"id": "connection-1"},
        project_id="project-1",
        workspace_id="workspace-1",
        remote_root="/srv/project",
        drive_root=tmp_path,
    )


def _transport(tmp_path, events):
    transport = object.__new__(OpenSSHExecdTransport)
    transport.request = _request(tmp_path)
    transport._known_operations = {
        ("request-1", "operation-1"): "a" * 64,
    }
    transport._operation_contexts = {
        ("request-1", "operation-1"): {
            "task_id": "task-1",
            "operation_id": "operation-1",
            "tool": "write_file",
            "validator": None,
            "pending_record": None,
        }
    }
    transport._ensure_session = MethodType(lambda _self: None, transport)
    transport._renew_lease = MethodType(lambda _self, _task_id: None, transport)
    transport._raise_diagnostic = MethodType(lambda _self, _row: None, transport)
    transport.fetch_blob = MethodType(
        lambda _self, _blob_id, _max_bytes: b"",
        transport,
    )
    sequence = {"value": 0}

    def _send(_self, kind, **_fields):
        sequence["value"] += 1
        events.append(kind)
        if kind == "continue":
            assert len(load_pending_operations(tmp_path)) == 1
        return sequence["value"]

    transport._send = MethodType(_send, transport)
    result = {
        "kind": "result",
        "seq": 11,
        "request_id": "request-1",
        "operation_id": "operation-1",
        "result": {
            "completion": "completed",
            "prepared_hash": "a" * 64,
            "envelope": {
                "text": "ok",
                "diagnostic": None,
                "process": None,
                "artifacts": [],
                "trace": {"completion": "complete"},
            },
            "output_blobs": {},
        },
    }

    def _wait(_self, predicate, timeout_sec=None):
        del timeout_sec
        candidates = [
            result,
            {
                "kind": "ack",
                "ack_seq": sequence["value"],
                "request_id": "request-1",
                "operation_id": "operation-1",
            },
        ]
        return next(row for row in candidates if predicate(row))

    transport._wait_control = MethodType(_wait, transport)
    return transport


def test_pending_record_is_fsynced_before_continue_and_removed_after_ack(
    tmp_path,
):
    events = []
    transport = _transport(tmp_path, events)

    result = transport.execute_prepared({
        "request_id": "request-1",
        "operation_id": "operation-1",
        "prepared_hash": "a" * 64,
        "prepared_token": "secret-prepared-token",
        "task_id": "task-1",
        "_home_import_kind": "task_result_v1",
        "_home_import_context": {},
    })

    assert result["text"] == "ok"
    assert events.index("continue") < events.index("ack")
    assert load_pending_operations(tmp_path) == []


def test_pending_write_failure_prevents_continue(tmp_path, monkeypatch):
    events = []
    transport = _transport(tmp_path, events)
    monkeypatch.setattr(
        "ouroboros.remote_ssh.bind_transport_intent",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("disk full")),
    )

    with pytest.raises(OSError, match="disk full"):
        transport.execute_prepared({
            "request_id": "request-1",
            "operation_id": "operation-1",
            "prepared_hash": "a" * 64,
            "prepared_token": "secret-prepared-token",
            "task_id": "task-1",
            "_home_import_kind": "task_result_v1",
            "_home_import_context": {},
        })

    assert "continue" not in events


def test_pending_record_contains_no_execution_or_transport_secrets(tmp_path):
    record = write_pending_operation(
        _request(tmp_path),
        task_id="task-1",
        request_id="request-1",
        operation_id="operation-1",
        prepared_hash="a" * 64,
        tool="run_command",
        import_kind="task_result_v1",
        import_context={},
    )

    stored = {
        key: value
        for key, value in record.items()
        if key != "_path"
    }
    rendered = str(stored)
    for forbidden in (
        "prepared_token",
        "canonical_args",
        "blobs",
        "ssh_alias",
        "expected_host_id",
        "server_generation",
    ):
        assert forbidden not in rendered


def test_duplicate_operation_identity_with_different_hash_fails_closed(tmp_path):
    request = _request(tmp_path)
    for prepared_hash in ("a" * 64, "b" * 64):
        write_pending_operation(
            request,
            task_id="task-1",
            request_id="request-1",
            operation_id="operation-1",
            prepared_hash=prepared_hash,
            tool="write_file",
            import_kind="task_result_v1",
            import_context={},
        )

    with pytest.raises(
        RuntimeError,
        match="conflicting pending remote operation identity",
    ):
        restore_transport_tracking(request)


def test_restart_restores_closed_import_context_from_pending_file(tmp_path):
    request = _request(tmp_path)
    record = write_pending_operation(
        request,
        task_id="task-1",
        request_id="request-1",
        operation_id="operation-1",
        prepared_hash="a" * 64,
        tool="write_file",
        import_kind="task_result_v1",
        import_context={},
    )

    known, contexts = restore_transport_tracking(request)

    assert pathlib.Path(record["_path"]).name.endswith(".pending.json")
    assert known == {("request-1", "operation-1"): "a" * 64}
    assert contexts[("request-1", "operation-1")]["import_kind"] == (
        "task_result_v1"
    )
    assert contexts[("request-1", "operation-1")]["validator"] is None


def test_callable_only_import_cannot_be_persisted_before_continue(tmp_path):
    events = []
    transport = _transport(tmp_path, events)

    with pytest.raises(ValueError, match="durable remote import kind"):
        transport.execute_prepared({
            "request_id": "request-1",
            "operation_id": "operation-1",
            "prepared_hash": "a" * 64,
            "prepared_token": "prepared-1",
            "task_id": "task-1",
            "_home_completion_validator": (
                lambda _wire, envelope, _fetched: dict(envelope)
            ),
        })

    assert "continue" not in events


def test_ack_cleanup_failure_keeps_tracking_but_returns_imported_result(
    tmp_path,
    monkeypatch,
):
    events = []
    transport = _transport(tmp_path, events)
    monkeypatch.setattr(
        "ouroboros.remote_ssh._remove_transport_pending",
        lambda _context: False,
    )

    result = transport.execute_prepared({
        "request_id": "request-1",
        "operation_id": "operation-1",
        "prepared_hash": "a" * 64,
        "prepared_token": "prepared-1",
        "task_id": "task-1",
        "_home_import_kind": "task_result_v1",
        "_home_import_context": {},
    })

    assert result["text"] == "ok"
    assert ("request-1", "operation-1") in transport._known_operations
    assert len(load_pending_operations(tmp_path)) == 1


def _unavailable_transport(tmp_path, record, *, attachment=False, lose_ack=False):
    request = _request(tmp_path)
    key = ("request-1", "operation-1")
    context = {
        "task_id": "task-1",
        "operation_id": "operation-1",
        "import_kind": (
            "attachment_stage_v1" if attachment else "task_result_v1"
        ),
        "import_context": {
            "expected_manifest": []
        } if attachment else {},
        "pending_record": record,
    }
    transport = SimpleNamespace(
        request=request,
        _known_operations={key: "a" * 64},
        _operation_contexts={key: context},
        fetch_blob=lambda *_args: pytest.fail("result_unavailable fetched a blob"),
    )
    sent = []

    def send(kind, **_fields):
        sent.append(kind)
        return len(sent)

    def wait(predicate, timeout_sec=None):
        if timeout_sec is not None and lose_ack:
            raise TimeoutError("ACK was lost")
        candidates = [
            {
                "kind": "reconcile_result",
                "seq": 8,
                "request_id": "request-1",
                "operation_id": "operation-1",
                "result": {
                    "completion": "completed",
                    "result_unavailable": True,
                },
            },
            {
                "kind": "ack",
                "ack_seq": 2,
                "request_id": "request-1",
                "operation_id": "operation-1",
            },
        ]
        return next(row for row in candidates if predicate(row))

    transport._send = send
    transport._wait_control = wait
    return transport, sent


@pytest.mark.parametrize("attachment", [False, True])
def test_result_unavailable_preserves_evidence_after_ack(tmp_path, attachment):
    record = write_pending_operation(
        _request(tmp_path),
        task_id="task-1",
        request_id="request-1",
        operation_id="operation-1",
        prepared_hash="a" * 64,
        tool="_stage_task_attachments" if attachment else "write_file",
        import_kind=(
            "attachment_stage_v1" if attachment else "task_result_v1"
        ),
        import_context={"expected_manifest": []} if attachment else {},
    )
    transport, sent = _unavailable_transport(
        tmp_path,
        record,
        attachment=attachment,
    )

    rows = reconcile_remote_operations(
        transport,
        ack_timeout_sec=1.0,
        retention_cap=512,
    )

    evidence = tmp_path / rows[0]["evidence_ref"]
    assert rows[0]["imported"] is True
    assert evidence.is_file()
    assert load_pending_operations(tmp_path) == []
    assert sent == ["reconcile", "ack"]


def test_lost_ack_keeps_pending_alongside_terminal_evidence(tmp_path):
    record = write_pending_operation(
        _request(tmp_path),
        task_id="task-1",
        request_id="request-1",
        operation_id="operation-1",
        prepared_hash="a" * 64,
        tool="write_file",
        import_kind="task_result_v1",
        import_context={},
    )
    transport, _sent = _unavailable_transport(
        tmp_path,
        record,
        lose_ack=True,
    )

    rows = reconcile_remote_operations(
        transport,
        ack_timeout_sec=1.0,
        retention_cap=512,
    )

    assert (tmp_path / rows[0]["evidence_ref"]).is_file()
    assert len(load_pending_operations(tmp_path)) == 1


def test_terminal_evidence_retention_never_prunes_another_pending_intent(
    tmp_path,
):
    first = write_pending_operation(
        _request(tmp_path),
        task_id="task-1",
        request_id="request-1",
        operation_id="operation-1",
        prepared_hash="a" * 64,
        tool="write_file",
        import_kind="task_result_v1",
        import_context={},
    )
    write_pending_operation(
        _request(tmp_path),
        task_id="task-2",
        request_id="request-2",
        operation_id="operation-2",
        prepared_hash="b" * 64,
        tool="write_file",
        import_kind="task_result_v1",
        import_context={},
    )
    transport, _sent = _unavailable_transport(tmp_path, first)

    reconcile_remote_operations(
        transport,
        ack_timeout_sec=1.0,
        retention_cap=1,
    )

    pending = load_pending_operations(tmp_path)
    assert [row["operation_id"] for row in pending] == ["operation-2"]


def test_mismatched_host_is_rejected_before_reconcile(tmp_path, monkeypatch):
    import ouroboros.remote_ssh as remote_ssh

    transport = object.__new__(OpenSSHExecdTransport)
    transport.request = SimpleNamespace(
        connection={"id": "connection-1", "expected_host_id": "trusted-host"},
        project_id="project-1",
        workspace_id="workspace-1",
        remote_root="/srv/project",
        drive_root=tmp_path,
        capability_manifest={"manifest_sha256": "capability-1"},
    )
    transport._session_lock = threading.RLock()
    transport._stop = threading.Event()
    transport._process = None
    transport._reader_error = None
    transport._known_operations = {
        ("request-1", "operation-1"): "a" * 64,
    }
    transport._operation_contexts = {}
    transport._reset_wire_state = lambda: None
    transport.bootstrap = lambda: None
    transport._start_session = lambda: setattr(
        transport,
        "_handshake",
        {
            "host_id": "changed-host",
            "workspace_id": "workspace-1",
            "canonical_root": "/srv/project",
            "capability_hash": "capability-1",
        },
    )
    reconciled = []
    monkeypatch.setattr(
        remote_ssh,
        "reconcile_remote_operations",
        lambda *_args, **_kwargs: reconciled.append(True) or [],
    )

    with pytest.raises(Exception) as caught:
        transport._ensure_session()

    assert caught.value.code == "host_identity_mismatch"
    assert reconciled == []


def test_broker_startup_reopens_scope_before_reconciliation(
    tmp_path,
    monkeypatch,
):
    from ouroboros.remote_workspace import RemoteSessionBroker

    group = {
        "connection_id": "connection-1",
        "project_id": "project-1",
        "workspace_id": "workspace-1",
        "remote_root": "/srv/project",
        "records": [{"task_id": "task-1"}],
    }
    monkeypatch.setattr(
        "ouroboros.remote_pending_operations.pending_operation_groups",
        lambda _drive_root: [group],
    )
    monkeypatch.setattr(
        "ouroboros.remote_pending_operations.resolve_pending_recovery_group",
        lambda _drive_root, _group: {
            "id": "connection-1",
            "ssh_alias": "build",
        },
    )
    reconciled = []
    session = SimpleNamespace(
        key=("connection-1", "project-1", "workspace-1", "generation-2"),
        transport=SimpleNamespace(
            reconcile=lambda: reconciled.append("reconciled") or [
                {"completion": "completed"}
            ]
        ),
    )
    broker = object.__new__(RemoteSessionBroker)
    broker.drive_root = tmp_path
    broker.server_generation = "generation-2"
    broker._state_lock = threading.RLock()
    broker._sessions = {}
    broker._task_sessions = {}
    broker._admission_key_locks = {}

    def _admit(_self, payload):
        assert payload["workspace_id"] == "workspace-1"
        broker._sessions[session.key] = session
        return {}

    broker._admit_locked = MethodType(_admit, broker)

    rows = broker._recover_on_broker({})

    assert reconciled == ["reconciled"]
    assert rows == [{"completion": "completed"}]
    assert broker._task_sessions["task-1"] == session.key


def test_retired_recovery_session_is_closed_after_reconciliation(
    tmp_path,
    monkeypatch,
):
    from ouroboros.remote_workspace import RemoteSessionBroker

    group = {
        "connection_id": "connection-1",
        "project_id": "project-1",
        "workspace_id": "workspace-1",
        "remote_root": "/srv/project",
        "records": [{"task_id": "task-1"}],
    }
    monkeypatch.setattr(
        "ouroboros.remote_pending_operations.pending_operation_groups",
        lambda _drive_root: [group],
    )
    monkeypatch.setattr(
        "ouroboros.remote_pending_operations.resolve_pending_recovery_group",
        lambda _drive_root, _group: {
            "id": "connection-1",
            "ssh_alias": "build",
            "lifecycle": "retired",
        },
    )
    closed = []
    session = SimpleNamespace(
        key=("connection-1", "project-1", "workspace-1", "generation-2"),
        remote_root="/srv/project",
        transport=SimpleNamespace(
            _last_reconciliation=[{"completion": "completed"}],
            reconcile=lambda: pytest.fail(
                "startup admission already reconciled this transport"
            ),
            task_lease=lambda *_args, **_kwargs: False,
            close=lambda: closed.append(True),
        ),
    )
    broker = object.__new__(RemoteSessionBroker)
    broker.drive_root = tmp_path
    broker.server_generation = "generation-2"
    broker._state_lock = threading.RLock()
    broker._sessions = {}
    broker._task_sessions = {}
    broker._admission_key_locks = {}
    broker._service_leases = SimpleNamespace(
        discard_session=lambda _key: None,
    )
    broker._browser_forwards = SimpleNamespace(
        close_task=lambda _task_id: None,
    )

    def admit(_self, _payload):
        broker._sessions[session.key] = session
        return {}

    broker._admit_locked = MethodType(admit, broker)

    rows = broker._recover_on_broker({})

    assert rows == [{"completion": "completed"}]
    assert broker._sessions == {}
    assert broker._task_sessions == {}
    assert closed == [True]


def test_recovery_failure_is_project_scoped_on_shared_workspace(
    tmp_path,
    monkeypatch,
):
    from ouroboros.remote_workspace import RemoteSessionBroker

    groups = [
        {
            "connection_id": "connection-1",
            "project_id": project_id,
            "workspace_id": "workspace-1",
            "remote_root": "/srv/project",
            "records": [],
        }
        for project_id in ("project-a", "project-b")
    ]
    monkeypatch.setattr(
        "ouroboros.remote_pending_operations.pending_operation_groups",
        lambda _drive_root: groups,
    )

    def resolve(_drive_root, group):
        if group["project_id"] == "project-a":
            raise RuntimeError("project-a unavailable")
        return {"id": "connection-1", "ssh_alias": "build"}

    monkeypatch.setattr(
        "ouroboros.remote_pending_operations.resolve_pending_recovery_group",
        resolve,
    )
    reconciled = []
    session = SimpleNamespace(
        key=("connection-1", "project-b", "workspace-1", "generation-2"),
        transport=SimpleNamespace(
            reconcile=lambda: reconciled.append(True) or [
                {"completion": "completed"}
            ]
        ),
    )
    broker = object.__new__(RemoteSessionBroker)
    broker.drive_root = tmp_path
    broker.server_generation = "generation-2"
    broker._state_lock = threading.RLock()
    broker._sessions = {}
    broker._task_sessions = {}
    broker._admission_key_locks = {}

    def admit(_self, _payload):
        broker._sessions[session.key] = session
        return {}

    broker._admit_locked = MethodType(admit, broker)

    rows = broker._recover_on_broker({})

    assert rows[0]["project_id"] == "project-a"
    assert rows[1] == {"completion": "completed"}
    assert reconciled == [True]
