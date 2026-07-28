import hashlib
import json
import os
import stat
import threading
from types import MethodType, SimpleNamespace

import pytest

from ouroboros.remote_finalization import (
    import_remote_result_to_home,
    prefetch_remote_result_import,
)
from ouroboros.remote_ssh import OpenSSHExecdTransport


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _process_result(stdout: bytes, stderr: bytes) -> dict:
    stdout_id = _digest(stdout)
    stderr_id = _digest(stderr)
    envelope = {
        "text": ("stdout preview\n" + "x" * 70_000) + "\nstderr preview",
        "diagnostic": None,
        "process": {
            "returncode": 0,
            "stdout": "stdout preview sk-" + "A" * 30,
            "stderr": "stderr preview",
            "backend_trace": {"backend": "ssh_exec", "cwd": "/srv/project"},
            "args": ["python", "-c", "print()"],
        },
        "artifacts": [
            {
                "name": "stdout.txt",
                "blob_id": stdout_id,
                "sha256": stdout_id,
                "size": len(stdout),
                "mime": "text/plain",
                "truncated": False,
            },
            {
                "name": "stderr.txt",
                "blob_id": stderr_id,
                "sha256": stderr_id,
                "size": len(stderr),
                "mime": "text/plain",
                "truncated": False,
            },
        ],
        "trace": {"backend": "ssh_exec", "output_blobs": []},
    }
    return {
        "completion": "completed",
        "prepared_hash": "a" * 64,
        "envelope": envelope,
        "output_blobs": {stdout_id: stdout_id, stderr_id: stderr_id},
    }


def _transport_for_result(result: dict, blobs: dict[str, bytes], events: list[str]):
    transport = object.__new__(OpenSSHExecdTransport)
    transport._ensure_session = MethodType(lambda _self: None, transport)
    transport._renew_lease = MethodType(
        lambda _self, _task_id: events.append("lease"),
        transport,
    )

    def _send(_self, kind, **_fields):
        events.append(kind)
        return len(events)

    transport._send = MethodType(_send, transport)
    transport._wait_control = MethodType(
        lambda _self, _predicate: {
            "kind": "result",
            "seq": 7,
            "request_id": "request-1",
            "operation_id": "operation-1",
            "result": result,
        },
        transport,
    )
    transport._raise_diagnostic = MethodType(lambda _self, _row: None, transport)

    def _fetch(_self, blob_id, max_bytes):
        events.append(f"fetch:{blob_id}")
        payload = blobs[blob_id]
        assert len(payload) <= max_bytes
        return payload

    transport.fetch_blob = MethodType(_fetch, transport)
    return transport


def test_remote_process_outputs_import_redacted_separate_and_pre_ack(tmp_path):
    secret = b"sk-" + b"A" * 30
    stdout = b"out\xff\n" + secret + b"\n" + b"x" * 70_000
    stderr = b"err\n" + "\ufffd".encode("utf-8") + b"y" * 70_000
    result = _process_result(stdout, stderr)
    events: list[str] = []
    transport = _transport_for_result(
        result,
        {_digest(stdout): stdout, _digest(stderr): stderr},
        events,
    )

    def _import(_result, envelope, fetched):
        events.append("home-import")
        return import_remote_result_to_home(
            tmp_path,
            "task-1",
            "operation-1",
            envelope,
            fetched,
        )

    envelope = transport.execute_prepared(
        {
            "request_id": "request-1",
            "operation_id": "operation-1",
            "prepared_hash": "a" * 64,
            "prepared_token": "prepared-1",
            "task_id": "task-1",
            "_home_completion_validator": _import,
        }
    )

    assert events.index("home-import") < events.index("ack")
    assert all(events.index(item) < events.index("ack") for item in events if item.startswith("fetch:"))
    assert len(envelope["text"]) < 65_000
    assert "full redacted output is in task artifacts" in envelope["text"]
    assert secret.decode() not in json.dumps(envelope)
    assert "***REDACTED***" in envelope["process"]["stdout"]

    refs = {item["name"]: item for item in envelope["artifacts"]}
    assert set(refs) == {"stdout.txt", "stderr.txt"}
    assert refs["stdout.txt"]["source_sha256"] == _digest(stdout)
    assert refs["stderr.txt"]["source_sha256"] == _digest(stderr)
    assert "blob_id" not in refs["stdout.txt"]
    stdout_path = (
        tmp_path
        / "task_results"
        / "artifacts"
        / "task-1"
        / refs["stdout.txt"]["home_ref"]["path"]
    )
    stderr_path = (
        tmp_path
        / "task_results"
        / "artifacts"
        / "task-1"
        / refs["stderr.txt"]["home_ref"]["path"]
    )
    assert stdout_path != stderr_path
    stdout_text = stdout_path.read_text(encoding="utf-8")
    assert "\ufffd" in stdout_text
    assert secret.decode() not in stdout_text
    assert "***REDACTED***" in stdout_text
    assert stderr_path.read_text(encoding="utf-8").startswith("err\n")
    assert refs["stdout.txt"]["sha256"] == _digest(stdout_path.read_bytes())
    assert refs["stderr.txt"]["sha256"] == _digest(stderr_path.read_bytes())

    manifest = json.loads(
        (
            tmp_path
            / "task_results"
            / "artifacts"
            / "task-1"
            / ".artifact_manifest.json"
        ).read_text(encoding="utf-8")
    )
    records = list(manifest["artifacts"].values())
    assert {record["stream"] for record in records} == {"stdout", "stderr"}
    assert next(record for record in records if record["stream"] == "stdout")[
        "invalid_utf8_replaced"
    ]
    assert not next(record for record in records if record["stream"] == "stderr")[
        "invalid_utf8_replaced"
    ]
    assert list((tmp_path / "observability" / "calls" / "task-1").glob("*.json"))
    assert not (tmp_path / "observability" / "blobs").exists()


def test_externalized_envelope_recovers_process_without_fetching_unreferenced_blob(
    tmp_path,
):
    stdout = b"x" * 70_001
    stderr = b"y" * 70_002
    full_result = _process_result(stdout, stderr)
    full_envelope = full_result["envelope"]
    full_envelope["artifacts"].append(
        {
            "name": "source-report.json",
            "sha256": "b" * 64,
            "size": 123,
            "mime": "application/json",
        }
    )
    full_envelope["trace"]["source_only"] = "survives externalization"
    serialized = json.dumps(
        full_envelope,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    envelope_id = _digest(serialized)
    envelope_ref = {
        "name": "operation-envelope.json",
        "blob_id": envelope_id,
        "sha256": envelope_id,
        "size": len(serialized),
        "mime": "application/json",
        "truncated": False,
    }
    unreferenced = b"must-not-fetch"
    unreferenced_id = _digest(unreferenced)
    wire_result = {
        "completion": "completed",
        "prepared_hash": "a" * 64,
        "envelope": {
            "text": "bounded externalized preview",
            "diagnostic": None,
            "process": None,
            "artifacts": [envelope_ref],
            "trace": {"completion": "complete", "externalized_result": envelope_ref},
        },
        "output_blobs": {
            **full_result["output_blobs"],
            unreferenced_id: unreferenced_id,
        },
    }
    blobs = {
        envelope_id: serialized,
        _digest(stdout): stdout,
        _digest(stderr): stderr,
        unreferenced_id: unreferenced,
    }
    fetched_ids: list[str] = []

    def _fetch(blob_id, max_bytes):
        fetched_ids.append(blob_id)
        assert len(blobs[blob_id]) <= max_bytes
        return blobs[blob_id]

    envelope, fetched = prefetch_remote_result_import(wire_result, _fetch)
    hydrated = import_remote_result_to_home(
        tmp_path,
        "task-2",
        "operation-2",
        envelope,
        fetched,
    )

    assert fetched_ids == [envelope_id, _digest(stdout), _digest(stderr)]
    assert unreferenced_id not in fetched_ids
    assert hydrated["process"]["returncode"] == 0
    assert "sk-" + "A" * 30 not in json.dumps(hydrated)
    assert {item["name"] for item in hydrated["artifacts"]} == {
        "operation-envelope.json",
        "source-report.json",
        "stdout.txt",
        "stderr.txt",
    }
    assert "externalized_result" not in hydrated["trace"]
    assert hydrated["trace"]["source_only"] == "survives externalization"
    assert {
        item["name"] for item in hydrated["trace"]["remote_process_outputs"]
    } == {"stdout.txt", "stderr.txt"}
    envelope_home_ref = next(
        item["home_ref"]
        for item in hydrated["artifacts"]
        if item["name"] == "operation-envelope.json"
    )
    imported_envelope = (
        tmp_path
        / "task_results"
        / "artifacts"
        / "task-2"
        / envelope_home_ref["path"]
    ).read_text(encoding="utf-8")
    assert "sk-" + "A" * 30 not in imported_envelope
    assert "***REDACTED***" in imported_envelope


def test_remote_blob_integrity_failure_prevents_ack():
    stdout = b"x" * 70_001
    stderr = b"y" * 70_002
    result = _process_result(stdout, stderr)
    events: list[str] = []
    transport = _transport_for_result(
        result,
        {_digest(stdout): b"corrupt", _digest(stderr): stderr},
        events,
    )

    with pytest.raises(Exception) as caught:
        transport.execute_prepared(
            {
                "request_id": "request-1",
                "operation_id": "operation-1",
                "prepared_hash": "a" * 64,
                "prepared_token": "prepared-1",
                "task_id": "task-1",
                "_home_completion_validator": (
                    lambda _result, envelope, _fetched: envelope
                ),
            }
        )
    assert caught.value.code == "remote_result_import_failed"
    assert caught.value.phase == "import"
    assert caught.value.completion == "completed"
    assert "ack" not in events


@pytest.mark.skipif(os.name == "nt", reason="directory fsync is POSIX-only")
def test_artifact_directory_fsync_failure_prevents_ack(tmp_path, monkeypatch):
    from ouroboros import artifacts

    stdout = b"x" * 70_001
    stderr = b"y" * 70_002
    result = _process_result(stdout, stderr)
    events: list[str] = []
    transport = _transport_for_result(
        result,
        {_digest(stdout): stdout, _digest(stderr): stderr},
        events,
    )
    real_fsync = os.fsync

    def fail_directory_fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("injected directory durability failure")
        return real_fsync(fd)

    monkeypatch.setattr(artifacts.os, "fsync", fail_directory_fsync)
    with pytest.raises(Exception) as caught:
        transport.execute_prepared(
            {
                "request_id": "request-durable",
                "operation_id": "operation-durable",
                "prepared_hash": "a" * 64,
                "prepared_token": "prepared-durable",
                "task_id": "task-durable",
                "_home_completion_validator": (
                    lambda _result, envelope, fetched: import_remote_result_to_home(
                        tmp_path,
                        "task-durable",
                        "operation-durable",
                        envelope,
                        fetched,
                    )
                ),
            }
        )
    assert caught.value.code == "remote_result_import_failed"
    assert caught.value.completion == "completed"
    assert "ack" not in events


def test_no_artifact_result_manifest_failure_prevents_ack(tmp_path, monkeypatch):
    from ouroboros import observability

    result = {
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
    }
    events: list[str] = []
    transport = _transport_for_result(result, {}, events)
    monkeypatch.setattr(
        observability,
        "write_call_manifest",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            OSError("injected observability durability failure")
        ),
    )
    with pytest.raises(Exception) as caught:
        transport.execute_prepared(
            {
                "request_id": "request-observability",
                "operation_id": "operation-observability",
                "prepared_hash": "a" * 64,
                "prepared_token": "prepared-observability",
                "task_id": "task-observability",
                "_home_completion_validator": (
                    lambda _result, envelope, fetched: import_remote_result_to_home(
                        tmp_path,
                        "task-observability",
                        "operation-observability",
                        envelope,
                        fetched,
                    )
                ),
            }
        )
    assert caught.value.code == "remote_result_import_failed"
    assert caught.value.completion == "completed"
    assert "ack" not in events


def test_broker_home_completion_keeps_artifacts_wire_canonical(tmp_path):
    from ouroboros.remote_workspace import RemoteSessionBroker

    class Transport:
        def execute_prepared(self, message):
            assert message["_home_import_kind"] == "task_result_v1"
            return {
                "text": "ok",
                "diagnostic": None,
                "process": None,
                "artifacts": [],
                "trace": {"completion": "complete"},
            }

    session = SimpleNamespace(
        key=("connection-1", "project-1", "workspace-1", "generation-1"),
        transport=Transport(),
    )
    broker = object.__new__(RemoteSessionBroker)
    broker.drive_root = tmp_path
    broker._session_for_ref = MethodType(
        lambda _self, _workspace_ref, *, task_id: session,
        broker,
    )
    broker._service_leases = SimpleNamespace(observe=lambda *args, **kwargs: None)

    response = broker._execute_on_broker(
        {
            "workspace_ref": {"kind": "ssh"},
            "task_id": "task-1",
            "prepared": {
                "request_id": "request-1",
                "operation_id": "operation-1",
                "tool": "read_file",
                "prepared_token": "prepared-1",
                "prepared_hash": "a" * 64,
                "expires_at_ms": 4_102_444_800_000,
                "execution_args": {},
                "native_facts": {},
            },
            "canonical_args": {},
        }
    )

    assert response["artifacts"] == []


def test_broker_binds_inherited_tasks_before_execute_and_blob_fetch():
    from ouroboros.remote_workspace import (
        RemoteSessionBroker,
        RemoteWorkspaceError,
    )

    class Transport:
        def __init__(self, marker):
            self.marker = marker

        def prepare(self, message, _blobs):
            return {
                "request_id": message["request_id"],
                "operation_id": message["operation_id"],
                "tool": message["tool"],
                "prepared_token": f"prepared-{self.marker}",
                "prepared_hash": self.marker * 64,
                "expires_at_ms": 4_102_444_800_000,
                "execution_args": message["args"],
                "native_facts": {},
            }

        def fetch_blob(self, _blob_id, _max_bytes):
            return self.marker.encode()

    broker = object.__new__(RemoteSessionBroker)
    broker.server_generation = "generation"
    broker._state_lock = threading.RLock()
    key_a = ("connection", "project-a", "workspace", "generation")
    key_b = ("connection", "project-b", "workspace", "generation")
    session_a = SimpleNamespace(
        key=key_a,
        transport=Transport("a"),
        last_used_at=0.0,
    )
    session_b = SimpleNamespace(
        key=key_b,
        transport=Transport("b"),
        last_used_at=0.0,
    )
    broker._sessions = {key_a: session_a, key_b: session_b}
    broker._task_sessions = {"parent-a": key_a}
    workspace_ref = {
        "kind": "ssh",
        "connection_id": "connection",
        "remote_root": "/srv/project",
        "workspace_id": "workspace",
    }

    def prepare(task_id, *, parent_task_id="", project_id=""):
        return broker._prepare_on_broker(
            {
                "workspace_ref": workspace_ref,
                "request_id": f"request-{task_id}",
                "operation_id": f"operation-{task_id}",
                "tool": "read_file",
                "args": {"path": "README.md"},
                "task_id": task_id,
                "parent_task_id": parent_task_id,
                "project_id": project_id,
            }
        )

    assert prepare(
        "child-a",
        parent_task_id="parent-a",
        project_id="project-a",
    )["prepared_token"] == "prepared-a"
    assert broker._task_sessions["child-a"] == key_a
    assert prepare(
        "child-b",
        parent_task_id="finished-parent",
        project_id="project-b",
    )["prepared_token"] == "prepared-b"
    assert broker._task_sessions["child-b"] == key_b
    with pytest.raises(RemoteWorkspaceError, match="another remote workspace"):
        prepare(
            "mismatched-child",
            parent_task_id="parent-a",
            project_id="project-b",
        )
    assert "mismatched-child" not in broker._task_sessions
    assert broker._fetch_blob_on_broker(
        {
            "workspace_ref": workspace_ref,
            "task_id": "child-b",
            "blob_id": "b" * 64,
            "max_bytes": 1,
        }
    ) == b"b"
    with pytest.raises(RemoteWorkspaceError, match="not bound"):
        broker._fetch_blob_on_broker(
            {
                "workspace_ref": workspace_ref,
                "task_id": "unknown-child",
                "blob_id": "a" * 64,
                "max_bytes": 1,
            }
        )


def test_every_remote_continue_requires_closed_home_import_contract():
    stdout = b"plain"
    stderr = b""
    result = _process_result(stdout, stderr)
    events: list[str] = []
    transport = _transport_for_result(
        result,
        {_digest(stdout): stdout, _digest(stderr): stderr},
        events,
    )

    with pytest.raises(Exception) as caught:
        transport.execute_prepared(
            {
                "request_id": "request-1",
                "operation_id": "operation-1",
                "prepared_hash": "a" * 64,
                "prepared_token": "prepared-1",
                "task_id": "task-1",
            }
        )

    assert isinstance(caught.value, ValueError)
    assert "continue" not in events
    assert "ack" not in events


def test_omitted_output_projection_uses_envelope_refs_but_contradiction_fails():
    stdout = b"x" * 70_001
    stderr = b"y" * 70_002
    result = _process_result(stdout, stderr)
    blobs = {_digest(stdout): stdout, _digest(stderr): stderr}
    result.pop("output_blobs")

    _envelope, fetched = prefetch_remote_result_import(
        result,
        lambda blob_id, _max_bytes: blobs[blob_id],
    )
    assert set(fetched["process_blobs"]) == {_digest(stdout), _digest(stderr)}

    result["output_blobs"] = {}
    with pytest.raises(RuntimeError, match="not a declared output blob"):
        prefetch_remote_result_import(
            result,
            lambda blob_id, _max_bytes: blobs[blob_id],
        )
