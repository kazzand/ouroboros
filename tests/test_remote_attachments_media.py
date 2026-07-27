from __future__ import annotations

import hashlib
import pathlib
import subprocess
import threading
from typing import Any

import pytest

from ouroboros.execd import ExecdService
from ouroboros.execd_state import initialize_continuity_host_id
from ouroboros.remote_task_files import (
    ATTACHMENT_STAGE_OPERATION,
    MEDIA_EXPORT_OPERATION,
    RemoteTaskFileCache,
    RemoteTaskFileError,
)
from ouroboros.remote_workspace import (
    PreparedRemoteCall,
    RemoteSessionBroker,
    RemoteWorkspaceError,
    _Session,
    set_remote_workspace_service,
)
from ouroboros.tools.registry import ToolContext, ToolRegistry
from ouroboros.workspace_diagnostics import ToolExecutionEnvelope
from ouroboros.workspace_native import MANDATORY_REMOTE_NATIVE_OPERATIONS


def _git_workspace(path: pathlib.Path) -> pathlib.Path:
    path.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    return path


def _execd_manifest() -> dict[str, Any]:
    return {
        "manifest_sha256": "a" * 64,
        "native_operations": sorted(MANDATORY_REMOTE_NATIVE_OPERATIONS),
    }


def _broker_manifest() -> dict[str, Any]:
    return {
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


def _manifest(payload: bytes, *, attachment_id: str = "attachment-a") -> list[dict]:
    return [
        {
            "attachment_id": attachment_id,
            "label": "input.txt",
            "root": "artifact_store",
            "relpath": "attachments/input.txt",
            "mime": "text/plain",
            "is_image": False,
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "stage_status": "ready",
        }
    ]


def test_home_stage_freezes_manifest_and_reports_bounded_omissions(tmp_path):
    from ouroboros.artifacts import stage_task_attachments

    drive = tmp_path / "data"
    good = tmp_path / "input.txt"
    secret = tmp_path / "secret.pem"
    good.write_bytes(b"ready")
    secret.write_bytes(b"do-not-stage")
    diagnostics: list[dict] = []

    manifest = stage_task_attachments(
        drive,
        "task-a",
        [
            {"path": str(good), "label": "Input"},
            {"path": str(secret), "label": "Private key"},
            {"path": str(tmp_path / "missing"), "label": "Missing"},
        ],
        diagnostics=diagnostics,
    )

    assert len(manifest) == 1
    entry = manifest[0]
    assert {
        "attachment_id",
        "label",
        "root",
        "relpath",
        "mime",
        "is_image",
        "size",
        "sha256",
        "stage_status",
        "execution_path",
    } <= set(entry)
    assert entry["stage_status"] == "ready"
    assert entry["execution_path"] == entry["abs_path"]
    assert pathlib.Path(entry["execution_path"]).read_bytes() == b"ready"
    assert [row["reason"] for row in diagnostics] == [
        "secret_source",
        "not_readable_file",
    ]
    assert all(str(tmp_path) not in str(row) for row in diagnostics)


def test_remote_task_cache_is_atomic_private_idempotent_and_generation_scoped(
    tmp_path,
):
    state = tmp_path / "state"
    payload = b"attachment bytes"
    manifest = _manifest(payload)
    digest = manifest[0]["sha256"]
    first = RemoteTaskFileCache(
        state,
        connection_id="connection-a",
        server_generation="generation-old",
    )
    old = first.stage_attachments("task-old", manifest, {digest: payload})
    assert pathlib.Path(old[0]["execution_path"]).exists()

    cache = RemoteTaskFileCache(
        state,
        connection_id="connection-a",
        server_generation="generation-new",
    )
    assert not pathlib.Path(old[0]["execution_path"]).exists()
    staged = cache.stage_attachments("task-a", manifest, {digest: payload})
    assert cache.stage_attachments("task-a", manifest, {digest: payload}) == staged
    target = pathlib.Path(staged[0]["execution_path"])
    assert target.read_bytes() == payload
    assert target.stat().st_mode & 0o777 == 0o600
    assert target.parent.stat().st_mode & 0o777 == 0o700
    assert staged[0]["execution_path"] == staged[0]["abs_path"]
    with pytest.raises(RemoteTaskFileError, match="every and only"):
        cache.stage_attachments("task-b", manifest, {})
    assert not (cache.generation_root / "task-b").exists()
    assert cache.cleanup_task("task-a") is True
    assert not target.exists()


def test_execd_prepared_stage_and_media_export_verify_exact_bytes(tmp_path):
    workspace = _git_workspace(tmp_path / "workspace")
    (workspace / "image.png").write_bytes(b"\x89PNG\r\n\x1a\npayload")
    initialize_continuity_host_id(tmp_path / "state")
    service = ExecdService(
        tmp_path / "state",
        workspace,
        connection_id="connection-a",
        project_id="project-a",
        server_generation="generation-a",
        capability_manifest=_execd_manifest(),
        release_id="test-release",
        artifact_sha256="f" * 64,
    )
    payload = b"attachment bytes"
    manifest = _manifest(payload)
    digest = manifest[0]["sha256"]

    prepared = service.prepare(
        request_id="request-stage",
        operation_id="operation-stage",
        tool=ATTACHMENT_STAGE_OPERATION,
        args={"manifest": manifest},
        task_id="task-a",
        blobs={digest: payload},
    )
    result = service.continue_prepared(
        request_id="request-stage",
        operation_id="operation-stage",
        prepared_hash=prepared["prepared_hash"],
        prepared_token=prepared["prepared_token"],
    )
    remote_manifest = result["envelope"]["trace"]["attachment_manifest"]
    assert pathlib.Path(remote_manifest[0]["execution_path"]).read_bytes() == payload

    media = service.prepare(
        request_id="request-media",
        operation_id="operation-media",
        tool=MEDIA_EXPORT_OPERATION,
        args={"path": "image.png", "max_bytes": 1024},
        task_id="task-a",
    )
    exported = service.continue_prepared(
        request_id="request-media",
        operation_id="operation-media",
        prepared_hash=media["prepared_hash"],
        prepared_token=media["prepared_token"],
    )
    artifact = exported["envelope"]["artifacts"][0]
    assert service.fetch_blob(artifact["blob_id"], 1024) == (
        workspace / "image.png"
    ).read_bytes()

    attachment_media = service.prepare(
        request_id="request-attachment-media",
        operation_id="operation-attachment-media",
        tool=MEDIA_EXPORT_OPERATION,
        args={"attachment_id": "attachment-a", "max_bytes": 1024},
        task_id="task-a",
    )
    exported_attachment = service.continue_prepared(
        request_id="request-attachment-media",
        operation_id="operation-attachment-media",
        prepared_hash=attachment_media["prepared_hash"],
        prepared_token=attachment_media["prepared_token"],
    )
    attachment_artifact = exported_attachment["envelope"]["artifacts"][0]
    assert service.fetch_blob(attachment_artifact["blob_id"], 1024) == payload
    assert service.cancel(task_id="task-a") is True
    assert not pathlib.Path(remote_manifest[0]["execution_path"]).exists()


def test_remote_shell_allows_only_exact_manifest_bound_cache_path(tmp_path):
    registry = ToolRegistry(repo_dir=tmp_path / "repo", drive_root=tmp_path / "data")
    exact = "/state/task_files/connection/generation/task/hash.txt"
    registry.set_context(
        ToolContext(
            repo_dir=tmp_path / "repo",
            drive_root=tmp_path / "data",
            workspace_mode="external",
            task_id="task",
            task_metadata={
                "_sealed_workspace_ref": {
                    "kind": "ssh",
                    "connection_id": "connection",
                    "remote_root": "/srv/project",
                    "workspace_id": "workspace",
                },
                "_remote_attachment_manifest": [
                    {
                        "attachment_id": "attachment-a",
                        "execution_path": exact,
                    }
                ],
            },
        )
    )

    assert (
        registry._remote_shell_safety_check(
            "run_command",
            {"cmd": ["cat", exact]},
            runtime_mode="advanced",
            remote_root="/srv/project",
        )
        == ""
    )
    for blocked in (
        pathlib.PurePosixPath(exact).parent.as_posix(),
        exact + ".neighbor",
        "/state/task_files/connection/generation/other/hash.txt",
        exact + "*",
    ):
        assert "REMOTE_ATTACHMENT_PATH_BLOCKED" in (
            registry._remote_shell_safety_check(
                "run_command",
                {"cmd": ["cat", blocked]},
                runtime_mode="advanced",
                remote_root="/srv/project",
            )
        )


class _MediaService:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.digest = hashlib.sha256(payload).hexdigest()
        self.prepare_calls = 0

    def prepare(self, _ref, **kwargs):
        self.prepare_calls += 1
        args = dict(kwargs["args"])
        return PreparedRemoteCall(
            request_id=kwargs["request_id"],
            operation_id=kwargs["operation_id"],
            tool=kwargs["tool"],
            prepared_token="token",
            prepared_hash="c" * 64,
            expires_at_ms=2**63 - 1,
            execution_args=args,
            native_facts={},
        )

    def execute_prepared(self, _ref, _prepared, *, canonical_args, task_id=""):
        del canonical_args, task_id
        return ToolExecutionEnvelope(
            text="exported",
            artifacts=(
                {
                    "blob_id": self.digest,
                    "sha256": self.digest,
                    "size": len(self.payload),
                    "name": "remote.png",
                    "mime": "image/png",
                },
            ),
        )

    def abort_prepared(self, *_args, **_kwargs):
        return True

    def fetch_blob(self, _ref, blob_id, *, max_bytes):
        assert blob_id == self.digest
        assert len(self.payload) <= max_bytes
        return self.payload


def test_view_image_imports_remote_file_to_home_then_cleans_cache(tmp_path):
    payload = (
        b"\x89PNG\r\n\x1a\n"
        b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
        b"\x08\x02\x00\x00\x00\x90wS\xde"
        b"\x00\x00\x00\x0cIDAT\x08\xd7c\xf8\xcf\xc0\x00\x00\x04\x00\x01"
        b"\x01\x0b\x0c\x02\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    repo = tmp_path / "repo"
    drive = tmp_path / "data"
    repo.mkdir()
    drive.mkdir()
    registry = ToolRegistry(repo_dir=repo, drive_root=drive)
    ctx = ToolContext(
        repo_dir=repo,
        drive_root=drive,
        workspace_mode="external",
        task_id="task-a",
        task_metadata={
            "_sealed_workspace_ref": {
                "kind": "ssh",
                "connection_id": "connection-a",
                "remote_root": "/srv/project",
                "workspace_id": "workspace-a",
            }
        },
        messages=[],
    )
    registry.set_context(ctx)
    set_remote_workspace_service(_MediaService(payload))
    try:
        result = registry.execute(
            "view_image",
            {"path": "/srv/project/remote.png"},
        )
    finally:
        set_remote_workspace_service(None)

    assert "attached as a local image block" in result
    assert any(
        isinstance(message, dict) and message.get("role") == "user"
        for message in ctx.messages
    )
    assert not (
        drive / "task_drives" / "task-a" / "remote_media_cache"
    ).exists()


def test_relative_remote_media_never_borrows_home_name_collision(tmp_path):
    repo = tmp_path / "repo"
    drive = tmp_path / "data"
    repo.mkdir()
    (drive / "task_drives" / "task-a").mkdir(parents=True)
    (drive / "task_drives" / "task-a" / "same.png").write_bytes(b"home")
    registry = ToolRegistry(repo_dir=repo, drive_root=drive)
    registry.set_context(
        ToolContext(
            repo_dir=repo,
            drive_root=drive,
            workspace_mode="external",
            task_id="task-a",
            task_metadata={
                "_sealed_workspace_ref": {
                    "kind": "ssh",
                    "connection_id": "connection-a",
                    "remote_root": "/srv/project",
                    "workspace_id": "workspace-a",
                }
            },
        )
    )

    assert registry._remote_media_source(
        {
            "kind": "ssh",
            "connection_id": "connection-a",
            "remote_root": "/srv/project",
            "workspace_id": "workspace-a",
        },
        "view_image",
        {"path": "same.png"},
    ) == {"path": "same.png", "arg_key": "path"}


@pytest.mark.parametrize(
    ("tool_name", "arguments", "path_key"),
    [
        ("view_image", {"path": "remote.bin"}, "path"),
        ("ocr_pdf", {"path": "remote.bin"}, "path"),
        (
            "vlm_query",
            {"prompt": "inspect", "file_path": "remote.bin"},
            "file_path",
        ),
    ],
)
def test_remote_media_bridge_calls_existing_home_handler_and_cleans(
    tmp_path,
    tool_name,
    arguments,
    path_key,
):
    payload = b"remote-media-bytes"
    repo = tmp_path / "repo"
    drive = tmp_path / "data"
    repo.mkdir()
    drive.mkdir()
    registry = ToolRegistry(repo_dir=repo, drive_root=drive)
    ctx = ToolContext(
        repo_dir=repo,
        drive_root=drive,
        workspace_mode="external",
        task_id="task-a",
        task_metadata={
            "_sealed_workspace_ref": {
                "kind": "ssh",
                "connection_id": "connection-a",
                "remote_root": "/srv/project",
                "workspace_id": "workspace-a",
            }
        },
    )
    registry.set_context(ctx)
    entry = registry._entries[tool_name]
    original = entry.handler
    observed: list[pathlib.Path] = []

    def home_handler(_ctx, **kwargs):
        path = pathlib.Path(kwargs[path_key])
        assert path.read_bytes() == payload
        observed.append(path)
        return f"home-handler:{tool_name}"

    entry.handler = home_handler
    service = _MediaService(payload)
    set_remote_workspace_service(service)
    try:
        result = registry.execute(tool_name, dict(arguments))
    finally:
        entry.handler = original
        set_remote_workspace_service(None)

    assert result == f"home-handler:{tool_name}"
    assert service.prepare_calls == 1
    assert observed and not observed[0].exists()
    assert not (
        drive / "task_drives" / "task-a" / "remote_media_cache"
    ).exists()


def test_remote_media_bridge_cleans_cache_when_home_handler_fails(tmp_path):
    payload = b"remote-media-bytes"
    repo = tmp_path / "repo"
    drive = tmp_path / "data"
    repo.mkdir()
    drive.mkdir()
    registry = ToolRegistry(repo_dir=repo, drive_root=drive)
    registry.set_context(
        ToolContext(
            repo_dir=repo,
            drive_root=drive,
            workspace_mode="external",
            task_id="task-a",
            task_metadata={
                "_sealed_workspace_ref": {
                    "kind": "ssh",
                    "connection_id": "connection-a",
                    "remote_root": "/srv/project",
                    "workspace_id": "workspace-a",
                }
            },
        )
    )
    entry = registry._entries["ocr_pdf"]
    original = entry.handler

    def failing_home_handler(_ctx, **kwargs):
        assert pathlib.Path(kwargs["path"]).read_bytes() == payload
        raise RuntimeError("local media handler failed")

    entry.handler = failing_home_handler
    set_remote_workspace_service(_MediaService(payload))
    try:
        result = registry.execute("ocr_pdf", {"path": "remote.pdf"})
    finally:
        entry.handler = original
        set_remote_workspace_service(None)

    assert "TOOL_ERROR (ocr_pdf): local media handler failed" in result
    assert not (
        drive / "task_drives" / "task-a" / "remote_media_cache"
    ).exists()


def test_vlm_external_url_never_uses_remote_media_import(tmp_path):
    repo = tmp_path / "repo"
    drive = tmp_path / "data"
    repo.mkdir()
    drive.mkdir()
    registry = ToolRegistry(repo_dir=repo, drive_root=drive)
    registry.set_context(
        ToolContext(
            repo_dir=repo,
            drive_root=drive,
            workspace_mode="external",
            task_id="task-a",
            task_metadata={
                "_sealed_workspace_ref": {
                    "kind": "ssh",
                    "connection_id": "connection-a",
                    "remote_root": "/srv/project",
                    "workspace_id": "workspace-a",
                }
            },
        )
    )
    entry = registry._entries["vlm_query"]
    original = entry.handler
    entry.handler = lambda _ctx, **_kwargs: "external-url-handler"
    service = _MediaService(b"unused")
    set_remote_workspace_service(service)
    try:
        result = registry.execute(
            "vlm_query",
            {
                "prompt": "inspect",
                "image_url": "https://example.invalid/image.png",
            },
        )
    finally:
        entry.handler = original
        set_remote_workspace_service(None)

    assert result == "external-url-handler"
    assert service.prepare_calls == 0


class _FailingStageTransport:
    def __init__(self, request=None) -> None:
        self.request = request
        self.cancelled: list[dict] = []
        self.closed = False

    def handshake(self):
        assert self.request is not None
        return {
            "host_id": "host-a",
            "workspace_id": "workspace-a",
            "capability_hash": "a" * 64,
            "canonical_root": self.request.remote_root,
            "build": "test",
        }

    def prepare(self, message, blobs):
        del message, blobs
        raise RemoteWorkspaceError(
            "attachment_disk_full",
            "attachment stage failed",
            phase="prepare",
        )

    def cancel(self, message):
        self.cancelled.append(dict(message))
        return True

    def close(self):
        self.closed = True

    def panic(self):
        self.closed = True


@pytest.mark.parametrize("reuse_existing", [False, True])
def test_attachment_stage_failure_never_binds_task_or_poison_session(
    tmp_path,
    reuse_existing,
):
    created: list[_FailingStageTransport] = []

    def factory(request):
        transport = _FailingStageTransport(request)
        created.append(transport)
        return transport

    broker = RemoteSessionBroker(
        tmp_path,
        "generation-a",
        _broker_manifest(),
        transport_factory=factory,
    )
    connection = {
        "id": "connection-a",
        "ssh_alias": "host-a",
        "expected_host_id": "",
    }
    key = ("connection-a", "project-a", "workspace-a", "generation-a")
    existing = None
    if reuse_existing:
        existing_transport = _FailingStageTransport()
        existing = _Session(
            key,
            connection,
            "/srv/project",
            existing_transport,
            {
                "host_id": "host-a",
                "workspace_id": "workspace-a",
                "capability_hash": "a" * 64,
                "canonical_root": "/srv/project",
                "build": "test",
            },
        )
        broker._sessions[key] = existing
    payload = b"x"
    manifest = _manifest(payload)
    with pytest.raises(RemoteWorkspaceError, match="attachment stage failed"):
        broker._admit_on_broker(
            {
                "connection": connection,
                "remote_root": "/srv/project",
                "project_id": "project-a",
                "workspace_id": "workspace-a" if reuse_existing else "",
                "task_id": "task-a",
                "cancel": threading.Event(),
                "external_cancel": None,
                "attachment_manifest": manifest,
                "attachment_blobs": {
                    manifest[0]["sha256"]: payload,
                },
            }
        )
    assert "task-a" not in broker._task_sessions
    if reuse_existing:
        assert broker._sessions[key] is existing
        assert existing.transport.closed is False
        assert existing.transport.cancelled
    else:
        assert broker._sessions == {}
        assert created and created[0].closed is True
        assert created[0].cancelled
    broker.close()


def test_same_project_admission_is_singleflight_and_shares_one_session(tmp_path):
    created = []
    entered = threading.Event()
    release = threading.Event()

    class Transport:
        def __init__(self, request):
            self.request = request
            self.closed = False
            created.append(self)

        def handshake(self):
            entered.set()
            assert release.wait(2)
            return {
                "host_id": "host-a",
                "workspace_id": "workspace-a",
                "capability_hash": "a" * 64,
                "canonical_root": "/srv/project",
                "build": "test",
            }

        def cancel(self, _message):
            return True

        def close(self):
            self.closed = True

        def panic(self):
            self.closed = True

    broker = RemoteSessionBroker(
        tmp_path,
        "generation-a",
        _broker_manifest(),
        transport_factory=Transport,
    )
    connection = {
        "id": "connection-a",
        "ssh_alias": "host-a",
        "expected_host_id": "",
    }
    results = []
    errors = []

    def admit(task_id):
        try:
            results.append(
                broker._admit_on_broker(
                    {
                        "connection": connection,
                        "remote_root": "/srv/project",
                        "project_id": "project-a",
                        "workspace_id": "",
                        "task_id": task_id,
                        "cancel": threading.Event(),
                        "external_cancel": None,
                        "attachment_manifest": [],
                        "attachment_blobs": {},
                    }
                )
            )
        except Exception as exc:
            errors.append(exc)

    first = threading.Thread(target=admit, args=("task-a",))
    second = threading.Thread(target=admit, args=("task-b",))
    first.start()
    assert entered.wait(1)
    second.start()
    release.set()
    first.join(2)
    second.join(2)

    assert errors == []
    assert len(created) == 1
    assert len(results) == 2
    assert {row["workspace_ref"]["workspace_id"] for row in results} == {
        "workspace-a"
    }
    assert set(broker._task_sessions) >= {"task-a", "task-b"}
    broker.close()


@pytest.mark.parametrize("exclusive", [False, True])
def test_admission_cancel_preserves_shared_session_only(tmp_path, exclusive):
    broker = RemoteSessionBroker(
        tmp_path,
        "generation-a",
        _broker_manifest(),
    )
    transport = _FailingStageTransport()
    broker._admission_cancels["task-a"] = threading.Event()
    broker._admission_transports["task-a"] = (transport, exclusive)

    assert broker.cancel_admission("task-a") is True
    assert broker._admission_cancels["task-a"].is_set()
    assert transport.closed is exclusive
    if exclusive:
        assert transport.cancelled == []
    else:
        assert transport.cancelled[-1]["task_id"] == "task-a"
    broker.close()


def test_broker_reconnect_uses_real_transport_health_and_reconciles(tmp_path):
    handshake = {
        "host_id": "host-a",
        "workspace_id": "workspace-a",
        "capability_hash": "a" * 64,
        "canonical_root": "/srv/project",
    }

    class Transport:
        def __init__(self):
            self.reconnects = 0

        def health(self):
            return {"status": "disconnected", "phase": "connect"}

        def reconnect(self, *, timeout_sec):
            assert timeout_sec == 7
            self.reconnects += 1
            return {
                "status": "ready",
                "handshake": dict(handshake),
                "reconciliation": [
                    {
                        "request_id": "request-a",
                        "operation_id": "operation-a",
                        "completion": "completed",
                    }
                ],
            }

        def close(self):
            return None

        def panic(self):
            return None

    broker = RemoteSessionBroker(
        tmp_path,
        "generation-a",
        _broker_manifest(),
    )
    transport = Transport()
    key = ("connection-a", "project-a", "workspace-a", "generation-a")
    broker._sessions[key] = _Session(
        key,
        {"id": "connection-a", "ssh_alias": "host-a"},
        "/srv/project",
        transport,
        dict(handshake),
    )

    assert broker.health("connection-a")["connections"][0]["status"] == "disconnected"
    result = broker.reconnect_connection(
        {"id": "connection-a", "ssh_alias": "host-a"},
        timeout_sec=7,
    )

    assert result["status"] == "ready"
    assert result["completion"] == "completed"
    assert result["reconciliation"][0]["completion"] == "completed"
    assert transport.reconnects == 1
    broker.close()
