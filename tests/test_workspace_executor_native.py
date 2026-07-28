from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import sys
from types import SimpleNamespace

import pytest

from ouroboros.remote_workspace import (
    PreparedRemoteCall,
    set_remote_workspace_service,
)
from ouroboros.tools.registry import ToolContext, ToolRegistry
from ouroboros.workspace_native import (
    execute_native_operation,
    prepare_native_operation,
)


class _Control:
    def __init__(self, *, cancel: bool = False, recovered: dict | None = None):
        self.cancel = cancel
        self.recovered = recovered
        self.registrations: list[dict] = []
        self.releases: list[dict] = []
        self.stopped_services: list[str] = []

    def cancelled(self) -> bool:
        return self.cancel

    def register_process(self, **row) -> None:
        self.registrations.append(dict(row))

    def release_process(self, **row) -> None:
        self.releases.append(dict(row))

    def recover_service(self, **row):
        del row
        return self.recovered

    def stop_service(self, *, service_id: str) -> bool:
        self.stopped_services.append(service_id)
        return True


class _FakeRemoteService:
    def __init__(self, target_root: pathlib.Path):
        self.target_root = target_root
        self.prepared: list[PreparedRemoteCall] = []
        self.executed: list[dict] = []
        self.aborted: list[str] = []
        self.blobs: dict[str, bytes] = {}

    def prepare(
        self,
        workspace_ref,
        *,
        request_id,
        operation_id,
        tool,
        args,
        blobs=None,
        deadline_ms=None,
        task_id="",
        **identity,
    ):
        del workspace_ref, deadline_ms, identity
        prepared_native = prepare_native_operation(
            self.target_root,
            tool,
            args,
            task_id=task_id,
        )
        payload = {
            "execution_args": prepared_native.execution_args,
            "native_facts": prepared_native.native_facts,
        }
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        prepared = PreparedRemoteCall(
            request_id=request_id,
            operation_id=operation_id,
            tool=tool,
            prepared_token=f"prepared-{len(self.prepared)}",
            prepared_hash=digest,
            expires_at_ms=2**63 - 1,
            execution_args=prepared_native.execution_args,
            native_facts=prepared_native.native_facts,
        )
        self.prepared.append(prepared)
        self.blobs.update(dict(blobs or {}))
        return prepared

    def execute_prepared(
        self,
        workspace_ref,
        prepared,
        *,
        canonical_args,
        task_id="",
    ):
        del workspace_ref
        assert canonical_args == prepared.execution_args
        self.executed.append(dict(canonical_args))
        result = execute_native_operation(
            self.target_root,
            prepared.tool,
            canonical_args,
            native_facts=prepared.native_facts,
            blobs=self.blobs,
            task_id=task_id,
            control=_Control(),
        )
        self.blobs.update(result.blobs)
        return result.envelope

    def abort_prepared(self, workspace_ref, prepared, *, task_id="", reason="denied"):
        del workspace_ref, task_id
        self.aborted.append(f"{prepared.prepared_token}:{reason}")
        return True

    def fetch_blob(self, workspace_ref, blob_id, *, max_bytes, **identity):
        del workspace_ref, identity
        data = self.blobs[blob_id]
        assert len(data) <= max_bytes
        return data

    def cancel(self, workspace_ref, **kwargs):
        del workspace_ref, kwargs
        return True


def _remote_registry(tmp_path, target_root):
    system = tmp_path / "system"
    data = tmp_path / "data"
    system.mkdir()
    data.mkdir()
    registry = ToolRegistry(repo_dir=system, drive_root=data)
    head = subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD"],
        cwd=target_root,
        capture_output=True,
        text=True,
    ).stdout.strip()
    registry.set_context(
        ToolContext(
            repo_dir=system,
            drive_root=data,
            workspace_mode="external",
            task_id="remote-task",
            task_metadata={
                "_sealed_workspace_ref": {
                    "kind": "ssh",
                    "connection_id": "conn",
                    "remote_root": "/srv/guaranteed-absent-on-home",
                    "workspace_id": "workspace",
                },
                "workspace_preflight": {
                    "schema_version": 1,
                    "workspace_root": "/srv/guaranteed-absent-on-home",
                    "git": {"head": head, "head_present": bool(head)},
                },
            },
            executor_ref={
                "type": "ssh_exec",
                "id": "conn",
                "workspace_id": "workspace",
            },
        )
    )
    fake = _FakeRemoteService(target_root)
    set_remote_workspace_service(fake)
    return registry, fake


def test_native_atomic_mutations_replace_final_symlink_and_preserve_modes(tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside.txt"
    outside.write_text("outside", encoding="utf-8")
    target = tmp_path / "target.txt"
    target.write_text("alpha beta\n", encoding="utf-8")
    os.chmod(target, 0o755)
    link = tmp_path / "link.txt"
    link.symlink_to(outside)

    written = execute_native_operation(
        tmp_path,
        "write_file",
        {"path": "link.txt", "content": "inside"},
    )

    assert written.envelope.diagnostic is None
    assert not link.is_symlink()
    assert link.read_text(encoding="utf-8") == "inside"
    assert outside.read_text(encoding="utf-8") == "outside"
    assert link.stat().st_mode & 0o777 == 0o644

    edited_link = tmp_path / "edit-link.txt"
    edited_link.symlink_to(target)
    edited = execute_native_operation(
        tmp_path,
        "edit_text",
        {"path": "edit-link.txt", "old_str": "alpha", "new_str": "omega"},
    )
    assert edited.envelope.diagnostic is None
    assert not edited_link.is_symlink()
    assert edited_link.read_text(encoding="utf-8") == "omega beta\n"
    assert target.read_text(encoding="utf-8") == "alpha beta\n"

    execute_native_operation(
        tmp_path,
        "write_file",
        {"path": "target.txt", "content": "changed"},
    )
    assert target.stat().st_mode & 0o777 == 0o755


def test_native_mutation_allows_internal_parent_symlink_but_blocks_escape(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    internal = tmp_path / "internal"
    internal.symlink_to(real, target_is_directory=True)
    ok = execute_native_operation(
        tmp_path,
        "write_file",
        {"path": "internal/result.txt", "content": "ok"},
    )
    assert ok.envelope.diagnostic is None
    assert (real / "result.txt").read_text(encoding="utf-8") == "ok"

    outside = tmp_path.parent / f"{tmp_path.name}-outside-dir"
    outside.mkdir()
    escaping = tmp_path / "escaping"
    escaping.symlink_to(outside, target_is_directory=True)
    blocked = execute_native_operation(
        tmp_path,
        "write_file",
        {"path": "escaping/no.txt", "content": "blocked"},
    )
    assert blocked.envelope.diagnostic is not None
    assert blocked.envelope.diagnostic.code == "permission_denied"
    assert not (outside / "no.txt").exists()


def test_native_search_honors_include_cap_and_skip_policy(tmp_path):
    (tmp_path / "a.py").write_text("needle\nneedle\n", encoding="utf-8")
    (tmp_path / "b.txt").write_text("needle\n", encoding="utf-8")
    vendor = tmp_path / "node_modules"
    vendor.mkdir()
    (vendor / "hidden.py").write_text("needle\n", encoding="utf-8")
    (tmp_path / "large.py").write_bytes(b"needle\n" + b"x" * (1024 * 1024))

    result = execute_native_operation(
        tmp_path,
        "search_code",
        {"query": "needle", "include": "*.py", "max_results": 1},
    ).envelope

    assert "a.py:1:" in result.text
    assert "b.txt" not in result.text
    assert "hidden.py" not in result.text
    assert "large.py" not in result.text
    assert result.trace["truncated"] is True


def test_native_search_surfaces_walk_permission_errors_as_partial(
    tmp_path,
    monkeypatch,
):
    import ouroboros.workspace_query_native as query_native

    denied = tmp_path / "denied"

    def broken_walk(scope, *, followlinks, onerror):
        del scope, followlinks
        onerror(PermissionError(13, "permission denied", str(denied)))
        return iter(())

    monkeypatch.setattr(query_native.os, "walk", broken_walk)
    result = execute_native_operation(
        tmp_path,
        "search_code",
        {"query": "needle"},
    ).envelope

    assert "SEARCH_PARTIAL" in result.text
    assert result.trace["completion"] == "partial"
    assert "PermissionError" in result.trace["unreadable"][0]


def test_native_edit_feedback_and_tracked_shrink_force(tmp_path):
    path = tmp_path / "tracked.txt"
    path.write_text("first needle\nsecond needle\n" + "x" * 200, encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "tracked.txt"], cwd=tmp_path, check=True)

    multiple = execute_native_operation(
        tmp_path,
        "edit_text",
        {"path": "tracked.txt", "old_str": "needle", "new_str": "value"},
    ).envelope.text
    assert "found 2 times" in multiple
    assert "line 1, line 2" in multiple

    missing = execute_native_operation(
        tmp_path,
        "edit_text",
        {"path": "tracked.txt", "old_str": "absent", "new_str": "value"},
    ).envelope.text
    assert "File preview (first 2000 chars)" in missing

    blocked = execute_native_operation(
        tmp_path,
        "write_file",
        {"path": "tracked.txt", "content": "short"},
    ).envelope.text
    assert blocked.startswith("⚠️ WRITE_BLOCKED")
    forced = execute_native_operation(
        tmp_path,
        "write_file",
        {"path": "tracked.txt", "content": "short", "force": True},
    ).envelope
    assert forced.diagnostic is None
    assert path.read_text(encoding="utf-8") == "short"


def test_remote_context_home_cwd_processes_do_not_hit_remote_broker(tmp_path):
    target = tmp_path / "actual-remote"
    target.mkdir()
    registry, fake = _remote_registry(tmp_path, target)
    task_drive = pathlib.Path(registry._ctx.drive_root) / "task_drives" / "remote-task"
    task_drive.mkdir(parents=True)
    try:
        command = registry.execute(
            "run_command",
            {"cmd": [sys.executable, "-c", "import os; print(os.getcwd())"], "cwd": "task_drive"},
        )
        script = registry.execute(
            "run_script",
            {"script": "print('home-script')", "cwd": "task_drive"},
        )
    finally:
        set_remote_workspace_service(None)
    assert str(task_drive) in command
    assert "home-script" in script
    assert fake.prepared == []


def test_keepalive_service_remains_an_active_connection_lease_after_task_finish(tmp_path):
    from ouroboros.remote_service_leases import RemoteServiceLeaseBook
    from ouroboros.remote_workspace import RemoteSessionBroker

    manifest = {
        "schema_version": 1,
        "manifest_sha256": "a" * 64,
        "public_schema_sha256": "b" * 64,
        "native_operations": [],
        "native_kernel_modules": [],
        "native_import_modules": [],
        "native_import_edges": {},
    }
    broker = RemoteSessionBroker(tmp_path, "generation", manifest)
    key = ("connection", "project", "workspace", "generation")
    prepared = SimpleNamespace(
        tool="start_service",
        execution_args={"name": "web", "keep_alive": True},
        native_facts={},
    )
    broker._service_leases = RemoteServiceLeaseBook()
    broker._service_leases.observe(
        key,
        prepared,
        {"diagnostic": None, "trace": {"service_ref": {"service_id": "service", "name": "web"}}},
        task_id="finished-task",
    )
    assert broker.has_active_lease("connection") is True
    broker._service_leases.observe(
        key,
        SimpleNamespace(
            tool="service_status",
            execution_args={},
            native_facts={"service_id": "service"},
        ),
        {"diagnostic": None, "trace": {"running": False}},
        task_id="finished-task",
    )
    assert broker.has_active_lease("connection") is False
    broker.close()


def test_native_process_drains_large_stdout_without_pipe_deadlock(tmp_path):
    control = _Control()
    result = execute_native_operation(
        tmp_path,
        "run_command",
        {
            "cmd": [sys.executable, "-c", "import sys; sys.stdout.write('x'*300000)"],
            "cwd": str(tmp_path),
            "timeout_sec": 10,
        },
        control=control,
    )

    assert result.envelope.process is not None
    assert result.envelope.process.returncode == 0
    assert len(result.envelope.process.stdout) < 100000
    output_artifact = result.envelope.artifacts[0]
    assert output_artifact["name"] == "stdout.txt"
    assert len(result.blobs[output_artifact["blob_id"]]) == 300000
    assert control.registrations and control.registrations[0]["pgid"] > 0
    assert control.releases == [{"pgid": control.registrations[0]["pgid"]}]


def test_native_process_cancel_is_registered_then_terminated(tmp_path):
    control = _Control(cancel=True)
    result = execute_native_operation(
        tmp_path,
        "run_command",
        {
            "cmd": [sys.executable, "-c", "import time; time.sleep(30)"],
            "cwd": str(tmp_path),
            "timeout_sec": 60,
        },
        control=control,
    )

    assert control.registrations
    assert result.envelope.diagnostic is not None
    assert result.envelope.diagnostic.domain == "process"
    assert result.envelope.diagnostic.completion == "unknown"


def test_native_frame_extraction_releases_registered_process(tmp_path, monkeypatch):
    source = tmp_path / "clip.mp4"
    source.write_bytes(b"video")
    second = tmp_path / "second.mp4"
    second.write_bytes(b"video-two")

    class _CompletedFfmpeg:
        pid = 1234
        returncode = 0

        def __init__(self, command, **kwargs):
            del kwargs
            pathlib.Path(command[-1]).write_bytes(b"\xff\xd8frame\xff\xd9")

        def poll(self):
            return self.returncode

        def communicate(self):
            return b"", b""

    monkeypatch.setattr(
        "ouroboros.workspace_native.subprocess.Popen",
        _CompletedFfmpeg,
    )
    monkeypatch.setattr(
        "ouroboros.workspace_native._ffmpeg_binary",
        lambda *_args: "/verified/ffmpeg",
    )
    monkeypatch.setattr(
        "ouroboros.workspace_native.process_group_id",
        lambda pid: 4321,
    )
    control = _Control()

    result = execute_native_operation(
        tmp_path,
        "extract_video_frames",
        {"path": "clip.mp4"},
        control=control,
    )
    spaced = execute_native_operation(
        tmp_path,
        "extract_video_frames",
        {"path": "second.mp4", "timestamps": "0 1.5", "max_frames": 12},
        control=control,
    )
    capped = execute_native_operation(
        tmp_path,
        "extract_video_frames",
        {"path": "second.mp4", "max_frames": 99},
        control=control,
    )

    assert len(result.envelope.artifacts) == 5
    assert [row["timestamp"] for row in result.envelope.artifacts] == [
        "0", "1", "2", "3", "4",
    ]
    assert [row["name"] for row in result.envelope.artifacts] == [
        f"clip_frame_{index:02d}.jpg" for index in range(1, 6)
    ]
    assert [row["timestamp"] for row in spaced.envelope.artifacts] == ["0", "1.5"]
    assert len(capped.envelope.artifacts) == 12
    assert {
        row["name"] for row in result.envelope.artifacts
    }.isdisjoint({row["name"] for row in spaced.envelope.artifacts})
    assert result.envelope.artifacts[0]["mime"] == "image/jpeg"
    assert control.registrations == [{"pgid": 4321}] * 19
    assert control.releases == [{"pgid": 4321}] * 19


def test_recovered_service_stop_uses_verified_custody_seam(tmp_path, monkeypatch):
    service_id = "opaque-recovered-service"
    control = _Control(
        recovered={
            "service_id": service_id,
            "task_id": "task-recovered",
            "pgid": 9876,
            "started_at_ms": 123,
        }
    )

    def _forbid_direct_group_kill(*args, **kwargs):
        del args, kwargs
        raise AssertionError("recovered services must be stopped by custody")

    monkeypatch.setattr(
        "ouroboros.workspace_native.kill_process_group_id",
        _forbid_direct_group_kill,
    )
    result = execute_native_operation(
        tmp_path,
        "stop_service",
        {"name": "web"},
        native_facts={
            "workspace_root": tmp_path.as_posix(),
            "service_id": service_id,
        },
        task_id="task-recovered",
        control=control,
    )

    assert result.envelope.text == "OK: service 'web' stopped."
    assert control.stopped_services == [service_id]
    assert control.releases == [{"pgid": 9876, "service_id": service_id}]


def test_absolute_ambiguous_path_is_classified_on_target(tmp_path):
    nested = tmp_path / "src" / "main.py"
    nested.parent.mkdir()
    nested.write_text("pass\n")

    prepared = prepare_native_operation(
        tmp_path,
        "classify_ambiguous_workspace_path",
        {"path": str(nested)},
    )
    result = execute_native_operation(
        tmp_path,
        "classify_ambiguous_workspace_path",
        prepared.execution_args,
        native_facts=prepared.native_facts,
    )

    assert result.envelope.trace["inside_workspace"] is True
    assert result.envelope.trace["relative_path"] == "src/main.py"


def test_native_services_are_task_scoped_and_follow_opaque_id(tmp_path):
    first = execute_native_operation(
        tmp_path,
        "start_service",
        {
            "name": "web",
            "cmd": [sys.executable, "-c", "import time; time.sleep(30)"],
            "cwd": str(tmp_path),
        },
        task_id="task-a",
        control=_Control(),
    )
    second = execute_native_operation(
        tmp_path,
        "start_service",
        {
            "name": "web",
            "cmd": [sys.executable, "-c", "import time; time.sleep(30)"],
            "cwd": str(tmp_path),
        },
        task_id="task-b",
        control=_Control(),
    )
    first_ref = first.envelope.trace["service_ref"]
    second_ref = second.envelope.trace["service_ref"]
    assert first_ref["service_id"] != second_ref["service_id"]

    try:
        prepared = prepare_native_operation(
            tmp_path,
            "service_status",
            {"name": "web", "_service_ref": first_ref},
            task_id="task-a",
        )
        status = execute_native_operation(
            tmp_path,
            "service_status",
            prepared.execution_args,
            native_facts=prepared.native_facts,
            task_id="task-a",
        )
        assert status.envelope.trace["service_ref"]["service_id"] == first_ref["service_id"]

        wrong_task = execute_native_operation(
            tmp_path,
            "service_status",
            prepared.execution_args,
            native_facts=prepared.native_facts,
            task_id="task-b",
        )
        assert "SERVICE_NOT_FOUND" in wrong_task.envelope.text
    finally:
        for task_id, service_ref in (("task-a", first_ref), ("task-b", second_ref)):
            prepared = prepare_native_operation(
                tmp_path,
                "stop_service",
                {"name": "web", "_service_ref": service_ref},
                task_id=task_id,
            )
            execute_native_operation(
                tmp_path,
                "stop_service",
                prepared.execution_args,
                native_facts=prepared.native_facts,
                task_id=task_id,
            )


def test_native_diagnostics_scrub_secrets_without_losing_errno(tmp_path):
    result = execute_native_operation(
        tmp_path,
        "read_file",
        {"path": "missing?token=supersecret"},
    )

    assert result.envelope.diagnostic is not None
    assert result.envelope.diagnostic.errno is not None
    assert "supersecret" not in result.envelope.text
    assert "[REDACTED]" in result.envelope.text


def test_registry_routes_remote_read_without_home_workspace_path(tmp_path):
    target = tmp_path / "actual-remote"
    target.mkdir()
    (target / "hello.txt").write_text("remote-only\n")
    registry, fake = _remote_registry(tmp_path, target)
    try:
        result = registry.execute(
            "read_file",
            {
                "root": "active_workspace",
                "path": "/srv/guaranteed-absent-on-home/hello.txt",
            },
        )
    finally:
        set_remote_workspace_service(None)

    assert "remote-only" in result
    assert [row.tool for row in fake.prepared] == ["read_file"]
    assert fake.executed[0]["path"] == "hello.txt"


def test_registry_uses_target_prepared_python_and_exact_canonical_args(tmp_path):
    target = tmp_path / "actual-remote"
    target.mkdir()
    venv_python = target / ".venv" / "bin" / "python"
    venv_python.parent.mkdir(parents=True)
    venv_python.symlink_to(sys.executable)
    registry, fake = _remote_registry(tmp_path, target)
    try:
        result = registry.execute(
            "run_script",
            {
                "script": "print('target-python')",
                "interpreter": "python3",
            },
        )
    finally:
        set_remote_workspace_service(None)

    assert "target-python" in result
    assert fake.executed[0]["interpreter"] == str(venv_python)
    assert fake.executed[0] == fake.prepared[0].execution_args


def test_registry_blocks_remote_shell_before_prepare(tmp_path):
    target = tmp_path / "actual-remote"
    target.mkdir()
    registry, fake = _remote_registry(tmp_path, target)
    try:
        result = registry.execute(
            "run_command",
            {"cmd": ["sudo", "cat", "/etc/shadow"]},
        )
    finally:
        set_remote_workspace_service(None)

    assert "SUDO_INTERACTIVE_BLOCKED" in result
    assert fake.prepared == []
    assert fake.executed == []


def test_remote_snapshot_bridge_verifies_and_materializes_cas(tmp_path):
    from ouroboros.workspace_executor import materialize_remote_workspace_snapshot

    target = tmp_path / "actual-remote"
    target.mkdir()
    (target / "nested").mkdir()
    (target / "nested" / "data.bin").write_bytes(b"\x00remote\xff")
    registry, fake = _remote_registry(tmp_path, target)
    try:
        snapshot = materialize_remote_workspace_snapshot(registry._ctx)
        materialized_root = snapshot.root
        assert (materialized_root / "nested" / "data.bin").read_bytes() == b"\x00remote\xff"
        assert snapshot.manifest["complete"] is True
        snapshot.close()
        assert not materialized_root.exists()
    finally:
        set_remote_workspace_service(None)


def test_remote_review_evidence_is_target_diff_and_fingerprint_bound(tmp_path):
    from ouroboros.review_evidence import collect_turn_diff

    target = tmp_path / "actual-remote"
    target.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=target, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=target, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=target, check=True)
    (target / "tracked.txt").write_text("before\n")
    subprocess.run(["git", "add", "tracked.txt"], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=target, check=True)
    (target / "tracked.txt").write_text("after\n")
    registry, fake = _remote_registry(tmp_path, target)
    try:
        evidence = collect_turn_diff(registry._ctx)
    finally:
        set_remote_workspace_service(None)

    assert "Remote snapshot fingerprint:" in evidence
    assert "-before" in evidence
    assert "+after" in evidence
    assert "/srv/guaranteed-absent-on-home" not in evidence


def test_remote_patch_export_imports_verified_blob_to_home(tmp_path):
    from ouroboros.headless import write_remote_workspace_patch_artifacts

    target = tmp_path / "actual-remote"
    target.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=target, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=target, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=target, check=True)
    (target / "tracked.txt").write_text("before\n")
    subprocess.run(["git", "add", "tracked.txt"], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=target, check=True)
    (target / "tracked.txt").write_text("after\n")
    (target / "new.txt").write_text("new\n")
    registry, fake = _remote_registry(tmp_path, target)
    artifact_dir = tmp_path / "artifacts"
    try:
        artifacts, manifest = write_remote_workspace_patch_artifacts(
            {
                "id": "remote-task",
                "metadata": registry._ctx.task_metadata,
            },
            artifact_dir,
        )
    finally:
        set_remote_workspace_service(None)

    patch = (artifact_dir / "workspace.patch").read_text()
    assert manifest["status"] == "ready_with_changes"
    assert manifest["snapshot_fingerprint"]
    assert "-before" in patch and "+after" in patch
    assert "new.txt" in patch
    assert any(item["kind"] == "workspace_patch" for item in artifacts)


@pytest.mark.parametrize("object_format", ["sha1", "sha256"])
def test_remote_patch_export_uses_target_empty_tree_for_unborn_git(
    tmp_path,
    object_format,
):
    from ouroboros.headless import write_remote_workspace_patch_artifacts

    target = tmp_path / "actual-remote"
    target.mkdir()
    init = subprocess.run(
        ["git", "init", "-q", f"--object-format={object_format}"],
        cwd=target,
        capture_output=True,
        text=True,
    )
    if init.returncode:
        pytest.skip(f"Git does not support {object_format}: {init.stderr}")
    (target / "new.txt").write_text("new unborn content\n")
    registry, _fake = _remote_registry(tmp_path, target)
    artifact_dir = tmp_path / "artifacts"
    task = {
        "id": "remote-task",
        "project_id": "project",
        "metadata": registry._ctx.task_metadata,
    }
    try:
        _artifacts, manifest = write_remote_workspace_patch_artifacts(
            task,
            artifact_dir,
        )
    finally:
        set_remote_workspace_service(None)

    empty_tree = subprocess.run(
        ["git", "hash-object", "-t", "tree", "--stdin"],
        cwd=target,
        input=b"",
        capture_output=True,
        check=True,
    ).stdout.decode().strip()
    assert manifest["status"] == "ready_with_changes"
    assert manifest["base_is_empty_tree"] is True
    assert manifest["base_ref"] == empty_tree
    assert len(empty_tree) == (64 if object_format == "sha256" else 40)
    assert "new.txt" in (artifact_dir / "workspace.patch").read_text()


def test_remote_patch_export_rejects_head_drift_after_admission(tmp_path):
    from ouroboros.headless import write_remote_workspace_patch_artifacts

    target = tmp_path / "actual-remote"
    target.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=target, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=target, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=target, check=True)
    (target / "tracked.txt").write_text("before\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked.txt"], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=target, check=True)
    registry, _fake = _remote_registry(tmp_path, target)
    (target / "tracked.txt").write_text("external head\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked.txt"], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "external"], cwd=target, check=True)
    try:
        with pytest.raises(RuntimeError, match="workspace HEAD changed"):
            write_remote_workspace_patch_artifacts(
                {
                    "id": "remote-task",
                    "metadata": registry._ctx.task_metadata,
                },
                tmp_path / "artifacts-drift",
            )
    finally:
        set_remote_workspace_service(None)


def test_remote_verify_runs_on_target_and_records_home_receipt(tmp_path):
    target = tmp_path / "actual-remote"
    target.mkdir()
    registry, fake = _remote_registry(tmp_path, target)
    try:
        result = registry.execute(
            "verify_and_record",
            {
                "contract_kind": "explicit_command",
                "criterion_id": "remote-check",
                "check": [sys.executable, "-c", "print('remote-green')"],
                "expected": "remote-green",
                "criterion_source": "task_stated",
            },
        )
    finally:
        set_remote_workspace_service(None)

    assert "PASS" in result
    assert "remote-green" in result
    assert fake.prepared[0].tool == "verify_remote_check"
    receipt_path = (
        registry._ctx.drive_root
        / "task_results"
        / "artifacts"
        / "remote-task"
        / "verification_receipts.jsonl"
    )
    assert receipt_path.is_file()


@pytest.mark.parametrize(
    "protected_paths",
    [
        ["reference", "secret.py"],
        ["/workspace/reference", "/workspace/secret.py"],
    ],
)
def test_remote_protected_artifacts_block_reads_but_allow_execution(
    tmp_path,
    protected_paths,
):
    target = tmp_path / "actual-remote"
    target.mkdir()
    reference = target / "reference"
    reference.write_text("#!/bin/sh\necho reference-ok\n")
    reference.chmod(0o700)
    (target / "secret.py").write_text("def hidden_symbol():\n    return 1\n")
    (target / "visible.txt").write_text("visible\n")
    registry, fake = _remote_registry(tmp_path, target)
    record = {
        "id": "reference",
        "role": "black_box_reference",
        "paths": protected_paths,
        "allow": ["execute"],
    }
    registry._ctx.task_contract = {
        "resource_policy": {"protected_artifacts": [record]}
    }
    registry._ctx.task_metadata["task_contract"] = registry._ctx.task_contract
    try:
        direct = registry.execute(
            "read_file",
            {"path": "reference", "root": "active_workspace"},
        )
        shell_read = registry.execute(
            "run_command",
            {"cmd": ["cat", "reference"]},
        )
        write = registry.execute(
            "write_file",
            {"path": "reference", "content": "stolen"},
        )
        byte_probe = registry.execute(
            "verify_and_record",
            {
                "contract_kind": "explicit_command",
                "check": [sys.executable, "-c", "print('checked')"],
                "expected_match": "bytes_equal",
                "artifact_paths": ["reference", "visible.txt"],
            },
        )
        executed = registry.execute(
            "run_command",
            {"cmd": ["./reference"]},
        )
        search = registry.execute(
            "search_code",
            {"query": "hidden_symbol", "path": "."},
        )
        query = registry.execute(
            "query_code",
            {"op": "symbols", "path": "."},
        )
    finally:
        set_remote_workspace_service(None)

    assert "RESOURCE_POLICY_BLOCKED" in direct
    assert "RESOURCE_POLICY_BLOCKED" in shell_read
    assert "RESOURCE_POLICY_BLOCKED" in write
    assert "bytes_equal refused" in byte_probe
    assert "reference-ok" in executed
    assert "No matches found" in search
    assert "hidden_symbol" not in query
    assert [prepared.tool for prepared in fake.prepared] == [
        "run_command",
        "search_code",
        "query_code",
    ]
    assert fake.prepared[-1].native_facts["protected_paths"] == [
        "reference",
        "secret.py",
    ]


def test_remote_project_room_lens_is_read_only_and_never_grants_processes(
    tmp_path,
    monkeypatch,
):
    target = tmp_path / "actual-remote"
    target.mkdir()
    (target / "room.txt").write_text("remote-room\n")
    (target / "search.txt").write_text("remote-needle\n")
    registry, fake = _remote_registry(tmp_path, target)
    monkeypatch.setattr(
        "ouroboros.tools.registry._builtin_tool_availability",
        lambda name, ctx: (True, "", ""),
    )
    room_ref = registry._ctx.task_metadata.pop("_sealed_workspace_ref")
    registry._ctx.task_metadata["_project_room_workspace_ref"] = room_ref
    try:
        read = registry.execute(
            "read_file",
            {"path": "room.txt", "root": "active_workspace"},
        )
        listed = registry.execute(
            "list_files",
            {"path": ".", "root": "active_workspace"},
        )
        searched = registry.execute(
            "search_code",
            {
                "query": "remote-needle",
                "path": ".",
                "root": "active_workspace",
            },
        )
        write = registry.execute(
            "write_file",
            {
                "path": "room.txt",
                "content": "changed",
                "root": "active_workspace",
            },
        )
        active_workspace_calls = {
            "query_code": {"op": "symbols", "path": ".", "root": "active_workspace"},
            "run_command": {"cmd": ["pwd"], "cwd": "active_workspace"},
            "vcs_status": {},
            "start_service": {"name": "web", "cmd": [sys.executable, "-m", "http.server"]},
            "service_status": {"name": "web"},
            "claude_code_edit": {"prompt": "change room.txt"},
            "integrate_subagent_patch": {
                "task_id": "child",
                "decision": "apply",
            },
            "verify_and_record": {
                "contract_kind": "explicit_command",
                "check": [sys.executable, "-c", "print('checked')"],
            },
        }
        blocked = {
            name: registry.execute(name, call_args)
            for name, call_args in active_workspace_calls.items()
        }
        home = registry.execute(
            "run_command",
            {"cmd": [sys.executable, "-c", "print('home-ok')"], "cwd": "task_drive"},
        )
    finally:
        set_remote_workspace_service(None)

    assert "remote-room" in read
    assert "room.txt" in listed
    assert "remote-needle" in searched
    assert "ROOM_ACTIVE_WORKSPACE_REQUIRES_TASK" in write
    assert all(
        "ROOM_ACTIVE_WORKSPACE_REQUIRES_TASK" in result
        for result in blocked.values()
    )
    assert "home-ok" in home
    assert [prepared.tool for prepared in fake.prepared] == [
        "read_file",
        "list_files",
        "search_code",
    ]
    assert (target / "room.txt").read_text() == "remote-room\n"


def test_remote_project_room_invalid_ref_fails_loud(tmp_path):
    target = tmp_path / "actual-remote"
    target.mkdir()
    (target / "room.txt").write_text("remote-room\n")
    registry, fake = _remote_registry(tmp_path, target)
    registry._ctx.task_metadata.pop("_sealed_workspace_ref")
    registry._ctx.task_metadata["_project_room_workspace_ref"] = {
        "kind": "ssh",
        "connection_id": "conn",
        "remote_root": "relative/path",
        "workspace_id": "workspace",
    }
    try:
        result = registry.execute(
            "read_file",
            {"path": "room.txt", "root": "active_workspace"},
        )
    finally:
        set_remote_workspace_service(None)

    assert "WORKSPACE_REF_INVALID" in result
    assert "NOT_FOUND" not in result
    assert not fake.prepared


def test_remote_verify_records_bytes_equal_and_artifact_lifecycle(tmp_path):
    target = tmp_path / "actual-remote"
    work_dir = target / "subdir"
    work_dir.mkdir(parents=True)
    (work_dir / "a.bin").write_bytes(b"same")
    (work_dir / "b.bin").write_bytes(b"same")
    registry, fake = _remote_registry(tmp_path, target)
    try:
        equal = registry.execute(
            "verify_and_record",
            {
                "contract_kind": "explicit_command",
                "check": [sys.executable, "-c", "print('checked')"],
                "expected_match": "bytes_equal",
                "artifact_paths": ["a.bin", "b.bin"],
                "cwd": "subdir",
            },
        )
        lifecycle = registry.execute(
            "verify_and_record",
            {
                "contract_kind": "explicit_command",
                "check": [sys.executable, "-c", "print('checked')"],
                "expected": "checked",
                "artifact_paths": ["a.bin", "missing.bin"],
                "cwd": "subdir",
            },
        )
    finally:
        set_remote_workspace_service(None)

    assert "PASS" in equal and "bytes_equal" in equal
    assert "PASS" in lifecycle
    receipt_path = (
        registry._ctx.drive_root
        / "task_results"
        / "artifacts"
        / "remote-task"
        / "verification_receipts.jsonl"
    )
    receipts = [
        json.loads(line)
        for line in receipt_path.read_text().splitlines()
        if line.strip()
    ]
    assert receipts[0]["matched"] is True
    assert all(
        row["exists_after"] is True
        for row in receipts[0]["artifact_lifecycle"]
    )
    assert receipts[1]["artifacts_missing_after"] == ["missing.bin"]
    assert fake.prepared[0].execution_args["expected_match"] == "bytes_equal"
    assert fake.prepared[0].execution_args["cwd"] == str(work_dir)


def test_local_verify_keeps_missing_check_precedence_for_bytes_equal(tmp_path):
    system = tmp_path / "system"
    data = tmp_path / "data"
    system.mkdir()
    data.mkdir()
    registry = ToolRegistry(repo_dir=system, drive_root=data)

    result = registry.execute(
        "verify_and_record",
        {
            "contract_kind": "explicit_command",
            "expected_match": "bytes_equal",
            "artifact_paths": ["only-one.bin"],
        },
    )

    assert "requires `check`" in result
    assert "exactly two" not in result


def test_remote_search_excludes_protected_paths_before_metadata(
    tmp_path,
    monkeypatch,
):
    protected = tmp_path / "secret.py"
    protected.write_text("hidden_symbol = 1\n")
    unreadable = tmp_path / "unreadable.py"
    unreadable.write_text("needle = 1\n")
    visible = tmp_path / "visible.py"
    visible.write_text("visible = 1\n")
    original_lstat = pathlib.Path.lstat
    calls: dict[pathlib.Path, int] = {}

    def guarded_lstat(path):
        resolved = pathlib.Path(path).resolve(strict=False)
        calls[resolved] = calls.get(resolved, 0) + 1
        if resolved == protected.resolve(strict=False):
            raise AssertionError("protected path metadata was touched")
        if resolved == unreadable.resolve(strict=False):
            raise PermissionError(13, "permission denied", str(path))
        return original_lstat(path)

    monkeypatch.setattr(pathlib.Path, "lstat", guarded_lstat)
    result = execute_native_operation(
        tmp_path,
        "search_code",
        {"query": "absent", "path": "."},
        native_facts={
            "workspace_root": str(tmp_path),
            "protected_paths": ["secret.py"],
        },
    ).envelope

    assert result.trace["completion"] == "partial"
    assert "SEARCH_PARTIAL" in result.text
    assert "unreadable.py" in result.text
    assert "secret.py" not in result.text
    assert calls.get(protected.resolve(strict=False), 0) == 0
    assert calls.get(visible.resolve(strict=False), 0) == 1

    direct = execute_native_operation(
        tmp_path,
        "search_code",
        {"query": "visible", "path": "visible.py"},
    ).envelope

    assert direct.trace["completion"] == "complete"
    assert "visible.py" in direct.text
    assert calls.get(visible.resolve(strict=False), 0) == 2


def test_registry_remote_service_follows_opaque_home_ledger(tmp_path):
    target = tmp_path / "actual-remote"
    target.mkdir()
    registry, fake = _remote_registry(tmp_path, target)
    try:
        started = registry.execute(
            "start_service",
            {
                "name": "web",
                "cmd": [sys.executable, "-c", "import time; time.sleep(30)"],
                "keep_alive": False,
            },
        )
        status = registry.execute("service_status", {"name": "web"})
        stopped = registry.execute("stop_service", {"name": "web"})
    finally:
        set_remote_workspace_service(None)

    assert "started" in started
    assert '"running": true' in status
    assert "stopped" in stopped
    assert fake.prepared[1].native_facts["service_id"]
    assert fake.prepared[2].native_facts["service_id"]


def test_guarded_remote_patch_requires_exact_snapshot_and_blob_digest(tmp_path):
    target = tmp_path / "remote"
    target.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=target, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=target, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=target, check=True)
    (target / "file.txt").write_text("before\n")
    subprocess.run(["git", "add", "file.txt"], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=target, check=True)
    snapshot = execute_native_operation(
        target,
        "snapshot_manifest_and_blob_export",
        {},
    ).envelope.trace["snapshot"]
    patch = (
        "diff --git a/file.txt b/file.txt\n"
        "index 90be1c4..6c72a3a 100644\n"
        "--- a/file.txt\n"
        "+++ b/file.txt\n"
        "@@ -1 +1 @@\n"
        "-before\n"
        "+after\n"
    ).encode()
    digest = hashlib.sha256(patch).hexdigest()
    before = next(
        row for row in snapshot["entries"] if row["path"] == "file.txt"
    )
    changes = [
        {
            "path": "file.txt",
            "before": before,
            "after": {
                "path": "file.txt",
                "kind": "file",
                "sha256": hashlib.sha256(b"after\n").hexdigest(),
                "size": len(b"after\n"),
                "mode": 0o644,
            },
        }
    ]

    refused = execute_native_operation(
        target,
        "guarded_patch_apply",
        {"expected_fingerprint": "0" * 64, "patch_blob_id": digest},
        blobs={digest: patch},
    )
    assert "SNAPSHOT_FINGERPRINT_MISMATCH" in refused.envelope.text
    assert (target / "file.txt").read_text() == "before\n"

    applied = execute_native_operation(
        target,
        "guarded_patch_apply",
        {
            "expected_fingerprint": snapshot["fingerprint"],
            "patch_blob_id": digest,
            "changes": changes,
        },
        blobs={digest: patch},
    )
    assert applied.envelope.text.startswith("OK:")
    assert (target / "file.txt").read_text() == "after\n"


def test_guarded_patch_rejects_integrity_partial_source_with_same_fingerprint(
    tmp_path,
    monkeypatch,
):
    from ouroboros import workspace_snapshot_native

    target = tmp_path / "remote"
    target.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=target, check=True)
    (target / "file.txt").write_text("before\n")
    snapshot, blobs = workspace_snapshot_native.snapshot_workspace(target)
    partial = dict(snapshot)
    partial.update(
        complete=False,
        materializable=False,
        integrity_complete=False,
        failures=[{"path": "ignored", "reason": "entry_read_error"}],
        failure_count=1,
    )
    monkeypatch.setattr(
        workspace_snapshot_native,
        "snapshot_workspace",
        lambda *_args, **_kwargs: (partial, blobs),
    )
    patch = (
        "diff --git a/file.txt b/file.txt\n"
        "index 90be1c4..6c72a3a 100644\n"
        "--- a/file.txt\n"
        "+++ b/file.txt\n"
        "@@ -1 +1 @@\n"
        "-before\n"
        "+after\n"
    ).encode()
    digest = hashlib.sha256(patch).hexdigest()
    result = workspace_snapshot_native.guarded_patch_apply(
        target,
        {
            "expected_fingerprint": snapshot["fingerprint"],
            "patch_blob_id": digest,
            "changes": [],
        },
        {digest: patch},
    )

    assert result.trace["completion"] == "not_started"
    assert "INTEGRITY_FAILED" in result.text
    assert (target / "file.txt").read_text() == "before\n"


def test_guarded_patch_rolls_back_integrity_partial_post_state(
    tmp_path,
    monkeypatch,
):
    from ouroboros import workspace_snapshot_native

    target = tmp_path / "remote"
    target.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=target, check=True)
    (target / "file.txt").write_text("before\n")
    before, _ = workspace_snapshot_native.snapshot_workspace(target)
    before_row = next(
        row for row in before["entries"] if row["path"] == "file.txt"
    )
    (target / "file.txt").write_text("after\n")
    after, _ = workspace_snapshot_native.snapshot_workspace(target)
    after_row = next(
        row for row in after["entries"] if row["path"] == "file.txt"
    )
    (target / "file.txt").write_text("before\n")
    original_snapshot = workspace_snapshot_native.snapshot_workspace
    calls = 0

    def _partial_after(*args, **kwargs):
        nonlocal calls
        calls += 1
        manifest, blobs = original_snapshot(*args, **kwargs)
        if calls == 2:
            manifest = dict(manifest)
            manifest.update(
                complete=False,
                materializable=False,
                integrity_complete=False,
                failures=[
                    {"path": "ignored", "reason": "entry_read_error"}
                ],
                failure_count=1,
            )
        return manifest, blobs

    monkeypatch.setattr(
        workspace_snapshot_native,
        "snapshot_workspace",
        _partial_after,
    )
    patch = (
        "diff --git a/file.txt b/file.txt\n"
        "index 90be1c4..6c72a3a 100644\n"
        "--- a/file.txt\n"
        "+++ b/file.txt\n"
        "@@ -1 +1 @@\n"
        "-before\n"
        "+after\n"
    ).encode()
    digest = hashlib.sha256(patch).hexdigest()
    result = workspace_snapshot_native.guarded_patch_apply(
        target,
        {
            "expected_fingerprint": before["fingerprint"],
            "expected_content_fingerprint": after["content_fingerprint"],
            "patch_blob_id": digest,
            "changes": [
                {
                    "path": "file.txt",
                    "before": before_row,
                    "after": after_row,
                }
            ],
        },
        {digest: patch},
    )

    assert result.trace["completion"] == "not_started"
    assert "ROLLED_BACK" in result.text
    assert (target / "file.txt").read_text() == "before\n"


def test_remote_patch_export_blocks_dynamic_protected_paths(tmp_path):
    target = tmp_path / "remote"
    target.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=target, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=target,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=target,
        check=True,
    )
    protected = target / "reference.bin"
    protected.write_bytes(b"old")
    subprocess.run(["git", "add", "reference.bin"], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=target, check=True)
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=target,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    protected.write_bytes(b"PROTECTED-NEW-BYTES")

    result = execute_native_operation(
        target,
        "vcs_diff",
        {
            "artifact_export": True,
            "expected_head": head,
            "expected_head_present": True,
            "expected_admission_known": True,
        },
        native_facts={
            "workspace_root": target.as_posix(),
            "protected_paths": ["reference.bin"],
        },
    )

    export = result.envelope.trace["patch_export"]
    assert export["status"] == "failed"
    assert export["protected_blocked"] == ["reference.bin"]
    assert result.blobs == {}


def test_remote_patch_export_blocks_rename_from_dynamic_protected_path(
    tmp_path,
):
    target = tmp_path / "remote"
    target.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=target, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=target,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=target,
        check=True,
    )
    protected = target / "reference.bin"
    protected.write_bytes(b"protected")
    subprocess.run(["git", "add", "reference.bin"], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=target, check=True)
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=target,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    protected.rename(target / "public.bin")

    result = execute_native_operation(
        target,
        "vcs_diff",
        {
            "artifact_export": True,
            "expected_head": head,
            "expected_head_present": True,
            "expected_admission_known": True,
        },
        native_facts={
            "workspace_root": target.as_posix(),
            "protected_paths": ["reference.bin"],
        },
    )

    export = result.envelope.trace["patch_export"]
    assert export["status"] == "failed"
    assert "reference.bin" in export["protected_blocked"]
    assert result.blobs == {}
