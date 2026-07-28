from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess

import pytest

from ouroboros.gateways.claude_code import ClaudeCodeResult
from ouroboros.remote_claude import run_remote_claude_edit
from ouroboros.remote_workspace import PreparedRemoteCall, set_remote_workspace_service
from ouroboros.workspace_diagnostics import ToolExecutionEnvelope
from ouroboros.workspace_executor import (
    RemoteWorkspaceOperationError,
    materialize_remote_workspace_snapshot,
)
from ouroboros.workspace_native import execute_native_operation, prepare_native_operation


class _Context:
    def __init__(self, root: pathlib.Path):
        self.task_id = "remote-claude-task"
        self.project_id = "project"
        self.repo_dir = root
        self.drive_root = root / "data"
        self.task_metadata = {
            "_sealed_workspace_ref": {
                "kind": "ssh",
                "connection_id": "connection",
                "remote_root": "/remote/project",
                "workspace_id": "workspace",
            }
        }


class _FakeRemote:
    def __init__(self, root: pathlib.Path):
        self.root = root
        self.blobs: dict[str, bytes] = {}

    def prepare(self, workspace_ref, **kwargs):
        del workspace_ref
        native = prepare_native_operation(
            self.root,
            kwargs["tool"],
            kwargs["args"],
            task_id=kwargs.get("task_id", ""),
        )
        digest = hashlib.sha256(
            json.dumps(
                {
                    "execution_args": native.execution_args,
                    "native_facts": native.native_facts,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        self.blobs.update(dict(kwargs.get("blobs") or {}))
        return PreparedRemoteCall(
            request_id=kwargs["request_id"],
            operation_id=kwargs["operation_id"],
            tool=kwargs["tool"],
            prepared_token="prepared",
            prepared_hash=digest,
            expires_at_ms=2**63 - 1,
            execution_args=native.execution_args,
            native_facts=native.native_facts,
        )

    def execute_prepared(self, workspace_ref, prepared, **kwargs):
        del workspace_ref
        result = execute_native_operation(
            self.root,
            prepared.tool,
            kwargs["canonical_args"],
            native_facts=prepared.native_facts,
            blobs=self.blobs,
            task_id=kwargs.get("task_id", ""),
        )
        self.blobs.update(result.blobs)
        return result.envelope

    def abort_prepared(self, workspace_ref, prepared, **kwargs):
        del workspace_ref, prepared, kwargs
        return True

    def fetch_blob(self, workspace_ref, blob_id, *, max_bytes, **identity):
        del workspace_ref, identity
        data = self.blobs[blob_id]
        assert len(data) <= max_bytes
        return data

    def cancel(self, workspace_ref, **kwargs):
        del workspace_ref, kwargs
        return True


@pytest.fixture
def remote_repo(tmp_path):
    root = tmp_path / "remote"
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "Test")
    _git(root, "config", "user.email", "test@example.invalid")
    (root / "tracked.txt").write_text("tracked\n")
    (root / "binary.bin").write_bytes(b"\x00before\xff")
    (root / "script.sh").write_text("#!/bin/sh\n")
    (root / "link").symlink_to("tracked.txt")
    (root / "rename-me.txt").write_text(
        "".join(f"line {index}\n" for index in range(20))
    )
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    (root / "staged.txt").write_text("staged\n")
    _git(root, "add", "staged.txt")
    (root / "tracked.txt").write_text("dirty worktree\n")
    (root / "untracked.txt").write_text("untracked\n")
    return root


def test_snapshot_materializes_binary_modes_symlink_and_git_facts(
    tmp_path,
    remote_repo,
):
    fake = _FakeRemote(remote_repo)
    set_remote_workspace_service(fake)
    try:
        with materialize_remote_workspace_snapshot(_Context(tmp_path)) as snapshot:
            assert (snapshot.root / "binary.bin").read_bytes() == b"\x00before\xff"
            assert (snapshot.root / "link").is_symlink()
            assert (snapshot.root / "link").readlink() == pathlib.Path("tracked.txt")
            assert snapshot.manifest["git"]["head"]
            assert snapshot.manifest["git"]["index_sha256"]
            assert snapshot.manifest["content_fingerprint"]
    finally:
        set_remote_workspace_service(None)


def test_snapshot_refuses_partial_sensitive_or_escaping_symlink_view(
    tmp_path,
    remote_repo,
):
    (remote_repo / ".env").write_text("SECRET=not-for-home\n")
    (remote_repo / "escape").symlink_to("/etc/passwd")
    fake = _FakeRemote(remote_repo)
    set_remote_workspace_service(fake)
    try:
        with pytest.raises(RemoteWorkspaceOperationError, match="partial"):
            materialize_remote_workspace_snapshot(_Context(tmp_path))
    finally:
        set_remote_workspace_service(None)


def test_snapshot_materializes_policy_filtered_sensitive_view(
    tmp_path,
    remote_repo,
):
    (remote_repo / ".env").write_text("SECRET=not-for-home\n")
    fake = _FakeRemote(remote_repo)
    set_remote_workspace_service(fake)
    try:
        with materialize_remote_workspace_snapshot(_Context(tmp_path)) as snapshot:
            assert not (snapshot.root / ".env").exists()
            assert (snapshot.root / "tracked.txt").read_text() == "dirty worktree\n"
            assert snapshot.manifest["complete"] is False
            assert snapshot.manifest["materializable"] is True
            assert {
                (row["path"], row["reason"])
                for row in snapshot.manifest["exclusions"]
            } >= {(".env", "sensitive_file")}
    finally:
        set_remote_workspace_service(None)


def test_snapshot_never_exports_tracked_secrets_or_protected_artifacts(
    tmp_path,
    remote_repo,
):
    secret = b"TRACKED_SECRET=must-stay-remote\n"
    protected = b"\x00protected-black-box\xff"
    (remote_repo / ".env").write_bytes(secret)
    (remote_repo / "reference.bin").write_bytes(protected)
    _git(remote_repo, "add", ".env", "reference.bin")
    _git(remote_repo, "commit", "-qm", "tracked protected inputs")
    os.link(remote_repo / ".env", remote_repo / "public-config.txt")
    os.link(remote_repo / "reference.bin", remote_repo / "reference-hardlink.bin")
    ctx = _Context(tmp_path)
    ctx.task_metadata["task_contract"] = {
        "resource_policy": {
            "protected_artifacts": [
                {
                    "role": "black_box_reference",
                    "paths": ["/remote/project/reference.bin"],
                }
            ]
        }
    }
    subject = {
        "id": ctx.task_id,
        "project_id": ctx.project_id,
        "metadata": ctx.task_metadata,
    }
    fake = _FakeRemote(remote_repo)
    set_remote_workspace_service(fake)
    try:
        with materialize_remote_workspace_snapshot(subject) as snapshot:
            assert not (snapshot.root / ".env").exists()
            assert not (snapshot.root / "public-config.txt").exists()
            assert not (snapshot.root / "reference.bin").exists()
            assert not (snapshot.root / "reference-hardlink.bin").exists()
            assert (snapshot.root / "tracked.txt").is_file()
            assert snapshot.manifest["materializable"] is True
    finally:
        set_remote_workspace_service(None)

    assert hashlib.sha256(secret).hexdigest() not in fake.blobs
    assert hashlib.sha256(protected).hexdigest() not in fake.blobs


def test_snapshot_never_exports_hardlink_to_protected_file_below_omitted_dir(
    tmp_path,
    remote_repo,
):
    protected_dir = remote_repo / ".ouroboros"
    protected_dir.mkdir()
    protected = b"protected-below-omitted-directory"
    (protected_dir / "blackbox.bin").write_bytes(protected)
    os.link(
        protected_dir / "blackbox.bin",
        remote_repo / "public-hardlink.bin",
    )
    ctx = _Context(tmp_path)
    ctx.task_metadata["task_contract"] = {
        "resource_policy": {
            "protected_artifacts": [
                {
                    "role": "black_box_reference",
                    "paths": [
                        "/remote/project/.ouroboros/blackbox.bin"
                    ],
                }
            ]
        }
    }
    fake = _FakeRemote(remote_repo)
    set_remote_workspace_service(fake)
    try:
        with materialize_remote_workspace_snapshot(ctx) as snapshot:
            assert not (snapshot.root / ".ouroboros").exists()
            assert not (snapshot.root / "public-hardlink.bin").exists()
    finally:
        set_remote_workspace_service(None)

    assert hashlib.sha256(protected).hexdigest() not in fake.blobs


def test_remote_claude_policy_filtered_patch_cannot_create_sensitive_file(
    tmp_path,
    remote_repo,
    monkeypatch,
):
    (remote_repo / ".env").write_text("SECRET=remote-only\n")
    fake = _FakeRemote(remote_repo)
    set_remote_workspace_service(fake)

    def _edit(**kwargs):
        mirror = pathlib.Path(kwargs["cwd"])
        (mirror / "tracked.txt").write_text("claude\n")
        (mirror / ".env").write_text("SECRET=overwrite\n")
        return ClaudeCodeResult(success=True, result_text="done")

    monkeypatch.setattr("ouroboros.gateways.claude_code.run_edit", _edit)
    try:
        with pytest.raises(
            RemoteWorkspaceOperationError,
            match="omitted policy path",
        ):
            run_remote_claude_edit(
                _Context(tmp_path),
                prompt="edit",
                budget=1,
                validate=False,
                system_prompt="governance",
            )
    finally:
        set_remote_workspace_service(None)

    assert (remote_repo / ".env").read_text() == "SECRET=remote-only\n"
    assert (remote_repo / "tracked.txt").read_text() == "dirty worktree\n"


def test_remote_claude_cannot_create_snapshot_omitted_runtime_path(
    tmp_path,
    remote_repo,
    monkeypatch,
):
    fake = _FakeRemote(remote_repo)
    set_remote_workspace_service(fake)

    def _edit(**kwargs):
        mirror = pathlib.Path(kwargs["cwd"])
        (mirror / "tracked.txt").write_text("claude\n")
        (mirror / ".ouroboros").mkdir()
        (mirror / ".ouroboros" / "hidden").write_text("hidden\n")
        return ClaudeCodeResult(success=True, result_text="done")

    monkeypatch.setattr("ouroboros.gateways.claude_code.run_edit", _edit)
    try:
        with pytest.raises(
            RemoteWorkspaceOperationError,
            match="omitted policy path",
        ):
            run_remote_claude_edit(
                _Context(tmp_path),
                prompt="edit",
                budget=1,
                validate=False,
                system_prompt="governance",
            )
    finally:
        set_remote_workspace_service(None)

    assert not (remote_repo / ".ouroboros").exists()
    assert (remote_repo / "tracked.txt").read_text() == "dirty worktree\n"


def test_home_rejects_complete_manifest_with_failed_integrity(
    tmp_path,
    remote_repo,
    monkeypatch,
):
    fake = _FakeRemote(remote_repo)
    native = execute_native_operation(
        remote_repo,
        "snapshot_manifest_and_blob_export",
        {},
    )
    fake.blobs.update(native.blobs)
    manifest = dict(native.envelope.trace["snapshot"])
    manifest.update(
        complete=True,
        integrity_complete=False,
        materializable=False,
        unstable=True,
        failures=[{"path": "bad", "reason": "entry_read_error"}],
        failure_count=1,
    )
    monkeypatch.setattr(
        "ouroboros.workspace_executor.execute_remote_system_operation",
        lambda *_args, **_kwargs: ToolExecutionEnvelope(
            text="",
            trace={"snapshot": manifest},
        ),
    )
    set_remote_workspace_service(fake)
    try:
        with pytest.raises(RemoteWorkspaceOperationError, match="partial"):
            materialize_remote_workspace_snapshot(_Context(tmp_path))
    finally:
        set_remote_workspace_service(None)


def test_home_rejects_duplicate_snapshot_entry_paths(
    tmp_path,
    remote_repo,
    monkeypatch,
):
    fake = _FakeRemote(remote_repo)
    native = execute_native_operation(
        remote_repo,
        "snapshot_manifest_and_blob_export",
        {},
    )
    fake.blobs.update(native.blobs)
    manifest = dict(native.envelope.trace["snapshot"])
    entries = [dict(row) for row in manifest["entries"]]
    entries.append(dict(entries[0]))
    entries.sort(key=lambda row: row["path"])
    manifest["entries"] = entries
    manifest["total_bytes"] = sum(int(row["size"]) for row in entries)
    manifest["content_fingerprint"] = hashlib.sha256(
        json.dumps(
            entries,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    manifest["fingerprint"] = hashlib.sha256(
        json.dumps(
            {
                "entries": entries,
                "git": manifest["git"],
                "policy_exclusions": manifest["policy_exclusions"],
                "protected_paths": manifest["protected_paths"],
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    monkeypatch.setattr(
        "ouroboros.workspace_executor.execute_remote_system_operation",
        lambda *_args, **_kwargs: ToolExecutionEnvelope(
            text="",
            trace={"snapshot": manifest},
        ),
    )
    set_remote_workspace_service(fake)
    try:
        with pytest.raises(
            RemoteWorkspaceOperationError,
            match="topology",
        ):
            materialize_remote_workspace_snapshot(_Context(tmp_path))
    finally:
        set_remote_workspace_service(None)


def test_continuous_snapshot_mutation_never_materializes_stale_blobs(
    tmp_path,
    remote_repo,
    monkeypatch,
):
    from ouroboros import workspace_snapshot_native as native

    original = native._snapshot_once
    counter = 0

    def _mutating_snapshot(root, **kwargs):
        nonlocal counter
        manifest, blobs = original(root, **kwargs)
        counter += 1
        pathlib.Path(root, "tracked.txt").write_text(f"mutation {counter}\n")
        return manifest, blobs

    monkeypatch.setattr(native, "_snapshot_once", _mutating_snapshot)
    fake = _FakeRemote(remote_repo)
    set_remote_workspace_service(fake)
    try:
        with pytest.raises(RemoteWorkspaceOperationError, match="partial"):
            materialize_remote_workspace_snapshot(_Context(tmp_path))
    finally:
        set_remote_workspace_service(None)


def test_remote_claude_applies_exact_binary_patch_without_touching_index(
    tmp_path,
    remote_repo,
    monkeypatch,
):
    fake = _FakeRemote(remote_repo)
    set_remote_workspace_service(fake)
    index_before = _git_bytes(remote_repo, "ls-files", "--stage", "-z")

    def _edit(**kwargs):
        mirror = pathlib.Path(kwargs["cwd"])
        (mirror / "tracked.txt").write_text("claude\n")
        (mirror / "binary.bin").write_bytes(b"\x00after\xfe")
        (mirror / "untracked.txt").write_text("claude untracked\n")
        (mirror / "script.sh").chmod(0o755)
        (mirror / "new-link").symlink_to("tracked.txt")
        (mirror / "rename-me.txt").rename(mirror / "renamed.txt")
        return ClaudeCodeResult(success=True, result_text="done")

    monkeypatch.setattr("ouroboros.gateways.claude_code.run_edit", _edit)
    try:
        outcome = run_remote_claude_edit(
            _Context(tmp_path),
            prompt="edit",
            budget=1,
            validate=False,
            system_prompt="governance",
        )
    finally:
        set_remote_workspace_service(None)

    assert outcome.apply_trace["completion"] == "complete"
    assert (remote_repo / "tracked.txt").read_text() == "claude\n"
    assert (remote_repo / "binary.bin").read_bytes() == b"\x00after\xfe"
    assert (remote_repo / "untracked.txt").read_text() == "claude untracked\n"
    assert (remote_repo / "script.sh").stat().st_mode & 0o111
    assert (remote_repo / "new-link").readlink() == pathlib.Path("tracked.txt")
    assert not (remote_repo / "rename-me.txt").exists()
    assert (remote_repo / "renamed.txt").read_text().startswith("line 0\n")
    assert _git_bytes(remote_repo, "ls-files", "--stage", "-z") == index_before


def test_remote_patch_rejects_omitted_touched_path_before_mutation(
    tmp_path,
    remote_repo,
    monkeypatch,
):
    fake = _FakeRemote(remote_repo)
    set_remote_workspace_service(fake)

    def _edit(**kwargs):
        mirror = pathlib.Path(kwargs["cwd"])
        (mirror / "tracked.txt").write_text("claude\n")
        (mirror / "binary.bin").write_bytes(b"\x00after\xfe")
        return ClaudeCodeResult(success=True, result_text="done")

    from ouroboros import remote_claude

    original_execute = remote_claude.execute_remote_system_operation

    def _omit_binary_change(subject, operation, args, *, blobs=None):
        tampered = dict(args)
        if operation == "guarded_patch_apply":
            tampered["changes"] = [
                row
                for row in list(tampered.get("changes") or [])
                if row.get("path") != "binary.bin"
            ]
        return original_execute(subject, operation, tampered, blobs=blobs)

    monkeypatch.setattr("ouroboros.gateways.claude_code.run_edit", _edit)
    monkeypatch.setattr(
        remote_claude,
        "execute_remote_system_operation",
        _omit_binary_change,
    )
    try:
        with pytest.raises(RemoteWorkspaceOperationError, match="exactly match"):
            run_remote_claude_edit(
                _Context(tmp_path),
                prompt="edit",
                budget=1,
                validate=False,
                system_prompt="governance",
            )
    finally:
        set_remote_workspace_service(None)

    assert (remote_repo / "tracked.txt").read_text() == "dirty worktree\n"
    assert (remote_repo / "binary.bin").read_bytes() == b"\x00before\xff"


def test_remote_change_during_claude_causes_conflict_without_claude_mutation(
    tmp_path,
    remote_repo,
    monkeypatch,
):
    fake = _FakeRemote(remote_repo)
    set_remote_workspace_service(fake)

    def _edit(**kwargs):
        pathlib.Path(kwargs["cwd"], "tracked.txt").write_text("claude\n")
        (remote_repo / "tracked.txt").write_text("human concurrent edit\n")
        return ClaudeCodeResult(success=True, result_text="done")

    monkeypatch.setattr("ouroboros.gateways.claude_code.run_edit", _edit)
    with pytest.raises(RemoteWorkspaceOperationError, match="changed"):
        run_remote_claude_edit(
            _Context(tmp_path),
            prompt="edit",
            budget=1,
            validate=False,
            system_prompt="governance",
        )
    set_remote_workspace_service(None)
    assert (remote_repo / "tracked.txt").read_text() == "human concurrent edit\n"


def test_remote_apply_postcondition_race_rolls_back(
    tmp_path,
    remote_repo,
    monkeypatch,
):
    fake = _FakeRemote(remote_repo)
    set_remote_workspace_service(fake)

    def _edit(**kwargs):
        mirror = pathlib.Path(kwargs["cwd"])
        (mirror / "tracked.txt").write_text("claude\n")
        (mirror / "binary.bin").write_bytes(b"\x00after\xfe")
        (mirror / "script.sh").chmod(0o755)
        (mirror / "rename-me.txt").rename(mirror / "renamed.txt")
        return ClaudeCodeResult(success=True, result_text="done")

    monkeypatch.setattr("ouroboros.gateways.claude_code.run_edit", _edit)
    from ouroboros import workspace_snapshot_native as native

    original_apply = native._git_apply

    def _racing_apply(root, patch, *, check):
        result = original_apply(root, patch, check=check)
        if not check and result.returncode == 0:
            pathlib.Path(root, "tracked.txt").write_text("hostile race\n")
        return result

    monkeypatch.setattr(native, "_git_apply", _racing_apply)
    with pytest.raises(RemoteWorkspaceOperationError, match="ROLLED_BACK"):
        run_remote_claude_edit(
            _Context(tmp_path),
            prompt="edit",
            budget=1,
            validate=False,
            system_prompt="governance",
        )
    set_remote_workspace_service(None)
    assert (remote_repo / "tracked.txt").read_text() == "dirty worktree\n"
    assert (remote_repo / "binary.bin").read_bytes() == b"\x00before\xff"
    assert not (remote_repo / "script.sh").stat().st_mode & 0o111
    assert (remote_repo / "rename-me.txt").is_file()
    assert not (remote_repo / "renamed.txt").exists()


def test_snapshot_cleanup_on_claude_failure(tmp_path, remote_repo, monkeypatch):
    fake = _FakeRemote(remote_repo)
    set_remote_workspace_service(fake)
    roots: list[pathlib.Path] = []
    from ouroboros import remote_snapshot_home

    original_mkdtemp = remote_snapshot_home.tempfile.mkdtemp

    def _recording_mkdtemp(*args, **kwargs):
        root = pathlib.Path(original_mkdtemp(*args, **kwargs))
        roots.append(root)
        return str(root)

    def _explode(**kwargs):
        del kwargs
        raise RuntimeError("SDK crash")

    monkeypatch.setattr(
        remote_snapshot_home.tempfile,
        "mkdtemp",
        _recording_mkdtemp,
    )
    monkeypatch.setattr("ouroboros.gateways.claude_code.run_edit", _explode)
    with pytest.raises(RuntimeError, match="SDK crash"):
        run_remote_claude_edit(
            _Context(tmp_path),
            prompt="edit",
            budget=1,
            validate=False,
            system_prompt="governance",
        )
    set_remote_workspace_service(None)
    assert roots and all(not root.exists() for root in roots)


def test_claude_tool_ssh_branch_never_requests_a_home_workspace_path(
    tmp_path,
    monkeypatch,
):
    from ouroboros.tools import shell

    ctx = _Context(tmp_path)
    ctx.emit_progress_fn = lambda _message: None
    ctx.pending_events = []
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-only")
    monkeypatch.setattr(
        shell,
        "active_repo_dir_for",
        lambda _ctx: (_ for _ in ()).throw(
            AssertionError("SSH Claude must not request a Home workspace path")
        ),
    )
    monkeypatch.setattr(
        shell,
        "_claude_code_edit_remote",
        lambda *_args, **_kwargs: "remote-branch",
    )

    assert shell._claude_code_edit(ctx, "edit") == "remote-branch"


def _git(root: pathlib.Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=root, check=True)


def _git_bytes(root: pathlib.Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
