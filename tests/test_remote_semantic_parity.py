from __future__ import annotations

import asyncio
import hashlib
import json
import pathlib
import re
import subprocess
import sys
from types import SimpleNamespace

import pytest

from ouroboros.gateway.tasks import _remote_admitted_task
from ouroboros.remote_finalization import _expected_git_base
from ouroboros.remote_plan_review import (
    close_materialized_plan_snapshot,
    materialized_plan_roots,
    remote_snapshot_lifecycle,
)
from ouroboros.remote_task_files import remote_task_admission_result
from ouroboros.tools.control import _constraint_workspace_root
from ouroboros.tools.registry import ToolContext, ToolRegistry
from ouroboros.tools.review_helpers import build_head_snapshot_section
from ouroboros.workspace_native import (
    execute_native_operation,
    prepare_native_operation,
)


def _reviewed_package(
    files: dict[str, bytes],
    *,
    kind: str,
    invocation: dict,
    skill_name: str = "remote_skill",
    entry: str = "",
) -> tuple[dict, dict[str, bytes]]:
    manifest = []
    blobs = {}
    aggregate = hashlib.sha256()
    for path, content in sorted(files.items()):
        digest = hashlib.sha256(content).hexdigest()
        manifest.append(
            {
                "path": path,
                "sha256": digest,
                "size": len(content),
                "mode": 0o600,
            }
        )
        blobs[digest] = content
        aggregate.update(path.encode())
        aggregate.update(b"\0")
        aggregate.update(bytes.fromhex(digest))
    return {
        "schema_version": 1,
        "kind": kind,
        "payload": {
            "skill_name": skill_name,
            "content_hash": aggregate.hexdigest(),
            "entry": entry,
            "runtime": "python3",
            "files": manifest,
        },
        "invocation": invocation,
    }, blobs


def _git_repo(root: pathlib.Path) -> str:
    root.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
    (root / "tracked.txt").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked.txt"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def test_remote_admission_carries_git_base_into_finalization(tmp_path):
    from ouroboros.execd import _admission_git_state

    root = tmp_path / "repo"
    head = _git_repo(root)
    (root / "tracked.txt").write_text("staged\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked.txt"], cwd=root, check=True)
    (root / "untracked.txt").write_text("new\n", encoding="utf-8")
    git = _admission_git_state(root)
    assert git["head"] == head
    assert git["head_present"] is True
    assert git["dirty"] is True
    assert git["status_count"] == 2
    assert len(git["index_sha256"]) == 64
    assert len(git["status_sha256"]) == 64

    session = SimpleNamespace(
        handshake={
            "host_id": "host",
            "build": "build",
            "capability_hash": "a" * 64,
            "canonical_root": "/srv/repo",
            "git": git,
        },
        key=("connection", "project", "workspace", "generation"),
        remote_root="/srv/repo",
    )
    result = remote_task_admission_result(session, None)
    sealed = result["workspace_ref"]
    admitted, error, code = _remote_admitted_task(result, sealed)
    assert (error, code) == ("", "")
    metadata = admitted["metadata"]
    assert metadata["workspace_preflight"]["authority"] == "remote_admission"
    assert metadata["workspace_preflight"]["git"]["head"] == head
    assert _expected_git_base({"metadata": metadata}) == (head, True)


def test_remote_plan_review_uses_one_verified_snapshot_and_always_closes(
    tmp_path,
    monkeypatch,
):
    snapshot_root = tmp_path / "snapshot"
    snapshot_root.mkdir()
    (snapshot_root / "src.py").write_text("print('remote')\n", encoding="utf-8")

    class Snapshot:
        root = snapshot_root
        closed = False

        def close(self):
            self.closed = True

    snapshot = Snapshot()
    monkeypatch.setattr(
        "ouroboros.workspace_executor.materialize_remote_workspace_snapshot",
        lambda _ctx: snapshot,
    )
    system = tmp_path / "system"
    system.mkdir()
    ctx = SimpleNamespace(
        repo_dir=system,
        system_repo_dir=system,
        task_metadata={
            "_sealed_workspace_ref": {
                "kind": "ssh",
                "connection_id": "connection",
                "remote_root": "/srv/repo",
                "workspace_id": "workspace",
            }
        },
    )
    first = materialized_plan_roots(ctx)
    second = materialized_plan_roots(ctx)
    assert first == second == (system, snapshot_root)
    section = build_head_snapshot_section(
        snapshot_root,
        ["src.py"],
        verified_filesystem_snapshot=True,
    )
    assert "print('remote')" in section

    @remote_snapshot_lifecycle
    async def fail(_ctx):
        raise RuntimeError("review failed")

    with pytest.raises(RuntimeError, match="review failed"):
        asyncio.run(fail(ctx))
    assert snapshot.closed is True
    assert not hasattr(ctx, "_remote_plan_review_snapshot")
    close_materialized_plan_snapshot(ctx)


def test_remote_child_constraint_uses_target_native_root_without_home_path():
    ref = {
        "kind": "ssh",
        "connection_id": "connection",
        "remote_root": "/srv/project",
        "workspace_id": "workspace",
    }
    assert _constraint_workspace_root("", ref) == "/srv/project"
    assert (
        _constraint_workspace_root(
            "/home/project",
            {"kind": "local", "local_root": "/home/project"},
        )
        == "/home/project"
    )


@pytest.mark.parametrize(
    ("tool", "args", "prefix"),
    [
        ("read_file", {"path": "missing"}, "⚠️ NOT_FOUND:"),
        ("list_files", {"path": "missing"}, "⚠️ LIST_FILES_ERROR:"),
        (
            "edit_text",
            {"path": "missing", "old_str": "a", "new_str": "b"},
            "⚠️ STR_REPLACE_ERROR:",
        ),
        (
            "search_code",
            {"path": "missing", "query": "a"},
            "⚠️ SEARCH_ERROR:",
        ),
    ],
)
def test_native_core_missing_paths_keep_public_error_contract(
    tmp_path,
    tool,
    args,
    prefix,
):
    result = execute_native_operation(tmp_path, tool, args).envelope
    assert result.text.startswith(prefix)
    assert result.diagnostic is not None
    assert result.diagnostic.code == "not_found"
    assert result.trace["operation"] == tool


def test_local_and_ssh_native_missing_path_text_is_identical(tmp_path):
    root = tmp_path / "repo"
    data = tmp_path / "data"
    system = tmp_path / "system"
    root.mkdir()
    data.mkdir()
    system.mkdir()
    registry = ToolRegistry(system, data)
    ctx = ToolContext(
        repo_dir=system,
        system_repo_dir=system,
        drive_root=data,
        workspace_root=str(root),
        workspace_mode="external",
        task_metadata={
            "_sealed_workspace_ref": {
                "kind": "local",
                "local_root": str(root),
            }
        },
    )
    cases = [
        ("read_file", {"path": "missing"}),
        ("list_files", {"path": "missing"}),
        ("edit_text", {"path": "missing", "old_str": "a", "new_str": "b"}),
        ("search_code", {"path": "missing", "query": "a"}),
    ]
    for tool, args in cases:
        local = registry._entries[tool].handler(
            ctx,
            root="active_workspace",
            **args,
        )
        remote = execute_native_operation(root, tool, args).envelope.text
        assert remote == local


def test_local_and_ssh_native_positive_file_and_search_parity(tmp_path):
    local_root = tmp_path / "local"
    remote_root = tmp_path / "remote"
    system = tmp_path / "system"
    data = tmp_path / "data"
    for root in (local_root, remote_root, system, data):
        root.mkdir()
    for root in (local_root, remote_root):
        (root / "a.txt").write_text("alpha\nbeta\n", encoding="utf-8")
        (root / "b.txt").write_text("alpha\n", encoding="utf-8")
        (root / "c.txt").write_text("gamma\n", encoding="utf-8")
    registry = ToolRegistry(system, data)
    ctx = ToolContext(
        repo_dir=system,
        system_repo_dir=system,
        drive_root=data,
        workspace_root=str(local_root),
        workspace_mode="external",
        task_metadata={
            "_sealed_workspace_ref": {
                "kind": "local",
                "local_root": str(local_root),
            }
        },
    )

    for tool, args in (
        ("read_file", {"path": "a.txt", "start_line": 2, "max_lines": 1}),
        ("list_files", {"path": ".", "max_entries": 2}),
        ("list_files", {"path": "a.txt"}),
        ("search_code", {"path": ".", "query": "alpha", "max_results": 2}),
    ):
        local = registry._entries[tool].handler(
            ctx,
            root="active_workspace",
            **args,
        )
        remote = execute_native_operation(remote_root, tool, args).envelope.text
        assert remote == local

    append = {"path": "a.txt", "content": "delta\n", "mode": "append"}
    local = registry._entries["write_file"].handler(
        ctx,
        root="active_workspace",
        **append,
    )
    remote = execute_native_operation(
        remote_root,
        "write_file",
        append,
    ).envelope.text
    assert remote == local
    assert (remote_root / "a.txt").read_bytes() == (local_root / "a.txt").read_bytes()

    edit = {"path": "a.txt", "old_str": "beta", "new_str": "BETA"}
    local = registry._entries["edit_text"].handler(
        ctx,
        root="active_workspace",
        **edit,
    )
    remote = execute_native_operation(
        remote_root,
        "edit_text",
        edit,
    ).envelope.text
    assert remote == local
    assert (remote_root / "a.txt").read_bytes() == (local_root / "a.txt").read_bytes()


def test_local_and_ssh_native_process_and_script_parity(tmp_path):
    root = tmp_path / "workspace"
    system = tmp_path / "system"
    data = tmp_path / "data"
    for path in (root, system, data):
        path.mkdir()
    (root / "search.txt").write_text("alpha\nbeta\n", encoding="utf-8")
    registry = ToolRegistry(system, data)
    ctx = ToolContext(
        repo_dir=system,
        system_repo_dir=system,
        drive_root=data,
        workspace_root=str(root),
        workspace_mode="external",
        task_metadata={
            "_sealed_workspace_ref": {
                "kind": "local",
                "local_root": str(root),
            }
        },
    )

    cases = [
        {
            "cmd": [
                sys.executable,
                "-c",
                "import sys; print('out'); print('err', file=sys.stderr)",
            ]
        },
        {
            "cmd": [
                sys.executable,
                "-c",
                "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)",
            ]
        },
        {"cmd": ["grep", "missing", "search.txt"]},
        {"cmd": ["grep", r"alpha\|beta", "search.txt"]},
        {
            "cmd": [sys.executable, "-c", "import time; time.sleep(2)"],
            "timeout_sec": 1,
        },
    ]
    for args in cases:
        local = registry._entries["run_command"].handler(ctx, **args)
        prepared = prepare_native_operation(root, "run_command", args)
        remote = execute_native_operation(
            root,
            "run_command",
            prepared.execution_args,
            native_facts=prepared.native_facts,
        ).envelope.text
        assert remote == local

    script_args = {
        "script": "import sys; print('out'); print('err', file=sys.stderr)",
    }
    local = registry._entries["run_script"].handler(ctx, **script_args)
    prepared = prepare_native_operation(root, "run_script", script_args)
    remote = execute_native_operation(
        root,
        "run_script",
        prepared.execution_args,
        native_facts=prepared.native_facts,
    ).envelope.text
    normalize = lambda text: re.sub(
        r"script_[0-9a-f]+\.py",
        "script_ID.py",
        text,
    )
    assert normalize(remote) == normalize(local)


def test_local_and_ssh_native_scratch_and_outputs_parity(tmp_path):
    local_root = tmp_path / "local"
    remote_root = tmp_path / "remote"
    system = tmp_path / "system"
    data = tmp_path / "data"
    for root in (local_root, remote_root, system, data):
        root.mkdir()
    for root in (local_root, remote_root):
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    registry = ToolRegistry(system, data)
    ctx = ToolContext(
        repo_dir=system,
        system_repo_dir=system,
        drive_root=data,
        workspace_root=str(local_root),
        workspace_mode="external",
        task_id="task-parity",
        task_metadata={
            "_sealed_workspace_ref": {
                "kind": "local",
                "local_root": str(local_root),
            }
        },
    )
    args = {
        "cmd": [
            sys.executable,
            "-c",
            (
                "from pathlib import Path; "
                "Path('out.txt').write_text('out'); "
                "Path('scratch.txt').write_text('scratch')"
            ),
        ],
        "outputs": ["out.txt"],
        "scratch": ["scratch.txt"],
    }

    local = registry._entries["run_command"].handler(ctx, **args)
    prepared = prepare_native_operation(
        remote_root,
        "run_command",
        args,
        task_id="task-parity",
    )
    remote = execute_native_operation(
        remote_root,
        "run_command",
        prepared.execution_args,
        native_facts=prepared.native_facts,
        task_id="task-parity",
    ).envelope.text
    normalized_local = local.replace(str(local_root.resolve()), "<WORKSPACE>")
    normalized_remote = remote.replace(str(remote_root.resolve()), "<WORKSPACE>")
    assert normalized_remote == normalized_local


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("read_file", {"path": "escape/secret.txt"}),
        ("list_files", {"path": "escape"}),
        (
            "write_file",
            {"path": "escape/new.txt", "content": "blocked"},
        ),
        (
            "edit_text",
            {"path": "escape/secret.txt", "old_str": "secret", "new_str": "leak"},
        ),
        ("search_code", {"path": "escape", "query": "secret"}),
    ],
)
def test_native_core_parent_symlink_escape_is_typed_permission_denied(
    tmp_path,
    tool,
    args,
):
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir(exist_ok=True)
    (outside / "secret.txt").write_text("secret\n", encoding="utf-8")
    (tmp_path / "escape").symlink_to(outside, target_is_directory=True)
    result = execute_native_operation(tmp_path, tool, args).envelope
    assert result.diagnostic is not None
    assert result.diagnostic.code == "permission_denied"
    assert "secret\n" not in result.text
    assert not (outside / "new.txt").exists()


def test_native_core_distinguishes_not_directory_directory_and_malformed(tmp_path):
    (tmp_path / "plain").write_text("text", encoding="utf-8")
    not_dir = execute_native_operation(
        tmp_path,
        "read_file",
        {"path": "plain/child"},
    ).envelope
    is_dir = execute_native_operation(
        tmp_path,
        "write_file",
        {"path": ".", "content": "bad"},
    ).envelope
    malformed = execute_native_operation(
        tmp_path,
        "search_code",
        {"path": ".", "query": "[", "regex": True},
    ).envelope
    traversal = execute_native_operation(
        tmp_path,
        "read_file",
        {"path": "../escape"},
    ).envelope
    assert not_dir.diagnostic and not_dir.diagnostic.code == "not_a_directory"
    assert is_dir.diagnostic and is_dir.diagnostic.code == "is_a_directory"
    assert malformed.diagnostic is None
    assert malformed.text.startswith("⚠️ SEARCH_ERROR: invalid regex:")
    assert traversal.diagnostic is not None
    assert traversal.text.startswith("⚠️ READ_FILE_ERROR:")


def test_tool_loop_persists_typed_remote_diagnostic_without_stale_carryover(tmp_path):
    from ouroboros.loop_tool_execution import _execute_single_tool
    from ouroboros.workspace_diagnostics import (
        ExecutionDiagnostic,
        ToolExecutionEnvelope,
        publish_execution_envelope,
    )

    class Tools:
        CODE_TOOLS = frozenset()
        _ctx = SimpleNamespace(task_metadata={}, task_depth=0)
        first = True

        def execute(self, _name, _args):
            if self.first:
                self.first = False
                publish_execution_envelope(
                    ToolExecutionEnvelope(
                        text="legacy-compatible error",
                        diagnostic=ExecutionDiagnostic(
                            domain="filesystem",
                            code="permission_denied",
                            message="denied",
                            phase="execute",
                            completion="not_started",
                            retryable=False,
                            errno=13,
                        ),
                    )
                )
                return "legacy-compatible error"
            return "OK"

    logs = tmp_path / "logs"
    logs.mkdir()
    tool = Tools()
    first = _execute_single_tool(
        tool,
        {"id": "one", "function": {"name": "read_file", "arguments": "{}"}},
        logs,
        "task",
    )
    second = _execute_single_tool(
        tool,
        {"id": "two", "function": {"name": "read_file", "arguments": "{}"}},
        logs,
        "task",
    )
    assert first["is_error"] is True
    assert first["result_meta"]["execution_diagnostic"]["code"] == "permission_denied"
    assert first["result_meta"]["execution_diagnostic"]["errno"] == 13
    assert "execution_diagnostic" not in second["result_meta"]


def test_oversized_output_blob_index_is_omitted_only_from_both_wire_shapes():
    from ouroboros.execd import _bounded_wire_result
    from ouroboros.remote_protocol import encode_control

    envelope_ref = {
        "name": "operation-envelope.json",
        "blob_id": "f" * 64,
        "sha256": "f" * 64,
        "size": 1234,
        "mime": "application/json",
        "truncated": False,
    }
    full = {
        "completion": "completed",
        "prepared_hash": "a" * 64,
        "envelope": {
            "text": "externalized",
            "diagnostic": None,
            "process": None,
            "artifacts": [envelope_ref],
            "trace": {
                "completion": "complete",
                "externalized_result": envelope_ref,
            },
        },
        "output_blobs": {
            f"{index:064x}": f"{index:064x}" for index in range(25_000)
        },
    }
    initial = _bounded_wire_result(full)
    reconcile = _bounded_wire_result(
        {
            "completion": "completed",
            "result": full,
            "result_unavailable": False,
        }
    )
    assert "output_blobs" not in initial
    assert "output_blobs" not in reconcile["result"]
    assert len(full["output_blobs"]) == 25_000
    encode_control(
        {
            "kind": "result",
            "seq": 1,
            "request_id": "request",
            "operation_id": "operation",
            "completion": "completed",
            "result": initial,
            "prepared_hash": "a" * 64,
        }
    )
    encode_control(
        {
            "kind": "reconcile_result",
            "seq": 2,
            "request_id": "request",
            "operation_id": "operation",
            "completion": "completed",
            "result": reconcile,
        }
    )
    small = {**full, "output_blobs": {"b" * 64: "b" * 64}}
    assert _bounded_wire_result(small)["output_blobs"] == small["output_blobs"]


def test_externalized_envelope_is_authoritative_when_wire_blob_map_is_omitted():
    from ouroboros.remote_finalization import prefetch_remote_result_import

    full_envelope = {
        "text": "full result",
        "diagnostic": None,
        "process": None,
        "artifacts": [
            {
                "name": "file.txt",
                "blob_id": "b" * 64,
                "sha256": "b" * 64,
                "size": 10,
                "mime": "text/plain",
            }
        ],
        "trace": {"completion": "complete"},
    }
    payload = json.dumps(
        full_envelope,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    digest = hashlib.sha256(payload).hexdigest()
    ref = {
        "name": "operation-envelope.json",
        "blob_id": digest,
        "sha256": digest,
        "size": len(payload),
        "mime": "application/json",
        "truncated": False,
    }
    wire_result = {
        "completion": "completed",
        "envelope": {
            "text": "preview",
            "diagnostic": None,
            "process": None,
            "artifacts": [ref],
            "trace": {"completion": "complete", "externalized_result": ref},
        },
    }
    envelope, fetched = prefetch_remote_result_import(
        wire_result,
        lambda blob_id, max_bytes: payload
        if blob_id == digest and len(payload) <= max_bytes
        else b"",
    )
    assert envelope["trace"]["externalized_result"] == ref
    assert fetched["externalized_envelope"] == payload


def test_reviewed_script_executes_in_canonical_remote_workspace(tmp_path):
    package, blobs = _reviewed_package(
        {
            "scripts/run.py": (
                b"from pathlib import Path\n"
                b"Path('remote-result.txt').write_text(str(Path.cwd()))\n"
                b"print('reviewed-script-ok')\n"
            ),
            "SKILL.md": b"reviewed payload\n",
        },
        kind="script",
        invocation={
            "entry": "scripts/run.py",
            "argv": [],
            "timeout_sec": 10,
        },
    )
    prepared = prepare_native_operation(
        tmp_path,
        "execute_reviewed_payload",
        package,
        task_id="task-script",
        blobs=blobs,
    )
    result = execute_native_operation(
        tmp_path,
        "execute_reviewed_payload",
        prepared.execution_args,
        native_facts=prepared.native_facts,
        blobs=blobs,
        task_id="task-script",
    )

    assert result.envelope.process is not None
    assert result.envelope.process.returncode == 0
    assert "reviewed-script-ok" in result.envelope.text
    assert (tmp_path / "remote-result.txt").read_text() == str(tmp_path)


def test_reviewed_extension_gets_workspace_only_context_and_no_home_key(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("OPENROUTER_API_KEY", "must-not-cross")
    package, blobs = _reviewed_package(
        {
            "SKILL.md": b"reviewed extension\n",
            "plugin.py": (
                b"import os\n"
                b"def inspect(ctx, suffix=''):\n"
                b"    leaked = os.environ.get('OPENROUTER_API_KEY', '')\n"
                b"    return f'{ctx.repo_dir}|{ctx.workspace_mode}|{suffix}|{leaked or \"clean\"}'\n"
                b"def register(api):\n"
                b"    api.register_tool('inspect', inspect, description='inspect', schema={})\n"
            ),
        },
        kind="extension_tool",
        skill_name="remote_skill",
        entry="plugin.py",
        invocation={
            "surface": "ext_14_r_remote_skill_inspect",
            "args": {"suffix": "ok"},
            "timeout_sec": 10,
        },
    )
    prepared = prepare_native_operation(
        tmp_path,
        "execute_reviewed_payload",
        package,
        task_id="task-extension",
        blobs=blobs,
    )
    result = execute_native_operation(
        tmp_path,
        "execute_reviewed_payload",
        prepared.execution_args,
        native_facts=prepared.native_facts,
        blobs=blobs,
        task_id="task-extension",
    )

    assert result.envelope.process is not None
    assert result.envelope.process.returncode == 0
    assert result.envelope.text == f"{tmp_path}|external|ok|clean"


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda package, blobs: package["payload"]["files"][0].update(
                {"path": "../escape.py"}
            ),
            "unsafe or colliding",
        ),
        (
            lambda package, blobs: package["payload"].update(
                {"skill_name": "skill\u00e9"}
            ),
            "identity is invalid",
        ),
        (
            lambda package, blobs: blobs.update({"f" * 64: b"undeclared"}),
            "undeclared blobs",
        ),
    ],
)
def test_reviewed_payload_validation_fails_closed(tmp_path, mutate, message):
    package, blobs = _reviewed_package(
        {"scripts/run.py": b"print('ok')\n"},
        kind="script",
        invocation={
            "entry": "scripts/run.py",
            "argv": [],
            "timeout_sec": 10,
        },
    )
    mutate(package, blobs)

    with pytest.raises(ValueError, match=message):
        prepare_native_operation(
            tmp_path,
            "execute_reviewed_payload",
            package,
            blobs=blobs,
        )


def test_reviewed_payload_rejects_casefold_collisions(tmp_path):
    package, blobs = _reviewed_package(
        {"A.py": b"print('A')\n", "a.py": b"print('a')\n"},
        kind="script",
        invocation={"entry": "A.py", "argv": [], "timeout_sec": 10},
    )

    with pytest.raises(ValueError, match="unsafe or colliding"):
        prepare_native_operation(
            tmp_path,
            "execute_reviewed_payload",
            package,
            blobs=blobs,
        )


def test_reviewed_payload_rejects_hash_and_mode_drift(tmp_path):
    package, blobs = _reviewed_package(
        {"run.py": b"print('ok')\n"},
        kind="script",
        invocation={"entry": "run.py", "argv": [], "timeout_sec": 10},
    )
    package["payload"]["files"][0]["mode"] = 0o777
    with pytest.raises(ValueError, match="metadata is invalid"):
        prepare_native_operation(
            tmp_path,
            "execute_reviewed_payload",
            package,
            blobs=blobs,
        )

    package["payload"]["files"][0]["mode"] = 0o600
    package["payload"]["content_hash"] = "0" * 64
    with pytest.raises(ValueError, match="content hash"):
        prepare_native_operation(
            tmp_path,
            "execute_reviewed_payload",
            package,
            blobs=blobs,
        )
