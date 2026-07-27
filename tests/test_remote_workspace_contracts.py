import copy
import json
import pathlib
import subprocess
import sys
from types import SimpleNamespace

import pytest

from ouroboros.tool_access import resource_root_path
from ouroboros.tools.registry import _WORKSPACE_ALLOWED_TOOLS, ToolContext, active_repo_dir_for
from ouroboros.workspace_diagnostics import (
    ProcessExecutionResult,
    ToolExecutionEnvelope,
)
from ouroboros.workspace_executor import ExecutorResult, execute_enveloped
from ouroboros.workspace_ref import (
    RemoteWorkspacePathError,
    has_workspace,
    is_remote_workspace,
    local_workspace_path_for,
    normalize_workspace_ref,
)


def _ssh_ref() -> dict[str, str]:
    return {
        "kind": "ssh",
        "connection_id": "conn-1",
        "remote_root": "/srv/project",
        "workspace_id": "workspace-1",
    }


def test_transport_created_after_panic_is_immediately_discarded(tmp_path):
    from ouroboros.remote_workspace import (
        RemoteSessionBroker,
        RemoteWorkspaceError,
    )

    class Transport:
        panic_calls = 0

        def panic(self):
            self.panic_calls += 1

    transport = Transport()
    manifest = {
        "schema_version": 1,
        "manifest_sha256": "a" * 64,
        "public_schema_sha256": "b" * 64,
        "native_operations": [],
        "native_kernel_modules": [],
        "native_import_modules": [],
        "native_import_edges": {},
    }
    broker = RemoteSessionBroker(
        tmp_path,
        "generation",
        manifest,
        transport_factory=lambda _request: transport,
    )
    broker._stop.set()
    try:
        with pytest.raises(RemoteWorkspaceError, match="broker is closed"):
            broker._new_transport(SimpleNamespace())
        assert transport.panic_calls == 1
    finally:
        broker._stop.clear()
        broker.close()


def test_workspace_ref_normalizes_local_and_ssh(tmp_path):
    local = normalize_workspace_ref({"kind": "local", "local_root": str(tmp_path)})
    assert local == {"kind": "local", "local_root": str(tmp_path.resolve())}
    assert normalize_workspace_ref({**_ssh_ref(), "remote_root": "/srv/project/"}) == _ssh_ref()


@pytest.mark.parametrize(
    "raw",
    [
        {"kind": "local", "local_root": "relative"},
        {"kind": "ssh", "connection_id": "c", "remote_root": "relative", "workspace_id": "w"},
        {"kind": "ssh", "connection_id": "c", "remote_root": "/x/../y", "workspace_id": "w"},
        {"kind": "ssh", "connection_id": "c", "remote_root": "/x", "workspace_id": "w", "host": "bad"},
        {"kind": "other"},
    ],
)
def test_workspace_ref_rejects_ambiguous_or_transport_bearing_shapes(raw):
    with pytest.raises(ValueError):
        normalize_workspace_ref(raw)


def test_only_sealed_remote_workspace_is_semantic_and_has_no_home_path(tmp_path):
    unsealed = SimpleNamespace(
        workspace_root=None,
        workspace_mode="external",
        task_metadata={"workspace_ref": _ssh_ref()},
    )
    assert not has_workspace(unsealed)
    assert not is_remote_workspace(unsealed)

    ctx = ToolContext(
        repo_dir=tmp_path / "system",
        drive_root=tmp_path / "data",
        workspace_mode="external",
        task_metadata={"_sealed_workspace_ref": _ssh_ref()},
    )
    assert has_workspace(ctx)
    assert is_remote_workspace(ctx)
    assert ctx.is_workspace_mode()
    with pytest.raises(RemoteWorkspacePathError):
        local_workspace_path_for(ctx)
    with pytest.raises(RemoteWorkspacePathError):
        ctx.active_repo_dir()
    with pytest.raises(RemoteWorkspacePathError):
        active_repo_dir_for(ctx)
    with pytest.raises(RemoteWorkspacePathError):
        resource_root_path(ctx, "active_workspace")


def test_absent_ref_preserves_legacy_workspace_behavior(tmp_path):
    ctx = SimpleNamespace(workspace_root=tmp_path, workspace_mode="external")
    assert has_workspace(ctx)
    assert not is_remote_workspace(ctx)
    assert local_workspace_path_for(ctx) == tmp_path
    assert has_workspace({"workspace_root": str(tmp_path)})
    assert has_workspace({"metadata": {"workspace_root": str(tmp_path)}})
    assert has_workspace(
        SimpleNamespace(
            workspace_root=None,
            task_metadata={"workspace_root": str(tmp_path)},
        )
    )
    with pytest.raises(ValueError, match="no workspace"):
        local_workspace_path_for({"workspace_root": ""})


def test_workspace_affinity_table_is_exhaustive_and_fail_closed():
    from ouroboros.tool_capabilities import (
        WORKSPACE_TOOL_EXECUTION_AFFINITY,
        builtin_execution_affinity,
        lexical_execution_placement,
        normalize_dynamic_execution_affinity,
    )

    assert set(WORKSPACE_TOOL_EXECUTION_AFFINITY) == set(_WORKSPACE_ALLOWED_TOOLS)
    assert len(WORKSPACE_TOOL_EXECUTION_AFFINITY) == 50
    assert builtin_execution_affinity("read_file") == "root"
    assert builtin_execution_affinity("knowledge_read") == "home"
    assert lexical_execution_placement("read_file", {}).placement == "active_workspace"
    assert lexical_execution_placement(
        "read_file", {"root": "runtime_data"}
    ).placement == "home"
    with pytest.raises(ValueError):
        builtin_execution_affinity("new_unclassified_tool")
    assert normalize_dynamic_execution_affinity(None, present=False) == "home"
    with pytest.raises(ValueError):
        normalize_dynamic_execution_affinity("remote", present=True)


def _workspace_public_schemas(registry):
    from ouroboros.tool_capabilities import WORKSPACE_TOOL_EXECUTION_AFFINITY

    return [
        registry._schema_for_entry(registry._entries[name])
        for name in sorted(WORKSPACE_TOOL_EXECUTION_AFFINITY)
    ]


def test_workspace_capability_manifest_is_deterministic_and_schema_exact(tmp_path):
    from ouroboros.tool_capabilities import (
        assert_workspace_capability_compatible,
        build_workspace_capability_manifest,
    )
    from ouroboros.tools.registry import ToolRegistry

    source_root = pathlib.Path(__file__).resolve().parents[1]
    system_repo = tmp_path / "system"
    local_root = tmp_path / "local-workspace"
    drive_root = tmp_path / "data"
    system_repo.mkdir()
    local_root.mkdir()
    local_registry = ToolRegistry(repo_dir=system_repo, drive_root=drive_root)
    local_registry.set_context(
        ToolContext(
            repo_dir=system_repo,
            drive_root=drive_root,
            workspace_root=local_root,
            workspace_mode="external",
        )
    )
    remote_registry = ToolRegistry(repo_dir=system_repo, drive_root=drive_root)
    remote_registry.set_context(
        ToolContext(
            repo_dir=system_repo,
            drive_root=drive_root,
            workspace_mode="external",
            task_metadata={"_sealed_workspace_ref": _ssh_ref()},
        )
    )

    local_schemas = _workspace_public_schemas(local_registry)
    remote_schemas = _workspace_public_schemas(remote_registry)
    local_manifest = build_workspace_capability_manifest(
        local_schemas,
        repo_root=source_root,
    )
    remote_manifest = build_workspace_capability_manifest(
        remote_schemas,
        repo_root=source_root,
    )
    assert json.dumps(local_manifest, sort_keys=True) == json.dumps(
        remote_manifest,
        sort_keys=True,
    )
    assert_workspace_capability_compatible(local_manifest, remote_manifest)

    claude_schema = next(
        row for row in local_manifest["public_tools"]
        if row["function"]["name"] == "claude_code_edit"
    )
    assert isinstance(
        claude_schema["function"]["parameters"]["properties"]["budget"]["default"],
        float,
    )
    from ouroboros.remote_workspace import RemoteSessionBroker

    broker = RemoteSessionBroker(
        drive_root,
        "generation-capability-proof",
        local_manifest,
    )
    try:
        assert broker.capability_projection["manifest_sha256"] == local_manifest[
            "manifest_sha256"
        ]
    finally:
        broker.close()

    drifted_schemas = copy.deepcopy(remote_schemas)
    drifted_schemas[0]["function"]["description"] += " drift"
    drifted_manifest = build_workspace_capability_manifest(
        drifted_schemas,
        repo_root=source_root,
    )
    with pytest.raises(ValueError, match="schema digest"):
        assert_workspace_capability_compatible(local_manifest, drifted_manifest)


def test_workspace_capability_manifest_fails_on_missing_mapping_or_forbidden_import(
    tmp_path,
):
    from ouroboros.tool_capabilities import build_workspace_capability_manifest
    from ouroboros.tools.registry import ToolRegistry
    from ouroboros.workspace_native import REMOTE_NATIVE_OPERATION_MODULE

    source_root = pathlib.Path(__file__).resolve().parents[1]
    registry = ToolRegistry(repo_dir=tmp_path, drive_root=tmp_path)
    schemas = _workspace_public_schemas(registry)
    incomplete = dict(REMOTE_NATIVE_OPERATION_MODULE)
    incomplete.pop("read_file")
    with pytest.raises(ValueError, match="missing=.*read_file"):
        build_workspace_capability_manifest(
            schemas,
            repo_root=source_root,
            operation_modules=incomplete,
        )

    forbidden = dict(REMOTE_NATIVE_OPERATION_MODULE)
    forbidden["read_file"] = "ouroboros.config"
    with pytest.raises(ValueError, match="forbidden Home dependencies"):
        build_workspace_capability_manifest(
            schemas,
            repo_root=source_root,
            operation_modules=forbidden,
        )


def test_remote_native_kernel_modules_import_cleanly_in_isolated_python():
    from ouroboros.tool_capabilities import FORBIDDEN_REMOTE_IMPORT_PREFIXES
    from ouroboros.workspace_native import REMOTE_NATIVE_KERNEL_MODULES

    source_root = pathlib.Path(__file__).resolve().parents[1]
    code = (
        "import importlib,json,sys\n"
        f"sys.path.insert(0, {str(source_root)!r})\n"
        f"modules={sorted(REMOTE_NATIVE_KERNEL_MODULES)!r}\n"
        "for name in modules: importlib.import_module(name)\n"
        "print(json.dumps(sorted(sys.modules)))\n"
    )
    proc = subprocess.run(
        [sys.executable, "-I", "-c", code],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    loaded = json.loads(proc.stdout)
    forbidden = {
        category: [
            module
            for module in loaded
            if any(
                module == prefix or module.startswith(prefix + ".")
                for prefix in prefixes
            )
        ]
        for category, prefixes in FORBIDDEN_REMOTE_IMPORT_PREFIXES.items()
    }
    assert {key: value for key, value in forbidden.items() if value} == {}


def test_worker_pipe_uses_canonical_operation_timeout():
    import time
    from types import MethodType

    from ouroboros.remote_worker_proxy import RemoteWorkspacePipeProxy
    from ouroboros.remote_workspace import PreparedRemoteCall

    proxy = object.__new__(RemoteWorkspacePipeProxy)
    observed = {}

    def call(_self, method, payload, *, timeout_sec=None):
        observed.update(method=method, payload=payload, timeout_sec=timeout_sec)
        return {"text": "ok"}

    proxy._call = MethodType(call, proxy)
    prepared = PreparedRemoteCall(
        request_id="request-a",
        operation_id="operation-a",
        tool="run_command",
        prepared_token="token-a",
        prepared_hash="a" * 64,
        expires_at_ms=int(time.time() * 1000) + 60_000,
        execution_args={"timeout_sec": 900},
        native_facts={},
    )

    result = proxy.execute_prepared(
        {"kind": "ssh"},
        prepared,
        canonical_args={"timeout_sec": 900},
    )

    assert result.text == "ok"
    assert observed["timeout_sec"] == 930.0


def test_process_result_and_local_envelope_have_one_request_scoped_authority(tmp_path):
    assert ExecutorResult is ProcessExecutionResult
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    ctx = SimpleNamespace(
        drive_root=tmp_path / "data",
        executor_ref={
            "type": "local",
            "id": "local-envelope",
            "workspace_host_path": str(workspace),
            "workspace_backend_path": "/workspace",
        },
        task_metadata={},
    )
    envelope = execute_enveloped(
        "req-1",
        ctx,
        [sys.executable, "-c", "print('envelope-ok', end='')"],
        workspace,
        10,
        operation_id="op-1",
    )
    assert isinstance(envelope, ToolExecutionEnvelope)
    assert envelope.text == "envelope-ok"
    assert envelope.process is not None
    assert envelope.process.stdout == "envelope-ok"
    assert envelope.trace["request_id"] == "req-1"
    assert envelope.trace["operation_id"] == "op-1"


def test_durable_remote_record_keeps_workspace_semantics():
    from ouroboros.task_pacing import _workspace_delivery
    from ouroboros.task_status import _normalize_workspace_artifact_status

    record = {
        "id": "remote-task",
        "status": "completed",
        "workspace_root": "",
        "workspace_mode": "external",
        "delegation_role": "root",
        "metadata": {"_sealed_workspace_ref": _ssh_ref()},
    }

    assert has_workspace(record)
    assert is_remote_workspace(record)
    assert _workspace_delivery(record)
    normalized = _normalize_workspace_artifact_status(record)
    assert normalized["status"] == "running"
    assert normalized["child_status"] == "completed"
    assert normalized["artifact_status"] == "finalizing"


def test_runtime_context_exposes_remote_workspace_without_transport_identity(
    tmp_path, monkeypatch
):
    import ouroboros.config as config
    from ouroboros.context import build_runtime_section
    from ouroboros.projects_registry import create_project

    project_dir = tmp_path / "project"
    project_dir.mkdir()
    create_project(
        tmp_path,
        "project-1",
        working_dir=str(project_dir),
    )

    monkeypatch.setenv("TOTAL_BUDGET", "1")
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    task = {
        "id": "remote-task",
        "project_id": "project-1",
        "_is_direct_chat": True,
        "workspace_root": "",
        "workspace_mode": "external",
        "metadata": {"_sealed_workspace_ref": _ssh_ref()},
    }
    rendered = build_runtime_section(
        SimpleNamespace(repo_dir=tmp_path, drive_root=tmp_path),
        task,
    )

    assert '"active_workspace"' in rendered
    assert '"kind": "ssh"' in rendered
    assert '"remote_root": "/srv/project"' in rendered
    assert '"connection_id"' not in rendered
    assert '"workspace_id"' not in rendered
    assert '"project_room"' not in rendered


def test_remote_external_workspace_does_not_lift_home_path_confinement(
    tmp_path, monkeypatch
):
    from ouroboros.tool_access import (
        resolve_user_file_path,
        user_files_path_block_reason,
    )

    home = tmp_path / "home"
    home.mkdir()
    outside = tmp_path / "host-scratch"
    monkeypatch.setenv("OUROBOROS_USER_FILES_ROOT", str(home))
    remote_ctx = ToolContext(
        repo_dir=tmp_path / "system-repo",
        drive_root=tmp_path / "runtime-store",
        workspace_mode="external",
        task_metadata={"_sealed_workspace_ref": _ssh_ref()},
    )

    assert "outside user home" in user_files_path_block_reason(remote_ctx, outside)
    with pytest.raises(ValueError, match="outside the user_files home"):
        resolve_user_file_path(remote_ctx, str(outside))

    local_ctx = ToolContext(
        repo_dir=tmp_path / "system-repo",
        drive_root=tmp_path / "runtime-store",
        workspace_root=tmp_path / "local-workspace",
        workspace_mode="external",
    )
    assert resolve_user_file_path(local_ctx, str(outside)) == outside.resolve()


def test_remote_snapshot_consumers_never_fall_back_to_system_repo(
    tmp_path, monkeypatch
):
    from ouroboros.review_evidence import collect_turn_diff
    from ouroboros.tools.plan_review import _resolve_plan_class

    ctx = ToolContext(
        repo_dir=tmp_path / "system-repo",
        drive_root=tmp_path / "runtime-store",
        workspace_mode="external",
        task_metadata={"_sealed_workspace_ref": _ssh_ref()},
    )

    def unexpected_subprocess(*_args, **_kwargs):
        raise AssertionError("remote snapshot must not inspect the Home system repo")

    monkeypatch.setattr(subprocess, "run", unexpected_subprocess)
    with pytest.raises(RemoteWorkspacePathError):
        collect_turn_diff(ctx)
    assert _resolve_plan_class(ctx, "", ["src/main.py"]) == ("external", "")


def test_schedule_contract_reserves_remote_placement_fields():
    from ouroboros.schedule_contract import RESERVED_TEMPLATE_FIELDS

    assert {
        "workspace_ref",
        "_sealed_workspace_ref",
        "_project_room_workspace_ref",
        "executor_ref",
        "connection_id",
        "remote_root",
        "workspace_id",
    } <= RESERVED_TEMPLATE_FIELDS


def test_remote_subagent_event_and_task_payload_preserve_sealed_placement():
    from ouroboros.tools.control import _populate_subagent_event_extras
    from supervisor.events import _build_scheduled_task_payload

    executor_ref = {
        "type": "ssh_exec",
        "id": "conn-1",
        "workspace_id": "workspace-1",
        "network": "host",
    }
    event = {}
    _populate_subagent_event_extras(
        event,
        current_chat_id=0,
        child_drive=None,
        workspace_root="",
        workspace_mode="external",
        workspace_ref=_ssh_ref(),
        executor_ref=executor_ref,
        context="",
        parent_task_id="parent-1",
    )
    assert event["metadata"]["_sealed_workspace_ref"] == _ssh_ref()
    assert event["metadata"]["executor_ref"] == executor_ref
    assert event["executor_ref"] == executor_ref

    task = _build_scheduled_task_payload(
        {
            "tid": "child-1",
            "workspace_mode": "external",
            "metadata": event["metadata"],
            "executor_ref": event["executor_ref"],
        }
    )
    assert task["workspace_root"] == ""
    assert task["workspace_mode"] == "external"
    assert task["metadata"]["_sealed_workspace_ref"] == _ssh_ref()
    assert task["metadata"]["executor_ref"] == executor_ref
    assert task["executor_ref"] == executor_ref
    assert has_workspace(task)
    assert is_remote_workspace(task)


def test_remote_parent_never_mints_home_cooperative_workspace(
    tmp_path, monkeypatch
):
    from ouroboros.tools import control_delegation

    ctx = ToolContext(
        repo_dir=tmp_path / "system-repo",
        drive_root=tmp_path / "runtime-store",
        workspace_mode="external",
        task_metadata={"_sealed_workspace_ref": _ssh_ref()},
    )

    def unexpected_home_workspace(*_args, **_kwargs):
        raise AssertionError("SSH placement must not mint a Home workspace")

    monkeypatch.setattr(
        control_delegation,
        "ensure_cooperative_shared_root",
        unexpected_home_workspace,
    )
    effective, profile, error = control_delegation.resolve_cooperative_write_root(
        ctx,
        "external_workspace",
        "",
        "",
        {"root_task_id": "root-1"},
    )
    assert (effective, profile, error) == ("", "external_workspace_task", "")


def test_remote_active_repo_inheritance_stays_remote(tmp_path):
    from ouroboros.tools.control import _inherited_workspace_from_active_repo

    ctx = ToolContext(
        repo_dir=tmp_path / "system-repo",
        drive_root=tmp_path / "runtime-store",
        workspace_mode="external",
        task_metadata={"_sealed_workspace_ref": _ssh_ref()},
    )

    assert _inherited_workspace_from_active_repo(ctx, "", "") == ("", "external")
