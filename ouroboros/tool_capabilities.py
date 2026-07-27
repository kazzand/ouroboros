"""Single source of truth for tool visibility, parallelism, and result limits."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import pathlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Literal

ExecutionAffinity = Literal["home", "root", "cwd", "workspace", "service", "hybrid"]
ExecutionPlacement = Literal["home", "active_workspace", "service_record", "hybrid"]
DynamicExecutionAffinity = Literal["home", "active_workspace"]


@dataclass(frozen=True)
class PlacementDecision:
    affinity: ExecutionAffinity
    placement: ExecutionPlacement
    reason: str


ROOT_AFFINITY_TOOL_NAMES: frozenset[str] = frozenset({
    "read_file", "list_files", "write_file", "edit_text", "search_code", "query_code",
})
CWD_AFFINITY_TOOL_NAMES: frozenset[str] = frozenset({"run_command", "run_script"})
WORKSPACE_AFFINITY_TOOL_NAMES: frozenset[str] = frozenset({"vcs_status", "vcs_diff"})
SERVICE_AFFINITY_TOOL_NAMES: frozenset[str] = frozenset({
    "start_service", "service_status", "service_logs", "stop_service",
})
HYBRID_AFFINITY_TOOL_NAMES: frozenset[str] = frozenset({
    "verify_and_record",
    "claude_code_edit",
    "schedule_subagent",
    "integrate_subagent_patch",
    "compare_subagent_patches",
    "browse_page",
    "browser_action",
    "analyze_screenshot",
    "vlm_query",
    "view_image",
    "ocr_pdf",
    "extract_video_frames",
})
HOME_AFFINITY_TOOL_NAMES: frozenset[str] = frozenset({
    "chat_history",
    "recent_tasks",
    "plan_task",
    "task_acceptance_review",
    "wait_task",
    "wait_tasks",
    "get_task_result",
    "peek_task",
    "cancel_task",
    "discard_child_result",
    "override_delegation_constraint",
    "knowledge_read",
    "knowledge_list",
    "knowledge_write",
    "journal_read",
    "journal_write",
    "workpad_read",
    "workpad_write",
    "tree_note",
    "tree_read",
    "web_search",
    "youtube_transcript",
    "list_available_tools",
    "enable_tools",
})

WORKSPACE_TOOL_EXECUTION_AFFINITY: dict[str, ExecutionAffinity] = {
    **{name: "root" for name in ROOT_AFFINITY_TOOL_NAMES},
    **{name: "cwd" for name in CWD_AFFINITY_TOOL_NAMES},
    **{name: "workspace" for name in WORKSPACE_AFFINITY_TOOL_NAMES},
    **{name: "service" for name in SERVICE_AFFINITY_TOOL_NAMES},
    **{name: "hybrid" for name in HYBRID_AFFINITY_TOOL_NAMES},
    **{name: "home" for name in HOME_AFFINITY_TOOL_NAMES},
}

WORKSPACE_CAPABILITY_MANIFEST_SCHEMA_VERSION = 1

FORBIDDEN_REMOTE_IMPORT_PREFIXES: dict[str, tuple[str, ...]] = {
    "registry": ("ouroboros.tools.registry",),
    "provider_or_model": (
        "ouroboros.llm",
        "ouroboros.local_model",
        "ouroboros.model_",
        "ouroboros.pricing",
        "ouroboros.provider_models",
        "ouroboros.tools.search",
    ),
    "review_or_planning": (
        "ouroboros.deep_self_review",
        "ouroboros.parallel_review",
        "ouroboros.plan_review",
        "ouroboros.review",
        "ouroboros.review_evidence",
        "ouroboros.review_state",
        "ouroboros.scope_review",
        "ouroboros.tools.claude_advisory_review",
        "ouroboros.tools.review",
        "ouroboros.triad_review",
    ),
    "server_or_gateway": (
        "server",
        "supervisor",
        "ouroboros.gateway",
        "ouroboros.server",
        "ouroboros.supervisor",
    ),
    "settings_or_owner_state": (
        "ouroboros.config",
        "ouroboros.owner",
        "ouroboros.settings_setup_contract",
    ),
    "home_task_or_artifact_state": (
        "ouroboros.artifacts",
        "ouroboros.mutation_attribution",
        "ouroboros.outcomes",
        "ouroboros.project_facts",
        "ouroboros.protected_artifacts",
        "ouroboros.task_pacing",
        "ouroboros.task_results",
        "ouroboros.task_status",
    ),
}


def build_workspace_capability_manifest(
    public_schemas: Iterable[Mapping[str, Any]],
    *,
    repo_root: pathlib.Path,
    operation_modules: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Build the canonical Home/execd capability contract from registry schemas.

    The caller supplies the registry's unfiltered built-in schemas. This module
    owns which of those tools belong to the workspace surface; execd owns only
    the explicit native operation allowlist in ``workspace_native``.
    """

    from ouroboros.workspace_native import REMOTE_NATIVE_OPERATION_MODULE

    native_map = (
        REMOTE_NATIVE_OPERATION_MODULE
        if operation_modules is None
        else operation_modules
    )
    schemas_by_name: dict[str, dict[str, Any]] = {}
    for raw in public_schemas:
        schema = _canonical_json_copy(raw, label="public tool schema")
        function = schema.get("function")
        name = str(function.get("name") or "").strip() if isinstance(function, dict) else ""
        if schema.get("type") != "function" or not name:
            raise ValueError("public tool schema must be a named function envelope")
        if name in schemas_by_name:
            raise ValueError(f"duplicate public tool schema: {name}")
        schemas_by_name[name] = schema

    expected_names = frozenset(WORKSPACE_TOOL_EXECUTION_AFFINITY)
    missing = sorted(expected_names - schemas_by_name.keys())
    if missing:
        raise ValueError(f"workspace capability manifest is missing public schemas: {missing}")
    public_tools = [
        schemas_by_name[name]
        for name in sorted(expected_names)
    ]
    public_schema_sha256 = hashlib.sha256(_canonical_json_bytes(public_tools)).hexdigest()
    import_audit = assert_remote_native_import_closure(
        pathlib.Path(repo_root),
        operation_modules=native_map,
    )
    native_operations = [
        {"name": name, "module": str(native_map[name])}
        for name in sorted(native_map)
    ]
    payload: dict[str, Any] = {
        "schema_version": WORKSPACE_CAPABILITY_MANIFEST_SCHEMA_VERSION,
        "public_tools": public_tools,
        "public_schema_sha256": public_schema_sha256,
        "native_operations": native_operations,
        "native_kernel_modules": list(import_audit["roots"]),
        "native_import_modules": list(import_audit["modules"]),
        "native_import_edges": dict(import_audit["edges"]),
    }
    payload["manifest_sha256"] = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
    return payload


def remote_native_import_closure(
    repo_root: pathlib.Path,
    *,
    operation_modules: Mapping[str, str] | None = None,
    extra_roots: Iterable[str] = (),
) -> dict[str, Any]:
    """Return the deterministic module-import-time closure for execd kernels.

    Function-local imports are deliberately outside this module-import boundary:
    each native operation gets a clean-subprocess invocation smoke when its
    implementation lands. This static gate prevents the already-proven class of
    accidental Home dependencies from entering merely by importing execd.
    """

    from ouroboros.workspace_native import (
        REMOTE_NATIVE_OPERATION_MODULE,
        validate_remote_native_operation_map,
    )

    native_map = (
        REMOTE_NATIVE_OPERATION_MODULE
        if operation_modules is None
        else operation_modules
    )
    validate_remote_native_operation_map(native_map)
    root = pathlib.Path(repo_root).resolve(strict=False)
    seeds = frozenset(
        {
            *native_map.values(),
            "ouroboros.shell_parse",
            *(str(root) for root in extra_roots),
        }
    )
    initial_modules = {
        module
        for seed in seeds
        for module in (seed, *_parent_packages(seed))
    }
    pending = sorted(initial_modules, reverse=True)
    visited: set[str] = set()
    missing: set[str] = set()
    edges: dict[str, tuple[str, ...]] = {}
    while pending:
        module = pending.pop()
        if module in visited:
            continue
        visited.add(module)
        module_path = _local_module_path(root, module)
        if module_path is None:
            missing.add(module)
            continue
        imports = tuple(sorted(_module_scope_local_imports(root, module, module_path)))
        edges[module] = imports
        for imported in reversed(imports):
            for dependency in (imported, *_parent_packages(imported)):
                if dependency not in visited:
                    pending.append(dependency)

    forbidden: dict[str, list[str]] = {}
    for category, prefixes in FORBIDDEN_REMOTE_IMPORT_PREFIXES.items():
        matches = sorted(
            module
            for module in visited
            if any(_module_matches_prefix(module, prefix) for prefix in prefixes)
        )
        if matches:
            forbidden[category] = matches
    return {
        "roots": sorted(seeds),
        "modules": sorted(visited),
        "edges": {module: list(edges[module]) for module in sorted(edges)},
        "missing_modules": sorted(missing),
        "forbidden": forbidden,
    }


def assert_remote_native_import_closure(
    repo_root: pathlib.Path,
    *,
    operation_modules: Mapping[str, str] | None = None,
    extra_roots: Iterable[str] = (),
) -> dict[str, Any]:
    """Return a clean closure, otherwise fail before an execd artifact is built."""

    audit = remote_native_import_closure(
        repo_root,
        operation_modules=operation_modules,
        extra_roots=extra_roots,
    )
    if audit["missing_modules"]:
        raise ValueError(
            "remote native import closure has missing modules: "
            f"{audit['missing_modules']}"
        )
    if audit["forbidden"]:
        raise ValueError(
            "remote native import closure reaches forbidden Home dependencies: "
            f"{audit['forbidden']}"
        )
    return audit


def _module_matches_prefix(module: str, prefix: str) -> bool:
    return module == prefix or module.startswith(prefix + ".")


def _parent_packages(module: str) -> tuple[str, ...]:
    parts = module.split(".")
    return tuple(".".join(parts[:index]) for index in range(1, len(parts)))


def _local_module_path(repo_root: pathlib.Path, module: str) -> pathlib.Path | None:
    relative = pathlib.Path(*module.split("."))
    module_file = repo_root / relative.with_suffix(".py")
    if module_file.is_file():
        return module_file
    package_file = repo_root / relative / "__init__.py"
    if package_file.is_file():
        return package_file
    return None


def _module_scope_local_imports(
    repo_root: pathlib.Path,
    module: str,
    module_path: pathlib.Path,
) -> set[str]:
    tree = ast.parse(module_path.read_text(encoding="utf-8"), filename=str(module_path))
    import_nodes: list[ast.Import | ast.ImportFrom] = []
    pending = list(tree.body)
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            import_nodes.append(node)
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        pending.extend(ast.iter_child_nodes(node))
    package = module if module_path.name == "__init__.py" else module.rpartition(".")[0]
    imports: set[str] = set()
    for node in import_nodes:
        candidates: list[str] = []
        if isinstance(node, ast.Import):
            candidates.extend(alias.name for alias in node.names)
        elif node.level:
            relative = "." * node.level + str(node.module or "")
            try:
                base = importlib.util.resolve_name(relative, package)
            except (ImportError, ValueError):
                continue
            candidates.append(base)
            candidates.extend(f"{base}.{alias.name}" for alias in node.names)
        elif node.module:
            candidates.append(node.module)
            candidates.extend(f"{node.module}.{alias.name}" for alias in node.names)
        for candidate in candidates:
            if _local_module_path(repo_root, candidate) is not None:
                imports.add(candidate)
    return imports


def assert_workspace_capability_compatible(
    home_manifest: Mapping[str, Any],
    backend_manifest: Mapping[str, Any],
) -> None:
    """Fail admission on a missing native operation or public-schema drift."""

    home = _validated_workspace_capability_manifest(home_manifest, label="Home")
    backend = _validated_workspace_capability_manifest(
        backend_manifest,
        label="workspace backend",
    )
    if home["native_operations"] != backend["native_operations"]:
        raise ValueError("workspace backend native capability allowlist differs from Home")
    if home["public_schema_sha256"] != backend["public_schema_sha256"]:
        raise ValueError("workspace backend public tool schema digest differs from Home")
    if home["public_tools"] != backend["public_tools"]:
        raise ValueError("workspace backend public tool schemas differ from Home")
    for field in (
        "native_kernel_modules",
        "native_import_modules",
        "native_import_edges",
    ):
        if home.get(field) != backend.get(field):
            raise ValueError(
                f"workspace backend {field} differs from the Home import closure"
            )


def _validated_workspace_capability_manifest(
    raw: Mapping[str, Any],
    *,
    label: str,
) -> dict[str, Any]:
    manifest = _canonical_json_copy(raw, label=f"{label} capability manifest")
    if manifest.get("schema_version") != WORKSPACE_CAPABILITY_MANIFEST_SCHEMA_VERSION:
        raise ValueError(f"{label} capability manifest has an unsupported schema version")
    claimed_manifest_hash = str(manifest.pop("manifest_sha256", "") or "")
    actual_manifest_hash = hashlib.sha256(_canonical_json_bytes(manifest)).hexdigest()
    if claimed_manifest_hash != actual_manifest_hash:
        raise ValueError(f"{label} capability manifest hash is invalid")
    public_tools = manifest.get("public_tools")
    if not isinstance(public_tools, list):
        raise ValueError(f"{label} capability manifest public_tools must be a list")
    actual_schema_hash = hashlib.sha256(_canonical_json_bytes(public_tools)).hexdigest()
    if manifest.get("public_schema_sha256") != actual_schema_hash:
        raise ValueError(f"{label} capability manifest public schema hash is invalid")
    native_operations = manifest.get("native_operations")
    if not isinstance(native_operations, list):
        raise ValueError(f"{label} capability manifest native_operations must be a list")
    from ouroboros.workspace_native import validate_remote_native_operation_map

    operation_map: dict[str, str] = {}
    for item in native_operations:
        if not isinstance(item, dict):
            raise ValueError(f"{label} native operation rows must be objects")
        name = str(item.get("name") or "")
        module = str(item.get("module") or "")
        if not name or name in operation_map:
            raise ValueError(f"{label} native operation names must be non-empty and unique")
        operation_map[name] = module
    validate_remote_native_operation_map(operation_map)
    manifest["manifest_sha256"] = claimed_manifest_hash
    return manifest


def _canonical_json_copy(value: Any, *, label: str) -> dict[str, Any]:
    try:
        copied = json.loads(_canonical_json_bytes(value))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not canonical JSON: {exc}") from exc
    if not isinstance(copied, dict):
        raise ValueError(f"{label} must be an object")
    return copied


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def builtin_execution_affinity(tool_name: str) -> ExecutionAffinity:
    """Return the explicit built-in placement class; unknown names fail closed."""

    name = str(tool_name or "").strip()
    try:
        return WORKSPACE_TOOL_EXECUTION_AFFINITY[name]
    except KeyError:
        raise ValueError(f"built-in tool has no execution-affinity declaration: {name!r}") from None


def normalize_dynamic_execution_affinity(
    value: Any,
    *,
    present: bool,
) -> DynamicExecutionAffinity:
    """A missing extension/script declaration stays Home; invalid values fail."""

    if not present:
        return "home"
    text = str(value or "").strip().lower()
    if text not in {"home", "active_workspace"}:
        raise ValueError("execution_affinity must be 'home' or 'active_workspace'")
    return text  # type: ignore[return-value]


def lexical_execution_placement(
    tool_name: str,
    args: dict[str, Any],
) -> PlacementDecision:
    """Pure first classification; native containment is resolved later."""

    affinity = builtin_execution_affinity(tool_name)
    if affinity == "home":
        return PlacementDecision(affinity, "home", "Home-owned faculty")
    if affinity == "root":
        root = str(args.get("root") or "active_workspace").strip()
        placement: ExecutionPlacement = (
            "active_workspace" if root == "active_workspace" else "home"
        )
        return PlacementDecision(affinity, placement, f"resource root={root}")
    if affinity == "workspace":
        return PlacementDecision(affinity, "active_workspace", "workspace VCS state")
    if affinity == "service":
        if tool_name == "start_service":
            return PlacementDecision(affinity, "active_workspace", "new service cwd")
        return PlacementDecision(affinity, "service_record", "existing service placement")
    if affinity == "cwd":
        return PlacementDecision(
            affinity,
            "active_workspace",
            "cwd requires native classification",
        )
    return PlacementDecision(
        affinity,
        "hybrid",
        "Home authority plus native workspace half",
    )


CORE_TOOL_NAMES: frozenset[str] = frozenset({
    "read_file", "list_files", "write_file", "edit_text",
    "search_code", "query_code", "plan_task",
    "run_command", "claude_code_edit", "run_script",
    "start_service", "service_status", "service_logs", "stop_service",
    "vcs_status", "vcs_diff", "vcs_commit_reviewed", "commit_reviewed",
    "vcs_restore", "vcs_revert", "vcs_pull_ff", "vcs_rollback",
    "schedule_subagent", "integrate_subagent_patch", "compare_subagent_patches",
    "wait_task", "wait_tasks", "get_task_result",
    # D#7 soft-join child controls (siblings of steer_task): inspect/decide a child's fate
    # before finalizing (peek = pure read, discard = explicit abandon, cancel = real stop).
    "cancel_task", "peek_task", "discard_child_result", "override_delegation_constraint",
    # Task-tree coordination must be in the round-one envelope so a parent can publish the
    # shared frame BEFORE fanning out interdependent children (no enable_tools detour).
    "tree_note", "tree_read",
    # Main-chat routing capabilities the SYSTEM.md decision turn relies on
    # (kept in the core envelope so the anti-freeze ephemeral turn never needs an
    # enable_tools detour to route — though initial_tool_schemas exposes the full
    # set today, this makes the coupling explicit).
    "list_projects", "route_to_project", "promote_chat_to_task", "steer_task",
    "ensure_project_scope",
    "update_scratchpad", "update_identity",
    "chat_history", "recent_tasks",
    "knowledge_read", "knowledge_write", "knowledge_list",
    "web_search",
    "browse_page", "browser_action", "analyze_screenshot", "view_image",
    "ocr_pdf", "youtube_transcript", "extract_video_frames",
    "send_user_message", "send_photo", "send_video", "send_file",
    "switch_model",
    "request_restart", "promote_to_stable",
    "advisory_review", "review_status", "task_acceptance_review", "verify_and_record",
    # Heal mode blocks enable_tools, so repair/review tools must be core.
    "list_skills", "skill_review", "skill_preflight",
    "submit_skill_to_hub",
})

# Meta-tools: always visible alongside core tools
META_TOOL_NAMES: frozenset[str] = frozenset({
    "list_available_tools", "enable_tools",
})

LOCAL_READONLY_SUBAGENT_MODE: str = "local_readonly_subagent"

# V1 subagents are read-only against local Ouroboros state. Browser interaction
# remains available by explicit product decision, so this mode is not a remote
# website sandbox.
LOCAL_READONLY_SUBAGENT_TOOL_NAMES: frozenset[str] = frozenset({
    "read_file", "list_files", "search_code", "query_code",
    "vcs_status", "vcs_diff",
    "chat_history", "recent_tasks", "get_task_result", "wait_task", "wait_tasks",
    "schedule_subagent",
    # Task-tree coordination: a child reads the shared frame and raises beacons. tree_note
    # is a bounded tree-scoped write; its tagged child-result disposition branch also
    # updates the existing child result through join_ledger's lineage/hash authority.
    # It has no repo/control-plane effect, so remains valid for read-only subagents.
    "tree_note", "tree_read", "override_delegation_constraint",
    "web_search", "browse_page", "browser_action", "analyze_screenshot", "vlm_query", "view_image",
    # Bounded media projection: writes derived frames only under artifact_store/video_frames.
    "ocr_pdf", "youtube_transcript", "extract_video_frames",
})

ACTING_SUBAGENT_MODE: str = "acting_subagent"

# Mutative ("acting") subagents may write inside an isolated write root
# (self_worktree / external_workspace) and run shell/services there.
# They explicitly CANNOT commit the live body (commit_reviewed /
# vcs_commit_reviewed), run runtime control, touch the skills lifecycle, enable
# tools, or write cognitive memory (update_identity/update_scratchpad/
# knowledge_write). The parent integrates and is the sole committer. Extension /
# MCP tools are denied unless explicitly granted per-child via
# TaskConstraint.external_tool_grants.
ACTING_SUBAGENT_TOOL_NAMES: frozenset[str] = frozenset({
    "read_file", "list_files", "search_code", "query_code",
    "vcs_status", "vcs_diff",
    "write_file", "edit_text",
    "run_command", "run_script",
    "start_service", "service_status", "service_logs", "stop_service",
    "integrate_subagent_patch", "compare_subagent_patches",
    "schedule_subagent", "wait_task", "wait_tasks", "get_task_result",
    "verify_and_record",
    "knowledge_read", "knowledge_list",
    "tree_note", "tree_read", "override_delegation_constraint",
    "web_search", "browse_page", "browser_action", "analyze_screenshot", "vlm_query", "view_image",
    "ocr_pdf", "youtube_transcript", "extract_video_frames",
    "list_available_tools",
})

READ_ONLY_PARALLEL_TOOLS: frozenset[str] = frozenset({
    "read_file", "list_files",
    "search_code", "query_code", "recent_tasks",
    "web_search", "chat_history",
    "vcs_status", "vcs_diff", "service_status", "service_logs",
    "get_task_result", "list_projects",
})

# Enqueue-only tools safe to emit in parallel within one tool-call round.
# schedule_subagent is fire-and-forget: it writes a `requested` task result and
# does event_queue.put_nowait(...) with no blocking LLM/RPC on the parent path.
# Parent-side shared ctx state touched during emission is guarded by
# _SCHEDULE_EMIT_LOCK in tools/control.py; the supervisor still drains EVENT_Q
# serially, so cap/dedup/enqueue remain single-threaded and safe.
PARALLEL_SAFE_ENQUEUE_TOOLS: frozenset[str] = frozenset({"schedule_subagent"})

# Stateful browser tools need the thread-sticky executor.
STATEFUL_BROWSER_TOOLS: frozenset[str] = frozenset({
    "browse_page", "browser_action",
})

# Full outputs are semantic (review verdicts, advisory findings, status).
UNTRUNCATED_TOOL_RESULTS: frozenset[str] = frozenset({
    "commit_reviewed",
    "vcs_commit_reviewed",
    "plan_task",
    "task_acceptance_review",
    "advisory_review",
    "skill_review",
    "review_status",
    "get_task_result",
    "wait_task",
    "wait_tasks",
})

# Cognitive artifacts must not be truncated.
UNTRUNCATED_REPO_READ_PATHS: frozenset[str] = frozenset({
    "BIBLE.md",
    "README.md",
    "docs/ARCHITECTURE.md",
    "docs/CHECKLISTS.md",
    "docs/DEVELOPMENT.md",
})

# Per-tool char caps; omitted tools use DEFAULT_TOOL_RESULT_LIMIT.
TOOL_RESULT_LIMITS: dict[str, int] = {
    "read_file": 80_000,
    "recent_tasks": 80_000,
    "knowledge_read": 80_000,
    "claude_code_edit": 80_000,
    "run_command": 80_000,
    "run_script": 80_000,
    "search_code": 80_000,
    "query_code": 80_000,
    "service_logs": 80_000,
    # Best-of-N patch comparison shows several candidate diffs side by side; the
    # default 15k cap would truncate after the first one and defeat the tool.
    "compare_subagent_patches": 80_000,
    # skill_exec wraps stdout/stderr; keep the full capped payload visible.
    "skill_exec": 300_000,
    # tree_read returns the shared task-tree coordination tail (up to 200 entries); the 15k
    # default would truncate the swarm blackboard and defeat the coordination contract.
    "tree_read": 80_000,
}

DEFAULT_TOOL_RESULT_LIMIT: int = 15_000

# Reviewed mutative tools must not end with ambiguous executor timeouts.
REVIEWED_MUTATIVE_TOOLS: frozenset[str] = frozenset({
    "commit_reviewed",
    "vcs_commit_reviewed",
})

# Foreground mutative tools may keep editing files after Python future timeout;
# the loop must wait for terminal completion instead of returning while they run.
FOREGROUND_MUTATIVE_TOOLS: frozenset[str] = frozenset({
    "claude_code_edit",
})
