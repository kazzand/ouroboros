"""Read-only structured code queries over the deterministic code inventory."""

from __future__ import annotations

import pathlib
from typing import Any, List

from ouroboros.protected_artifacts import block_reason_for_path
from ouroboros.tool_access import normalize_root_relative, resolve_user_file_path
from ouroboros.tools.registry import (
    ToolContext,
    ToolEntry,
    active_repo_dir_for,
    system_repo_dir_for,
)
from ouroboros.workspace_query_native import (
    QUERY_OPERATION_ORDER,
    query_workspace,
    walk_candidate_files,
)


_OPS = QUERY_OPERATION_ORDER
# Backward-compatible private seam used by existing bounded/symlink-safety tests.
_walk_candidate_files = walk_candidate_files


def _safe_path(repo_root: pathlib.Path, path: str) -> str:
    text = str(path or "").strip().replace("\\", "/")
    if not text or text == ".":
        return ""
    target = (repo_root / text).resolve(strict=False)
    try:
        return target.relative_to(repo_root.resolve(strict=False)).as_posix()
    except ValueError as exc:
        raise ValueError(f"path escapes root: {path}") from exc


def _visible_file(ctx: ToolContext, repo_root: pathlib.Path, rel_path: str) -> bool:
    try:
        target = (repo_root / rel_path).resolve(strict=False)
    except Exception:
        return False
    try:
        from ouroboros.tools.core import (
            _is_subagent_secret_repo_target,
            is_restricted_subagent_profile as _is_local_readonly_subagent,
        )

        if _is_local_readonly_subagent(ctx) and _is_subagent_secret_repo_target(target, repo_root):
            return False
    except Exception:
        pass
    return not (
        block_reason_for_path(ctx, target, "read_bytes")
        or block_reason_for_path(ctx, target, "static_introspection")
    )


def _query_code(ctx: ToolContext, op: str, **options: Any) -> str:
    query = str(options.get("query") or "")
    path = str(options.get("path") or "")
    root = str(options.get("root") or "active_workspace")
    op = str(op or "").strip()
    if op not in _OPS:
        return f"⚠️ TOOL_ARG_ERROR (query_code): op must be one of {', '.join(_OPS)}."
    if op not in ("symbols", "digest") and not str(query or "").strip():
        return f"⚠️ TOOL_ARG_ERROR (query_code): op '{op}' requires query."
    try:
        normalized_root = str(root or "active_workspace").strip() or "active_workspace"
        if normalized_root == "system_repo":
            try:
                from ouroboros.tool_access import active_tool_profile

                if active_tool_profile(ctx) == "acting_subagent":
                    return "⚠️ TOOL_ACCESS_BLOCKED: query_code root=system_repo is not available to acting subagents."
            except Exception:
                pass
            repo_root = pathlib.Path(system_repo_dir_for(ctx)).resolve(strict=False)
        elif normalized_root == "active_workspace":
            repo_root = pathlib.Path(active_repo_dir_for(ctx)).resolve(strict=False)
            try:
                from ouroboros.tool_access import project_room_lens_dir

                _room = project_room_lens_dir(ctx)
                if _room is not None:
                    # Room lens (v6.61.3): folder-room chat queries the PROJECT
                    # FOLDER; self-repo queries stay on root="system_repo".
                    repo_root = _room
            except Exception:
                pass
        elif normalized_root == "user_files":
            # Read-only structured intelligence over an EXTERNAL workspace target
            # (e.g. the SWE-bench dig-direct /app) — R1. Restricted subagents must
            # not read arbitrary owner home; the main/live task is allowed. An
            # empty path is a HARD ERROR: it will not scan the entire home.
            try:
                from ouroboros.tool_access import active_tool_profile

                if active_tool_profile(ctx) in ("acting_subagent", "local_readonly_subagent"):
                    return "⚠️ TOOL_ACCESS_BLOCKED: query_code root=user_files is not available to subagents."
            except Exception:
                pass
            if not str(path or "").strip():
                raise ValueError(
                    "root=user_files requires an explicit path (e.g. '/app' or a project subdir); "
                    "it will not scan the entire home"
                )
            # Documented external-target contract (v6.47.0): read-only code
            # intelligence over an absolute path OUTSIDE the user_files home
            # (e.g. a benchmark /app) stays supported — opt out of the v6.54.3
            # home-membership rejection; the credential/control-plane block
            # reasons still apply inside resolve_user_file_path.
            target = resolve_user_file_path(ctx, str(path).strip(), allow_outside_home=True)
            if target.is_dir():
                repo_root = target.resolve(strict=False)
                path = ""
            elif target.is_file():
                repo_root = target.parent.resolve(strict=False)
                path = target.name
            else:
                raise ValueError(f"user_files path does not exist: {str(path).strip()}")
        else:
            raise ValueError("root must be active_workspace, system_repo, or user_files")
        # Accept absolute/redundant-prefix paths inside the root (e.g. '/app/x'
        # or 'app/x' under a root at /app); _safe_path still confines below.
        path = normalize_root_relative(repo_root, path)
        scoped_path = _safe_path(repo_root, path)
    except ValueError as exc:
        return f"⚠️ TOOL_ARG_ERROR (query_code): {exc}"

    try:
        from ouroboros.code_intelligence import build_code_inventory
        from ouroboros.protected_artifacts import protected_artifact_paths

        exclude_paths: list[pathlib.Path] = list(protected_artifact_paths(ctx))
        persist = not exclude_paths and normalized_root != "user_files"
        try:
            from ouroboros.tools.core import (
                _is_subagent_secret_repo_target,
                is_restricted_subagent_profile as _is_local_readonly_subagent,
            )

            if _is_local_readonly_subagent(ctx):
                persist = False
                exclude_paths = [
                    candidate
                    for candidate in repo_root.rglob("*")
                    if _is_subagent_secret_repo_target(candidate, repo_root)
                ]
        except Exception:
            pass
        inventory = None
        if op != "structural":
            inventory = build_code_inventory(
                repo_root,
                drive_root=pathlib.Path(ctx.drive_root),
                persist=persist,
                exclude_paths=exclude_paths,
            )
        envelope = query_workspace(
            repo_root,
            {
                **options,
                "op": op,
                "query": query,
                "path": scoped_path,
                "root": "active_workspace",
            },
            inventory=inventory,
            visible=lambda relative: _visible_file(ctx, repo_root, relative),
        )
        return envelope.text
    except Exception as exc:
        return f"⚠️ QUERY_CODE_ERROR: {type(exc).__name__}: {exc}"


def get_tools() -> List[ToolEntry]:
    return [
        ToolEntry("query_code", {
            "name": "query_code",
            "description": (
                "Read-only structured code intelligence over the active workspace — prefer this "
                "over grep/find/sed-as-reader for anything symbol-aware. Start with "
                "op=relevant_files (task text -> the files to read) when you don't yet know where "
                "to look; op=digest maps an unfamiliar repo FIRST; then symbols/definition/"
                "references/callers/callees/impact/structural for precise navigation. Use search_code "
                "only for plain text/regex. Symbol intelligence (digest/symbols/definition/references/"
                "callers/callees/impact) is polyglot via tree-sitter (Python/JS/TS/Go/Rust/Java/Ruby/C/"
                "...); op=structural (node-type queries) is polyglot too — tree-sitter for every supported "
                "language (Python/JS/TS/Go/Rust/Java/Ruby/C/C++/C#/PHP/Kotlin/Swift/Scala/Lua/Bash), with a "
                "visible structural_unavailable:<lang> marker when a grammar is missing (Python also has a "
                "stdlib-ast fallback). Returns compact file:line anchors and signatures/snippets, never full bodies."
            ),
            "parameters": {"type": "object", "properties": {
                "op": {"type": "string", "enum": list(_OPS), "description": "Operation: relevant_files (where to look), digest (whole-repo map), symbols, definition, references, callers, callees, impact, structural."},
                "query": {"type": "string", "default": "", "description": "Exact symbol name (definition/references/callers/...), AST node type (structural), or task text (relevant_files). Empty for digest."},
                "path": {"type": "string", "default": "", "description": "Optional file/dir scope or definition disambiguator. REQUIRED for root=user_files (the explicit target dir/file, e.g. '/app' or '/app/src'); it is never the whole home."},
                "lang": {"type": "string", "enum": ["python", "javascript", "typescript", "go", "rust", "java", "ruby", "c", "cpp", "csharp", "php", "kotlin", "swift", "scala", "lua", "bash", "any"], "default": "any"},
                "kind": {"type": "string", "enum": ["function", "async_function", "class", "constant", "any"], "default": "any"},
                "depth": {"type": "integer", "default": 1, "description": "Graph depth for impact."},
                "root": {"type": "string", "enum": ["active_workspace", "system_repo", "user_files"], "default": "active_workspace", "description": "active_workspace/system_repo are Ouroboros repos; user_files runs read-only intelligence over an EXTERNAL target dir/file named by path= (e.g. /app), never the whole home."},
                "limit": {"type": "integer", "default": 40},
                "offset": {"type": "integer", "default": 0},
            }, "required": ["op"]},
        }, _query_code, timeout_sec=120),
    ]
