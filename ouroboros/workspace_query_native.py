"""Dependency-light query_code kernel shared by local and remote workspaces."""

from __future__ import annotations

import ast
import errno
import fnmatch
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import time
from collections.abc import Mapping
from typing import Any, Callable

from ouroboros.code_intelligence import (
    _TS_LANGUAGES,
    _language,
    build_code_inventory,
    impact_files,
    relevant_files,
    render_codebase_digest,
    symbol_callees,
    symbol_callers,
    symbol_definitions,
    symbol_references,
)
from ouroboros.workspace_diagnostics import (
    ExecutionDiagnostic,
    ProcessExecutionResult,
    ToolExecutionEnvelope,
)
from ouroboros.workspace_native_contract import NativeOperationResult
from ouroboros.workspace_snapshot_native import snapshot_workspace

QUERY_OPERATION_ORDER = (
    "relevant_files",
    "symbols",
    "definition",
    "references",
    "callers",
    "callees",
    "impact",
    "structural",
    "digest",
)
QUERY_OPERATIONS = frozenset(QUERY_OPERATION_ORDER)
_MAX_LIMIT = 200
_STRUCTURAL_MAX_FILES = 20_000
_SEARCH_MAX_FILES = 20_000
_SEARCH_MAX_MATCHES = 200
_SEARCH_MAX_FILE_BYTES = 1024 * 1024
_SEARCH_EXCLUDED_DIRS = frozenset({
    ".git", ".ouroboros", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", ".venv", "venv", "env", "node_modules", "dist", "build",
    ".tox", ".eggs", "python-standalone", "assets",
})


def classify_workspace_path(
    root: pathlib.Path,
    args: Mapping[str, Any],
) -> ToolExecutionEnvelope:
    """Classify one absolute path against the target's canonical workspace."""

    raw = str(args.get("path") or "")
    if not raw.startswith("/"):
        raise ValueError("ambiguous workspace classifier requires an absolute path")
    try:
        resolved = pathlib.Path(raw).resolve(strict=False)
        resolved.relative_to(root)
        inside = True
    except (OSError, ValueError):
        resolved = pathlib.Path(raw)
        inside = False
    relative = resolved.relative_to(root).as_posix() if inside else ""
    payload = {
        "classification": "active_workspace" if inside else "outside_workspace",
        "inside_workspace": inside,
        "resolved_path": resolved.as_posix(),
        "relative_path": relative,
    }
    return ToolExecutionEnvelope(
        text=json.dumps(payload, sort_keys=True),
        trace={"completion": "complete", **payload},
    )
_SEARCH_SKIP_GLOBS = frozenset({
    "*.pyc", "*.pyo", "*.so", "*.dylib", "*.dll", "*.exe", "*.bin", "*.o",
    "*.a", "*.tar", "*.gz", "*.zip", "*.png", "*.jpg", "*.jpeg", "*.gif",
    "*.ico", "*.webp", "*.woff", "*.woff2", "*.ttf", "*.eot", "*.min.js",
    "*.min.css", "*.map", "*.db", "*.sqlite", "*.sqlite3", "*.lock",
})
_PATCH_MAX_BYTES = 64 * 1024 * 1024
_SENSITIVE_PATCH_NAMES = frozenset({
    ".env", ".netrc", ".npmrc", ".pypirc", "credentials", "credentials.json",
    "secrets.json", "token.json", "tokens.json",
})


def _structural_wall_budget() -> float:
    try:
        return max(
            5.0,
            float(os.environ.get("OUROBOROS_SEARCH_CODE_WALL_SEC", "45") or 45),
        )
    except Exception:
        return 45.0


def walk_candidate_files(
    scope: pathlib.Path,
    repo_root: pathlib.Path,
) -> tuple[list[pathlib.Path], str]:
    """Return a bounded, symlink-confined structural-query file list."""

    if scope.is_file():
        return [scope], ""
    root_resolved = repo_root.resolve(strict=False)
    deadline = time.monotonic() + _structural_wall_budget()
    files: list[pathlib.Path] = []
    for dirpath, dirnames, filenames in os.walk(scope, followlinks=False):
        if time.monotonic() > deadline:
            return files, (
                f"walk stopped after {_structural_wall_budget():.0f}s wall budget "
                "(narrow path=)"
            )
        dirnames[:] = [
            name
            for name in sorted(dirnames)
            if not (pathlib.Path(dirpath) / name).is_symlink()
        ]
        for name in sorted(filenames):
            candidate = pathlib.Path(dirpath) / name
            try:
                resolved = candidate.resolve(strict=False)
                resolved.relative_to(root_resolved)
            except (OSError, ValueError):
                continue
            files.append(candidate)
            if len(files) >= _STRUCTURAL_MAX_FILES:
                return files, (
                    f"walk stopped at {_STRUCTURAL_MAX_FILES} files (narrow path=)"
                )
    return files, ""


def _search_skippable(path: pathlib.Path) -> bool:
    if any(fnmatch.fnmatch(path.name, pattern) for pattern in _SEARCH_SKIP_GLOBS):
        return True
    stat_result = path.lstat()
    return (
        stat.S_ISLNK(stat_result.st_mode)
        or not stat.S_ISREG(stat_result.st_mode)
        or stat_result.st_size > _SEARCH_MAX_FILE_BYTES
    )


def search_workspace(
    workspace_root: pathlib.Path | str,
    args: Mapping[str, Any],
    *,
    path_allowed: Callable[[pathlib.Path], bool] | None = None,
    excluded_paths: set[str] | None = None,
) -> ToolExecutionEnvelope:
    """Run the case-sensitive public search_code contract on a workspace."""

    root = pathlib.Path(workspace_root).resolve(strict=True)
    query = str(args.get("query") or "")
    if not query:
        return ToolExecutionEnvelope(
            text="⚠️ SEARCH_ERROR: query is required.",
            trace={"completion": "complete"},
        )
    excluded = set(excluded_paths or ())
    raw_scope = str(args.get("path") or "").strip().replace("\\", "/")
    pure_scope = pathlib.PurePosixPath(raw_scope or ".")
    lexical_scope = (
        pure_scope.as_posix().removeprefix("./")
        if not pure_scope.is_absolute() and ".." not in pure_scope.parts
        else ""
    )
    scope_excluded = bool(
        lexical_scope not in {"", "."}
        and any(
            lexical_scope == denied or lexical_scope.startswith(denied + "/")
            for denied in excluded
        )
    )
    try:
        if scope_excluded:
            rel = lexical_scope
            scope: pathlib.Path | None = None
        else:
            rel = _relative_scope(root, args.get("path"))
            scope = (root / (rel or ".")).resolve(strict=True)
            scope.relative_to(root)
    except FileNotFoundError:
        raise
    except (OSError, ValueError) as exc:
        raise PermissionError(
            errno.EACCES,
            f"search path escapes the workspace: {exc}",
        ) from exc
    regex_mode = bool(args.get("regex", False))
    try:
        pattern = re.compile(query if regex_mode else re.escape(query))
    except re.error as exc:
        return ToolExecutionEnvelope(
            text=f"⚠️ SEARCH_ERROR: invalid regex: {exc}",
            trace={"completion": "complete"},
        )
    max_results = max(
        1,
        min(_SEARCH_MAX_MATCHES, int(args.get("max_results") or 200)),
    )
    include = str(args.get("include") or "")
    matches: list[str] = []
    unreadable: list[str] = []
    scanned = 0
    truncated = False
    scan_limit_hit = False
    metadata_checked: set[pathlib.Path] = set()
    paths: list[pathlib.Path] = []
    if scope is not None:
        try:
            if not _search_skippable(scope):
                paths = [scope]
            metadata_checked.add(scope)
        except OSError as exc:
            if len(unreadable) < 20:
                unreadable.append(
                    f"{rel or '.'}: {type(exc).__name__}: {exc}"
                )
            scope = None
    if scope is not None and not paths:
        for dirpath, dirnames, filenames in os.walk(
            scope,
            followlinks=False,
            onerror=lambda exc: unreadable.append(
                f"{getattr(exc, 'filename', scope)}: "
                f"{type(exc).__name__}: {exc}"
            )
            if len(unreadable) < 20
            else None,
        ):
            directory = pathlib.Path(dirpath)
            try:
                directory_rel = directory.relative_to(root)
            except ValueError:
                directory_rel = pathlib.Path(".")
            kept_dirs: list[str] = []
            for name in sorted(dirnames):
                child_rel = (directory_rel / name).as_posix()
                if child_rel.startswith("./"):
                    child_rel = child_rel[2:]
                if name in _SEARCH_EXCLUDED_DIRS or any(
                    child_rel == denied or child_rel.startswith(denied + "/")
                    for denied in excluded
                ):
                    continue
                kept_dirs.append(name)
            dirnames[:] = kept_dirs
            for name in sorted(filenames):
                path = pathlib.Path(dirpath) / name
                try:
                    relpath = path.relative_to(root).as_posix()
                except ValueError:
                    continue
                if any(
                    relpath == denied or relpath.startswith(denied + "/")
                    for denied in excluded
                ):
                    continue
                try:
                    if _search_skippable(path):
                        continue
                    resolved = path.resolve(strict=True)
                    resolved.relative_to(root)
                except OSError as exc:
                    if len(unreadable) < 20:
                        try:
                            display = path.relative_to(root).as_posix()
                        except (OSError, ValueError):
                            display = path.as_posix()
                        unreadable.append(
                            f"{display}: {type(exc).__name__}: {exc}"
                        )
                    continue
                except ValueError:
                    continue
                paths.append(resolved)
                metadata_checked.add(resolved)
                if len(paths) >= _SEARCH_MAX_FILES:
                    scan_limit_hit = True
                    break
            if scan_limit_hit:
                break
    for path in paths:
        if include and not fnmatch.fnmatch(path.name, include):
            continue
        try:
            relpath = path.relative_to(root).as_posix()
        except ValueError:
            continue
        if any(
            relpath == denied or relpath.startswith(denied + "/")
            for denied in excluded
        ):
            continue
        try:
            if path not in metadata_checked and _search_skippable(path):
                continue
        except OSError as exc:
            if len(unreadable) < 20:
                try:
                    display = path.relative_to(root).as_posix()
                except (OSError, ValueError):
                    display = path.as_posix()
                unreadable.append(
                    f"{display}: {type(exc).__name__}: {exc}"
                )
            continue
        if path_allowed is not None and not path_allowed(path):
            continue
        scanned += 1
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            unreadable.append(
                f"{path.relative_to(root).as_posix()}: {type(exc).__name__}: {exc}"
            )
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            if pattern.search(line):
                matches.append(
                    f"active_workspace:{relpath}:{line_no}: {line.rstrip()}"
                )
                if len(matches) >= max_results:
                    truncated = True
                    break
        if truncated:
            break
    complete = (
        not unreadable
        and not scan_limit_hit
        and not truncated
    )
    display_path = f"active_workspace:{rel or '.'}"
    if matches:
        header = (
            f"Found {len(matches)} match"
            f"{'es' if len(matches) != 1 else ''} in {display_path} "
            f"({scanned} files searched)"
        )
        if scan_limit_hit:
            header += (
                f" — scan stopped at {_SEARCH_MAX_FILES} files "
                "(narrow the path or glob)"
            )
        if truncated:
            header += f" — truncated at {max_results} results"
        text = header + "\n\n" + "\n".join(matches)
    else:
        text = (
            f"No matches found for {'regex' if regex_mode else 'literal'} "
            f"`{query}` in {display_path} ({scanned} files searched)."
        )
        if scan_limit_hit:
            text += (
                f" Scan stopped after {_SEARCH_MAX_FILES} files — "
                "narrow the path or glob."
            )
    if unreadable:
        text += "\n\n⚠️ SEARCH_PARTIAL: unreadable paths:\n" + "\n".join(
            unreadable[:20]
        )
    return ToolExecutionEnvelope(
        text=text,
        trace={
            "completion": "complete" if complete else "partial",
            "scanned_files": scanned,
            "unreadable": unreadable[:20],
            "truncated": truncated,
        },
    )


def execute_workspace_query_operation(
    root: pathlib.Path,
    operation: str,
    args: Mapping[str, Any],
    native_facts: Mapping[str, Any],
) -> ToolExecutionEnvelope:
    """Apply private visibility facts to the two public query operations."""

    protected = {
        str(item)
        for item in native_facts.get("protected_paths") or []
        if str(item or "")
    }
    if operation == "search_code":
        return search_workspace(root, args, excluded_paths=protected)
    if operation != "query_code":
        raise ValueError(f"unsupported workspace query operation: {operation}")
    return query_workspace(
        root,
        args,
        visible=lambda relative: not any(
            relative == denied or relative.startswith(denied + "/")
            for denied in protected
        ),
        exclude_paths=[root / path for path in protected],
    )


def git_workspace(
    workspace_root: pathlib.Path | str,
    args: Mapping[str, Any],
    subcommand: list[str],
) -> ToolExecutionEnvelope:
    """Run one bounded read-only Git projection with public VCS rendering."""

    root = pathlib.Path(workspace_root).resolve(strict=True)
    path = _relative_scope(root, args.get("path"))
    cmd = ["git", *subcommand]
    if path:
        cmd.extend(["--", path])
    proc = subprocess.run(
        cmd,
        cwd=str(root),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    stdout = proc.stdout.decode("utf-8", errors="replace")
    stderr = proc.stderr.decode("utf-8", errors="replace")
    process = ProcessExecutionResult(
        proc.returncode,
        stdout,
        stderr,
        {"backend": "ssh_exec", "cwd": root.as_posix()},
        cmd,
    )
    if proc.returncode:
        detail = " ".join((stderr or f"git exited {proc.returncode}").split())
        return ToolExecutionEnvelope(
            text=f"⚠️ GIT_ERROR: {detail}",
            process=process,
            trace={"completion": "complete"},
        )
    cap = int(args.get("max_chars") or 0)
    text = stdout
    if cap > 0 and len(text) > cap:
        text = (
            text[:cap]
            + f"\n⚠️ OUTPUT_TRUNCATED: git output limited to {cap} "
            "characters by max_chars."
        )
    return ToolExecutionEnvelope(
        text=text,
        process=process,
        trace={"completion": "complete"},
    )


def _git_bytes(
    root: pathlib.Path,
    argv: list[str],
    *,
    allow: frozenset[int] = frozenset({0}),
) -> bytes:
    proc = subprocess.run(
        ["git", *argv],
        cwd=str(root),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
    )
    if proc.returncode not in allow:
        raise RuntimeError(
            proc.stderr.decode("utf-8", errors="replace")
            or f"git {' '.join(argv)} exited {proc.returncode}"
        )
    return bytes(proc.stdout or b"")


def _sensitive_patch_path(rel: str) -> bool:
    parts = [
        part.casefold()
        for part in str(rel).replace("\\", "/").split("/")
        if part
    ]
    if not parts:
        return True
    name = parts[-1]
    return (
        name in _SENSITIVE_PATCH_NAMES
        or name.startswith(".env.")
        or any(part in {".ssh", ".aws", ".gnupg"} for part in parts)
        or name.startswith(("id_rsa", "id_ed25519"))
    )


def export_workspace_patch(
    root: pathlib.Path,
    args: Mapping[str, Any],
) -> NativeOperationResult:
    before, _ = snapshot_workspace(root)
    expected_head = str(args.get("expected_head") or "")
    current_head = _git_bytes(
        root,
        ["rev-parse", "--verify", "HEAD"],
        allow=frozenset({0, 128}),
    ).decode().strip()
    expected_present = bool(args.get("expected_head_present", bool(expected_head)))
    expected_known = bool(args.get("expected_admission_known", bool(expected_head)))
    if expected_present and expected_head != current_head:
        raise RuntimeError(
            f"workspace HEAD changed: expected={expected_head}, current={current_head}"
        )
    if expected_known and not expected_present and current_head:
        raise RuntimeError(
            f"workspace HEAD changed: expected=<unborn>, current={current_head}"
        )
    base_ref = str(
        args.get("base_ref")
        or expected_head
        or "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
    )
    tracked = [
        item.decode("utf-8", errors="replace")
        for item in _git_bytes(
            root,
            [
                "diff", "--name-only", "-z", "--no-ext-diff",
                "--no-textconv", "--no-color", base_ref, "--",
            ],
        ).split(b"\0")
        if item
    ]
    untracked = [
        item.decode("utf-8", errors="replace")
        for item in _git_bytes(
            root,
            ["ls-files", "-z", "--others", "--exclude-standard"],
        ).split(b"\0")
        if item
    ]
    scratch_raw = args.get("scratch_fingerprints")
    scratch = (
        {str(path): str(digest) for path, digest in scratch_raw.items()}
        if isinstance(scratch_raw, Mapping)
        else {}
    )
    scratch_excluded: list[str] = []
    kept_untracked: list[str] = []
    for rel in untracked:
        expected = scratch.get(rel)
        candidate = (root / rel).resolve(strict=False)
        try:
            candidate.relative_to(root)
            confined = True
        except ValueError:
            confined = False
        if expected and confined and candidate.is_file():
            try:
                if hashlib.sha256(candidate.read_bytes()).hexdigest() == expected:
                    scratch_excluded.append(rel)
                    continue
            except OSError:
                pass
        kept_untracked.append(rel)
    untracked = kept_untracked
    sensitive = sorted(
        rel for rel in {*tracked, *untracked} if _sensitive_patch_path(rel)
    )
    if sensitive:
        return NativeOperationResult(
            ToolExecutionEnvelope(
                text="⚠️ REMOTE_PATCH_SENSITIVE_FILES: refusing patch export.",
                trace={
                    "completion": "complete",
                    "patch_export": {
                        "status": "failed",
                        "sensitive_blocked": sensitive,
                        "snapshot_fingerprint": before["fingerprint"],
                    },
                },
            )
        )
    chunks: list[bytes] = []
    tracked_patch = _git_bytes(
        root,
        [
            "diff", "--binary", "--no-ext-diff", "--no-textconv",
            "--no-color", base_ref, "--",
        ],
    )
    if tracked_patch:
        chunks.append(tracked_patch)
    for rel in untracked:
        patch = _git_bytes(
            root,
            [
                "diff", "--no-index", "--binary", "--no-ext-diff",
                "--no-textconv", "--no-color", "--", os.devnull, rel,
            ],
            allow=frozenset({0, 1}),
        )
        if patch:
            chunks.append(patch)
    patch_bytes = b"\n".join(chunks)
    if len(patch_bytes) > _PATCH_MAX_BYTES:
        raise ValueError("remote workspace patch exceeds export limit")
    after, _ = snapshot_workspace(root)
    if before["fingerprint"] != after["fingerprint"]:
        raise RuntimeError("remote workspace changed while patch was exported")
    digest = hashlib.sha256(patch_bytes).hexdigest() if patch_bytes else ""
    status = "ready_with_changes" if patch_bytes else "ready_no_changes"
    artifact = (
        {
            "name": "workspace.patch", "blob_id": digest, "sha256": digest,
            "size": len(patch_bytes), "mime": "text/x-diff",
        }
        if patch_bytes
        else None
    )
    export = {
        "status": status,
        "base_ref": base_ref,
        "base_head": current_head,
        "current_head": current_head,
        "tracked_changed": tracked,
        "untracked_included": untracked,
        "scratch_excluded": scratch_excluded,
        "sensitive_blocked": [],
        "patch_size": len(patch_bytes),
        "sha256": digest,
        "snapshot_fingerprint": before["fingerprint"],
    }
    return NativeOperationResult(
        ToolExecutionEnvelope(
            text=json.dumps(export, sort_keys=True),
            artifacts=(artifact,) if artifact else (),
            trace={"completion": "complete", "patch_export": export},
        ),
        {digest: patch_bytes} if patch_bytes else {},
    )


def _relative_scope(root: pathlib.Path, value: Any) -> str:
    text = str(value or "").strip().replace("\\", "/")
    if text in {"", "."}:
        return ""
    candidate = pathlib.PurePosixPath(text)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError(f"path escapes root: {value}")
    target = root.joinpath(*candidate.parts).resolve(strict=False)
    try:
        return target.relative_to(root).as_posix()
    except ValueError as exc:
        raise ValueError(f"path escapes root: {value}") from exc


def _inventory_rows(inventory: Any, options: Mapping[str, Any]) -> list[str]:
    op = str(options.get("op") or "")
    query = str(options.get("query") or "")
    path = str(options.get("path") or "")
    kind = str(options.get("kind") or "any")
    depth = int(options.get("depth") or 1)
    limit = int(options.get("limit") or 40)
    offset = int(options.get("offset") or 0)
    rows: list[str] = []
    if op in {"symbols", "definition"}:
        for file, symbol in symbol_definitions(
            inventory,
            query,
            path=path,
            kind=kind or "any",
        ):
            rows.append(
                f"{file.path}:{symbol.line_start} {symbol.kind} "
                f"{symbol.signature or symbol.name}"
            )
    elif op == "references":
        for file, ref in symbol_references(inventory, query, path=path):
            enclosing = f" in {ref.enclosing}" if ref.enclosing else ""
            rows.append(f"{file.path}:{ref.line} {query}{enclosing}")
    elif op in {"callers", "callees"}:
        iterator = (
            symbol_callers(inventory, query, path=path)
            if op == "callers"
            else symbol_callees(inventory, query, path=path)
        )
        for file, call in iterator:
            enclosing = f"{call.enclosing} -> " if call.enclosing else ""
            rows.append(f"{file.path}:{call.line} {enclosing}{call.name}")
    elif op == "impact":
        for file, reason in impact_files(inventory, path or query, depth=depth):
            rows.append(f"{file.path}  {reason}")
    elif op == "relevant_files":
        selected = relevant_files(
            inventory,
            query,
            limit=min(_MAX_LIMIT, offset + limit),
        )
        for index, (file, score, reason) in enumerate(selected, 1):
            symbols = ", ".join(symbol.name for symbol in file.symbols[:5])
            suffix = f" symbols={symbols}" if symbols else ""
            rows.append(
                f"{index}. {file.path} score={score:.2f} reason={reason}{suffix}"
            )
    return rows


def _node_type(query: str) -> str:
    text = str(query or "").strip()
    if text.startswith("("):
        match = re.match(r"\(\s*([A-Za-z_][\w-]*)", text)
        return match.group(1) if match else ""
    return text


def _tree_rows(grammar: str, rel: str, text: str, node_type: str) -> list[str] | None:
    from ouroboros import code_intelligence

    parser = code_intelligence._ts_parser(grammar)
    if parser is None:
        return None
    try:
        tree = parser.parse(text.encode("utf-8", errors="replace"))
    except Exception:
        return None
    rows: list[str] = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == node_type:
            rows.append(f"{rel}:{int(node.start_point[0]) + 1} {node.type}")
        stack.extend(reversed(list(node.children)))
    return rows


def _structural_rows(
    root: pathlib.Path,
    *,
    query: str,
    path: str,
    lang: Any,
    limit: int,
    visible: Callable[[str], bool] | None,
) -> tuple[list[str], list[str]]:
    wanted_type = _node_type(query)
    grammar_text = str(lang or "").strip().lower()
    wanted_grammar = (
        None
        if grammar_text in {"", "any"}
        else _TS_LANGUAGES.get(grammar_text, grammar_text)
    )
    rows: list[str] = []
    issues: list[str] = []
    unavailable: set[str] = set()
    scope = (root / (path or ".")).resolve(strict=False)
    candidates, walk_note = walk_candidate_files(scope, root)
    for file_path in candidates:
        if len(rows) >= limit:
            break
        try:
            relative = file_path.relative_to(root).as_posix()
        except ValueError:
            continue
        if visible is not None and not visible(relative):
            continue
        lang_id = _language(file_path)
        grammar = "python" if lang_id == "python" else _TS_LANGUAGES.get(lang_id)
        if wanted_grammar is not None and grammar != wanted_grammar:
            continue
        if grammar is None or not wanted_type:
            continue
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            issues.append(f"unreadable:{relative}")
            continue
        tree_rows = _tree_rows(grammar, relative, text, wanted_type)
        if tree_rows or (tree_rows is not None and lang_id != "python"):
            rows.extend(tree_rows[: max(0, limit - len(rows))])
            continue
        if lang_id != "python":
            if lang_id not in unavailable:
                unavailable.add(lang_id)
                rows.append(
                    f"structural_unavailable:{lang_id} "
                    "(tree-sitter grammar not loaded)"
                )
            continue
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if node.__class__.__name__.casefold() == wanted_type.casefold():
                rows.append(
                    f"{relative}:{int(getattr(node, 'lineno', 0) or 0)} "
                    f"{node.__class__.__name__}"
                )
                if len(rows) >= limit:
                    break
    if walk_note and len(rows) < limit:
        issues.append(f"walk_truncated:{walk_note}")
    return rows, issues


def _empty_hint(op: str, label: str) -> str:
    if op in {"definition", "references", "callers", "callees", "impact"}:
        return (
            "Check the exact symbol name (these ops match a defined symbol, not "
            f"text). Use op=relevant_files query=\"{label}\" to find where to "
            "look, or op=symbols to list what's defined."
        )
    if op == "symbols":
        return (
            "Narrow with path= to a file/dir, or use op=relevant_files to locate "
            "the area first."
        )
    if op == "structural":
        return (
            "structural needs a node type, not free text — an AST class for "
            "Python (FunctionDef/ClassDef) or a tree-sitter node for other "
            "langs (function_declaration for Go, struct_item for Rust, etc.). "
            "Add lang=go|rust|... to filter by language."
        )
    if op == "relevant_files":
        return (
            "Rephrase the task in domain words, or use search_code for an exact "
            "string you expect in the source."
        )
    return "Verify the symbol/path; use search_code only for plain-text matches."


def _next_step_hint(op: str) -> str:
    return {
        "relevant_files": (
            "\n\nNext: read_file(...) the top hit, or "
            "query_code(op=symbols, path=...) to list its symbols."
        ),
        "symbols": (
            "\n\nNext: query_code(op=definition/references, query=<name>) on a "
            "symbol of interest."
        ),
        "definition": (
            "\n\nNext: query_code(op=references/callers, query=<name>) to see "
            "how it is used."
        ),
        "callers": (
            "\n\nNext: read_file(...) a caller, or "
            "query_code(op=impact, query=<name>) for blast radius."
        ),
        "callees": (
            "\n\nNext: query_code(op=definition, query=<callee>) to read what it calls."
        ),
    }.get(op, "")


def query_workspace(
    workspace_root: pathlib.Path | str,
    args: Mapping[str, Any],
    *,
    inventory: Any | None = None,
    visible: Callable[[str], bool] | None = None,
    exclude_paths: list[pathlib.Path] | None = None,
) -> ToolExecutionEnvelope:
    """Run a model-visible query_code operation without Home authority imports."""

    root = pathlib.Path(workspace_root).resolve(strict=True)
    op = str(args.get("op") or "").strip()
    query = str(args.get("query") or "")
    if op not in QUERY_OPERATIONS:
        allowed = ", ".join(QUERY_OPERATION_ORDER)
        return ToolExecutionEnvelope(
            f"⚠️ TOOL_ARG_ERROR (query_code): op must be one of {allowed}."
        )
    if op not in {"symbols", "digest"} and not query.strip():
        return ToolExecutionEnvelope(
            f"⚠️ TOOL_ARG_ERROR (query_code): op '{op}' requires query."
        )
    try:
        path = _relative_scope(root, args.get("path"))
        limit = min(max(1, int(args.get("limit") or 40)), _MAX_LIMIT)
        offset = max(0, int(args.get("offset") or 0))
        options = {
            **dict(args),
            "op": op,
            "query": query,
            "path": path,
            "limit": limit,
            "offset": offset,
        }
        issues: list[str] = []
        direct_text = ""
        if op == "structural":
            rows, issues = _structural_rows(
                root,
                query=query,
                path=path,
                lang=args.get("lang"),
                limit=min(_MAX_LIMIT, offset + limit),
                visible=visible,
            )
        else:
            if inventory is None:
                inventory = build_code_inventory(
                    root,
                    persist=False,
                    exclude_paths=exclude_paths,
                )
            if visible is not None:
                inventory.files = [
                    fact for fact in inventory.files if visible(str(fact.path))
                ]
            issues = [
                f"{fact.disposition}:{fact.path}"
                for fact in inventory.files
                if fact.disposition.startswith("read_error:")
                or fact.disposition.startswith("structural_unavailable:")
            ]
            if op == "digest":
                direct_text = render_codebase_digest(inventory)
                rows = []
            else:
                rows = _inventory_rows(inventory, options)
    except Exception as exc:
        return ToolExecutionEnvelope(
            f"⚠️ QUERY_CODE_ERROR: {type(exc).__name__}: {exc}",
            trace={"op": op, "completion": "unknown"},
        )
    total = len(rows)
    shown = rows[offset : offset + limit]
    label = query or path or "."
    if direct_text:
        text = direct_text
    elif not shown:
        text = f"No results for op `{op}` `{label}`. {_empty_hint(op, label)}"
    else:
        text = f"{op} `{label}` — {len(shown)} of {total}"
        if offset + limit < total:
            text += f" — next offset={offset + limit}"
        text += "\n\n" + "\n".join(shown) + _next_step_hint(op)
    diagnostic = None
    completion = "complete"
    if issues:
        completion = "partial"
        text += (
            "\n\n⚠️ QUERY_PARTIAL: some workspace files were not readable or "
            "structurally available; a no-result answer is not authoritative.\n"
            + "\n".join(issues[:20])
        )
        diagnostic = ExecutionDiagnostic(
            domain="filesystem",
            code="query_partial",
            message="Workspace query covered only a readable structural subset.",
            phase="execute",
            completion="unknown",
            retryable=True,
            details={"issues": issues[:20]},
        )
    return ToolExecutionEnvelope(
        text,
        diagnostic=diagnostic,
        trace={"op": op, "completion": completion, "issues": issues[:20]},
    )
