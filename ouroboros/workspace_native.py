"""Dependency-light native workspace primitives shared by Home and execd.

This module deliberately contains no task/model/review authority.  It accepts
already-authorized, canonical arguments and performs only target-native facts
and effects below one workspace root.
"""

from __future__ import annotations

import errno
import functools
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ouroboros.platform_layer import (
    kill_process_group_id,
    kill_process_tree,
    process_group_id,
    process_group_status,
    subprocess_new_group_kwargs,
    terminate_process_group_id,
)
from ouroboros.workspace_diagnostics import (
    ProcessExecutionResult,
    ToolExecutionEnvelope,
    diagnostic_from_exception,
    render_diagnostic_text,
    sanitize_execution_text,
)
from ouroboros.workspace_native_contract import (
    MANDATORY_REMOTE_NATIVE_OPERATIONS as MANDATORY_REMOTE_NATIVE_OPERATIONS,
    PROCESS_PREVIEW_HEAD_BYTES,
    PROCESS_PREVIEW_TAIL_BYTES,
    REMOTE_NATIVE_KERNEL_MODULES as REMOTE_NATIVE_KERNEL_MODULES,
    REMOTE_NATIVE_OPERATION_MODULE as REMOTE_NATIVE_OPERATION_MODULE,
    BoundedProcessStream,
    NativeExecutionControl,
    NativeOperationResult,
    NativePreparedOperation,
    autocorrect_grep_backslash_pipe as _maybe_autocorrect_grep_backslash_pipe,
    describe_process_returncode as _describe_returncode,
    format_process_output as _format_process_output,
    process_is_search_no_match as _is_search_no_match,
    validate_remote_native_operation_map as validate_remote_native_operation_map,
)
from ouroboros.workspace_payload_native import (
    attach_remote_verification_facts, collect_declared_outputs,
    execute_inline_script,
    execute_reviewed_payload,
    scratch_fingerprints,
    snapshot_declared_outputs,
    validate_declared_output_context,
    validate_reviewed_payload,
)
from ouroboros.workspace_query_native import (
    classify_workspace_path,
    execute_git_workspace_operation,
    execute_workspace_query_operation,
)
from ouroboros.workspace_snapshot_native import (
    guarded_patch_apply as _guarded_patch_apply,
    snapshot_operation,
)

_SERVICE_LOG_TAIL_MAX = 80_000
@dataclass
class _NativeService:
    name: str
    service_id: str
    proc: subprocess.Popen[bytes] | None
    log_path: pathlib.Path
    cwd: pathlib.Path | None
    command: list[str]
    started_at_ms: int
    pgid: int
    control: NativeExecutionControl | None = None
    released: bool = False
    readiness: dict[str, Any] | None = None
    ready: bool = False
    outputs: tuple[str, ...] = ()
    keep_alive: bool = False
    declared_outputs_before: dict[str, Any] | None = None


_SERVICES_BY_TASK_NAME: dict[tuple[str, str], _NativeService] = {}
_SERVICES_BY_ID: dict[str, _NativeService] = {}
_SERVICES_LOCK = threading.RLock()


def path_is_relative_to(path: pathlib.Path, root: pathlib.Path) -> bool:
    try:
        pathlib.Path(path).resolve(strict=False).relative_to(
            pathlib.Path(root).resolve(strict=False)
        )
        return True
    except (OSError, ValueError):
        return False


def _workspace_root(value: pathlib.Path | str) -> pathlib.Path:
    root = pathlib.Path(value).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise NotADirectoryError(str(root))
    return root


def _relative_text(value: Any, *, default: str = ".") -> str:
    text = str(value if value is not None else default).strip().replace("\\", "/")
    text = text or default
    if text.startswith("/"):
        raise ValueError("workspace-native path must be relative")
    parts = [part for part in text.split("/") if part not in {"", "."}]
    if any(part == ".." for part in parts):
        raise ValueError("workspace-native path contains traversal")
    return "/".join(parts) or "."


def _target(root: pathlib.Path, value: Any, *, must_exist: bool = False) -> pathlib.Path:
    rel = _relative_text(value)
    candidate = root if rel == "." else root.joinpath(*rel.split("/"))
    resolved = candidate.resolve(strict=must_exist)
    if not path_is_relative_to(resolved, root):
        raise PermissionError(
            errno.EACCES,
            f"path escapes workspace through symlink: {value}",
        )
    return resolved


def _mutation_target(root: pathlib.Path, value: Any) -> pathlib.Path:
    """Confine the parent but leave the final component for atomic replacement."""
    rel = _relative_text(value)
    if rel == ".":
        return root
    candidate = root if rel == "." else root.joinpath(*rel.split("/"))
    parent = candidate.parent.resolve(strict=False)
    if not path_is_relative_to(parent, root):
        raise PermissionError(
            errno.EACCES,
            f"path escapes workspace through symlink: {value}",
        )
    return parent / candidate.name


def _cwd(root: pathlib.Path, value: Any) -> pathlib.Path:
    text = str(value or "").strip().replace("\\", "/")
    if text.startswith("/"):
        normalized_root = root.as_posix().rstrip("/")
        if text == normalized_root:
            rel = "."
        elif text.startswith(normalized_root + "/"):
            rel = text[len(normalized_root) + 1 :]
        else:
            raise ValueError("cwd is outside the remote workspace")
    else:
        rel = text or "."
    target = _target(root, rel, must_exist=True)
    if not target.is_dir():
        raise NotADirectoryError(str(target))
    return target


def _atomic_write(path: pathlib.Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        existing_mode = None if path.is_symlink() else os.stat(path).st_mode & 0o7777
    except OSError:
        existing_mode = None
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, existing_mode if existing_mode is not None else 0o644)
        os.replace(tmp_name, path)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


def _error_result(
    exc: BaseException,
    *,
    operation: str,
    args: Mapping[str, Any],
    phase: str = "execute",
    domain: str = "filesystem",
    completion: str = "not_started",
) -> NativeOperationResult:
    diagnostic = diagnostic_from_exception(
        exc,
        request_id=str(args.get("_request_id") or ""),
        operation_id=str(args.get("_operation_id") or ""),
        phase=phase,
        domain=domain,  # type: ignore[arg-type]
        completion=completion,  # type: ignore[arg-type]
        details={"operation": operation},
    )
    rel = sanitize_execution_text(str(args.get("path") or "."))
    message = diagnostic.message
    if operation == "read_file":
        text = (
            f"⚠️ NOT_FOUND: active_workspace:{rel}"
            if isinstance(exc, FileNotFoundError)
            else f"⚠️ READ_FILE_ERROR: {type(exc).__name__}: {message}"
        )
    elif operation == "list_files":
        if isinstance(exc, FileNotFoundError):
            text = f"⚠️ LIST_FILES_ERROR: Directory not found: {rel}"
        elif isinstance(exc, NotADirectoryError):
            text = f"⚠️ LIST_FILES_ERROR: {message}"
        else:
            text = f"⚠️ LIST_FILES_ERROR ({type(exc).__name__}): {message}"
    elif operation == "write_file":
        text = (
            f"⚠️ FILE_WRITE_ERROR on '{rel}': {message}\n"
            "Successfully written before error: (none)"
        )
    elif operation == "edit_text":
        text = (
            f"⚠️ STR_REPLACE_ERROR: file not found: {rel}"
            if isinstance(exc, FileNotFoundError)
            else f"⚠️ STR_REPLACE_ERROR: {type(exc).__name__}: {message}"
        )
    elif operation == "search_code":
        text = (
            f"⚠️ SEARCH_ERROR: path not found: active_workspace:{rel}"
            if isinstance(exc, FileNotFoundError)
            else f"⚠️ SEARCH_ERROR: {type(exc).__name__}: {message}"
        )
    elif operation == "run_command" and isinstance(
        exc,
        subprocess.TimeoutExpired,
    ):
        timeout = max(
            1,
            int(float(args.get("timeout_sec") or args.get("timeout") or 120)),
        )
        cwd = str(args.get("cwd") or ".")
        text = (
            "⚠️ TOOL_TIMEOUT (run_command): command exceeded the per-command "
            f"timeout of {timeout}s and its subprocess tree was terminated "
            f"(cwd={pathlib.Path(cwd).resolve(strict=False)}). NOTE: this is "
            "the per-command FOREGROUND timeout, NOT the task deadline. For "
            "genuinely long-running compute (training, sampling, large "
            "builds/downloads), start it with start_service and poll "
            "service_status/service_logs while you do other work, or pass an "
            "explicit timeout_sec=<seconds> (up to the per-call ceiling) — and "
            "preserve a best-effort deliverable before the task deadline."
        )
    else:
        text = render_diagnostic_text(diagnostic)
    return NativeOperationResult(
        ToolExecutionEnvelope(
            text=text,
            diagnostic=diagnostic,
            trace={"operation": operation},
        )
    )


def prepare_native_operation(
    workspace_root: pathlib.Path | str,
    tool: str,
    args: Mapping[str, Any],
    *,
    task_id: str = "",
    blobs: Mapping[str, bytes] | None = None,
) -> NativePreparedOperation:
    """Resolve target-native facts without producing an effect.

    The returned ``execution_args`` are the exact values Home must authorize.
    In particular, a Python interpreter is selected here, on the target, before
    Home safety sees argv; no launcher may select a different binary later.
    """

    operation = str(tool or "").strip()
    if operation not in MANDATORY_REMOTE_NATIVE_OPERATIONS:
        raise ValueError(f"unsupported native operation: {operation}")
    root = _workspace_root(workspace_root)
    execution_args = {
        str(key): value
        for key, value in args.items()
        if not str(key).startswith("_")
    }
    facts: dict[str, Any] = {
        "workspace_root": root.as_posix(),
        "task_id": str(task_id or ""),
    }
    if isinstance((protected_rows := args.get("_protected_paths")), list):
        if len(protected_rows) > 1000:
            raise ValueError("protected path policy exceeds the supported limit")
        facts["protected_paths"] = [
            _relative_text(item)
            for item in protected_rows
            if str(item or "").strip()
        ]
    if operation == "execute_reviewed_payload":
        execution_args, payload_facts = validate_reviewed_payload(
            execution_args,
            dict(blobs or {}),
        )
        payload = execution_args["payload"]
        runtime_name = str(payload.get("runtime") or "python3")
        if execution_args["kind"] == "extension_tool":
            runtime_name = "python3"
        allowed = {"python", "python3", "bash", "sh", "node", "deno", "ruby", "go"}
        if pathlib.PurePath(runtime_name).name not in allowed:
            raise PermissionError("reviewed payload runtime is not allowlisted")
        resolved_runtime = shutil.which(runtime_name)
        if not resolved_runtime:
            raise FileNotFoundError(
                f"reviewed payload runtime unavailable on target: {runtime_name}"
            )
        facts.update(payload_facts)
        facts["resolved_runtime"] = str(pathlib.Path(resolved_runtime).resolve())
        return NativePreparedOperation(execution_args=execution_args, native_facts=facts)

    if operation in {
        "read_file",
        "list_files",
        "write_file",
        "edit_text",
        "search_code",
        "query_code",
        "classify_ambiguous_workspace_path",
        "extract_video_frames",
    }:
        key = "path"
        if operation == "classify_ambiguous_workspace_path":
            raw_path = str(execution_args.get(key) or "")
            if not raw_path.startswith("/"):
                raise ValueError("ambiguous workspace classifier requires an absolute path")
            facts["candidate_path"] = raw_path
        else:
            rel = _relative_text(execution_args.get(key), default=".")
            execution_args[key] = rel
            facts["resolved_path"] = _target(root, rel).as_posix()
    elif operation in {"run_command", "run_script", "start_service", "verify_remote_check"}:
        cwd = _cwd(root, execution_args.get("cwd"))
        execution_args["cwd"] = cwd.as_posix()
        facts["resolved_cwd"] = cwd.as_posix()
        if operation in {"run_command", "run_script", "start_service"}:
            facts["declared_outputs_before"] = snapshot_declared_outputs(
                root,
                execution_args,
            )
            scratch_fingerprints(root, execution_args)
            if execution_args.get("scratch"):
                probe = subprocess.run(
                    ["git", "rev-parse", "--is-inside-work-tree"],
                    cwd=str(cwd),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                )
                if probe.returncode or probe.stdout.strip() != b"true":
                    raise PermissionError(
                        "scratch requires a Git-worktree command cwd"
                    )
            for raw in execution_args.get("scratch") or []:
                candidate = (
                    pathlib.Path(str(raw))
                    if pathlib.Path(str(raw)).is_absolute()
                    else cwd / str(raw)
                ).resolve(strict=False)
                rel = candidate.relative_to(root).as_posix()
                tracked = subprocess.run(
                    ["git", "ls-files", "--error-unmatch", "--", rel],
                    cwd=str(root),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                )
                if tracked.returncode == 0:
                    raise PermissionError(
                        f"scratch path is git-tracked, not throwaway: {rel}"
                    )

    if operation in {"run_command", "start_service", "verify_remote_check"}:
        argv = [str(item) for item in execution_args.get("cmd") or []]
        if operation == "run_command":
            argv, autocorrect_note = _maybe_autocorrect_grep_backslash_pipe(argv)
            if autocorrect_note:
                execution_args["cmd"] = argv
                facts["autocorrect_note"] = autocorrect_note
        requested = argv[0] if argv else ""
        if pathlib.PurePath(requested).name in {"python", "python3"}:
            candidates = (
                root / ".venv" / "bin" / "python",
                root / "venv" / "bin" / "python",
            )
            resolved = next((path for path in candidates if path.is_file()), None)
            if resolved is None:
                found = shutil.which(requested)
                if not found:
                    raise FileNotFoundError(f"interpreter unavailable on target: {requested}")
                resolved = pathlib.Path(found)
            argv[0] = str(resolved)
            execution_args["cmd"] = argv
            facts["interpreter"] = str(resolved)
    elif operation == "run_script":
        requested = str(execution_args.get("interpreter") or "python3")
        if pathlib.PurePath(requested).name in {"python", "python3"}:
            candidates = (
                root / ".venv" / "bin" / "python",
                root / "venv" / "bin" / "python",
            )
            resolved = next((path for path in candidates if path.is_file()), None)
            if resolved is None:
                found = shutil.which(requested)
                if not found:
                    raise FileNotFoundError(f"interpreter unavailable on target: {requested}")
                resolved = pathlib.Path(found)
            execution_args["interpreter"] = str(resolved)
            facts["interpreter"] = str(resolved)

    if operation in {"service_status", "service_logs", "stop_service"}:
        service_ref = args.get("_service_ref")
        if isinstance(service_ref, Mapping):
            service_id = str(service_ref.get("service_id") or "")
            if service_id:
                facts["service_id"] = service_id
                output_context = validate_declared_output_context(root, service_ref)
                facts["service_cwd"] = output_context["cwd"]
                facts["service_outputs"] = output_context["outputs"]
                facts["service_declared_outputs_before"] = output_context["before"]
                facts["service_ready"] = bool(service_ref.get("ready", False))

    return NativePreparedOperation(execution_args=execution_args, native_facts=facts)


def _read_file(root: pathlib.Path, args: Mapping[str, Any]) -> ToolExecutionEnvelope:
    rel = _relative_text(args.get("path"))
    path = _target(root, rel, must_exist=True)
    content = path.read_text(encoding="utf-8", errors="replace")
    lines = content.splitlines(keepends=True)
    try:
        start = int(args.get("start_line", 1))
    except (TypeError, ValueError):
        start = 1
    try:
        limit = int(args.get("max_lines", 2000))
    except (TypeError, ValueError):
        limit = 2000
    start = max(1, start)
    limit = max(1, limit)
    start = min(start, len(lines) + 1)
    end = min(len(lines), start + limit - 1)
    body = "".join(lines[start - 1 : end])
    return ToolExecutionEnvelope(
        text=f"# active_workspace:{rel} — lines {start}–{end} of {len(lines)}\n{body}",
        trace={"completion": "complete", "path": rel},
    )


def _list_files(root: pathlib.Path, args: Mapping[str, Any]) -> ToolExecutionEnvelope:
    rel = _relative_text(args.get("path"))
    path = _target(root, rel, must_exist=True)
    if not path.is_dir():
        raise NotADirectoryError(f"Not a directory: {rel}")
    limit = max(1, min(10_000, int(args.get("max_entries") or 500)))
    rows: list[str] = []
    truncated = False
    for item in sorted(path.iterdir()):
        if len(rows) >= limit:
            rows.append(f"...(truncated at {limit})")
            truncated = True
            break
        item_resolved = item.resolve(strict=False)
        if not path_is_relative_to(item_resolved, root):
            continue
        display = item.relative_to(root).as_posix()
        rows.append(display + ("/" if item.is_dir() else ""))
    return ToolExecutionEnvelope(
        text=json.dumps(rows, ensure_ascii=False, indent=2),
        trace={"completion": "complete", "path": rel, "truncated": truncated},
    )


def _write_file(root: pathlib.Path, args: Mapping[str, Any]) -> ToolExecutionEnvelope:
    rows = args.get("files")
    items: list[dict[str, Any]]
    if isinstance(rows, list) and rows:
        items = [dict(row) for row in rows if isinstance(row, Mapping)]
    else:
        items = [{"path": args.get("path"), "content": args.get("content")}]
    mode = str(args.get("mode") or "overwrite")
    results: list[str] = []
    written_paths: list[str] = []
    for item in items:
        rel = _relative_text(item.get("path"))
        path = _mutation_target(root, rel)
        body = str(item.get("content") or "")
        try:
            if mode == "append":
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("a", encoding="utf-8") as handle:
                    handle.write(body)
            else:
                shrink = _tracked_shrink_block(
                    root, rel, path, body, bool(args.get("force", False))
                )
                if shrink:
                    return ToolExecutionEnvelope(
                        text=shrink,
                        trace={"completion": "complete", "paths": [rel]},
                    )
                _atomic_write(path, body.encode("utf-8"))
        except OSError as exc:
            diagnostic = diagnostic_from_exception(
                exc,
                request_id=str(args.get("_request_id") or ""),
                operation_id=str(args.get("_operation_id") or ""),
                phase="execute",
                details={"operation": "write_file"},
            )
            already = ", ".join(results) if results else "(none)"
            return ToolExecutionEnvelope(
                text=(
                    f"⚠️ FILE_WRITE_ERROR on '{rel}': {diagnostic.message}\n"
                    f"Successfully written before error: {already}"
                ),
                diagnostic=diagnostic,
                trace={"completion": "completed", "paths": written_paths},
            )
        results.append(
            f"active_workspace:{rel} ({len(body)} chars)"
        )
        written_paths.append(rel)
    summary = ", ".join(results)
    return ToolExecutionEnvelope(
        text=(
            f"✅ Written {len(results)} file(s): {summary}\n"
            "Files are on disk in the active workspace. Do not commit; "
            "the headless runner will emit a patch artifact."
        ),
        trace={"completion": "complete", "paths": written_paths},
    )


def _edit_text(root: pathlib.Path, args: Mapping[str, Any]) -> ToolExecutionEnvelope:
    rel = _relative_text(args.get("path"))
    read_path = _target(root, rel, must_exist=True)
    write_path = _mutation_target(root, rel)
    old = str(args.get("old_str") or "")
    new = str(args.get("new_str") or "")
    if not old:
        return ToolExecutionEnvelope(
            text="⚠️ STR_REPLACE_ERROR: old_str is required (cannot be empty).",
            trace={"completion": "complete", "matched": 0, "path": rel},
        )
    content = read_path.read_text(encoding="utf-8")
    count = content.count(old)
    if count == 0:
        return ToolExecutionEnvelope(
            text=(
                f"⚠️ STR_REPLACE_ERROR: old_str not found in {rel}.\n"
                f"File preview (first 2000 chars):\n{content[:2000]}"
            ),
            trace={"completion": "complete", "matched": 0, "path": rel},
        )
    if count != 1:
        positions: list[str] = []
        start = 0
        for _ in range(min(count, 5)):
            index = content.index(old, start)
            positions.append(f"line {content[:index].count(chr(10)) + 1}")
            start = index + 1
        return ToolExecutionEnvelope(
            text=(
                f"⚠️ STR_REPLACE_ERROR: old_str found {count} times in {rel} "
                f"(must be unique). Occurrences at: {', '.join(positions)}. "
                "Include more surrounding context in old_str to make it unique."
            ),
            trace={"completion": "complete", "matched": count, "path": rel},
        )
    updated = content.replace(old, new, 1)
    _atomic_write(write_path, updated.encode("utf-8"))
    replacement_line = updated[:updated.index(new)].count("\n") + 1
    context_start = max(0, replacement_line - 3)
    context_lines = updated.splitlines()[
        context_start:replacement_line + len(new.splitlines()) + 2
    ]
    context_preview = "\n".join(
        f"{context_start + index + 1:>4}| {line}"
        for index, line in enumerate(context_lines)
    )
    return ToolExecutionEnvelope(
        text=(
            f"✅ Replaced in active_workspace:{rel} (line {replacement_line}).\n"
            f"Context:\n{context_preview}\n\n"
            "File is on disk but NOT committed.\n"
            "Do not commit; the headless runner will emit a patch artifact."
        ),
        trace={"completion": "complete", "matched": 1, "path": rel},
    )


def _tracked_shrink_block(
    root: pathlib.Path,
    rel: str,
    target: pathlib.Path,
    new_content: str,
    force: bool,
) -> str:
    if force or not target.exists() or target.is_symlink():
        return ""
    try:
        tracked = subprocess.run(
            ["git", "ls-files", "--error-unmatch", rel],
            cwd=str(root),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        if tracked.returncode:
            return ""
        old_len = len(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, subprocess.SubprocessError):
        return ""
    new_len = len(new_content)
    if old_len <= 0 or new_len >= old_len * 0.7:
        return ""
    pct = round(new_len / old_len * 100)
    return (
        f"⚠️ WRITE_BLOCKED: new content for '{rel}' is {pct}% of original "
        f"({old_len} -> {new_len} chars). This looks like accidental truncation. "
        "Use edit_text for surgical edits, or pass force=true to confirm "
        "intentional rewrite."
    )


def _run_process(
    root: pathlib.Path,
    args: Mapping[str, Any],
    *,
    cmd: list[str],
    control: NativeExecutionControl | None,
    env: Mapping[str, str] | None = None,
    native_facts: Mapping[str, Any] | None = None,
    process_registry: tuple[set[Any], Any] | None = None,
    backend: str = "ssh_exec",
) -> NativeOperationResult:
    cwd = _cwd(root, args.get("cwd"))
    timeout = max(
        1.0,
        float(args.get("timeout_sec") or args.get("timeout") or 120),
    )
    started = time.monotonic()
    effective_cmd, local_autocorrect_note = (
        _maybe_autocorrect_grep_backslash_pipe([str(part) for part in cmd])
    )
    proc = subprocess.Popen(
        effective_cmd,
        cwd=str(cwd),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=dict(env) if env is not None else None,
        **subprocess_new_group_kwargs(),
    )
    if (pgid := process_group_id(proc.pid)) <= 0 and control is not None:
        kill_process_tree(proc)
        raise RuntimeError("could not resolve child process group")
    if control is not None:
        try:
            control.register_process(pgid=pgid)
        except Exception:
            _kill_process_group(proc)
            raise
    if process_registry is not None:
        processes, lock = process_registry
        with lock:
            processes.add(proc)
    stdout_capture = BoundedProcessStream()
    stderr_capture = BoundedProcessStream()

    def _drain(stream: Any, target: BoundedProcessStream) -> None:
        if stream is None:
            return
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                return
            target.append(chunk)

    stdout_thread = threading.Thread(
        target=_drain, args=(proc.stdout, stdout_capture), daemon=True
    )
    stderr_thread = threading.Thread(
        target=_drain, args=(proc.stderr, stderr_capture), daemon=True
    )
    stdout_thread.start()
    stderr_thread.start()
    try:
        deadline = started + timeout
        while proc.poll() is None:
            if control is not None and control.cancelled():
                _kill_process_group(proc)
                raise InterruptedError("remote operation cancelled")
            if time.monotonic() >= deadline:
                _kill_process_group(proc)
                raise subprocess.TimeoutExpired(cmd, timeout)
            time.sleep(0.05)
    finally:
        # Custody is not released while a foreground process group (or one of
        # its inherited pipe writers) can still be alive.  This keeps timeout,
        # cancellation, and normal-return teardown on the same ownership path.
        if proc.poll() is None:
            _kill_process_group(proc)
        else:
            proc.wait()
        stdout_thread.join(timeout=2)
        stderr_thread.join(timeout=2)
        if stdout_thread.is_alive() or stderr_thread.is_alive():
            _kill_process_group(proc)
            stdout_thread.join(timeout=2)
            stderr_thread.join(timeout=2)
        if pgid > 0:
            _stop_residual_process_group(pgid)
        if control is not None:
            release = getattr(control, "release_process", None)
            if callable(release):
                release(pgid=pgid)
        if process_registry is not None:
            processes, lock = process_registry
            with lock:
                processes.discard(proc)
    stdout = stdout_capture.preview("stdout")
    stderr = stderr_capture.preview("stderr")
    capture_meta = {
        "stdout": stdout_capture.metadata("stdout"),
        "stderr": stderr_capture.metadata("stderr"),
    }
    result = ProcessExecutionResult(
        returncode=int(proc.returncode or 0),
        stdout=stdout,
        stderr=stderr,
        args=effective_cmd,
        backend_trace={
            "backend": backend,
            "cwd": cwd.as_posix(),
            "duration_ms": int((time.monotonic() - started) * 1000),
            "output_capture": capture_meta,
        },
    )
    autocorrect_note = str(
        (native_facts or {}).get("autocorrect_note")
        or local_autocorrect_note
        or ""
    )
    if _is_search_no_match(result):
        text = (
            autocorrect_note
            + f"{_describe_returncode(result.returncode, cwd=cwd)} (no matches)\n"
            + _format_process_output(result.stdout, "")
        )
    elif result.returncode:
        text = (
            autocorrect_note
            + "⚠️ SHELL_EXIT_ERROR: command exited with "
            + f"{_describe_returncode(result.returncode, cwd=cwd)}.\n\n"
            + _format_process_output(result.stdout, result.stderr)
        )
    else:
        text = (
            autocorrect_note
            + f"{_describe_returncode(0, cwd=cwd)}\n"
            + _format_process_output(result.stdout, result.stderr)
        )
    blobs: dict[str, bytes] = {}
    artifacts: list[dict[str, Any]] = []
    for stream_name, capture in (
        ("stdout", stdout_capture),
        ("stderr", stderr_capture),
    ):
        if capture.total_bytes <= (
            PROCESS_PREVIEW_HEAD_BYTES + PROCESS_PREVIEW_TAIL_BYTES
        ):
            continue
        if capture.full is None:
            # Metadata above is the honest recovery handle: exact size/line
            # counters and full-stream hash, but no false "full log" artifact.
            continue
        data = bytes(capture.full)
        digest = hashlib.sha256(data).hexdigest()
        blobs[digest] = data
        artifacts.append(
            {
                "name": f"{stream_name}.txt",
                "blob_id": digest,
                "sha256": digest,
                "size": len(data),
                "mime": "text/plain",
                "truncated": False,
                "full_log": True,
            }
        )
    scratch = scratch_fingerprints(root, args)
    output_notes: list[str] = []
    output_failed = False
    if result.returncode == 0 and args.get("outputs"):
        output_blobs, output_artifacts, output_notes, output_failed = (
            collect_declared_outputs(
                root,
                args,
                (
                    native_facts.get("declared_outputs_before", {})
                    if isinstance(native_facts, Mapping)
                    else {}
                ),
            )
        )
        blobs.update(output_blobs)
        artifacts.extend(output_artifacts)
        marker = (
            "⚠️ ARTIFACT_OUTPUT_ERROR"
            if output_failed
            else (
                "ARTIFACT_OUTPUTS"
                if output_artifacts
                else "ARTIFACT_OUTPUT_NOTE"
            )
        )
        text += f"\n\n{marker}:\n" + "\n".join(
            f"- {note}" for note in output_notes
        )
    if scratch:
        text += (
            "\n\n⚠️ SCRATCH_REMAINS: declared scratch still on disk after "
            "the command: " + ", ".join(list(scratch)[:5])
            + ". It is excluded from the workspace patch, but delete it before "
            "finishing so it does not linger."
        )
    return NativeOperationResult(
        ToolExecutionEnvelope(
            text=text,
            process=result,
            artifacts=tuple(artifacts),
            trace={
                **result.backend_trace,
                "output_blobs": artifacts,
                "output_capture": capture_meta,
                "scratch_fingerprints": scratch,
                "artifact_output_failed": output_failed,
            },
        ),
        blobs,
    )


def _kill_process_group(proc: subprocess.Popen[Any]) -> None:
    pgid = process_group_id(proc.pid)
    if pgid <= 0:
        kill_process_tree(proc)
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        return
    terminate_process_group_id(pgid)
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        kill_process_group_id(pgid)
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
    if proc.poll() is None:
        proc.kill()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass


def _stop_residual_process_group(pgid: int, *, grace_sec: float = 2.0) -> None:
    """Ensure no descendant remains in a foreground command's custody group."""

    if pgid <= 0 or process_group_status(pgid) == "gone":
        return
    terminate_process_group_id(pgid)
    deadline = time.monotonic() + max(0.0, grace_sec)
    while time.monotonic() < deadline:
        if process_group_status(pgid) == "gone":
            return
        time.sleep(0.05)
    kill_process_group_id(pgid)
    deadline = time.monotonic() + max(0.0, grace_sec)
    while time.monotonic() < deadline:
        if process_group_status(pgid) == "gone":
            return
        time.sleep(0.05)


def _start_service(
    root: pathlib.Path,
    args: Mapping[str, Any],
    *,
    control: NativeExecutionControl | None,
    task_id: str,
    native_facts: Mapping[str, Any],
) -> ToolExecutionEnvelope:
    name = str(args.get("name") or "service")
    cmd = [str(part) for part in args.get("cmd") or []]
    if not cmd:
        raise ValueError("cmd is required")
    cwd = _cwd(root, args.get("cwd"))
    readiness = (
        dict(args.get("readiness") or {})
        if isinstance(args.get("readiness"), Mapping)
        else {}
    )
    try:
        readiness_timeout = min(
            25.0,
            max(0.0, float(readiness.get("timeout_sec", 5))),
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("readiness.timeout_sec must be numeric") from exc
    contains = str(
        readiness.get("stdout_contains")
        or readiness.get("log_contains")
        or ""
    )
    log_dir = root / ".ouroboros" / "services"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"{re.sub(r'[^A-Za-z0-9_.-]+', '_', name)}.log"
    with _SERVICES_LOCK:
        service_key = (str(task_id or ""), name)
        existing = _SERVICES_BY_TASK_NAME.get(service_key)
        if existing is not None:
            existing_rc = (
                existing.proc.poll()
                if existing.proc is not None
                else (
                    0
                    if process_group_status(existing.pgid) == "gone"
                    else None
                )
            )
            if existing_rc is None:
                raise RuntimeError(f"service already running: {name}")
        log_handle = log_path.open("ab")
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=str(cwd),
                stdin=subprocess.DEVNULL,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                **subprocess_new_group_kwargs(),
            )
        finally:
            log_handle.close()
        service_id = uuid.uuid4().hex
        if (pgid := process_group_id(proc.pid)) <= 0 and control is not None:
            kill_process_tree(proc)
            raise RuntimeError("could not resolve service process group")
        if control is not None:
            try:
                control.register_process(
                    pgid=pgid,
                    keep_alive=bool(args.get("keep_alive", False)),
                    service_id=service_id,
                )
            except Exception:
                _kill_process_group(proc)
                raise
        record = _NativeService(
            name=name,
            service_id=service_id,
            proc=proc,
            log_path=log_path,
            cwd=cwd,
            command=cmd,
            started_at_ms=int(time.time() * 1000),
            pgid=pgid if pgid > 0 else proc.pid,
            control=control,
            readiness=readiness,
            outputs=tuple(str(item) for item in args.get("outputs") or []),
            keep_alive=bool(args.get("keep_alive", False)),
            declared_outputs_before=dict(
                native_facts.get("declared_outputs_before") or {}
            ),
        )
        _SERVICES_BY_TASK_NAME[service_key] = record
        _SERVICES_BY_ID[service_id] = record
    deadline = time.monotonic() + readiness_timeout
    while time.monotonic() <= deadline:
        if not contains:
            record.ready = True
            break
        try:
            record.ready = contains in record.log_path.read_text(
                encoding="utf-8",
                errors="replace",
            )[-20_000:]
        except OSError:
            record.ready = False
        if record.ready or proc.poll() is not None:
            break
        time.sleep(0.2)
    payload = {
        "service_id": service_id,
        "name": name,
        "state": "running" if proc.poll() is None else "exited",
        "ready": record.ready,
        "returncode": proc.poll(),
        "cwd": cwd.as_posix(),
        "outputs": list(record.outputs),
        "keep_alive": record.keep_alive,
        "note": "started",
    }
    return ToolExecutionEnvelope(
        text=json.dumps(payload, sort_keys=True),
        trace={
            "completion": "complete",
            "service_ref": {
                "kind": "ssh_exec",
                "service_id": service_id,
                "name": name,
                "ready": record.ready,
                "outputs": list(record.outputs),
                "keep_alive": record.keep_alive,
                "cwd": cwd.as_posix(),
                "declared_outputs_before": dict(
                    record.declared_outputs_before or {}
                ),
            },
        },
    )


def _service_record(
    root: pathlib.Path,
    args: Mapping[str, Any],
    *,
    native_facts: Mapping[str, Any],
    task_id: str,
    control: NativeExecutionControl | None,
) -> _NativeService | None:
    name = str(args.get("name") or "service")
    with _SERVICES_LOCK:
        service_id = str(native_facts.get("service_id") or "")
        if service_id:
            record = _SERVICES_BY_ID.get(service_id)
            if record is not None:
                if record.name != name:
                    return None
                task_record = _SERVICES_BY_TASK_NAME.get((str(task_id or ""), name))
                return record if task_record is record else None
            recover = (
                getattr(control, "recover_service", None)
                if control is not None
                else None
            )
            if not callable(recover):
                return None
            recovered = recover(service_id=service_id, name=name)
            if not isinstance(recovered, Mapping):
                return None
            if (
                str(recovered.get("service_id") or "") != service_id
                or str(recovered.get("task_id") or "") != str(task_id or "")
            ):
                return None
            try:
                pgid = int(recovered.get("pgid"))
            except (TypeError, ValueError):
                return None
            service_cwd = _cwd(
                root,
                str(native_facts.get("service_cwd") or root),
            )
            safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", name)
            record = _NativeService(
                name=name,
                service_id=service_id,
                proc=None,
                log_path=root / ".ouroboros" / "services" / f"{safe_name}.log",
                cwd=service_cwd,
                command=[],
                started_at_ms=int(
                    recovered.get("started_at_ms")
                    or recovered.get("registered_at_ms")
                    or 0
                ),
                pgid=pgid,
                control=control,
                ready=bool(native_facts.get("service_ready", False)),
                outputs=tuple(
                    str(item)
                    for item in native_facts.get("service_outputs") or []
                ),
                keep_alive=bool(recovered.get("keep_alive", False)),
                declared_outputs_before=dict(
                    native_facts.get("service_declared_outputs_before") or {}
                ),
            )
            _SERVICES_BY_ID[service_id] = record
            _SERVICES_BY_TASK_NAME[(str(task_id or ""), name)] = record
            return record
        return _SERVICES_BY_TASK_NAME.get((str(task_id or ""), name))


def _service_status(
    root: pathlib.Path,
    args: Mapping[str, Any],
    *,
    native_facts: Mapping[str, Any],
    task_id: str,
    control: NativeExecutionControl | None,
) -> ToolExecutionEnvelope:
    record = _service_record(
        root,
        args,
        native_facts=native_facts,
        task_id=task_id,
        control=control,
    )
    if record is None:
        return ToolExecutionEnvelope(
            text="⚠️ SERVICE_NOT_FOUND",
            trace={"completion": "complete", "running": False},
        )
    rc = (
        record.proc.poll()
        if record.proc is not None
        else (0 if process_group_status(record.pgid) == "gone" else None)
    )
    if rc is not None:
        _release_service_process(record)
    payload = {
        "name": record.name,
        "service_ref": {
            "kind": "ssh_exec",
            "service_id": record.service_id,
            "name": record.name,
            "ready": bool(record.ready),
            "outputs": list(record.outputs),
            "keep_alive": bool(record.keep_alive),
            "cwd": record.cwd.as_posix() if record.cwd is not None else "",
            "declared_outputs_before": dict(
                record.declared_outputs_before or {}
            ),
        },
        "running": rc is None,
        "returncode": rc,
        "ready": bool(record.ready),
        "outputs": list(record.outputs),
        "keep_alive": bool(record.keep_alive),
        "cwd": record.cwd.as_posix() if record.cwd is not None else "",
        "started_at_ms": record.started_at_ms,
    }
    return ToolExecutionEnvelope(
        text=json.dumps(payload, sort_keys=True),
        trace={"completion": "complete", **payload},
    )


def _service_logs(
    root: pathlib.Path,
    args: Mapping[str, Any],
    *,
    native_facts: Mapping[str, Any],
    task_id: str,
    control: NativeExecutionControl | None,
) -> ToolExecutionEnvelope:
    record = _service_record(
        root,
        args,
        native_facts=native_facts,
        task_id=task_id,
        control=control,
    )
    if record is None:
        return ToolExecutionEnvelope(
            text="⚠️ SERVICE_NOT_FOUND",
            trace={"completion": "complete"},
        )
    tail = max(1, min(_SERVICE_LOG_TAIL_MAX, int(args.get("tail") or 8000)))
    data = record.log_path.read_bytes()[-tail:]
    return ToolExecutionEnvelope(
        text=data.decode("utf-8", errors="replace"),
        trace={
            "completion": "complete",
            "service_ref": {
                "kind": "ssh_exec",
                "service_id": record.service_id,
                "name": record.name,
                "ready": bool(record.ready),
                "outputs": list(record.outputs),
                "keep_alive": bool(record.keep_alive),
                "cwd": record.cwd.as_posix() if record.cwd is not None else "",
                "declared_outputs_before": dict(
                    record.declared_outputs_before or {}
                ),
            },
        },
    )


def _stop_service(
    root: pathlib.Path,
    args: Mapping[str, Any],
    *,
    native_facts: Mapping[str, Any],
    task_id: str,
    control: NativeExecutionControl | None,
) -> NativeOperationResult:
    record = _service_record(
        root,
        args,
        native_facts=native_facts,
        task_id=task_id,
        control=control,
    )
    if record is None:
        return NativeOperationResult(
            ToolExecutionEnvelope(
                text="⚠️ SERVICE_NOT_FOUND",
                trace={"completion": "complete"},
            )
        )
    if record.proc is not None:
        if record.proc.poll() is None:
            _kill_process_group(record.proc)
    else:
        stop = (
            getattr(record.control, "stop_service", None)
            if record.control is not None
            else None
        )
        if not callable(stop) or not stop(service_id=record.service_id):
            raise RuntimeError(
                "custody could not verify and stop the recovered service"
            )
    _release_service_process(record)
    with _SERVICES_LOCK:
        _SERVICES_BY_TASK_NAME.pop((str(task_id or ""), record.name), None)
        _SERVICES_BY_ID.pop(record.service_id, None)
    blobs: dict[str, bytes] = {}
    artifacts: list[dict[str, Any]] = []
    notes: list[str] = []
    output_failed = False
    if record.outputs and record.cwd is not None:
        blobs, artifacts, notes, output_failed = collect_declared_outputs(
            root,
            {"cwd": record.cwd.as_posix(), "outputs": list(record.outputs)},
            record.declared_outputs_before or {},
        )
    text = f"OK: service '{record.name}' stopped."
    if notes:
        marker = (
            "⚠️ ARTIFACT_OUTPUT_ERROR"
            if output_failed
            else ("ARTIFACT_OUTPUTS" if artifacts else "ARTIFACT_OUTPUT_NOTE")
        )
        text += f"\n\n{marker}:\n" + "\n".join(f"- {note}" for note in notes)
    return NativeOperationResult(
        ToolExecutionEnvelope(
            text=text,
            artifacts=tuple(artifacts),
            trace={
                "completion": "complete",
                "artifact_output_failed": output_failed,
                "service_ref": {
                    "kind": "ssh_exec",
                    "service_id": record.service_id,
                    "name": record.name,
                },
            },
        ),
        blobs,
    )


def _release_service_process(record: _NativeService) -> None:
    if record.released:
        return
    record.released = True
    release = (
        getattr(record.control, "release_process", None)
        if record.control is not None
        else None
    )
    if callable(release):
        release(pgid=record.pgid, service_id=record.service_id)


@functools.lru_cache(maxsize=4)
def _ffmpeg_binary(configured: str = "", expected_sha256: str = "") -> str:
    """Resolve the helper absolutely; execd additionally verifies its pinned digest."""

    candidate = str(configured or "").strip()
    if not candidate:
        try:
            import imageio_ffmpeg

            candidate = str(imageio_ffmpeg.get_ffmpeg_exe() or "")
        except Exception:
            candidate = str(shutil.which("ffmpeg") or "")
    if not candidate:
        raise FileNotFoundError("ffmpeg is unavailable on the target")
    resolved = pathlib.Path(candidate).expanduser().resolve(strict=True)
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise PermissionError("ffmpeg helper is not an executable regular file")
    if configured:
        if (
            len(expected_sha256) != 64
            or hashlib.sha256(resolved.read_bytes()).hexdigest() != expected_sha256
        ):
            raise PermissionError("bundled ffmpeg helper failed integrity verification")
    return str(resolved)


def _extract_video_frames(
    root: pathlib.Path,
    args: Mapping[str, Any],
    *,
    control: NativeExecutionControl | None,
) -> NativeOperationResult:
    source = _target(root, args.get("path"), must_exist=True)
    try:
        max_frames = max(1, min(12, int(args.get("max_frames") or 5)))
    except (TypeError, ValueError):
        max_frames = 5
    raw_times = str(args.get("timestamps") or "")
    timestamps = [
        value.strip() for value in re.split(r"[,\s]+", raw_times)
        if value.strip()
    ][:max_frames]
    if not timestamps:
        timestamps = [str(index) for index in range(max_frames)]
    blobs: dict[str, bytes] = {}
    artifacts: list[dict[str, Any]] = []
    errors: list[str] = []
    ffmpeg = _ffmpeg_binary(
        os.environ.get("OUROBOROS_EXECD_FFMPEG", ""),
        os.environ.get("OUROBOROS_EXECD_FFMPEG_SHA256", ""),
    )
    for index, stamp in enumerate(timestamps, 1):
        try:
            float(stamp)
        except ValueError:
            errors.append(f"invalid timestamp {stamp!r}")
            continue
        with tempfile.NamedTemporaryFile(suffix=".jpg") as handle:
            command = [
                ffmpeg,
                "-nostdin",
                "-loglevel",
                "error",
                "-ss",
                stamp,
                "-i",
                str(source),
                "-frames:v",
                "1",
                "-y",
                handle.name,
            ]
            proc = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                **subprocess_new_group_kwargs(),
            )
            if (pgid := process_group_id(proc.pid)) <= 0 and control is not None:
                kill_process_tree(proc)
                raise RuntimeError("could not resolve ffmpeg process group")
            registered = False
            try:
                if control is not None:
                    try:
                        control.register_process(pgid=pgid)
                    except Exception:
                        _kill_process_group(proc)
                        raise
                    registered = True
                deadline = time.monotonic() + 60
                while proc.poll() is None:
                    if control is not None and control.cancelled():
                        _kill_process_group(proc)
                        raise InterruptedError("remote frame extraction cancelled")
                    if time.monotonic() >= deadline:
                        _kill_process_group(proc)
                        raise subprocess.TimeoutExpired(command, 60)
                    time.sleep(0.05)
                _stdout, stderr = proc.communicate()
                if proc.returncode:
                    raise RuntimeError(stderr.decode("utf-8", errors="replace"))
                data = pathlib.Path(handle.name).read_bytes()
            finally:
                if registered and control is not None:
                    control.release_process(pgid=pgid)
        digest = hashlib.sha256(data).hexdigest()
        blobs[digest] = data
        artifacts.append(
            {
                "name": f"{source.stem}_frame_{index:02d}.jpg",
                "blob_id": digest,
                "sha256": digest,
                "size": len(data),
                "mime": "image/jpeg",
                "timestamp": stamp,
            }
        )
    if not artifacts:
        detail = "; ".join(errors[:5]) or "no frames produced"
        return NativeOperationResult(
            ToolExecutionEnvelope(
                text=f"⚠️ EXTRACT_VIDEO_FRAMES_UNAVAILABLE: {detail}",
                trace={"completion": "complete", "source": source.relative_to(root).as_posix()},
            )
        )
    warning = f"\nWarnings: {'; '.join(errors[:5])}" if errors else ""
    return NativeOperationResult(
        ToolExecutionEnvelope(
            text=json.dumps({"frames": artifacts}, sort_keys=True) + warning,
            artifacts=tuple(artifacts),
            trace={"completion": "complete", "source": source.relative_to(root).as_posix()},
        ),
        blobs,
    )


def execute_native_operation(
    workspace_root: pathlib.Path | str,
    tool: str,
    canonical_args: Mapping[str, Any],
    *,
    native_facts: Mapping[str, Any] | None = None,
    blobs: Mapping[str, bytes] | None = None,
    task_id: str = "",
    control: NativeExecutionControl | None = None,
) -> NativeOperationResult:
    """Execute one authorized native operation and return typed evidence."""

    operation = str(tool or "").strip()
    args = {
        str(key): value
        for key, value in canonical_args.items()
        if not str(key).startswith("_")
    }
    native_facts = dict(native_facts or {})
    supplied_blobs = dict(blobs or {})
    root: pathlib.Path
    try:
        root = _workspace_root(workspace_root)
        if native_facts:
            attested_root = str(native_facts.get("workspace_root") or "")
            if attested_root and attested_root != root.as_posix():
                raise PermissionError("prepared native workspace root changed")
        if operation == "read_file":
            return NativeOperationResult(_read_file(root, args))
        if operation == "list_files":
            return NativeOperationResult(_list_files(root, args))
        if operation == "write_file":
            return NativeOperationResult(_write_file(root, args))
        if operation == "edit_text":
            return NativeOperationResult(_edit_text(root, args))
        if operation in {"search_code", "query_code"}:
            return NativeOperationResult(execute_workspace_query_operation(root, operation, args, native_facts))
        if operation == "run_command":
            cmd = [str(part) for part in args.get("cmd") or []]
            if not cmd:
                raise ValueError("cmd is required")
            return _run_process(
                root,
                args,
                cmd=cmd,
                control=control,
                native_facts=native_facts,
            )
        if operation == "run_script":
            return execute_inline_script(
                root,
                args,
                control=control,
                native_facts=native_facts,
                process_runner=_run_process,
                atomic_write=_atomic_write,
            )
        if operation == "execute_reviewed_payload":
            return execute_reviewed_payload(
                root,
                args,
                native_facts=native_facts,
                blobs=supplied_blobs,
                control=control,
                process_runner=_run_process,
            )
        if operation in {"vcs_status", "vcs_diff"}:
            return execute_git_workspace_operation(
                root,
                operation,
                args,
                native_facts,
            )
        if operation == "snapshot_manifest_and_blob_export":
            return snapshot_operation(root, protected_paths=tuple(native_facts.get("protected_paths") or ()))
        if operation == "guarded_patch_apply":
            return NativeOperationResult(
                _guarded_patch_apply(
                    root,
                    args,
                    supplied_blobs,
                    protected_paths=tuple(
                        native_facts.get("protected_paths") or ()
                    ),
                )
            )
        if operation == "classify_ambiguous_workspace_path":
            return NativeOperationResult(classify_workspace_path(root, args))
        if operation == "start_service":
            return NativeOperationResult(
                _start_service(
                    root,
                    args,
                    control=control,
                    task_id=str(task_id or ""),
                    native_facts=native_facts,
                )
            )
        if operation == "service_status":
            return NativeOperationResult(
                _service_status(
                    root,
                    args,
                    native_facts=native_facts,
                    task_id=str(task_id or ""),
                    control=control,
                )
            )
        if operation == "service_logs":
            return NativeOperationResult(
                _service_logs(
                    root,
                    args,
                    native_facts=native_facts,
                    task_id=str(task_id or ""),
                    control=control,
                )
            )
        if operation == "stop_service":
            return _stop_service(
                root,
                args,
                native_facts=native_facts,
                task_id=str(task_id or ""),
                control=control,
            )
        if operation == "verify_remote_check":
            cmd = [str(part) for part in args.get("cmd") or []]
            if not cmd:
                raise ValueError("cmd is required")
            return attach_remote_verification_facts(
                root, args, _run_process(root, args, cmd=cmd, control=control),
            )
        if operation == "extract_video_frames":
            return _extract_video_frames(root, args, control=control)
        raise ValueError(f"unsupported native operation: {operation}")
    except subprocess.TimeoutExpired as exc:
        return _error_result(
            exc,
            operation=operation,
            args=args,
            domain="process",
            completion="unknown",
        )
    except InterruptedError as exc:
        return _error_result(
            exc,
            operation=operation,
            args=args,
            domain="process",
            completion="unknown",
        )
    except BaseException as exc:
        return _error_result(exc, operation=operation, args=args)
