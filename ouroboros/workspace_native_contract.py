"""Dependency-light public contract for the execd native workspace kernel."""

from __future__ import annotations

import hashlib
import pathlib
import re
import signal
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol, runtime_checkable

from ouroboros.workspace_diagnostics import (
    ProcessExecutionResult,
    ToolExecutionEnvelope,
)

PROCESS_PREVIEW_HEAD_BYTES = 32_000
PROCESS_PREVIEW_TAIL_BYTES = 32_000
PROCESS_FULL_CAPTURE_BYTES = 16_000_000
REVIEWED_PAYLOAD_FILE_CAP = 512
REVIEWED_PAYLOAD_FILE_BYTES = 8 * 1024 * 1024
REVIEWED_PAYLOAD_TOTAL_BYTES = 32 * 1024 * 1024
DECLARED_OUTPUT_FILE_CAP = 1000
DECLARED_OUTPUT_TOTAL_BYTES = 32 * 1024 * 1024
_GREP_TOOLS = frozenset(("grep", "egrep", "fgrep"))
_GREP_REGEX_MODE_FLAGS = frozenset((
    "-E", "--extended-regexp",
    "-P", "--perl-regexp",
    "-F", "--fixed-strings",
    "-G", "--basic-regexp",
))
_GREP_BACKSLASH_PIPE_PATTERN = re.compile(r'\\\|')
_NO_MATCH_EXIT_TOOLS = frozenset(("grep", "egrep", "fgrep", "rg", "ag", "ack"))


def describe_process_returncode(
    returncode: int,
    *,
    cwd: pathlib.Path | str | None = None,
) -> str:
    """Render a return code identically on Home and target."""

    suffix: list[str] = []
    if int(returncode) < 0:
        signal_num = abs(int(returncode))
        try:
            signal_name = signal.Signals(signal_num).name
        except ValueError:
            signal_name = f"SIG{signal_num}"
        suffix.append(f"signal={signal_name}")
    if cwd is not None:
        suffix.append(f"cwd={pathlib.Path(cwd).resolve(strict=False)}")
    rendered_suffix = f" ({', '.join(suffix)})" if suffix else ""
    return f"exit_code={returncode}{rendered_suffix}"


def format_process_output(
    stdout: str,
    stderr: str,
    *,
    limit: int = 50_000,
) -> str:
    """Render bounded stdout/stderr sections identically on Home and target."""

    parts: list[str] = []
    if str(stdout or "").strip():
        parts.append(f"STDOUT:\n{stdout}")
    if str(stderr or "").strip():
        parts.append(f"STDERR:\n{stderr}")
    rendered = "\n\n".join(parts) if parts else "STDOUT:\n(empty)"
    if len(rendered) > limit:
        rendered = (
            rendered[: limit // 2]
            + "\n...(truncated)...\n"
            + rendered[-limit // 2 :]
        )
    return rendered


def process_is_search_no_match(res: ProcessExecutionResult) -> bool:
    tool = pathlib.Path(str(res.args[0] if res.args else "")).name.lower()
    return (
        int(res.returncode) == 1
        and tool in _NO_MATCH_EXIT_TOOLS
        and not str(res.stderr or "").strip()
    )


def autocorrect_grep_backslash_pipe(
    cmd: list[str],
) -> tuple[list[str], str]:
    if not cmd or pathlib.Path(cmd[0]).name.lower() not in _GREP_TOOLS:
        return cmd, ""
    tool = pathlib.Path(cmd[0]).name.lower()
    explicit = tool in ("egrep", "fgrep")
    if not explicit:
        for arg in cmd[1:]:
            if arg in _GREP_REGEX_MODE_FLAGS:
                explicit = True
                break
            if (
                arg.startswith("-")
                and not arg.startswith("--")
                and any(flag in arg[1:] for flag in ("E", "P", "F", "G"))
            ):
                explicit = True
                break
    if explicit:
        return cmd, ""
    corrected = list(cmd)
    changed_args: list[str] = []
    for idx, arg in enumerate(corrected[1:], start=1):
        if _GREP_BACKSLASH_PIPE_PATTERN.search(arg):
            corrected[idx] = _GREP_BACKSLASH_PIPE_PATTERN.sub("|", arg)
            changed_args.append(arg)
    if not changed_args:
        return cmd, ""
    corrected.insert(1, "-E")
    return corrected, (
        "⚠️ SHELL_REGEX_AUTO_CORRECTED: converted grep backslash-escaped "
        "alternation (\\|) to extended regex mode (`grep -E`) and rewrote "
        f"{changed_args!r} to use `|`.\n"
    )

MANDATORY_REMOTE_NATIVE_OPERATIONS: frozenset[str] = frozenset({
    "classify_ambiguous_workspace_path",
    "edit_text",
    "execute_reviewed_payload",
    "extract_video_frames",
    "guarded_patch_apply",
    "list_files",
    "query_code",
    "read_file",
    "run_command",
    "run_script",
    "search_code",
    "service_logs",
    "service_status",
    "snapshot_manifest_and_blob_export",
    "start_service",
    "stop_service",
    "vcs_diff",
    "vcs_status",
    "verify_remote_check",
    "write_file",
})

REMOTE_NATIVE_OPERATION_MODULE: dict[str, str] = {
    name: "ouroboros.workspace_native"
    for name in sorted(MANDATORY_REMOTE_NATIVE_OPERATIONS)
}

REMOTE_NATIVE_KERNEL_MODULES: frozenset[str] = frozenset({
    *REMOTE_NATIVE_OPERATION_MODULE.values(),
    "ouroboros.code_intelligence",
    "ouroboros.remote_task_files",
    "ouroboros.shell_parse",
    "ouroboros.utils",
    "ouroboros.workspace_payload_native",
    "ouroboros.workspace_query_native",
    "ouroboros.workspace_snapshot_native",
})


@runtime_checkable
class NativeExecutionControl(Protocol):
    """Execd-owned cancellation/custody callbacks for spawned process groups."""

    cancelled: Callable[[], bool]
    register_process: Callable[..., None]
    release_process: Callable[..., None]
    recover_service: Callable[..., Mapping[str, Any] | None]
    stop_service: Callable[..., bool]


@dataclass
class BoundedProcessStream:
    """Hash a whole process stream while retaining bounded head/tail evidence."""

    total_bytes: int = 0
    newline_count: int = 0
    last_byte: int | None = None
    digest: Any = field(default_factory=hashlib.sha256)
    head: bytearray = field(default_factory=bytearray)
    tail: bytearray = field(default_factory=bytearray)
    full: bytearray | None = field(default_factory=bytearray)

    def append(self, chunk: bytes) -> None:
        if not chunk:
            return
        self.total_bytes += len(chunk)
        self.newline_count += chunk.count(b"\n")
        self.last_byte = chunk[-1]
        self.digest.update(chunk)
        if len(self.head) < PROCESS_PREVIEW_HEAD_BYTES:
            self.head.extend(chunk[: PROCESS_PREVIEW_HEAD_BYTES - len(self.head)])
        self.tail.extend(chunk)
        if len(self.tail) > PROCESS_PREVIEW_TAIL_BYTES:
            del self.tail[:-PROCESS_PREVIEW_TAIL_BYTES]
        if self.full is not None:
            if len(self.full) + len(chunk) <= PROCESS_FULL_CAPTURE_BYTES:
                self.full.extend(chunk)
            else:
                self.full = None

    @property
    def total_lines(self) -> int:
        if self.total_bytes <= 0:
            return 0
        return self.newline_count + (0 if self.last_byte == ord("\n") else 1)

    def metadata(self, stream_name: str) -> dict[str, Any]:
        previewed = min(
            self.total_bytes,
            PROCESS_PREVIEW_HEAD_BYTES + PROCESS_PREVIEW_TAIL_BYTES,
        )
        omitted_newlines = max(
            0,
            self.newline_count
            - bytes(self.head).count(b"\n")
            - bytes(self.tail).count(b"\n"),
        )
        return {
            "stream": stream_name,
            "sha256": self.digest.hexdigest(),
            "total_bytes": self.total_bytes,
            "total_lines": self.total_lines,
            "previewed_bytes": previewed,
            "omitted_bytes": max(0, self.total_bytes - previewed),
            "omitted_newlines": omitted_newlines,
            "full_log_available": self.full is not None,
        }

    def preview(self, stream_name: str) -> str:
        if self.total_bytes <= PROCESS_PREVIEW_HEAD_BYTES + PROCESS_PREVIEW_TAIL_BYTES:
            return bytes(self.full or self.head).decode("utf-8", errors="replace")
        meta = self.metadata(stream_name)
        marker = (
            f"\n… {stream_name}: omitted {meta['omitted_bytes']} bytes "
            f"({meta['omitted_newlines']} newline separators); "
            f"total={meta['total_bytes']} bytes/{meta['total_lines']} lines; "
            f"sha256={meta['sha256']} …\n"
        )
        return (
            bytes(self.head).decode("utf-8", errors="replace")
            + marker
            + bytes(self.tail).decode("utf-8", errors="replace")
        )


@dataclass(frozen=True)
class NativePreparedOperation:
    execution_args: dict[str, Any]
    native_facts: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class NativeOperationResult:
    envelope: ToolExecutionEnvelope
    blobs: dict[str, bytes] = field(default_factory=dict)


def validate_remote_native_operation_map(
    operation_modules: Mapping[str, str] = REMOTE_NATIVE_OPERATION_MODULE,
) -> None:
    """Fail if the explicit execd operation map is incomplete or over-broad."""

    names = frozenset(str(name) for name in operation_modules)
    missing = sorted(MANDATORY_REMOTE_NATIVE_OPERATIONS - names)
    unexpected = sorted(names - MANDATORY_REMOTE_NATIVE_OPERATIONS)
    if missing or unexpected:
        raise ValueError(
            "remote native operation map mismatch: "
            f"missing={missing}, unexpected={unexpected}"
        )
    invalid = sorted(
        name
        for name, module in operation_modules.items()
        if not str(module or "").startswith("ouroboros.")
    )
    if invalid:
        raise ValueError(
            f"remote native operation modules must be Ouroboros modules: {invalid}"
        )
