"""Typed internal execution evidence with compatible public rendering."""

from __future__ import annotations

import contextvars
import errno as errno_module
import re
from dataclasses import dataclass, field
from typing import Any, Literal

DiagnosticDomain = Literal[
    "transport", "protocol", "policy", "filesystem", "process", "artifact"
]
CompletionState = Literal["not_started", "completed", "unknown"]

_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|secret)"
    r"\b\s*[:=]\s*)([\"']?)([^\s,\"']+)(\2)"
)
_BEARER_RE = re.compile(r"(?i)(\b(?:authorization\s*:\s*)?bearer\s+)[A-Za-z0-9._~+/=-]+")
_URL_SECRET_RE = re.compile(
    r"(?i)([?&](?:token|access_token|api_key|key|secret|password)=)[^&#\s]+"
)


def sanitize_execution_text(value: Any) -> str:
    """Dependency-light wire/log scrubber that preserves diagnostic structure."""

    text = str(value if value is not None else "")
    text = _BEARER_RE.sub(r"\1[REDACTED]", text)
    text = _URL_SECRET_RE.sub(r"\1[REDACTED]", text)
    return _SECRET_ASSIGNMENT_RE.sub(r"\1[REDACTED]", text)


def _sanitize_value(value: Any) -> Any:
    if isinstance(value, str):
        return sanitize_execution_text(value)
    if isinstance(value, dict):
        return {sanitize_execution_text(key): _sanitize_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(_sanitize_value(item) for item in value)
    return value


@dataclass
class ProcessExecutionResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""
    backend_trace: dict[str, Any] = field(default_factory=dict)
    args: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.stdout = sanitize_execution_text(self.stdout)
        self.stderr = sanitize_execution_text(self.stderr)
        self.backend_trace = _sanitize_value(dict(self.backend_trace))
        self.args = [sanitize_execution_text(item) for item in self.args]


@dataclass(frozen=True)
class ExecutionDiagnostic:
    domain: DiagnosticDomain
    code: str
    message: str
    phase: str
    request_id: str = ""
    operation_id: str = ""
    completion: CompletionState = "not_started"
    retryable: bool = False
    errno: int | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "message", sanitize_execution_text(self.message))
        object.__setattr__(self, "details", _sanitize_value(dict(self.details)))


@dataclass(frozen=True)
class ToolExecutionEnvelope:
    text: str
    diagnostic: ExecutionDiagnostic | None = None
    process: ProcessExecutionResult | None = None
    artifacts: tuple[dict[str, Any], ...] = ()
    trace: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "text", sanitize_execution_text(self.text))
        object.__setattr__(
            self,
            "artifacts",
            tuple(_sanitize_value(dict(item)) for item in self.artifacts),
        )
        object.__setattr__(self, "trace", _sanitize_value(dict(self.trace)))


WorkspaceExecutionEnvelope = ToolExecutionEnvelope

_CURRENT_EXECUTION_ENVELOPE: contextvars.ContextVar[
    ToolExecutionEnvelope | None
] = contextvars.ContextVar(
    "ouroboros_current_execution_envelope",
    default=None,
)

_ERRNO_CODES = {
    errno_module.ENOENT: "not_found",
    errno_module.EACCES: "permission_denied",
    errno_module.EPERM: "permission_denied",
    errno_module.ENOTDIR: "not_a_directory",
    errno_module.EISDIR: "is_a_directory",
    errno_module.ENOSPC: "no_space",
    errno_module.EROFS: "read_only_filesystem",
}


def publish_execution_envelope(
    envelope: ToolExecutionEnvelope | None,
) -> contextvars.Token[ToolExecutionEnvelope | None]:
    """Publish one envelope in the current request context.

    Callers that need the structured result consume it immediately; no mutable
    ``ToolContext.last_diagnostic`` exists for concurrent requests to race on.
    """

    return _CURRENT_EXECUTION_ENVELOPE.set(envelope)


def current_execution_envelope() -> ToolExecutionEnvelope | None:
    return _CURRENT_EXECUTION_ENVELOPE.get()


def reset_execution_envelope(
    token: contextvars.Token[ToolExecutionEnvelope | None],
) -> None:
    _CURRENT_EXECUTION_ENVELOPE.reset(token)


def diagnostic_from_exception(
    exc: BaseException,
    *,
    request_id: str,
    operation_id: str = "",
    phase: str,
    domain: DiagnosticDomain = "filesystem",
    completion: CompletionState = "not_started",
    retryable: bool = False,
    details: dict[str, Any] | None = None,
) -> ExecutionDiagnostic:
    """Preserve native errno distinctions without parsing rendered strings."""

    native_errno = getattr(exc, "errno", None)
    try:
        errno_value = int(native_errno) if native_errno is not None else None
    except (TypeError, ValueError):
        errno_value = None
    code = _ERRNO_CODES.get(errno_value, "operation_failed")
    message = str(exc or type(exc).__name__).strip() or type(exc).__name__
    return ExecutionDiagnostic(
        domain=domain,
        code=code,
        message=message[:2000],
        phase=str(phase or "execute"),
        request_id=str(request_id or ""),
        operation_id=str(operation_id or ""),
        completion=completion,
        retryable=bool(retryable),
        errno=errno_value,
        details=dict(details or {}),
    )


def render_diagnostic_text(
    diagnostic: ExecutionDiagnostic,
    *,
    prefix: str = "REMOTE_WORKSPACE_ERROR",
) -> str:
    """Stable fallback text when a typed failure has no legacy rendering."""

    completion = (
        f", completion={diagnostic.completion}"
        if diagnostic.completion != "not_started"
        else ""
    )
    return (
        f"⚠️ {prefix} [{diagnostic.code}] during {diagnostic.phase}"
        f"{completion}: {diagnostic.message}"
    )


def envelope_from_exception(
    exc: BaseException,
    *,
    request_id: str,
    operation_id: str = "",
    phase: str,
    domain: DiagnosticDomain = "filesystem",
    completion: CompletionState = "not_started",
    retryable: bool = False,
    text: str = "",
    details: dict[str, Any] | None = None,
) -> ToolExecutionEnvelope:
    diagnostic = diagnostic_from_exception(
        exc,
        request_id=request_id,
        operation_id=operation_id,
        phase=phase,
        domain=domain,
        completion=completion,
        retryable=retryable,
        details=details,
    )
    return ToolExecutionEnvelope(
        text=text or render_diagnostic_text(diagnostic),
        diagnostic=diagnostic,
        trace={
            "request_id": str(request_id or ""),
            "operation_id": str(operation_id or ""),
        },
    )


def process_execution_envelope(
    request_id: str,
    result: ProcessExecutionResult,
    *,
    operation_id: str = "",
) -> ToolExecutionEnvelope:
    """Wrap one local/backend process result without inventing transport errors."""

    text = result.stdout
    if result.stderr:
        text = f"{text}\n{result.stderr}" if text else result.stderr
    trace = dict(result.backend_trace)
    trace["request_id"] = str(request_id or "")
    if operation_id:
        trace["operation_id"] = str(operation_id)
    return ToolExecutionEnvelope(text=text, process=result, trace=trace)
