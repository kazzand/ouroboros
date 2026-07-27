"""Private pickle-safe worker Pipe proxy for the server-owned SSH broker."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import pathlib
import re
import threading
import time
import uuid
from collections.abc import Mapping
from multiprocessing.connection import Connection
from typing import Any

from ouroboros.remote_protocol import canonical_json
from ouroboros.workspace_diagnostics import (
    ExecutionDiagnostic,
    ProcessExecutionResult,
    ToolExecutionEnvelope,
)

_REQUEST_TIMEOUT_SEC = 120.0
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_OPAQUE_RE = re.compile(r"^[A-Za-z0-9_:@-](?:[A-Za-z0-9_.:@-]{0,254}[A-Za-z0-9_:@-])?$")


def opaque(value: Any, field_name: str) -> str:
    text = str(value or "").strip()
    if not _OPAQUE_RE.fullmatch(text):
        raise ValueError(f"{field_name} must be a file-safe opaque ID")
    return text


def optional_opaque(value: Any, field_name: str) -> str:
    text = str(value or "").strip()
    return opaque(text, field_name) if text else ""


def json_copy(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    try:
        copied = json.loads(canonical_json(dict(value)).decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"{label} must be bounded canonical JSON: {exc}") from exc
    if not isinstance(copied, dict):
        raise ValueError(f"{label} must be an object")
    return copied


def capability_projection(manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Return the strict, JSON-safe native-capability proof sent to execd."""

    hashes = {
        "manifest_sha256": manifest.get("manifest_sha256"),
        "public_schema_sha256": manifest.get("public_schema_sha256"),
    }
    if any(not isinstance(value, str) or not _HASH_RE.fullmatch(value) for value in hashes.values()):
        raise ValueError("capability manifest hashes are invalid")
    operations = manifest.get("native_operations")
    if not isinstance(operations, list):
        raise ValueError("capability manifest native_operations must be a list")
    names = [str(row.get("name") or "") for row in operations if isinstance(row, dict)]
    if len(names) != len(operations) or any(not name for name in names):
        raise ValueError("capability manifest native_operations are invalid")
    projection = {
        "schema_version": int(manifest.get("schema_version") or 0),
        **hashes,
        "native_operations": sorted(names),
        "native_operations_sha256": hashlib.sha256(canonical_json(sorted(names))).hexdigest(),
        "native_kernel_modules_sha256": hashlib.sha256(
            canonical_json(sorted(str(item) for item in manifest.get("native_kernel_modules") or []))
        ).hexdigest(),
        "native_import_modules_sha256": hashlib.sha256(
            canonical_json(sorted(str(item) for item in manifest.get("native_import_modules") or []))
        ).hexdigest(),
        "native_import_edges_sha256": hashlib.sha256(
            canonical_json(manifest.get("native_import_edges") or {})
        ).hexdigest(),
    }
    return json.loads(canonical_json(projection).decode("utf-8"))


class RemoteWorkspacePipeProxy:
    """Worker client containing only one Pipe endpoint, never an SSH handle."""

    def __init__(self, endpoint: Connection) -> None:
        self._endpoint = endpoint
        self._lock = threading.Lock()
        self._closed = False

    def __getstate__(self) -> dict[str, Any]:
        return {"endpoint": self._endpoint, "closed": self._closed}

    def __setstate__(self, state: Mapping[str, Any]) -> None:
        self._endpoint = state["endpoint"]
        self._lock = threading.Lock()
        self._closed = bool(state.get("closed"))

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._endpoint.close()
        except (OSError, EOFError):
            pass

    close_parent_copy = close

    def prepare(self, workspace_ref: Mapping[str, Any], **kwargs: Any) -> Any:
        result = self._call("prepare", {"workspace_ref": dict(workspace_ref), **kwargs})
        return prepared_from_dict(result)

    def execute_prepared(
        self,
        workspace_ref: Mapping[str, Any],
        prepared: Any,
        *,
        canonical_args: Mapping[str, Any],
        task_id: str = "",
        timeout_sec: float | None = None,
    ) -> ToolExecutionEnvelope:
        result = self._call(
            "execute_prepared",
            {
                "workspace_ref": dict(workspace_ref),
                "prepared": dataclasses.asdict(prepared),
                "canonical_args": dict(canonical_args),
                "task_id": task_id,
                "timeout_sec": timeout_sec,
            },
            timeout_sec=execution_wait_timeout(canonical_args, timeout_sec),
        )
        return envelope_from_dict(result)

    def abort_prepared(
        self,
        workspace_ref: Mapping[str, Any],
        prepared: Any,
        *,
        task_id: str = "",
        reason: str = "denied",
    ) -> bool:
        return bool(
            self._call(
                "abort_prepared",
                {
                    "workspace_ref": dict(workspace_ref),
                    "prepared": dataclasses.asdict(prepared),
                    "task_id": task_id,
                    "reason": reason,
                },
            )
        )

    def fetch_blob(
        self,
        workspace_ref: Mapping[str, Any],
        blob_id: str,
        *,
        max_bytes: int,
    ) -> bytes:
        result = self._call(
            "fetch_blob",
            {
                "workspace_ref": dict(workspace_ref),
                "blob_id": blob_id,
                "max_bytes": max_bytes,
            },
        )
        if not isinstance(result, bytes):
            raise self._error(
                "remote_blob_invalid",
                "Remote blob response was not bytes.",
                phase="import",
            )
        return result

    def cancel(self, workspace_ref: Mapping[str, Any], **kwargs: Any) -> bool:
        return bool(self._call("cancel", {"workspace_ref": dict(workspace_ref), **kwargs}))

    def open_browser_forward(
        self,
        workspace_ref: Mapping[str, Any],
        *,
        remote_port: int,
        task_id: str,
    ) -> dict[str, Any]:
        return dict(
            self._call(
                "open_browser_forward",
                {
                    "workspace_ref": dict(workspace_ref),
                    "remote_port": int(remote_port),
                    "task_id": task_id,
                },
            )
        )

    def close_browser_forward(self, forward_id: str) -> bool:
        return bool(
            self._call(
                "close_browser_forward",
                {"forward_id": str(forward_id)},
            )
        )

    def _call(
        self,
        method: str,
        payload: dict[str, Any],
        *,
        timeout_sec: float | None = None,
    ) -> Any:
        if self._closed:
            raise self._error(
                "broker_pipe_closed",
                "Remote workspace worker channel is closed.",
                phase="stream",
            )
        correlation_id = uuid.uuid4().hex
        message = {"correlation_id": correlation_id, "method": method, "payload": payload}
        wait_sec = _REQUEST_TIMEOUT_SEC if timeout_sec is None else max(1.0, float(timeout_sec))
        with self._lock:
            try:
                self._endpoint.send(message)
                deadline = time.monotonic() + wait_sec
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not self._endpoint.poll(remaining):
                        raise self._error(
                            "broker_pipe_timeout",
                            "Remote workspace broker did not answer before the deadline.",
                            phase="stream",
                            completion="unknown",
                            retryable=True,
                        )
                    response = self._endpoint.recv()
                    if not isinstance(response, dict):
                        break
                    # Requests are serialized by _lock, but a timed-out request
                    # may finish later. Drain only those stale replies instead
                    # of poisoning the next correlation on this durable pipe.
                    if response.get("correlation_id") == correlation_id:
                        break
            except (EOFError, OSError) as exc:
                raise self._error(
                    "broker_pipe_closed",
                    "Remote workspace broker channel closed.",
                    phase="stream",
                    completion="unknown",
                    retryable=True,
                ) from exc
        if not isinstance(response, dict):
            raise self._error(
                "broker_pipe_protocol",
                "Remote workspace broker returned a mismatched response.",
                phase="stream",
                completion="unknown",
            )
        if not response.get("ok"):
            error = response.get("error") if isinstance(response.get("error"), dict) else {}
            raise self._error(
                str(error.get("code") or "remote_workspace_error"),
                str(error.get("message") or "Remote workspace request failed."),
                phase=str(error.get("phase") or "stream"),
                completion=str(error.get("completion") or "unknown"),
                retryable=bool(error.get("retryable")),
                details=error.get("details") if isinstance(error.get("details"), dict) else {},
            )
        return response.get("result")

    @staticmethod
    def _error(code: str, message: str, **kwargs: Any) -> Exception:
        from ouroboros.remote_workspace import RemoteWorkspaceError

        return RemoteWorkspaceError(code, message, **kwargs)


def prepared_from_dict(raw: Any) -> Any:
    from ouroboros.remote_workspace import PreparedRemoteCall

    if isinstance(raw, PreparedRemoteCall):
        return raw
    values = validated_prepared(raw)
    diagnostic = values.get("diagnostic")
    return PreparedRemoteCall(
        **{
            key: values[key]
            for key in (
                "request_id",
                "operation_id",
                "tool",
                "prepared_token",
                "prepared_hash",
                "expires_at_ms",
                "execution_args",
                "native_facts",
            )
        },
        diagnostic=diagnostic_from_dict(diagnostic) if isinstance(diagnostic, dict) else None,
    )


def validated_prepared(raw: Any) -> dict[str, Any]:
    from ouroboros.remote_workspace import RemoteWorkspaceError

    if not isinstance(raw, Mapping):
        raise RemoteWorkspaceError(
            "prepared_response_invalid",
            "Execd returned an invalid prepared response.",
            phase="prepare",
        )
    result = {
        "request_id": opaque(raw.get("request_id"), "request_id"),
        "operation_id": opaque(raw.get("operation_id"), "operation_id"),
        "tool": str(raw.get("tool") or ""),
        "prepared_token": opaque(raw.get("prepared_token"), "prepared_token"),
        "prepared_hash": str(raw.get("prepared_hash") or ""),
        "expires_at_ms": int(raw.get("expires_at_ms") or 0),
        "execution_args": json_copy(raw.get("execution_args"), "execution_args"),
        "native_facts": json_copy(raw.get("native_facts"), "native_facts"),
    }
    if not result["tool"] or re.fullmatch(r"[0-9a-f]{64}", result["prepared_hash"]) is None:
        raise RemoteWorkspaceError(
            "prepared_response_invalid",
            "Execd returned invalid prepared identity.",
            phase="prepare",
        )
    if result["expires_at_ms"] <= int(time.time() * 1000):
        raise RemoteWorkspaceError(
            "prepared_call_expired",
            "Execd prepared call is already expired.",
            phase="prepare",
        )
    if isinstance(raw.get("diagnostic"), Mapping):
        result["diagnostic"] = dict(raw["diagnostic"])
    return result


def diagnostic_from_dict(raw: Mapping[str, Any]) -> ExecutionDiagnostic:
    domains = {"transport", "protocol", "policy", "filesystem", "process", "artifact"}
    completions = {"not_started", "completed", "unknown"}
    domain = str(raw.get("domain") or "protocol")
    completion = str(raw.get("completion") or "unknown")
    return ExecutionDiagnostic(
        domain=domain if domain in domains else "protocol",  # type: ignore[arg-type]
        code=str(raw.get("code") or "remote_error"),
        message=str(raw.get("message") or "Remote operation failed."),
        phase=str(raw.get("phase") or "execute"),
        request_id=str(raw.get("request_id") or ""),
        operation_id=str(raw.get("operation_id") or ""),
        completion=completion if completion in completions else "unknown",  # type: ignore[arg-type]
        retryable=bool(raw.get("retryable")),
        errno=int(raw["errno"]) if isinstance(raw.get("errno"), int) else None,
        details=dict(raw.get("details") or {}) if isinstance(raw.get("details"), dict) else {},
    )


def envelope_from_dict(raw: Any) -> ToolExecutionEnvelope:
    values = validated_envelope_dict(raw)
    diagnostic = diagnostic_from_dict(values["diagnostic"]) if isinstance(values.get("diagnostic"), dict) else None
    process_raw = values.get("process")
    process = None
    if isinstance(process_raw, dict):
        process = ProcessExecutionResult(
            returncode=int(process_raw.get("returncode") or 0),
            stdout=str(process_raw.get("stdout") or ""),
            stderr=str(process_raw.get("stderr") or ""),
            backend_trace=dict(process_raw.get("backend_trace") or {}),
            args=[str(item) for item in list(process_raw.get("args") or [])],
        )
    return ToolExecutionEnvelope(
        text=str(values.get("text") or ""),
        diagnostic=diagnostic,
        process=process,
        artifacts=tuple(dict(item) for item in list(values.get("artifacts") or []) if isinstance(item, dict)),
        trace=dict(values.get("trace") or {}),
    )


def validated_envelope_dict(raw: Any) -> dict[str, Any]:
    from ouroboros.remote_workspace import RemoteWorkspaceError

    if isinstance(raw, ToolExecutionEnvelope):
        raw = dataclasses.asdict(raw)
    if not isinstance(raw, Mapping):
        raise RemoteWorkspaceError(
            "remote_result_invalid",
            "Execd returned an invalid operation envelope.",
            phase="finalize",
            completion="unknown",
        )
    copied = json_copy(raw, "operation envelope")
    if not isinstance(copied.get("text", ""), str):
        raise RemoteWorkspaceError(
            "remote_result_invalid",
            "Execd operation envelope text is invalid.",
            phase="finalize",
            completion="unknown",
        )
    return copied


def execution_wait_timeout(canonical_args: Mapping[str, Any], supplied: Any) -> float:
    value = supplied
    if value is None:
        value = canonical_args.get("timeout_sec", canonical_args.get("timeout"))
    if value is None:
        return _REQUEST_TIMEOUT_SEC
    try:
        execution_sec = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("remote execution timeout must be numeric") from exc
    if not 1.0 <= execution_sec <= 86_400.0:
        raise ValueError("remote execution timeout must be in 1..86400 seconds")
    return execution_sec + 30.0


def reconnect_failure(
    connection_id: str,
    error: BaseException | None = None,
) -> dict[str, Any]:
    detail = (
        error_dict(error)
        if error is not None
        else {
            "code": "remote_session_absent",
            "message": "No admitted project session is available to reconnect.",
            "phase": "connect",
            "completion": "not_started",
            "retryable": False,
        }
    )
    return {
        "status": "error" if error is not None else "disconnected",
        "phase": detail["phase"],
        "completion": detail["completion"],
        "error_code": detail["code"],
        "action": "retry_reconnect" if detail["retryable"] else "readmit_project",
        "diagnostic": detail["message"],
        "log_refs": [],
        "connection_id": connection_id,
        "sessions": [],
        "reconciliation": [],
    }


def error_dict(exc: BaseException) -> dict[str, Any]:
    from ouroboros.remote_workspace import RemoteWorkspaceError

    if isinstance(exc, RemoteWorkspaceError):
        diagnostic = exc.diagnostic()
        try:
            from ouroboros.observability import redact_projection

            redacted = redact_projection(dict(diagnostic.details)).value
            details = dict(redacted) if isinstance(redacted, Mapping) else {}
        except Exception:
            redacted_diagnostic = ExecutionDiagnostic(
                domain="transport",
                code="redacted_details",
                message="Remote transport details.",
                phase="stream",
                details=dict(diagnostic.details),
            )
            details = dict(redacted_diagnostic.details)
        return {
            "code": exc.code,
            "message": safe_error_text(diagnostic.message),
            "phase": exc.phase,
            "completion": exc.completion,
            "retryable": exc.retryable,
            "details": details,
        }
    return {
        "code": type(exc).__name__,
        "message": safe_error_text(exc),
        "phase": "stream",
        "completion": "unknown",
        "retryable": False,
        "details": {},
    }


def safe_error_text(exc: Any) -> str:
    text = str(exc).replace("\x00", "")
    try:
        from ouroboros.observability import redact_projection

        text = str(redact_projection(text).value)
    except Exception:
        pass
    home = str(pathlib.Path.home())
    if home and home != "/":
        text = text.replace(home, "<home>")
    return " ".join(text.split())[:2000] or type(exc).__name__
