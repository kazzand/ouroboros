"""Owner-only remote connection metadata and lifecycle service."""

from __future__ import annotations

import asyncio
import inspect
import json
import pathlib
import secrets
import threading
import time
from contextlib import contextmanager
from functools import partial
from typing import Any, Callable, Iterator

from starlette.requests import Request
from starlette.responses import JSONResponse

from ouroboros.platform_layer import (
    acquire_exclusive_file_lock,
    release_exclusive_file_lock,
)
from ouroboros.utils import atomic_write_json, utc_now_iso

CONNECTION_STORE_SCHEMA_VERSION = 1
CONNECTION_LIFECYCLES = frozenset({"active", "retired"})
_LOCK_TIMEOUT_SEC = 4.0
_LOCK_STALE_SEC = 90.0
_LIVE_TEXT_LIMIT = 4000
_LIVE_COLLECTION_LIMIT = 32
_CONNECTION_HEALTH_FRESH_SEC = 300.0
_RUNTIME_EVIDENCE_LOCK = threading.RLock()
_RUNTIME_EVIDENCE: dict[tuple[str, str], dict[str, Any]] = {}


def connection_store_path() -> pathlib.Path:
    from ouroboros.config import REMOTE_CONNECTIONS_PATH

    return pathlib.Path(REMOTE_CONNECTIONS_PATH)


def _record_runtime_health(
    path: pathlib.Path,
    connection_id: str,
    result: dict[str, Any],
    *,
    bootstrap_compatible: bool = False,
) -> None:
    """Record process-local compatibility/health without widening store schema."""

    key = (
        str(pathlib.Path(path).resolve(strict=False)),
        str(connection_id),
    )
    with _RUNTIME_EVIDENCE_LOCK:
        previous = _RUNTIME_EVIDENCE.get(key)
        if previous is None and not bootstrap_compatible:
            return
        row = dict(previous or {})
        if bootstrap_compatible:
            row["bootstrap_compatible"] = True
            for name in ("build", "capability_hash"):
                value = str(result.get(name) or "").strip()
                if value:
                    row[name] = value
            observed = _observed_host_id(result)
            if observed:
                row["host_id"] = observed
        status = str(result.get("status") or "").strip().lower()
        if status in {"ready", "degraded", "disconnected", "unknown"}:
            row["status"] = status
            row["health_checked_monotonic"] = time.monotonic()
        _RUNTIME_EVIDENCE[key] = row


def _runtime_evidence_fields(
    path: pathlib.Path,
    connection_id: str,
) -> dict[str, Any]:
    with _RUNTIME_EVIDENCE_LOCK:
        row = dict(
            _RUNTIME_EVIDENCE.get(
                (
                    str(pathlib.Path(path).resolve(strict=False)),
                    str(connection_id),
                ),
                {},
            )
        )
    if not row.get("bootstrap_compatible"):
        return {
            "bootstrap_compatible": False,
            "health_fresh": False,
        }
    checked = float(row.get("health_checked_monotonic") or 0.0)
    fresh = checked > 0 and time.monotonic() - checked <= _CONNECTION_HEALTH_FRESH_SEC
    result: dict[str, Any] = {
        "bootstrap_compatible": True,
        "health_fresh": fresh,
    }
    if fresh and row.get("status"):
        result["status"] = str(row["status"])
    for name in ("build",):
        if row.get(name):
            result[name] = str(row[name])
    return result


def is_connection_store_path(
    candidate: pathlib.Path,
    *,
    store_path: pathlib.Path | None = None,
) -> bool:
    """Match the owner store and its lock/atomic aliases without following writes."""

    target = pathlib.Path(store_path or connection_store_path()).resolve(strict=False)
    path = pathlib.Path(candidate)
    try:
        if path.exists() and target.exists() and path.samefile(target):
            return True
    except OSError:
        pass
    try:
        if path.parent.resolve(strict=False) != target.parent:
            return False
    except OSError:
        return False
    name = path.name.casefold()
    target_name = target.name.casefold()
    return (
        name == target_name
        or name == f"{target_name}.lock"
        or name.startswith(f".{target_name}.tmp.")
    )


def normalize_ssh_alias(value: Any) -> str:
    alias = str(value or "").strip()
    if not alias or alias.startswith("-"):
        raise ValueError("ssh_alias must be a non-empty host token without a leading dash")
    if len(alias) > 255:
        raise ValueError("ssh_alias must be at most 255 characters")
    if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in alias):
        raise ValueError("ssh_alias must not contain whitespace or control characters")
    return alias


def _clean_text(value: Any, field: str, *, maximum: int) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field} is required")
    if len(text) > maximum or any(ord(char) < 32 or ord(char) == 127 for char in text):
        raise ValueError(f"{field} is invalid")
    return text


@contextmanager
def _owner_store_lock(path: pathlib.Path) -> Iterator[None]:
    """Serialize owner-store updates with the shared owner-only lock primitive."""

    lock_path = path.with_name(path.name + ".lock")
    fd = acquire_exclusive_file_lock(
        lock_path,
        timeout_sec=_LOCK_TIMEOUT_SEC,
        stale_sec=_LOCK_STALE_SEC,
        mode=0o600,
    )
    if fd is None:
        raise TimeoutError(f"could not lock remote connection store {path}")
    try:
        yield
    finally:
        release_exclusive_file_lock(lock_path, fd)


def _read_store(path: pathlib.Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "_schema_version": CONNECTION_STORE_SCHEMA_VERSION,
            "connections": [],
        }
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("remote connection store is unreadable or malformed") from exc
    if (
        not isinstance(payload, dict)
        or payload.get("_schema_version") != CONNECTION_STORE_SCHEMA_VERSION
        or not isinstance(payload.get("connections"), list)
        or any(not isinstance(item, dict) for item in payload["connections"])
    ):
        raise ValueError("remote connection store has an unsupported schema")
    return payload


def _write_store(path: pathlib.Path, payload: dict[str, Any]) -> None:
    atomic_write_json(
        path,
        payload,
        fsync=True,
        mode=0o600,
        fsync_directory=True,
    )


def _mutate_store(
    path: pathlib.Path,
    mutator: Callable[[list[dict[str, Any]]], Any],
) -> Any:
    with _owner_store_lock(path):
        payload = _read_store(path)
        connections = [dict(item) for item in payload["connections"]]
        result = mutator(connections)
        _write_store(
            path,
            {
                "_schema_version": CONNECTION_STORE_SCHEMA_VERSION,
                "connections": connections,
            },
        )
        return result


def list_connections(
    path: pathlib.Path | None = None,
    *,
    include_retired: bool = False,
) -> list[dict[str, Any]]:
    rows = [
        dict(item)
        for item in _read_store(pathlib.Path(path or connection_store_path()))[
            "connections"
        ]
    ]
    if include_retired:
        return rows
    return [row for row in rows if row.get("lifecycle", "active") == "active"]


def get_connection(
    connection_id: str,
    path: pathlib.Path | None = None,
    *,
    include_retired: bool = True,
) -> dict[str, Any] | None:
    wanted = str(connection_id or "").strip()
    for row in list_connections(path, include_retired=include_retired):
        if str(row.get("id") or "") == wanted:
            return row
    return None


def add_connection(
    *,
    name: str,
    ssh_alias: str,
    path: pathlib.Path | None = None,
) -> dict[str, Any]:
    display_name = _clean_text(name, "name", maximum=80)
    alias = normalize_ssh_alias(ssh_alias)
    target = pathlib.Path(path or connection_store_path())

    def add(rows: list[dict[str, Any]]) -> dict[str, Any]:
        if any(
            row.get("lifecycle", "active") == "active"
            and row.get("ssh_alias") == alias
            for row in rows
        ):
            raise ValueError("an active connection already uses this ssh_alias")
        now = utc_now_iso()
        row = {
            "id": f"conn_{secrets.token_hex(8)}",
            "name": display_name,
            "ssh_alias": alias,
            "expected_host_id": "",
            "host_id_history": [],
            "lifecycle": "active",
            "retired_at": None,
            "created_at": now,
            "updated_at": now,
        }
        rows.append(row)
        return dict(row)

    return _mutate_store(target, add)


def pin_connection_host(
    connection_id: str,
    host_id: str,
    *,
    path: pathlib.Path | None = None,
) -> dict[str, Any]:
    wanted = _clean_text(connection_id, "connection_id", maximum=80)
    observed = _clean_text(host_id, "host_id", maximum=256)

    def pin(rows: list[dict[str, Any]]) -> dict[str, Any]:
        for row in rows:
            if row.get("id") != wanted:
                continue
            if row.get("lifecycle", "active") != "active":
                raise ValueError("connection_retired")
            expected = str(row.get("expected_host_id") or "")
            if expected and expected != observed:
                raise ValueError("remote host identity changed; explicit owner retrust is required")
            if not expected:
                now = utc_now_iso()
                row["expected_host_id"] = observed
                row["host_id_history"] = [
                    {"host_id": observed, "trusted_at": now, "superseded_at": None}
                ]
                row["updated_at"] = now
            return dict(row)
        raise KeyError(wanted)

    return _mutate_store(pathlib.Path(path or connection_store_path()), pin)


def retrust_connection(
    connection_id: str,
    new_host_id: str,
    *,
    path: pathlib.Path | None = None,
    has_active_lease: bool = False,
) -> dict[str, Any]:
    if has_active_lease:
        raise ValueError("connection has an active task or lease")
    wanted = _clean_text(connection_id, "connection_id", maximum=80)
    replacement = _clean_text(new_host_id, "host_id", maximum=256)

    def retrust(rows: list[dict[str, Any]]) -> dict[str, Any]:
        for row in rows:
            if row.get("id") != wanted:
                continue
            if row.get("lifecycle", "active") != "active":
                raise ValueError("connection_retired")
            current = str(row.get("expected_host_id") or "")
            if not current:
                raise ValueError("connection has no pinned host identity")
            if current == replacement:
                return dict(row)
            now = utc_now_iso()
            history = [dict(item) for item in row.get("host_id_history", [])]
            for item in history:
                if item.get("host_id") == current and not item.get("superseded_at"):
                    item["superseded_at"] = now
            history.append(
                {"host_id": replacement, "trusted_at": now, "superseded_at": None}
            )
            row["host_id_history"] = history
            row["expected_host_id"] = replacement
            row["updated_at"] = now
            return dict(row)
        raise KeyError(wanted)

    return _mutate_store(pathlib.Path(path or connection_store_path()), retrust)


def retire_connection(
    connection_id: str,
    *,
    path: pathlib.Path | None = None,
    has_active_lease: bool = False,
) -> dict[str, Any]:
    if has_active_lease:
        raise ValueError("connection has an active task or lease")
    wanted = _clean_text(connection_id, "connection_id", maximum=80)

    def retire(rows: list[dict[str, Any]]) -> dict[str, Any]:
        for row in rows:
            if row.get("id") != wanted:
                continue
            if row.get("lifecycle", "active") == "retired":
                return dict(row)
            now = utc_now_iso()
            row["lifecycle"] = "retired"
            row["retired_at"] = now
            row["updated_at"] = now
            return dict(row)
        raise KeyError(wanted)

    return _mutate_store(pathlib.Path(path or connection_store_path()), retire)


def _request_store_path(request: Request) -> pathlib.Path:
    state = getattr(request.app, "state", None)
    injected = getattr(state, "remote_connections_path", None) if state is not None else None
    return pathlib.Path(injected) if injected else connection_store_path()


def _remote_service(request: Request) -> Any:
    state = getattr(request.app, "state", None)
    injected = (
        getattr(state, "remote_workspace_service", None)
        if state is not None
        else None
    )
    if injected is not None:
        return injected
    try:
        from ouroboros.remote_workspace import get_remote_workspace_service

        return get_remote_workspace_service()
    except (ImportError, RuntimeError):
        return None


async def _service_call(service: Any, method: str, *args: Any, **kwargs: Any) -> dict[str, Any]:
    fn = getattr(service, method, None)
    if not callable(fn):
        return {
            "ok": False,
            "error": "remote workspace service is unavailable",
            "error_code": "remote_service_unavailable",
            "phase": "connect",
            "action": "restart_ouroboros",
        }
    try:
        result = await asyncio.to_thread(fn, *args, **kwargs)
        if inspect.isawaitable(result):
            result = await result
    except Exception as exc:
        from ouroboros.workspace_diagnostics import sanitize_execution_text

        result = _public_live_fields(exc, default_phase="connect")
        return {
            **result,
            "ok": False,
            "error": sanitize_execution_text(
                f"{type(exc).__name__}: {exc}"
            )[:2000],
        }
    return dict(result) if isinstance(result, dict) else {
        "ok": False,
        "error": "remote workspace service returned an invalid response",
        "error_code": "remote_service_invalid_response",
        "phase": "connect",
        "action": "restart_ouroboros",
    }


def _typed_error(
    error: str,
    status_code: int,
    *,
    error_code: str,
    phase: str = "",
    action: str = "",
    connection_id: str = "",
) -> JSONResponse:
    payload = {
        "ok": False,
        "error": str(error or error_code),
        "error_code": error_code,
    }
    if phase:
        payload["phase"] = phase
    if action:
        payload["action"] = action
    if connection_id:
        payload["connection_id"] = connection_id
    return JSONResponse(payload, status_code=status_code)


def _service_status_code(result: dict[str, Any]) -> int:
    code = str(result.get("error_code") or "")
    if code in {"connection_retired", "connection_conflict", "active_lease"}:
        return 409
    if code in {"connection_not_found", "workspace_not_found"}:
        return 404
    if code in {"host_identity_changed", "owner_action_required", "auth_required"}:
        return 409
    if code in {
        "invalid_request",
        "invalid_remote_root",
        "workspace_not_git",
        "workspace_not_git_root",
        "workspace_root_mismatch",
    }:
        return 400
    return 503


def _bounded_live_value(value: Any, *, depth: int = 0) -> Any:
    """Keep live diagnostics useful without turning WS frames into log dumps."""

    from ouroboros.workspace_diagnostics import sanitize_execution_text

    if depth >= 4:
        return "[truncated]"
    if isinstance(value, str):
        return sanitize_execution_text(value)[:_LIVE_TEXT_LIMIT]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, dict):
        return {
            sanitize_execution_text(str(key))[:128]: _bounded_live_value(
                item, depth=depth + 1
            )
            for key, item in list(value.items())[:_LIVE_COLLECTION_LIMIT]
        }
    if isinstance(value, (list, tuple)):
        return [
            _bounded_live_value(item, depth=depth + 1)
            for item in list(value)[:_LIVE_COLLECTION_LIMIT]
        ]
    return sanitize_execution_text(str(value))[:_LIVE_TEXT_LIMIT]


def _public_live_fields(
    value: Any,
    *,
    default_phase: str = "",
) -> dict[str, Any]:
    """Bound live mappings and project typed exceptions through one projection."""

    if isinstance(value, BaseException):
        row: dict[str, Any] = {
            "status": "degraded",
            "error_code": str(
                getattr(value, "code", None)
                or getattr(value, "error_code", None)
                or "remote_service_error"
            ),
            "phase": str(getattr(value, "phase", None) or default_phase),
            "completion": str(
                getattr(value, "completion", None) or "not_started"
            ),
            "action": str(getattr(value, "action", None) or "retry"),
        }
        diagnostic_fn = getattr(value, "diagnostic", None)
        if callable(diagnostic_fn):
            try:
                diagnostic = diagnostic_fn()
                row["diagnostic"] = {
                    key: getattr(diagnostic, key)
                    for key in (
                        "domain",
                        "code",
                        "message",
                        "phase",
                        "request_id",
                        "operation_id",
                        "completion",
                        "retryable",
                        "errno",
                        "details",
                    )
                }
            except Exception:
                pass
    else:
        row = dict(value) if isinstance(value, dict) else {}
    if not row.get("platform") and row.get("system"):
        row["platform"] = row["system"]
    if not row.get("architecture") and row.get("machine"):
        row["architecture"] = row["machine"]
    result = {
        key: str(row[key])[:512]
        for key in (
            "status",
            "phase",
            "task_id",
            "project_id",
            "platform",
            "architecture",
            "build",
            "completion",
            "error_code",
            "action",
        )
        if key in row and row[key] is not None
    }
    for key in ("bootstrap_compatible", "health_fresh"):
        if key in row:
            result[key] = bool(row[key])
    if isinstance(row.get("diagnostic"), dict):
        result["diagnostic"] = _bounded_live_value(row["diagnostic"])
    if isinstance(row.get("log_refs"), list):
        result["log_refs"] = [
            _bounded_live_value(item)
            for item in row["log_refs"][:_LIVE_COLLECTION_LIMIT]
            if isinstance(item, dict)
        ]
    if isinstance(row.get("warnings"), list):
        result["warnings"] = [
            _bounded_live_value(item)
            for item in row["warnings"][:_LIVE_COLLECTION_LIMIT]
            if isinstance(item, dict)
        ]
    return result


def _broadcast_connection_state(connection_id: str, result: dict[str, Any]) -> None:
    try:
        from supervisor.message_bus import get_bridge

        get_bridge().broadcast({
            "type": "connection_state",
            "connection_id": connection_id,
            **_public_live_fields(result),
        })
    except Exception:
        pass


def _observed_host_id(result: dict[str, Any]) -> str:
    for source in (
        result,
        result.get("handshake") if isinstance(result.get("handshake"), dict) else {},
        result.get("admission_evidence")
        if isinstance(result.get("admission_evidence"), dict)
        else {},
        result.get("diagnostic") if isinstance(result.get("diagnostic"), dict) else {},
    ):
        host_id = str(source.get("host_id") or source.get("observed_host_id") or "").strip()
        if host_id:
            return host_id
    return ""


def _connection_busy(service: Any, connection_id: str) -> bool:
    """Fail-closed live-task plus broker-lease check for owner mutations."""

    try:
        from ouroboros.workspace_ref import workspace_ref_for
        from supervisor import queue as supervisor_queue
        from supervisor.task_lifecycle import REMOTE_ADMISSIONS
        from supervisor.workers import PENDING, RUNNING

        with supervisor_queue._queue_lock:
            tasks = [
                row.get("task")
                for row in REMOTE_ADMISSIONS.values()
                if isinstance(row, dict)
            ]
            tasks.extend(PENDING)
            tasks.extend(
                row.get("task")
                for row in RUNNING.values()
                if isinstance(row, dict)
            )
            for task in tasks:
                if not isinstance(task, dict):
                    continue
                try:
                    ref = workspace_ref_for(task)
                except ValueError:
                    continue
                if (
                    ref
                    and ref["kind"] == "ssh"
                    and ref["connection_id"] == connection_id
                ):
                    return True
    except Exception:
        # Lifecycle lookup failure must not make a destructive trust/lifecycle
        # operation look safe.
        return True
    probe = getattr(service, "has_active_lease", None)
    if not callable(probe):
        return True
    try:
        return bool(probe(connection_id))
    except Exception:
        return True


async def api_connections_list(request: Request) -> JSONResponse:
    path = _request_store_path(request)
    try:
        rows = list_connections(path, include_retired=True)
    except Exception as exc:
        return _typed_error(
            str(exc), 500, error_code="connection_store_unavailable",
            action="repair_connection_store",
        )
    service = _remote_service(request)
    live: dict[str, dict[str, Any]] = {}
    if service is not None:
        status = await _service_call(service, "status", None)
        items = status.get("connections") if isinstance(status, dict) else None
        if isinstance(items, list):
            live = {
                str(item.get("connection_id") or item.get("id") or ""):
                    _public_live_fields(item)
                for item in items
                if (
                    isinstance(item, dict)
                    and str(item.get("connection_id") or item.get("id") or "")
                )
            }
        elif isinstance(items, dict):
            live = {
                str(key): _public_live_fields(value)
                for key, value in items.items()
                if str(key)
            }
        elif isinstance(status, dict):
            connection_id = str(status.get("connection_id") or "")
            if connection_id:
                live = {connection_id: _public_live_fields(status)}
    projected = []
    for row in rows:
        connection_id = str(row.get("id") or "")
        live_row = live.get(connection_id, {})
        if live_row:
            _record_runtime_health(path, connection_id, live_row)
        evidence = _runtime_evidence_fields(path, connection_id)
        projected.append({
            **row,
            "status": "unknown" if row.get("lifecycle") == "active" else "disconnected",
            **live_row,
            # Bootstrap compatibility/freshness are Home process-local
            # admission evidence. A transport status projection must never
            # manufacture or override them.
            **evidence,
        })
    return JSONResponse({"connections": projected})


async def api_connections_add(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        body = None
    if not isinstance(body, dict):
        return _typed_error(
            "body must be a JSON object", 400, error_code="invalid_request",
        )
    try:
        row = add_connection(
            name=body.get("name"),
            ssh_alias=body.get("ssh_alias"),
            path=_request_store_path(request),
        )
    except ValueError as exc:
        return _typed_error(
            str(exc), 409 if "already uses" in str(exc) else 400,
            error_code="connection_conflict" if "already uses" in str(exc) else "invalid_request",
        )
    except Exception as exc:
        return _typed_error(
            str(exc), 500, error_code="connection_store_unavailable",
        )
    return JSONResponse({"ok": True, "connection": {**row, "status": "unknown"}}, status_code=201)


async def _connection_action(request: Request, method: str) -> JSONResponse:
    connection_id = str(request.path_params.get("connection_id") or "").strip()
    path = _request_store_path(request)
    row = get_connection(connection_id, path)
    if row is None:
        return _typed_error(
            "connection not found", 404, error_code="connection_not_found",
            connection_id=connection_id,
        )
    if row.get("lifecycle") != "active":
        return _typed_error(
            "connection is retired", 409, error_code="connection_retired",
            action="rebind_project", connection_id=connection_id,
        )
    service = _remote_service(request)
    if service is None:
        return _typed_error(
            "remote workspace service is unavailable", 503,
            error_code="remote_service_unavailable", action="restart_ouroboros",
            connection_id=connection_id,
        )
    from ouroboros.config import get_ssh_timeout_sec

    timeout_kind = {
        "bootstrap": "bootstrap",
        "reconnect_connection": "reconcile",
    }.get(method, "connect")
    result = await _service_call(
        service,
        method,
        row,
        timeout_sec=float(get_ssh_timeout_sec(timeout_kind)),
    )
    if not result.get("platform") and result.get("system"):
        result["platform"] = result["system"]
    if not result.get("architecture") and result.get("machine"):
        result["architecture"] = result["machine"]
    observed = _observed_host_id(result)
    expected = str(row.get("expected_host_id") or "").strip()
    if (
        result.get("ok")
        and observed
        and expected
        and observed != expected
    ):
        result = {
            **result,
            "ok": False,
            "status": "degraded",
            "error": "remote host identity differs from the pinned identity",
            "error_code": "host_identity_changed",
            "action": "retrust",
        }
    if method == "bootstrap" and result.get("ok") and not observed:
        result = {
            **result,
            "ok": False,
            "status": "degraded",
            "error": "bootstrap did not return a remote host identity",
            "error_code": "host_identity_missing",
            "action": "retry_bootstrap",
        }
    if method == "bootstrap" and result.get("ok") and observed:
        try:
            row = pin_connection_host(
                connection_id, observed, path=path,
            )
        except ValueError as exc:
            result = {
                **result,
                "ok": False,
                "status": "degraded",
                "error": str(exc),
                "error_code": "host_identity_changed",
                "action": "retrust",
            }
    if method == "reconnect_connection" and str(result.get("status") or "") != "ready":
        result["ok"] = False
        result.setdefault("error", "remote project session was not reconnected")
        result.setdefault("error_code", "remote_session_disconnected")
        result.setdefault("action", "readmit_project")
    _record_runtime_health(
        path,
        connection_id,
        result,
        bootstrap_compatible=bool(method == "bootstrap" and result.get("ok")),
    )
    result.update(_runtime_evidence_fields(path, connection_id))
    result.setdefault("connection_id", connection_id)
    result.setdefault("connection", row)
    _broadcast_connection_state(connection_id, result)
    return JSONResponse(
        result,
        status_code=200 if result.get("ok") else _service_status_code(result),
    )


api_connection_test = partial(_connection_action, method="test_connection")
api_connection_test.__name__ = "api_connection_test"
api_connection_bootstrap = partial(_connection_action, method="bootstrap")
api_connection_bootstrap.__name__ = "api_connection_bootstrap"
api_connection_reconnect = partial(
    _connection_action,
    method="reconnect_connection",
)
api_connection_reconnect.__name__ = "api_connection_reconnect"


async def api_connection_dirs(request: Request) -> JSONResponse:
    connection_id = str(request.path_params.get("connection_id") or "").strip()
    row = get_connection(connection_id, _request_store_path(request))
    if row is None:
        return _typed_error(
            "connection not found", 404, error_code="connection_not_found",
            connection_id=connection_id,
        )
    if row.get("lifecycle") != "active":
        return _typed_error(
            "connection is retired", 409, error_code="connection_retired",
            action="rebind_project", connection_id=connection_id,
        )
    service = _remote_service(request)
    if service is None:
        return _typed_error(
            "remote workspace service is unavailable", 503,
            error_code="remote_service_unavailable", action="restart_ouroboros",
            connection_id=connection_id,
        )
    from ouroboros.config import get_ssh_timeout_sec

    result = await _service_call(
        service,
        "list_directories",
        row,
        remote_root=str(request.query_params.get("path") or ""),
        timeout_sec=float(get_ssh_timeout_sec("connect")),
    )
    if not result.get("ok", True):
        return JSONResponse(result, status_code=_service_status_code(result))
    dirs = [
        {
            "name": str(item.get("name") or ""),
            "path": str(item.get("path") or ""),
            "is_git": bool(item.get("is_git")),
        }
        for item in (result.get("dirs") or [])
        if isinstance(item, dict)
    ][:500]
    return JSONResponse({
        "connection_id": connection_id,
        "path": str(result.get("path") or ""),
        "parent": str(result.get("parent") or ""),
        "dirs": dirs,
        "truncated": bool(result.get("truncated")) or len(result.get("dirs") or []) > 500,
    })


async def api_connection_retrust(request: Request) -> JSONResponse:
    connection_id = str(request.path_params.get("connection_id") or "").strip()
    path = _request_store_path(request)
    row = get_connection(connection_id, path)
    if row is None:
        return _typed_error(
            "connection not found", 404, error_code="connection_not_found",
            connection_id=connection_id,
        )
    if row.get("lifecycle", "active") != "active":
        return _typed_error(
            "connection is retired", 409, error_code="connection_retired",
            action="choose_active_connection", connection_id=connection_id,
        )
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict) or body.get("confirm") is not True:
        return _typed_error(
            "explicit retrust confirmation is required", 400,
            error_code="confirmation_required", action="confirm_retrust",
            connection_id=connection_id,
        )
    service = _remote_service(request)
    if service is None:
        return _typed_error(
            "remote workspace service is unavailable", 503,
            error_code="remote_service_unavailable", action="restart_ouroboros",
            connection_id=connection_id,
        )
    if _connection_busy(service, connection_id):
        return _typed_error(
            "connection has an active task or lease", 409,
            error_code="active_lease", action="cancel_active_tasks",
            connection_id=connection_id,
        )
    from ouroboros.config import get_ssh_timeout_sec

    probe = await _service_call(
        service,
        "test_connection",
        row,
        timeout_sec=float(get_ssh_timeout_sec("connect")),
    )
    observed = _observed_host_id(probe)
    if not probe.get("ok") and not observed:
        probe.setdefault("connection_id", connection_id)
        return JSONResponse(probe, status_code=_service_status_code(probe))
    expected_old = str(body.get("old_host_id") or "").strip()
    expected_new = str(body.get("new_host_id") or "").strip()
    current = str(row.get("expected_host_id") or "")
    if not observed or expected_old != current or expected_new != observed:
        return _typed_error(
            "host identity changed while retrust was being confirmed", 409,
            error_code="host_identity_confirmation_stale", action="test_connection",
            connection_id=connection_id,
        )
    try:
        from supervisor import queue as supervisor_queue

        with supervisor_queue._queue_lock:
            if _connection_busy(service, connection_id):
                return _typed_error(
                    "connection has an active task or lease", 409,
                    error_code="active_lease", action="cancel_active_tasks",
                    connection_id=connection_id,
                )
            trusted = retrust_connection(
                connection_id,
                observed,
                path=path,
                has_active_lease=False,
            )
    except ValueError as exc:
        return _typed_error(
            str(exc), 409, error_code="connection_conflict",
            connection_id=connection_id,
        )
    with _RUNTIME_EVIDENCE_LOCK:
        _RUNTIME_EVIDENCE.pop(
            (
                str(pathlib.Path(path).resolve(strict=False)),
                str(connection_id),
            ),
            None,
        )
    result = {
        "ok": True,
        "connection_id": connection_id,
        "connection": trusted,
        "status": "unknown",
        "phase": "retrust",
        "completion": "retrusted",
        "action": "bootstrap_connection",
        "bootstrap_compatible": False,
        "health_fresh": False,
    }
    _broadcast_connection_state(connection_id, result)
    return JSONResponse(result)


async def api_connection_retire(request: Request) -> JSONResponse:
    connection_id = str(request.path_params.get("connection_id") or "").strip()
    path = _request_store_path(request)
    row = get_connection(connection_id, path)
    if row is None:
        return _typed_error(
            "connection not found", 404, error_code="connection_not_found",
            connection_id=connection_id,
        )
    service = _remote_service(request)
    if service is None:
        return _typed_error(
            "remote workspace service is unavailable", 503,
            error_code="remote_service_unavailable", action="restart_ouroboros",
            connection_id=connection_id,
        )
    try:
        from supervisor import queue as supervisor_queue

        with supervisor_queue._queue_lock:
            if _connection_busy(service, connection_id):
                return _typed_error(
                    "connection has an active task or lease", 409,
                    error_code="active_lease", action="cancel_active_tasks",
                    connection_id=connection_id,
                )
            retired = retire_connection(
                connection_id,
                path=path,
                has_active_lease=False,
            )
    except ValueError as exc:
        return _typed_error(
            str(exc), 409, error_code="connection_conflict",
            connection_id=connection_id,
        )
    cancel_connection = getattr(service, "cancel_connection", None)
    if callable(cancel_connection):
        try:
            await asyncio.to_thread(cancel_connection, connection_id)
        except Exception:
            pass
    result = {
        "ok": True,
        "connection_id": connection_id,
        "connection": retired,
        "status": "disconnected",
        "completion": "retired",
    }
    with _RUNTIME_EVIDENCE_LOCK:
        _RUNTIME_EVIDENCE.pop(
            (
                str(pathlib.Path(path).resolve(strict=False)),
                str(connection_id),
            ),
            None,
        )
    _broadcast_connection_state(connection_id, result)
    return JSONResponse(result)


__all__ = [
    "add_connection",
    "api_connection_bootstrap",
    "api_connection_dirs",
    "api_connection_reconnect",
    "api_connection_retrust",
    "api_connection_retire",
    "api_connection_test",
    "api_connections_add",
    "api_connections_list",
    "connection_store_path",
    "get_connection",
    "is_connection_store_path",
    "list_connections",
    "normalize_ssh_alias",
    "pin_connection_host",
    "retrust_connection",
    "retire_connection",
]
