"""Durable Home reconciliation intents for remote mutations."""

from __future__ import annotations

import json
import os
import pathlib
import threading
import time
from collections.abc import Mapping
from hashlib import sha256
from typing import Any

from ouroboros.remote_protocol import canonical_json
from ouroboros.utils import atomic_write_json

_SCHEMA_VERSION = 2
_RECORD_TYPE = "pending_remote_operation"
_IMPORT_KINDS = frozenset({"task_result_v1", "attachment_stage_v1"})


def _scope_identity(
    connection_id: str,
    project_id: str,
    workspace_id: str,
) -> str:
    return sha256(
        canonical_json(
            {
                "connection_id": connection_id,
                "project_id": project_id,
                "workspace_id": workspace_id,
            }
        )
    ).hexdigest()


def _operation_identity(
    request_id: str,
    operation_id: str,
    prepared_hash: str,
) -> str:
    return sha256(
        canonical_json(
            {
                "request_id": request_id,
                "operation_id": operation_id,
                "prepared_hash": prepared_hash,
            }
        )
    ).hexdigest()


def _record_path(drive_root: pathlib.Path, record: Mapping[str, Any]) -> pathlib.Path:
    scope = _scope_identity(
        str(record["connection_id"]),
        str(record["project_id"]),
        str(record["workspace_id"]),
    )
    identity = _operation_identity(
        str(record["request_id"]),
        str(record["operation_id"]),
        str(record["prepared_hash"]),
    )
    return (
        pathlib.Path(drive_root)
        / "state"
        / "remote_reconciliation"
        / scope
        / f"{identity}.pending.json"
    )


def _validated_record(raw: Any, *, path: pathlib.Path) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        raise RuntimeError(f"invalid remote reconciliation record: {path}")
    if raw.get("record_type") != _RECORD_TYPE:
        # Schema-v1 retained terminal evidence shares this directory.
        if raw.get("schema_version") == 1 and raw.get("completion") == "completed":
            return None
        raise RuntimeError(f"unknown remote reconciliation record: {path}")
    required = (
        "connection_id",
        "project_id",
        "workspace_id",
        "remote_root",
        "task_id",
        "request_id",
        "operation_id",
        "prepared_hash",
        "tool",
        "import_kind",
        "import_context",
    )
    if raw.get("schema_version") != _SCHEMA_VERSION or any(
        not isinstance(raw.get(key), str) for key in required[:-1]
    ):
        raise RuntimeError(f"malformed pending remote operation: {path}")
    if not isinstance(raw.get("import_context"), dict):
        raise RuntimeError(f"malformed pending remote import context: {path}")
    if str(raw.get("import_kind") or "") not in _IMPORT_KINDS:
        raise RuntimeError(f"unknown pending remote import kind: {path}")
    prepared_hash = str(raw.get("prepared_hash") or "")
    if len(prepared_hash) != 64 or any(
        character not in "0123456789abcdef"
        for character in prepared_hash
    ):
        raise RuntimeError(f"malformed pending remote prepared hash: {path}")
    record = dict(raw)
    record["_path"] = str(path)
    return record


def write_pending_operation(
    request: Any,
    *,
    task_id: str,
    request_id: str,
    operation_id: str,
    prepared_hash: str,
    tool: str,
    import_kind: str,
    import_context: Mapping[str, Any],
) -> dict[str, Any]:
    """Fsync one intent before Home can send CONTINUE."""

    kind = str(import_kind or "")
    if kind not in _IMPORT_KINDS:
        raise ValueError("unsupported remote import kind")
    context = json.loads(
        json.dumps(dict(import_context), ensure_ascii=False, sort_keys=True)
    )
    record = {
        "schema_version": _SCHEMA_VERSION,
        "record_type": _RECORD_TYPE,
        "recorded_at_ms": int(time.time() * 1000),
        "connection_id": str(request.connection["id"]),
        "project_id": str(request.project_id),
        "workspace_id": str(request.workspace_id),
        "remote_root": str(request.remote_root),
        "task_id": str(task_id or ""),
        "request_id": str(request_id),
        "operation_id": str(operation_id),
        "prepared_hash": str(prepared_hash),
        "tool": str(tool),
        "import_kind": kind,
        "import_context": context,
    }
    path = _record_path(pathlib.Path(request.drive_root), record)
    if path.exists():
        existing = _validated_record(
            json.loads(path.read_text(encoding="utf-8")),
            path=path,
        )
        comparable = {
            key: value
            for key, value in record.items()
            if key != "recorded_at_ms"
        }
        existing_comparable = {
            key: value
            for key, value in dict(existing or {}).items()
            if key not in {"recorded_at_ms", "_path"}
        }
        if existing_comparable != comparable:
            raise RuntimeError("conflicting pending remote operation identity")
        return dict(existing or record)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    atomic_write_json(
        path,
        record,
        fsync=True,
        mode=0o600,
        fsync_directory=True,
    )
    os.chmod(path, 0o600)
    return {**record, "_path": str(path)}


def load_pending_operations(
    drive_root: pathlib.Path,
    *,
    connection_id: str = "",
    project_id: str = "",
    workspace_id: str = "",
) -> list[dict[str, Any]]:
    root = pathlib.Path(drive_root) / "state" / "remote_reconciliation"
    if not root.is_dir():
        return []
    if connection_id and project_id and workspace_id:
        scopes = [
            root / _scope_identity(connection_id, project_id, workspace_id)
        ]
    else:
        scopes = [path for path in sorted(root.iterdir()) if path.is_dir()]
    rows: list[dict[str, Any]] = []
    operation_identities: dict[
        tuple[str, str, str, str, str],
        dict[str, Any],
    ] = {}
    for scope in scopes:
        if not scope.is_dir():
            continue
        for path in sorted(scope.glob("*.pending.json")):
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise RuntimeError(
                    f"unreadable remote reconciliation record: {path}"
                ) from exc
            record = _validated_record(raw, path=path)
            if record is not None:
                identity = (
                    str(record["connection_id"]),
                    str(record["project_id"]),
                    str(record["workspace_id"]),
                    str(record["request_id"]),
                    str(record["operation_id"]),
                )
                previous = operation_identities.get(identity)
                if previous is not None and (
                    previous["prepared_hash"] != record["prepared_hash"]
                    or previous["remote_root"] != record["remote_root"]
                    or previous["import_kind"] != record["import_kind"]
                    or previous["import_context"] != record["import_context"]
                ):
                    raise RuntimeError(
                        "conflicting pending remote operation identity"
                    )
                operation_identities[identity] = record
                rows.append(record)
    return rows


def pending_operation_groups(
    drive_root: pathlib.Path,
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    for record in load_pending_operations(drive_root):
        key = (
            str(record["connection_id"]),
            str(record["project_id"]),
            str(record["workspace_id"]),
            str(record["remote_root"]),
        )
        grouped.setdefault(key, []).append(record)
    return [
        {
            "connection_id": key[0],
            "project_id": key[1],
            "workspace_id": key[2],
            "remote_root": key[3],
            "records": records,
        }
        for key, records in sorted(grouped.items())
    ]


def restore_transport_tracking(
    request: Any,
) -> tuple[
    dict[tuple[str, str], str],
    dict[tuple[str, str], dict[str, Any]],
]:
    if not all(
        hasattr(request, field)
        for field in ("drive_root", "project_id", "workspace_id")
    ):
        return {}, {}
    known: dict[tuple[str, str], str] = {}
    contexts: dict[tuple[str, str], dict[str, Any]] = {}
    for pending in load_pending_operations(
        pathlib.Path(request.drive_root),
        connection_id=str(request.connection["id"]),
        project_id=str(request.project_id),
        workspace_id=str(request.workspace_id),
    ):
        key = (str(pending["request_id"]), str(pending["operation_id"]))
        known[key] = str(pending["prepared_hash"])
        contexts[key] = {
            "task_id": str(pending.get("task_id") or ""),
            "operation_id": str(pending["operation_id"]),
            "tool": str(pending.get("tool") or ""),
            "import_kind": str(pending.get("import_kind") or ""),
            "import_context": dict(pending.get("import_context") or {}),
            "validator": None,
            "pending_record": pending,
        }
    return known, contexts


def persist_transport_intent(
    request: Any,
    context: Mapping[str, Any],
    *,
    request_id: str,
    operation_id: str,
    prepared_hash: str,
) -> dict[str, Any] | None:
    if request is None or not all(
        hasattr(request, field)
        for field in ("drive_root", "project_id", "workspace_id", "remote_root")
    ):
        return None
    return write_pending_operation(
        request,
        task_id=str(context.get("task_id") or ""),
        request_id=request_id,
        operation_id=operation_id,
        prepared_hash=prepared_hash,
        tool=str(context.get("tool") or ""),
        import_kind=str(context.get("import_kind") or ""),
        import_context=(
            context.get("import_context")
            if isinstance(context.get("import_context"), Mapping)
            else {}
        ),
    )


def bind_transport_intent(
    transport: Any,
    message: Mapping[str, Any],
    *,
    request_id: str,
    operation_id: str,
    prepared_hash: str,
) -> dict[str, Any]:
    key = (request_id, operation_id)
    contexts = getattr(transport, "_operation_contexts", None)
    if contexts is None:
        contexts = {}
        transport._operation_contexts = contexts
    context = contexts.setdefault(
        key,
        {
            "operation_id": operation_id,
            "tool": "",
            "validator": None,
            "pending_record": None,
        },
    )
    context["task_id"] = str(message.get("task_id") or "")
    context["validator"] = message.get("_home_completion_validator")
    import_kind = str(message.get("_home_import_kind") or "")
    request = getattr(transport, "request", None)
    durable_request = request is not None and all(
        hasattr(request, field)
        for field in (
            "drive_root",
            "project_id",
            "workspace_id",
            "remote_root",
        )
    )
    if not import_kind:
        if callable(context["validator"]) and not durable_request:
            context["import_kind"] = ""
            context["import_context"] = {}
            context["pending_record"] = None
            return context
        raise ValueError("durable remote import kind is required")
    raw_import_context = message.get("_home_import_context")
    context["import_kind"] = import_kind
    context["import_context"] = (
        dict(raw_import_context)
        if isinstance(raw_import_context, Mapping)
        else {}
    )
    context["pending_record"] = persist_transport_intent(
        request,
        context,
        request_id=request_id,
        operation_id=operation_id,
        prepared_hash=prepared_hash,
    )
    return context


def validate_transport_session_identity(transport: Any) -> None:
    """Reject changed target identity before querying any pending operation."""

    from ouroboros.remote_ssh import _error

    request = transport.request
    facts = transport._handshake if isinstance(transport._handshake, dict) else {}
    checks = (
        (
            str(request.connection.get("expected_host_id") or ""),
            str(facts.get("host_id") or ""),
            "host_identity_mismatch",
            "Remote host identity changed; explicit re-trust is required.",
        ),
        (
            str(request.workspace_id or ""),
            str(facts.get("workspace_id") or ""),
            "workspace_identity_mismatch",
            "Remote workspace identity changed.",
        ),
        (
            str(request.remote_root or "").rstrip("/"),
            str(facts.get("canonical_root") or ""),
            "workspace_root_mismatch",
            "Remote canonical git root differs from the selected path.",
        ),
        (
            str(request.capability_manifest.get("manifest_sha256") or ""),
            str(facts.get("capability_hash") or ""),
            "capability_mismatch",
            "Remote execd capabilities differ from Home.",
        ),
    )
    for expected, observed, code, message in checks:
        if expected and observed != expected:
            raise _error(code, message, phase="bootstrap")


def resolve_pending_recovery_group(
    drive_root: pathlib.Path,
    group: Mapping[str, Any],
) -> dict[str, Any]:
    from ouroboros.gateway.connections import get_connection
    from ouroboros.projects_registry import get_reserved_project
    from ouroboros.workspace_ref import normalize_workspace_ref

    connection = get_connection(str(group.get("connection_id") or ""))
    if connection is None:
        raise RuntimeError("pending remote connection is unavailable")
    project = get_reserved_project(
        drive_root,
        str(group.get("project_id") or ""),
    )
    if not isinstance(project, dict):
        raise RuntimeError("pending remote project is unavailable")
    workspace_ref = normalize_workspace_ref(project.get("workspace_ref"))
    expected = {
        "kind": "ssh",
        "connection_id": str(group.get("connection_id") or ""),
        "workspace_id": str(group.get("workspace_id") or ""),
        "remote_root": str(group.get("remote_root") or ""),
    }
    if workspace_ref != expected:
        raise RuntimeError("pending remote workspace identity changed")
    return connection


def recover_pending_on_broker(broker: Any) -> list[dict[str, Any]]:
    """Reopen and reconcile each durable scope through its admission lock."""

    from ouroboros.remote_workspace import _error_dict

    rows: list[dict[str, Any]] = []
    retired_keys: set[tuple[str, str, str, str]] = set()
    for group in pending_operation_groups(broker.drive_root):
        try:
            connection = resolve_pending_recovery_group(
                broker.drive_root,
                group,
            )
            broker._admit_on_broker({
                "connection": connection,
                "remote_root": group["remote_root"],
                "project_id": group["project_id"],
                "workspace_id": group["workspace_id"],
                "task_id": f"project:{group['project_id']}",
                "cancel": threading.Event(),
            })
            key = (
                group["connection_id"],
                group["project_id"],
                group["workspace_id"],
                broker.server_generation,
            )
            if connection.get("lifecycle", "active") == "retired":
                retired_keys.add(key)
            with broker._state_lock:
                session = broker._sessions[key]
                for record in group["records"]:
                    if record.get("task_id"):
                        broker._task_sessions[str(record["task_id"])] = key
        except Exception as exc:
            rows.append({
                "connection_id": group["connection_id"],
                "project_id": group["project_id"],
                "workspace_id": group["workspace_id"],
                "status": "reconcile_failed",
                "error": _error_dict(exc),
            })
    with broker._state_lock:
        sessions = list(broker._sessions.values())
    for session in sessions:
        if any(
            row.get("connection_id") == session.key[0]
            and row.get("project_id") == session.key[1]
            and row.get("workspace_id") == session.key[2]
            for row in rows
        ):
            continue
        try:
            cached = getattr(
                session.transport,
                "_last_reconciliation",
                None,
            )
            if isinstance(cached, list) and cached:
                rows.extend(
                    dict(row)
                    for row in cached
                    if isinstance(row, Mapping)
                )
            else:
                rows.extend(session.transport.reconcile())
        except Exception as exc:
            rows.append({
                "connection_id": session.key[0],
                "project_id": session.key[1],
                "workspace_id": session.key[2],
                "status": "reconcile_failed",
                "error": _error_dict(exc),
            })
        finally:
            if session.key in retired_keys:
                broker._close_project_session_on_broker({
                    "workspace_ref": {
                        "kind": "ssh",
                        "connection_id": session.key[0],
                        "workspace_id": session.key[2],
                        "remote_root": session.remote_root,
                    },
                    "project_id": session.key[1],
                })
    return rows


def remove_pending_operation(record: Mapping[str, Any]) -> None:
    path = pathlib.Path(str(record.get("_path") or ""))
    if not path.is_absolute():
        raise RuntimeError("pending remote operation path is unavailable")
    path.unlink(missing_ok=True)
    try:
        directory_fd = os.open(path.parent, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
