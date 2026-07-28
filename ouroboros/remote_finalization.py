"""Focused Home bridge for remote patch and deliverable finalization."""

from __future__ import annotations

import json
import os
import pathlib
import re
import time
from collections import Counter
from collections.abc import Mapping
from hashlib import sha256
from typing import Any, Callable

from ouroboros.remote_protocol import (
    MAX_REMOTE_EXTERNAL_ENVELOPE_BYTES,
    canonical_json,
)
from ouroboros.utils import atomic_write_json, utc_now_iso
from ouroboros.workspace_ref import workspace_ref_for

ARTIFACT_STATUS_FAILED = "failed"
ARTIFACT_STATUS_READY_WITH_CHANGES = "ready_with_changes"
_PATCH_EXCLUDE_RULES_VERSION = 2
_DELIVERABLE_MANIFEST_FILE_CAP = 10_000
_DELIVERABLE_MANIFEST_HASH_CHUNK = 1024 * 1024
_DELIVERABLE_MANIFEST_HASH_BYTE_CAP = 64 * 1024 * 1024
_DELIVERABLE_EXCLUDED_DIRS = frozenset(
    {".git", ".ouroboros", ".venv", "venv", "env"}
)
_REMOTE_PROCESS_STREAM_ORDER = ("stdout.txt", "stderr.txt")
_REMOTE_PROCESS_STREAM_NAMES = frozenset(_REMOTE_PROCESS_STREAM_ORDER)
_REMOTE_PROCESS_PREVIEW_BYTES = 64_000
_REMOTE_PROCESS_BLOB_MAX_BYTES = 16_000_000
_REMOTE_DECLARED_OUTPUT_MAX_BYTES = 32 * 1024 * 1024
_REMOTE_RESULT_IMPORT_MAX_BYTES = (
    2 * _REMOTE_PROCESS_BLOB_MAX_BYTES
    + _REMOTE_DECLARED_OUTPUT_MAX_BYTES
    + MAX_REMOTE_EXTERNAL_ENVELOPE_BYTES
)
_REMOTE_MODEL_PREVIEW_CHARS = 64_000
_REMOTE_HOME_ARTIFACT_LIMIT = 128
_REMOTE_HOME_TRACE_KEYS = 128
_REMOTE_HOME_TRACE_VALUE_BYTES = 256 * 1024
_REMOTE_IMPORT_JSON_MAX_DEPTH = 64
_REMOTE_IMPORT_JSON_MAX_ITEMS = 100_000
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def complete_remote_import(
    drive_root: pathlib.Path,
    context: Mapping[str, Any],
    wire_result: Mapping[str, Any],
    envelope: Mapping[str, Any],
    fetched: Mapping[str, Any],
) -> dict[str, Any]:
    """Dispatch only closed, serializable Home import contracts."""

    del wire_result
    kind = str(context.get("import_kind") or "")
    import_context = (
        context.get("import_context")
        if isinstance(context.get("import_context"), Mapping)
        else {}
    )
    if kind == "task_result_v1":
        return import_remote_result_to_home(
            pathlib.Path(drive_root),
            str(context.get("task_id") or ""),
            str(context.get("operation_id") or ""),
            envelope,
            fetched,
        )
    if kind == "attachment_stage_v1":
        from ouroboros.remote_task_files import (
            validate_staged_attachment_envelope,
        )

        expected = import_context.get("expected_manifest")
        if not isinstance(expected, list):
            raise RuntimeError("attachment import context is unavailable")
        validate_staged_attachment_envelope(expected, envelope, fetched)
        return dict(envelope)
    raise RuntimeError("Home completion importer is unavailable")


def _complete_transport_import(
    transport: Any,
    context: Mapping[str, Any],
    wire_result: Mapping[str, Any],
    envelope: Mapping[str, Any],
    fetched: Mapping[str, Any],
) -> dict[str, Any]:
    validator = context.get("validator")
    if str(context.get("import_kind") or ""):
        imported = complete_remote_import(
            pathlib.Path(transport.request.drive_root),
            context,
            wire_result,
            envelope,
            fetched,
        )
    elif callable(validator):
        imported = validator(wire_result, envelope, fetched)
    else:
        raise RuntimeError("Home completion importer is unavailable")
    if not isinstance(imported, dict):
        raise RuntimeError("Home completion importer returned a non-object")
    return imported


def _remove_transport_pending(context: Mapping[str, Any]) -> bool:
    pending = context.get("pending_record")
    if not isinstance(pending, Mapping):
        return True
    from ouroboros.remote_pending_operations import remove_pending_operation

    try:
        remove_pending_operation(pending)
    except Exception:
        return False
    return True


def reconcile_remote_operations(
    transport: Any,
    *,
    ack_timeout_sec: float,
    retention_cap: int,
) -> list[dict[str, Any]]:
    """Import, durably fix and ACK the transport's bounded operation ledger."""

    rows: list[dict[str, Any]] = []
    contexts = getattr(transport, "_operation_contexts", None)
    if contexts is None:
        contexts = {}
        transport._operation_contexts = contexts
    for (request_id, operation_id), prepared_hash in list(
        transport._known_operations.items()
    ):
        transport._send(
            "reconcile",
            request_id=request_id,
            operation_id=operation_id,
            prepared_hash=prepared_hash,
        )
        response = transport._wait_control(
            lambda item: (
                item.get("kind") == "reconcile_result"
                and item.get("request_id") == request_id
                and item.get("operation_id") == operation_id
            )
        )
        row = dict(response)
        reconciled = response.get("result")
        reconciled = reconciled if isinstance(reconciled, dict) else {}
        completion = str(
            reconciled.get("completion")
            or response.get("completion")
            or ""
        )
        key = (request_id, operation_id)
        context = contexts.get(key, {})
        row.update(
            completion=completion,
            task_id=str(context.get("task_id") or ""),
        )
        should_ack = False
        if completion == "completed":
            stored = reconciled.get("result")
            if isinstance(stored, dict):
                try:
                    envelope, fetched = prefetch_remote_result_import(
                        stored,
                        transport.fetch_blob,
                    )
                    imported = _complete_transport_import(
                        transport,
                        context,
                        stored,
                        envelope,
                        fetched,
                    )
                except Exception as exc:
                    row.update(
                        imported=False,
                        import_error=type(exc).__name__,
                    )
                else:
                    row.update(imported=True, envelope=imported)
                    should_ack = True
            elif bool(reconciled.get("result_unavailable")):
                terminal = {
                    "text": (
                        "The remote operation completed, but its retained "
                        "result is unavailable."
                    ),
                    "diagnostic": {
                        "domain": "protocol",
                        "code": "remote_result_unavailable",
                        "message": (
                            "The operation will not be repeated because "
                            "remote completion is already durable."
                        ),
                        "phase": "finalize",
                        "request_id": request_id,
                        "operation_id": operation_id,
                        "completion": "completed",
                        "retryable": False,
                        "details": {},
                    },
                    "process": None,
                    "artifacts": [],
                    "trace": {"reconciled": True},
                }
                try:
                    if context.get("import_kind") != "attachment_stage_v1":
                        terminal = _complete_transport_import(
                            transport,
                            context,
                            {
                                "completion": "completed",
                                "prepared_hash": prepared_hash,
                                "envelope": terminal,
                                "output_blobs": {},
                            },
                            terminal,
                            {
                                "externalized_envelope": b"",
                                "process_blobs": {},
                            },
                        )
                    elif not isinstance(
                        (
                            context.get("import_context")
                            if isinstance(context.get("import_context"), Mapping)
                            else {}
                        ).get("expected_manifest"),
                        list,
                    ):
                        raise RuntimeError(
                            "attachment import context is unavailable"
                        )
                    scope = sha256(
                        canonical_json(
                            {
                                "connection_id": transport.request.connection[
                                    "id"
                                ],
                                "project_id": transport.request.project_id,
                                "workspace_id": transport.request.workspace_id,
                            }
                        )
                    ).hexdigest()
                    identity = sha256(
                        canonical_json(
                            {
                                "request_id": request_id,
                                "operation_id": operation_id,
                                "prepared_hash": prepared_hash,
                            }
                        )
                    ).hexdigest()
                    root = (
                        pathlib.Path(transport.request.drive_root)
                        / "state"
                        / "remote_reconciliation"
                        / scope
                    )
                    root.mkdir(parents=True, exist_ok=True, mode=0o700)
                    os.chmod(root, 0o700)
                    path = root / f"{identity}.json"
                    atomic_write_json(
                        path,
                        {
                            "schema_version": 1,
                            "recorded_at_ms": int(time.time() * 1000),
                            "connection_id": transport.request.connection["id"],
                            "project_id": transport.request.project_id,
                            "workspace_id": transport.request.workspace_id,
                            "task_id": str(context.get("task_id") or ""),
                            "request_id": request_id,
                            "operation_id": operation_id,
                            "prepared_hash": prepared_hash,
                            "completion": "completed",
                            "envelope": terminal,
                        },
                        fsync=True,
                        mode=0o600,
                        fsync_directory=True,
                    )
                    os.chmod(path, 0o600)
                    retained = sorted(
                        (
                            item
                            for item in root.glob("*.json")
                            if not item.name.endswith(".pending.json")
                        ),
                        key=lambda item: item.stat().st_mtime_ns,
                        reverse=True,
                    )
                    for stale in retained[retention_cap:]:
                        try:
                            stale.unlink()
                        except OSError:
                            pass
                    evidence_ref = str(
                        path.relative_to(transport.request.drive_root)
                    )
                except Exception as exc:
                    row.update(
                        imported=False,
                        import_error=type(exc).__name__,
                    )
                else:
                    row.update(
                        result_unavailable=True,
                        imported=True,
                        envelope=terminal,
                        evidence_ref=evidence_ref,
                    )
                    should_ack = True
        elif completion == "not_started":
            if _remove_transport_pending(context):
                transport._known_operations.pop(key, None)
                contexts.pop(key, None)
            else:
                row["cleanup_pending"] = True
        if should_ack:
            sequence = transport._send(
                "ack",
                ack_seq=int(response["seq"]),
                request_id=request_id,
                operation_id=operation_id,
                optional={"prepared_hash": prepared_hash},
            )
            try:
                ack = transport._wait_control(
                    lambda item: (
                        item.get("kind") in {"ack", "diagnostic"}
                        and (
                            item.get("ack_seq") == sequence
                            or (
                                item.get("request_id") == request_id
                                and item.get("operation_id") == operation_id
                            )
                        )
                    ),
                    timeout_sec=ack_timeout_sec,
                )
            except Exception:
                pass
            else:
                if ack.get("kind") == "ack":
                    if _remove_transport_pending(context):
                        transport._known_operations.pop(key, None)
                        contexts.pop(key, None)
                    else:
                        row["cleanup_pending"] = True
        rows.append(row)
    return rows


def _remote_blob_ref(
    raw: Any,
    *,
    label: str,
    expected_mime: str,
    max_bytes: int,
) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise RuntimeError(f"{label} is not an object")
    blob_id = str(raw.get("blob_id") or "")
    digest = str(raw.get("sha256") or "")
    size_raw = raw.get("size")
    if (
        not _SHA256_RE.fullmatch(blob_id)
        or digest != blob_id
        or not isinstance(size_raw, int)
        or isinstance(size_raw, bool)
        or size_raw < 0
        or size_raw > max_bytes
        or str(raw.get("mime") or "") != expected_mime
    ):
        raise RuntimeError(f"{label} declaration is invalid")
    return {
        "name": str(raw.get("name") or ""),
        "blob_id": blob_id,
        "sha256": digest,
        "size": size_raw,
        "mime": expected_mime,
        "truncated": bool(raw.get("truncated")),
    }


def _strict_remote_envelope(payload: bytes) -> dict[str, Any]:
    def _reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON constant: {value}")

    def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        decoded = payload.decode("utf-8", errors="strict")
        value = json.loads(
            decoded,
            object_pairs_hook=_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise RuntimeError(f"externalized operation envelope is invalid: {exc}") from exc
    if not isinstance(value, dict):
        raise RuntimeError("externalized operation envelope is not an object")
    stack: list[tuple[Any, int]] = [(value, 0)]
    item_count = 0
    while stack:
        current, depth = stack.pop()
        if depth > _REMOTE_IMPORT_JSON_MAX_DEPTH:
            raise RuntimeError("externalized operation envelope exceeds depth limit")
        if isinstance(current, dict):
            item_count += len(current)
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            item_count += len(current)
            stack.extend((item, depth + 1) for item in current)
        elif isinstance(current, float):
            raise RuntimeError("externalized operation envelope contains a float")
        elif isinstance(current, int) and not (-(1 << 63) <= current <= (1 << 63) - 1):
            raise RuntimeError("externalized operation envelope contains an oversized integer")
        elif not isinstance(current, (str, int, bool, type(None))):
            raise RuntimeError("externalized operation envelope contains an invalid value")
        if item_count > _REMOTE_IMPORT_JSON_MAX_ITEMS:
            raise RuntimeError("externalized operation envelope exceeds item limit")
    return value


def _externalized_envelope_ref(envelope: Mapping[str, Any]) -> dict[str, Any] | None:
    trace = envelope.get("trace")
    raw_ref = trace.get("externalized_result") if isinstance(trace, Mapping) else None
    if raw_ref is None:
        return None
    ref = _remote_blob_ref(
        raw_ref,
        label="externalized operation envelope",
        expected_mime="application/json",
        max_bytes=MAX_REMOTE_EXTERNAL_ENVELOPE_BYTES,
    )
    if ref["name"] != "operation-envelope.json" or ref["size"] <= 0:
        raise RuntimeError("externalized operation envelope identity is invalid")
    artifacts = envelope.get("artifacts")
    rows = list(artifacts) if isinstance(artifacts, list) else []
    matching = [
        item
        for item in rows
        if isinstance(item, Mapping)
        and str(item.get("name") or "") == "operation-envelope.json"
    ]
    if len(matching) != 1 or _remote_blob_ref(
        matching[0],
        label="externalized operation envelope artifact",
        expected_mime="application/json",
        max_bytes=MAX_REMOTE_EXTERNAL_ENVELOPE_BYTES,
    ) != ref:
        raise RuntimeError("externalized operation envelope declarations disagree")
    return ref


def _process_blob_refs(envelope: Mapping[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(envelope.get("process"), Mapping):
        return []
    artifacts = envelope.get("artifacts")
    rows = list(artifacts) if isinstance(artifacts, list) else []
    refs: list[dict[str, Any]] = []
    for name in _REMOTE_PROCESS_STREAM_ORDER:
        matches = [
            item
            for item in rows
            if isinstance(item, Mapping) and str(item.get("name") or "") == name
        ]
        if len(matches) > 1:
            raise RuntimeError(f"remote process returned duplicate {name} declarations")
        if not matches:
            continue
        ref = _remote_blob_ref(
            matches[0],
            label=f"remote process {name}",
            expected_mime="text/plain",
            max_bytes=_REMOTE_PROCESS_BLOB_MAX_BYTES,
        )
        if ref["size"] <= _REMOTE_PROCESS_PREVIEW_BYTES:
            raise RuntimeError(f"remote process {name} blob is below externalization threshold")
        refs.append(ref)
    return refs


def _declared_output_refs(envelope: Mapping[str, Any]) -> list[dict[str, Any]]:
    artifacts = envelope.get("artifacts")
    rows = list(artifacts) if isinstance(artifacts, list) else []
    refs: list[dict[str, Any]] = []
    total = 0
    for index, item in enumerate(rows):
        if not isinstance(item, Mapping) or item.get("kind") != "declared_output":
            continue
        ref = _remote_blob_ref(
            item,
            label=f"remote declared output {index}",
            expected_mime="application/octet-stream",
            max_bytes=_REMOTE_DECLARED_OUTPUT_MAX_BYTES,
        )
        total += ref["size"]
        if total > _REMOTE_DECLARED_OUTPUT_MAX_BYTES:
            raise RuntimeError("remote declared outputs exceed aggregate limit")
        ref.update({
            "declared_as": str(item.get("declared_as") or ""),
            "member_path": str(item.get("member_path") or ""),
        })
        refs.append(ref)
    return refs


def prefetch_remote_result_import(
    result: Mapping[str, Any],
    fetch_blob: Callable[[str, int], bytes],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Fetch only declared process/envelope blobs, verify them, and stay bounded."""

    raw_envelope = result.get("envelope")
    if not isinstance(raw_envelope, Mapping):
        raise RuntimeError("execd result omitted its operation envelope")
    envelope = dict(raw_envelope)
    imported_bytes = 0
    external_payload = b""
    external_ref = _externalized_envelope_ref(envelope)
    source_envelope = envelope
    if external_ref is not None:
        external_payload = bytes(
            fetch_blob(external_ref["blob_id"], external_ref["size"])
        )
        if (
            len(external_payload) != external_ref["size"]
            or sha256(external_payload).hexdigest() != external_ref["sha256"]
        ):
            raise RuntimeError("externalized operation envelope failed integrity verification")
        imported_bytes += len(external_payload)
        source_envelope = _strict_remote_envelope(external_payload)

    output_projection_present = "output_blobs" in result
    declared_outputs = result.get("output_blobs")
    if output_projection_present and not isinstance(declared_outputs, Mapping):
        raise RuntimeError("remote output blob projection is invalid")
    output_blobs = declared_outputs if isinstance(declared_outputs, Mapping) else {}
    process_refs = _process_blob_refs(source_envelope)
    declared_output_refs = _declared_output_refs(source_envelope)
    payloads: dict[str, bytes] = {}
    for ref in [*process_refs, *declared_output_refs]:
        blob_id = ref["blob_id"]
        if (
            output_projection_present
            and str(output_blobs.get(blob_id) or "") != blob_id
        ):
            raise RuntimeError(f"remote result {ref['name']} is not a declared output blob")
        if blob_id in payloads:
            continue
        if imported_bytes + ref["size"] > _REMOTE_RESULT_IMPORT_MAX_BYTES:
            raise RuntimeError("remote result import exceeds aggregate byte limit")
        payload = bytes(fetch_blob(blob_id, ref["size"]))
        if len(payload) != ref["size"] or sha256(payload).hexdigest() != blob_id:
            raise RuntimeError(f"remote process {ref['name']} failed integrity verification")
        imported_bytes += len(payload)
        payloads[blob_id] = payload
    return envelope, {
        "externalized_envelope": external_payload,
        "process_blobs": payloads,
    }


def _safe_remote_artifact_ref(
    record: Mapping[str, Any],
    *,
    display_name: str,
    artifact_name: str,
    mime: str,
    source_sha256: str,
    source_size: int,
    redacted: bool,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "name": display_name,
        "mime": mime,
        "sha256": str(record["sha256"]),
        "size": int(record["size"]),
        "source_sha256": source_sha256,
        "source_size": source_size,
        "redacted": redacted,
        "home_ref": {
            "root": "artifact_store",
            "path": artifact_name,
        },
        **dict(extra or {}),
    }


def _bounded_remote_trace(
    raw: Any,
    *,
    full_envelope_ref: Mapping[str, Any] | None,
) -> dict[str, Any]:
    from ouroboros.remote_protocol import canonical_json

    if not isinstance(raw, Mapping):
        return {}
    rows = list(raw.items())
    bounded: dict[str, Any] = {}
    omitted_values: list[str] = []
    for key, value in rows[:_REMOTE_HOME_TRACE_KEYS]:
        try:
            encoded = canonical_json(value)
        except (TypeError, ValueError):
            encoded = b""
        if encoded and len(encoded) <= _REMOTE_HOME_TRACE_VALUE_BYTES:
            bounded[str(key)] = value
        else:
            omitted_values.append(str(key))
    if len(rows) > _REMOTE_HOME_TRACE_KEYS:
        bounded["externalized_trace_keys_omitted"] = (
            len(rows) - _REMOTE_HOME_TRACE_KEYS
        )
    if omitted_values:
        bounded["externalized_trace_values_omitted"] = omitted_values
    if (omitted_values or len(rows) > _REMOTE_HOME_TRACE_KEYS) and full_envelope_ref:
        bounded["externalized_trace_full_ref"] = dict(full_envelope_ref)
    return bounded


def import_remote_result_to_home(
    drive_root: pathlib.Path,
    task_id: str,
    operation_id: str,
    envelope: Mapping[str, Any],
    fetched: Mapping[str, Any],
) -> dict[str, Any]:
    """Redact fetched process bytes, persist safe Home artifacts, and hydrate evidence."""

    from ouroboros.artifacts import (
        write_task_artifact_bytes,
        write_task_artifact_text,
    )
    from ouroboros.observability import (
        redact_projection,
        write_call_manifest,
    )
    from ouroboros.remote_protocol import canonical_json

    external_payload = fetched.get("externalized_envelope")
    raw_source = (
        _strict_remote_envelope(bytes(external_payload))
        if isinstance(external_payload, (bytes, bytearray)) and external_payload
        else dict(envelope)
    )
    source_redaction = redact_projection(raw_source)
    source = dict(source_redaction.value)
    process_refs = _process_blob_refs(source)
    declared_output_refs = _declared_output_refs(source)
    raw_blobs = fetched.get("process_blobs")
    blobs = raw_blobs if isinstance(raw_blobs, Mapping) else {}
    imported_refs: list[dict[str, Any]] = []
    full_envelope_ref: dict[str, Any] | None = None
    if isinstance(external_payload, (bytes, bytearray)) and external_payload:
        source_text = json.dumps(
            source,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        source_digest = sha256(bytes(external_payload)).hexdigest()
        safe_digest = sha256(source_text.encode("utf-8")).hexdigest()
        artifact_name = (
            f"remote-{operation_id[:16]}-operation-envelope-"
            f"{safe_digest[:12]}.json"
        )
        rule_counts = Counter(item.rule for item in source_redaction.records)
        record = write_task_artifact_text(
            drive_root,
            task_id,
            artifact_name,
            source_text,
            kind="remote_operation_envelope",
            metadata={
                "source_sha256": source_digest,
                "source_size": len(external_payload),
                "redacted": bool(source_redaction.records),
                "redaction_count": len(source_redaction.records),
                "redaction_rules": dict(sorted(rule_counts.items())),
            },
        )
        full_envelope_ref = _safe_remote_artifact_ref(
            record,
            display_name="operation-envelope.json",
            artifact_name=artifact_name,
            mime="application/json",
            source_sha256=source_digest,
            source_size=len(external_payload),
            redacted=bool(source_redaction.records),
        )
        imported_refs.append(full_envelope_ref)
    for ref in process_refs:
        raw = blobs.get(ref["blob_id"])
        if not isinstance(raw, bytes):
            raise RuntimeError(f"Home import omitted remote process {ref['name']}")
        if len(raw) != ref["size"] or sha256(raw).hexdigest() != ref["blob_id"]:
            raise RuntimeError(f"Home import could not reverify remote process {ref['name']}")
        try:
            decoded = raw.decode("utf-8", errors="strict")
            invalid_utf8_replaced = False
        except UnicodeDecodeError:
            decoded = raw.decode("utf-8", errors="replace")
            invalid_utf8_replaced = True
        redaction = redact_projection(decoded)
        safe_text = str(redaction.value)
        safe_digest = sha256(safe_text.encode("utf-8")).hexdigest()
        stream = ref["name"].removesuffix(".txt")
        artifact_name = (
            f"remote-{operation_id[:16]}-{stream}-{safe_digest[:12]}.txt"
        )
        rule_counts = Counter(item.rule for item in redaction.records)
        record = write_task_artifact_text(
            drive_root,
            task_id,
            artifact_name,
            safe_text,
            kind="remote_process_output",
            metadata={
                "source_sha256": ref["sha256"],
                "source_size": ref["size"],
                "stream": stream,
                "redacted": bool(redaction.records),
                "redaction_count": len(redaction.records),
                "redaction_rules": dict(sorted(rule_counts.items())),
                "invalid_utf8_replaced": invalid_utf8_replaced,
                "remote_truncated": ref["truncated"],
            },
        )
        imported_refs.append(
            _safe_remote_artifact_ref(
                record,
                display_name=ref["name"],
                artifact_name=artifact_name,
                mime="text/plain; charset=utf-8",
                source_sha256=ref["sha256"],
                source_size=ref["size"],
                redacted=bool(redaction.records),
                extra={"truncated": ref["truncated"]},
            )
        )
    for ref in declared_output_refs:
        raw = blobs.get(ref["blob_id"])
        if not isinstance(raw, bytes):
            raise RuntimeError(f"Home import omitted remote output {ref['name']}")
        if len(raw) != ref["size"] or sha256(raw).hexdigest() != ref["blob_id"]:
            raise RuntimeError(f"Home import could not reverify remote output {ref['name']}")
        safe_source_name = pathlib.PurePosixPath(ref["name"]).name or "output.bin"
        suffix = pathlib.PurePosixPath(safe_source_name).suffix[:20]
        artifact_name = (
            f"remote-{operation_id[:16]}-output-{ref['sha256'][:12]}{suffix}"
        )
        record = write_task_artifact_bytes(
            drive_root,
            task_id,
            artifact_name,
            raw,
            kind="process_output",
            metadata={
                "source_sha256": ref["sha256"],
                "source_size": ref["size"],
                "remote_declared_as": ref["declared_as"],
                "remote_member_path": ref["member_path"],
            },
        )
        imported_refs.append(
            _safe_remote_artifact_ref(
                record,
                display_name=ref["name"],
                artifact_name=artifact_name,
                mime="application/octet-stream",
                source_sha256=ref["sha256"],
                source_size=ref["size"],
                redacted=False,
                extra={
                    "declared_as": ref["declared_as"],
                    "member_path": ref["member_path"],
                },
            )
        )

    source_artifacts: list[dict[str, Any]] = []
    omitted_artifacts = 0
    for item in list(source.get("artifacts") or []):
        if (
            not isinstance(item, Mapping)
            or str(item.get("name") or "")
            in _REMOTE_PROCESS_STREAM_NAMES | {"operation-envelope.json"}
            or item.get("kind") == "declared_output"
        ):
            continue
        row = dict(item)
        try:
            encoded = canonical_json(row)
        except (TypeError, ValueError):
            encoded = b""
        if encoded and len(encoded) <= _REMOTE_HOME_TRACE_VALUE_BYTES:
            source_artifacts.append(row)
        else:
            omitted_artifacts += 1
    keep_count = max(0, _REMOTE_HOME_ARTIFACT_LIMIT - len(imported_refs))
    artifacts = source_artifacts[:keep_count] + imported_refs
    text = str(source.get("text") or "")
    if len(text) > _REMOTE_MODEL_PREVIEW_CHARS:
        text = (
            text[:_REMOTE_MODEL_PREVIEW_CHARS]
            + "\n… remote result preview bounded; full redacted output is in task artifacts"
        )
    trace = _bounded_remote_trace(
        source.get("trace"),
        full_envelope_ref=full_envelope_ref,
    )
    trace.pop("externalized_result", None)
    trace.pop("output_blobs", None)
    omitted_artifacts += max(0, len(source_artifacts) - keep_count)
    if omitted_artifacts:
        trace["externalized_artifacts_omitted"] = omitted_artifacts
        if full_envelope_ref:
            trace["externalized_artifacts_full_ref"] = dict(full_envelope_ref)
    process_imports = [
        item
        for item in imported_refs
        if str(item.get("name") or "") in _REMOTE_PROCESS_STREAM_NAMES
    ]
    if process_imports:
        trace["remote_process_outputs"] = process_imports
    result = {
        "text": text,
        "diagnostic": (
            dict(source["diagnostic"])
            if isinstance(source.get("diagnostic"), Mapping)
            else None
        ),
        "process": (
            dict(source["process"])
            if isinstance(source.get("process"), Mapping)
            else None
        ),
        "artifacts": artifacts,
        "trace": trace,
    }
    manifest_ref = write_call_manifest(
        drive_root,
        task_id=task_id,
        call_id=f"remote_result_{operation_id}",
        manifest={
            "call_type": "remote_result_import",
            "operation_id": operation_id,
            "full_payload_redacted": True,
            "artifacts": imported_refs,
            "result": result,
        },
    )
    trace["observability_ref"] = {
        "call_id": manifest_ref["call_id"],
        "sha256": manifest_ref["sha256"],
    }
    return result


def build_deliverable_manifest(
    workspace_root: pathlib.Path,
    task_id: str,
    project_id: str,
) -> dict[str, Any]:
    """Bounded, symlink-safe content inventory for a genesis workspace."""

    contents: list[dict[str, Any]] = []
    count = 0
    truncated = False
    for root, dirs, files in os.walk(workspace_root):
        dirs[:] = [name for name in dirs if name not in _DELIVERABLE_EXCLUDED_DIRS]
        for name in sorted(files):
            if count >= _DELIVERABLE_MANIFEST_FILE_CAP:
                truncated = True
                break
            path = pathlib.Path(root) / name
            if path.is_symlink():
                contents.append(
                    {
                        "rel": str(path.relative_to(workspace_root)),
                        "symlink": True,
                        "sha256": "",
                    }
                )
                count += 1
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            row: dict[str, Any] = {
                "rel": str(path.relative_to(workspace_root)),
                "size": size,
            }
            if size > _DELIVERABLE_MANIFEST_HASH_BYTE_CAP:
                row["sha256"] = ""
                row["hash_skipped"] = "size_over_cap"
            else:
                try:
                    digest = sha256()
                    with path.open("rb") as handle:
                        for chunk in iter(
                            lambda: handle.read(_DELIVERABLE_MANIFEST_HASH_CHUNK),
                            b"",
                        ):
                            digest.update(chunk)
                    row["sha256"] = digest.hexdigest()
                except OSError:
                    continue
            contents.append(row)
            count += 1
        if truncated:
            break
    return {
        "schema_version": 1,
        "task_id": task_id,
        "project_id": project_id,
        "project_root": str(workspace_root),
        "created_at": utc_now_iso(),
        "file_count": count,
        "truncated": truncated,
        "contents": contents,
    }


def _expected_git_base(task: dict[str, Any]) -> tuple[str, bool]:
    constraint = (
        task.get("task_constraint")
        if isinstance(task.get("task_constraint"), dict)
        else {}
    )
    metadata = task.get("metadata") if isinstance(task.get("metadata"), dict) else {}
    if not constraint and isinstance(metadata.get("task_constraint"), dict):
        constraint = metadata["task_constraint"]
    if str(constraint.get("mode") or "") == "acting_subagent":
        base = str(constraint.get("base_sha") or "").strip()
        if base:
            return base, True
    preflight = (
        metadata.get("workspace_preflight")
        if isinstance(metadata.get("workspace_preflight"), dict)
        else {}
    )
    git = preflight.get("git") if isinstance(preflight.get("git"), dict) else {}
    if "head_present" not in git and "head" not in git:
        raise RuntimeError(
            "remote admission omitted the Git base required for patch finalization"
        )
    head = str(git.get("head") or "")
    present = bool(git.get("head_present", bool(head)))
    if present and not head:
        raise RuntimeError("remote admission Git base is internally inconsistent")
    return head, present


def write_remote_workspace_patch_artifacts(
    task: dict[str, Any],
    artifact_dir: pathlib.Path,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Capture a remote patch natively and import its verified blob to Home."""

    from ouroboros.remote_workspace import get_remote_workspace_service
    from ouroboros.workspace_executor import execute_remote_system_operation

    workspace_ref = workspace_ref_for(task)
    if workspace_ref is None or workspace_ref["kind"] != "ssh":
        raise ValueError("remote patch export requires a sealed SSH workspace")
    artifact_dir.mkdir(parents=True, exist_ok=True)
    expected_head, expected_head_present = _expected_git_base(task)
    from ouroboros.artifacts import read_task_scratch_fingerprints

    task_id = str(task.get("id") or "")
    metadata = task.get("metadata") if isinstance(task.get("metadata"), dict) else {}
    raw_budget_root = str(
        task.get("budget_drive_root") or metadata.get("budget_drive_root") or ""
    )
    remote_root = str(workspace_ref["remote_root"]).rstrip("/")
    scratch_fingerprints: dict[str, str] = {}
    if task_id and raw_budget_root:
        for raw_path, digest in read_task_scratch_fingerprints(
            pathlib.Path(raw_budget_root),
            task_id,
        ).items():
            normalized = str(raw_path).replace("\\", "/")
            if normalized.startswith(remote_root + "/"):
                scratch_fingerprints[
                    normalized[len(remote_root) + 1 :]
                ] = str(digest)
    envelope = execute_remote_system_operation(
        task,
        "vcs_diff",
        {
            "artifact_export": True,
            "expected_head": expected_head,
            "expected_head_present": expected_head_present,
            "expected_admission_known": True,
            "scratch_fingerprints": scratch_fingerprints,
        },
    )
    export = (
        envelope.trace.get("patch_export")
        if isinstance(envelope.trace, dict)
        else None
    )
    if not isinstance(export, dict):
        raise RuntimeError("remote patch export omitted typed metadata")
    status = str(export.get("status") or ARTIFACT_STATUS_FAILED)
    manifest_path = artifact_dir / "workspace_patch.json"
    patch_path = artifact_dir / "workspace.patch"
    errors: list[dict[str, Any]] = []
    if status == ARTIFACT_STATUS_FAILED:
        errors.append(
            {
                "type": "remote_patch_export_failed",
                "message": str(envelope.text or "remote patch export failed"),
                "sensitive_blocked": list(export.get("sensitive_blocked") or []),
                "protected_blocked": list(export.get("protected_blocked") or []),
            }
        )
    patch_artifact = next(
        (
            dict(item)
            for item in envelope.artifacts
            if isinstance(item, dict) and item.get("name") == "workspace.patch"
        ),
        None,
    )
    digest = str(export.get("sha256") or "")
    size = int(export.get("patch_size") or 0)
    if status == ARTIFACT_STATUS_READY_WITH_CHANGES:
        if (
            patch_artifact is None
            or str(patch_artifact.get("blob_id") or "") != digest
            or int(patch_artifact.get("size") or -1) != size
        ):
            raise RuntimeError("remote patch blob declaration is inconsistent")
        data = get_remote_workspace_service().fetch_blob(
            workspace_ref,
            digest,
            max_bytes=size,
            task_id=str(task.get("id") or task.get("task_id") or ""),
        )
        if len(data) != size or sha256(data).hexdigest() != digest:
            raise RuntimeError("remote patch blob failed Home integrity verification")
        patch_path.write_bytes(data)
    else:
        patch_path.unlink(missing_ok=True)

    manifest = {
        "schema_version": 1,
        "created_at": utc_now_iso(),
        "status": status,
        "workspace_root": str(workspace_ref["remote_root"]),
        "patch_name": "workspace.patch",
        "manifest_name": "workspace_patch.json",
        "base_ref": str(export.get("base_ref") or ""),
        "base_head": str(export.get("base_head") or ""),
        "base_is_empty_tree": bool(export.get("base_is_empty_tree")),
        "current_head": str(export.get("current_head") or ""),
        "patch_size": size if status == ARTIFACT_STATUS_READY_WITH_CHANGES else 0,
        "sha256": digest if status == ARTIFACT_STATUS_READY_WITH_CHANGES else "",
        "diffstat": "",
        "counts": {
            "tracked_changed": len(export.get("tracked_changed") or []),
            "tracked_excluded": 0,
            "untracked_included": len(export.get("untracked_included") or []),
            "untracked_excluded": 0,
            "sensitive_blocked": len(export.get("sensitive_blocked") or []),
        },
        "tracked_changed": list(export.get("tracked_changed") or []),
        "tracked_excluded": [],
        "untracked_included": list(export.get("untracked_included") or []),
        "untracked_excluded": [],
        "sensitive_blocked": list(export.get("sensitive_blocked") or []),
        "exclude_rules_version": _PATCH_EXCLUDE_RULES_VERSION,
        "snapshot_fingerprint": str(export.get("snapshot_fingerprint") or ""),
        "diagnostics": [],
        "errors": errors,
    }
    atomic_write_json(manifest_path, manifest, trailing_newline=True)
    artifacts = [
        {
            "kind": "workspace_patch_manifest",
            "name": "workspace_patch.json",
            "path": str(manifest_path),
            "size": manifest_path.stat().st_size,
            "workspace_root": str(workspace_ref["remote_root"]),
            "snapshot_fingerprint": manifest["snapshot_fingerprint"],
        }
    ]
    if status == ARTIFACT_STATUS_READY_WITH_CHANGES:
        artifacts.insert(
            0,
            {
                "kind": "workspace_patch",
                "name": "workspace.patch",
                "path": str(patch_path),
                "size": size,
                "sha256": digest,
                "workspace_root": str(workspace_ref["remote_root"]),
                "snapshot_fingerprint": manifest["snapshot_fingerprint"],
            },
        )
    return artifacts, manifest


def write_deliverable_manifest_artifact(
    *,
    task: dict[str, Any],
    task_id: str,
    artifact_dir: pathlib.Path,
    workspace_root: pathlib.Path | None,
    remote: bool,
    build_manifest: Callable[[pathlib.Path, str, str], dict[str, Any]],
) -> tuple[dict[str, Any], bool]:
    """Materialize only when remote, then write one Home deliverable manifest."""

    snapshot = None
    try:
        root = workspace_root
        display_root = str(workspace_root or "")
        if remote:
            from ouroboros.workspace_executor import (
                materialize_remote_workspace_snapshot,
            )

            snapshot = materialize_remote_workspace_snapshot(task)
            root = snapshot.root
            ref = workspace_ref_for(task) or {}
            display_root = str(ref.get("remote_root") or "")
        if root is None or not root.is_dir():
            raise FileNotFoundError("workspace deliverable root is unavailable")
        manifest = build_manifest(
            root,
            task_id,
            str(task.get("project_id") or ""),
        )
        manifest["workspace_root"] = display_root
        if snapshot is not None:
            omissions = [
                dict(row)
                for row in list(
                    snapshot.manifest.get("policy_exclusions") or []
                )[:100]
                if isinstance(row, dict)
            ]
            manifest["source_snapshot_scope"] = str(
                snapshot.manifest.get("policy_scope") or "full"
            )
            manifest["policy_excluded_count"] = int(
                snapshot.manifest.get("policy_excluded_count") or 0
            )
            manifest["policy_exclusions"] = omissions
        path = artifact_dir / "deliverable_manifest.json"
        atomic_write_json(path, manifest, trailing_newline=True)
        return (
            {
                "kind": "deliverable_manifest",
                "name": "deliverable_manifest.json",
                "path": str(path),
                "size": path.stat().st_size,
                "file_count": int(manifest.get("file_count") or 0),
                "truncated": bool(manifest.get("truncated")),
                "workspace_root": display_root,
            },
            bool(manifest.get("truncated")),
        )
    finally:
        if snapshot is not None:
            snapshot.close()
