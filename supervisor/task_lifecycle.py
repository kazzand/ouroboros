"""Queue-owned acceptance, cancellation, and replay-safe resume transitions.

This module is a code boundary only: ``supervisor.queue`` remains the single
state authority and every mutation still runs under its existing process lock.
Imports of the queue are intentionally lazy so the public queue API can re-export
these helpers without creating an import cycle.
"""

from __future__ import annotations

import json
import pathlib
import threading
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

from ouroboros.utils import utc_now_iso

_PROJECT_DELETE_WORKERS_LOCK = threading.Lock()
_PROJECT_DELETE_WORKERS: set[tuple[str, str]] = set()
BUDGET_ROOT_FENCES: Dict[str, Dict[str, Any]] = {}
REMOTE_ADMISSIONS: Dict[str, Dict[str, Any]] = {}
_ADMISSION_COMPLETION_FIELDS = frozenset({"metadata", "attachments"})
_ADMISSION_METADATA_FIELDS = frozenset({
    "_sealed_workspace_ref",
    "executor_ref",
    "_remote_admission_evidence",
    "_remote_attachment_manifest",
})


def apply_budget_root_admission_fence(task: Dict[str, Any], root_task_id: str) -> bool:
    """Reject new work while a root is explicitly budget-paused.

    The monetary authority remains the physical-attempt ledger.  This marker is
    only an admission latch, preventing a budget increase from silently resuming
    a root after one of its dispatches was refused.
    """
    fence = BUDGET_ROOT_FENCES.get(str(root_task_id or ""))
    if not isinstance(fence, dict) or str(fence.get("status") or "") not in {
        "active", "paused",
    }:
        return False
    task["_admission_blocked"] = "root_budget_fence"
    task["_budget_root_task_id"] = root_task_id
    task["_budget_fence_id"] = str(fence.get("fence_id") or "")
    return True


def restore_queue_fences(
    raw_acceptance: Any, raw_budget: Any,
) -> tuple[set[str], bool, bool]:
    """Validate snapshot fences and restore the small root-budget admission map."""
    malformed_acceptance = not isinstance(raw_acceptance, list)
    fenced_roots: set[str] = set()
    if not malformed_acceptance:
        for fence in raw_acceptance:
            if not isinstance(fence, dict):
                malformed_acceptance = True
                break
            status = str(fence.get("status") or "")
            root_id = str(fence.get("root_task_id") or "")
            if status in {"active", "sealed"}:
                if not root_id:
                    malformed_acceptance = True
                    break
                fenced_roots.add(root_id)
    malformed_budget = not isinstance(raw_budget, list)
    restored: Dict[str, Dict[str, Any]] = {}
    if not malformed_budget:
        for fence in raw_budget:
            if not isinstance(fence, dict):
                malformed_budget = True
                break
            root_id = str(fence.get("root_task_id") or "").strip()
            fence_id = str(fence.get("fence_id") or "").strip()
            status = str(fence.get("status") or "")
            if status in {"active", "paused"}:
                if not root_id or not fence_id:
                    malformed_budget = True
                    break
                # Read old v6.64 candidates, but deliberately discard their
                # synchronized subtree lists and replay classification.  One
                # durable marker is the complete admission state.
                restored[root_id] = {
                    "status": "paused",
                    "scope": "root",
                    "root_task_id": root_id,
                    "fence_id": fence_id,
                    "auto_resume": False,
                    "paused_at": str(fence.get("paused_at") or utc_now_iso()),
                }
    if not malformed_budget:
        BUDGET_ROOT_FENCES.clear()
        BUDGET_ROOT_FENCES.update(restored)
    return fenced_roots, malformed_acceptance, malformed_budget


def _queue_module():
    from supervisor import queue

    return queue


def parse_iso_to_ts(iso_ts: str) -> Optional[float]:
    """Parse an ISO timestamp for queue snapshot age checks."""

    from datetime import datetime, timezone

    text = str(iso_ts or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).timestamp()
    except Exception:
        return None


def apply_task_admission_fences_locked(
    task: Dict[str, Any],
    *,
    restoring_snapshot: bool = False,
) -> bool:
    """Apply the one queue-owned admission policy to runnable and requested work."""

    q = _queue_module()
    project_id = str(task.get("project_id") or "").strip()
    if project_id:
        try:
            from ouroboros.projects_registry import get_reserved_project

            project = get_reserved_project(q.DRIVE_ROOT, project_id)
            lifecycle = str((project or {}).get("lifecycle") or "active")
            if project is not None and lifecycle != "active":
                task.update(
                    _admission_blocked="project_routing_fence",
                    _project_lifecycle=lifecycle,
                    _project_id=project_id,
                )
                return True
        except Exception:
            q.log.warning("Project admission check failed for %s", project_id, exc_info=True)
            task.update(
                _admission_blocked="project_routing_fence_lookup_failed",
                _project_id=project_id,
            )
            return True
    root_id = str(task.get("root_task_id") or "").strip()
    if root_id and not restoring_snapshot and apply_budget_root_admission_fence(task, root_id):
        return True
    fence = q.ACCEPTANCE_FENCES.get(root_id) if root_id else None
    if isinstance(fence, dict) and str(fence.get("status") or "") in {"active", "sealed"}:
        task.update(
            _admission_blocked="task_acceptance_fence",
            _acceptance_fence_token=str(fence.get("token") or ""),
            _acceptance_fence_status=str(fence.get("status") or "active"),
        )
        return True
    return False


def _task_result_fields(task: Dict[str, Any]) -> Dict[str, Any]:
    return {
        key: value
        for key, value in task.items()
        if key not in {"id", "task_id", "status", "updated_at", "ts"}
    }


def _durable_copy(value: Any) -> Any:
    """Deep-copy through the same JSON boundary used by queue persistence."""

    try:
        return json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"requested admission state must be JSON-serializable: {exc}") from exc


def _merge_admission_completion(
    task: Dict[str, Any],
    projection: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Merge only broker-attested execution facts, never routing authority."""

    if not projection:
        return _durable_copy(task)
    if not isinstance(projection, dict):
        raise ValueError("admission completion projection must be an object")
    unknown = set(projection) - _ADMISSION_COMPLETION_FIELDS
    if unknown:
        raise ValueError(f"admission completion cannot replace task authority: {sorted(unknown)}")
    result = _durable_copy(task)
    if "attachments" in projection:
        if not isinstance(projection["attachments"], list):
            raise ValueError("admission completion attachments must be a list")
        attachments = _durable_copy(projection["attachments"])
        result["attachments"] = attachments
        result["attachment_images"] = [
            item
            for item in attachments
            if isinstance(item, dict) and item.get("is_image")
        ]
        from ouroboros.artifacts import render_task_attachment_lines

        rendered = render_task_attachment_lines(attachments)
        text = str(result.get("text") or "")
        begin = text.rfind("[ATTACHMENTS]")
        end = text.find("[END_ATTACHMENTS]", begin) if begin >= 0 else -1
        if begin >= 0 and end >= begin:
            result["text"] = (
                text[:begin]
                + f"[ATTACHMENTS]\n{rendered}\n[END_ATTACHMENTS]"
                + text[end + len("[END_ATTACHMENTS]") :]
            )
    if "metadata" in projection:
        metadata = projection["metadata"]
        if not isinstance(metadata, dict):
            raise ValueError("admission completion metadata must be an object")
        unknown_metadata = set(metadata) - _ADMISSION_METADATA_FIELDS
        if unknown_metadata:
            raise ValueError(
                "admission completion metadata contains non-execution authority: "
                f"{sorted(unknown_metadata)}"
            )
        current = result.get("metadata") if isinstance(result.get("metadata"), dict) else {}
        result["metadata"] = {**current, **_durable_copy(metadata)}
    return result


def register_requested_admission(
    task: Dict[str, Any],
    *,
    cancel: Optional[Callable[[], Any]] = None,
    recovered: bool = False,
    admission_id: str = "",
    _persist_snapshot: bool = True,
) -> Dict[str, Any]:
    """Register one asynchronous SSH admission before it can become runnable."""

    q = _queue_module()
    try:
        candidate = _durable_copy(task)
    except ValueError as exc:
        return {"ok": False, "status": "error", "error": str(exc)}
    task_id = str(candidate.get("id") or candidate.get("task_id") or "").strip()
    if not task_id:
        return {"ok": False, "status": "error", "error": "missing_task_id"}
    candidate["id"] = task_id
    q.attach_task_contract(candidate)
    admission_id = str(admission_id or uuid.uuid4().hex).strip()
    if (
        not admission_id
        or len(admission_id) > 128
        or any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-" for char in admission_id)
    ):
        return {"ok": False, "status": "error", "error": "invalid_admission_id"}
    with q._queue_lock:
        existing = REMOTE_ADMISSIONS.get(task_id)
        if isinstance(existing, dict):
            if cancel is not None and existing.get("_cancel") is None:
                existing["_cancel"] = cancel
                existing["state"] = "connecting"
            return {
                "ok": True,
                "status": str(existing.get("state") or "requested"),
                "task_id": task_id,
                "admission_id": str(existing.get("admission_id") or ""),
                "duplicate": True,
            }
        if any(str(item.get("id") or "") == task_id for item in q.PENDING) or task_id in q.RUNNING:
            return {
                "ok": False,
                "status": "conflict",
                "task_id": task_id,
                "error": "task_already_runnable",
            }
        try:
            from ouroboros.task_results import (
                _TRULY_TERMINAL_STATUSES,
                STATUS_CANCEL_REQUESTED,
                load_task_result,
            )

            prior = load_task_result(
                pathlib.Path(candidate.get("budget_drive_root") or q.DRIVE_ROOT),
                task_id,
            ) or {}
            prior_status = str(prior.get("status") or "")
            if prior_status in _TRULY_TERMINAL_STATUSES or prior_status == STATUS_CANCEL_REQUESTED:
                return {
                    "ok": False,
                    "status": "conflict",
                    "task_id": task_id,
                    "error": "task_id_is_terminal",
                }
        except Exception as exc:
            return {
                "ok": False,
                "status": "error",
                "task_id": task_id,
                "error": f"task_status_unavailable: {type(exc).__name__}: {exc}",
            }
        if apply_task_admission_fences_locked(
            candidate,
            restoring_snapshot=recovered,
        ):
            return {
                "ok": False,
                "status": "blocked",
                "task_id": task_id,
                "reason_code": str(candidate.get("_admission_blocked") or "admission_blocked"),
                "task": candidate,
            }
        REMOTE_ADMISSIONS[task_id] = {
            "task": candidate,
            "admission_id": admission_id,
            "state": "recovery_required" if recovered else ("connecting" if cancel else "requested"),
            "requested_at": utc_now_iso(),
            "_cancel": cancel,
        }
    with q._queue_lock:
        try:
            from ouroboros.task_results import STATUS_REQUESTED, write_task_result

            written = write_task_result(
                pathlib.Path(candidate.get("budget_drive_root") or q.DRIVE_ROOT),
                task_id,
                STATUS_REQUESTED,
                **_task_result_fields(candidate),
                remote_admission={
                    "admission_id": admission_id,
                    "state": "recovery_required" if recovered else "requested",
                },
                result=(
                    "Remote workspace admission requires recovery after restart."
                    if recovered
                    else "Remote workspace admission requested."
                ),
            )
            if str(written.get("status") or "") != STATUS_REQUESTED:
                REMOTE_ADMISSIONS.pop(task_id, None)
                return {
                    "ok": False,
                    "status": "stale",
                    "task_id": task_id,
                    "error": "task_status_rejected_requested_transition",
                }
            if _persist_snapshot:
                q.persist_queue_snapshot(reason="remote_admission_requested", required=True)
        except Exception as exc:
            current = REMOTE_ADMISSIONS.get(task_id)
            if isinstance(current, dict) and current.get("admission_id") == admission_id:
                REMOTE_ADMISSIONS.pop(task_id, None)
            try:
                from ouroboros.task_results import STATUS_FAILED, write_task_result

                write_task_result(
                    pathlib.Path(candidate.get("budget_drive_root") or q.DRIVE_ROOT),
                    task_id,
                    STATUS_FAILED,
                    reason_code="remote_admission_persistence_failed",
                    result=f"Remote admission could not be persisted: {type(exc).__name__}: {exc}",
                )
            except Exception as exc:
                q.log.exception("Failed to terminalize unpersisted admission %s", task_id)
            return {
                "ok": False,
                "status": "error",
                "task_id": task_id,
                "error": "remote_admission_persistence_failed",
            }
    return {
        "ok": True,
        "status": str(REMOTE_ADMISSIONS.get(task_id, {}).get("state") or "requested"),
        "task_id": task_id,
        "admission_id": admission_id,
    }


def list_requested_admissions(
    *,
    recovery_required_only: bool = False,
) -> List[Dict[str, Any]]:
    """Return a serialization-safe snapshot for broker recovery and diagnostics."""

    q = _queue_module()
    with q._queue_lock:
        rows = []
        for task_id, row in REMOTE_ADMISSIONS.items():
            if not isinstance(row, dict) or not isinstance(row.get("task"), dict):
                continue
            state = str(row.get("state") or "requested")
            if recovery_required_only and state != "recovery_required":
                continue
            rows.append(
                {
                    "task_id": task_id,
                    "admission_id": str(row.get("admission_id") or ""),
                    "state": state,
                    "requested_at": str(row.get("requested_at") or ""),
                    "task": _durable_copy(row["task"]),
                }
            )
        return rows


def requested_admission_snapshot() -> List[Dict[str, Any]]:
    """Return only the durable portion stored in the queue snapshot."""

    return [
        {
            "id": row["task_id"],
            "admission_id": row["admission_id"],
            "state": row["state"],
            "requested_at": row["requested_at"],
            "task": row["task"],
        }
        for row in list_requested_admissions()
    ]


def restore_requested_admissions(raw_rows: Any) -> tuple[int, List[str]]:
    """Restore only durable requested state; the broker must rebind each future."""

    if not isinstance(raw_rows, list):
        return 0, ["<requested_admissions>"]
    q = _queue_module()
    restored = 0
    malformed: List[str] = []
    for raw in raw_rows:
        task = raw.get("task") if isinstance(raw, dict) else None
        task_id = (
            str((task or {}).get("id") or (task or {}).get("task_id") or raw.get("id") or "").strip()
            if isinstance(raw, dict)
            else ""
        )
        if not isinstance(task, dict) or not task_id:
            malformed.append(task_id or "<unknown>")
            continue
        try:
            from ouroboros.task_results import (
                _TRULY_TERMINAL_STATUSES,
                STATUS_CANCEL_REQUESTED,
                load_task_result,
            )

            existing = load_task_result(
                pathlib.Path(task.get("budget_drive_root") or q.DRIVE_ROOT),
                task_id,
            ) or {}
            status = str(existing.get("status") or "")
            if status in _TRULY_TERMINAL_STATUSES or status == STATUS_CANCEL_REQUESTED:
                continue
        except Exception:
            q.log.warning(
                "Requested-admission restore status lookup failed for %s",
                task_id,
                exc_info=True,
            )
            malformed.append(task_id)
            continue
        recovered_admission_id = (
            str(raw.get("admission_id") or "").strip()
            if isinstance(raw, dict)
            else ""
        )
        if not recovered_admission_id:
            malformed.append(task_id)
            continue
        result = register_requested_admission(
            task,
            recovered=True,
            admission_id=recovered_admission_id,
            _persist_snapshot=False,
        )
        if result.get("ok") and not result.get("duplicate"):
            restored += 1
        elif result.get("error") == "task_already_runnable":
            continue
        elif not result.get("ok"):
            malformed.append(task_id)
            try:
                from ouroboros.task_results import STATUS_CANCELLED, write_task_result

                write_task_result(
                    pathlib.Path(task.get("budget_drive_root") or q.DRIVE_ROOT),
                    task_id,
                    STATUS_CANCELLED,
                    _explicit_cancellation=True,
                    **_task_result_fields(task),
                    reason_code=str(result.get("reason_code") or "restart_admission_blocked"),
                    result="Remote admission was not restored because its lifecycle fence is closed.",
                )
            except Exception:
                q.log.warning(
                    "Failed to terminalize blocked recovered admission %s",
                    task_id,
                    exc_info=True,
                )
    if malformed:
        q.append_jsonl(
            pathlib.Path(q.DRIVE_ROOT) / "logs" / "supervisor.jsonl",
            {
                "ts": utc_now_iso(),
                "type": "queue_restore_invalid_requested_admissions",
                "action": "fail_closed_drop_invalid_rows",
                "invalid_task_ids": malformed,
            },
        )
    return restored, malformed


def restore_requested_admissions_from_results() -> int:
    """Recover marked remote admissions when the queue snapshot is absent/corrupt."""

    q = _queue_module()
    try:
        from ouroboros.task_results import (
            STATUS_REQUESTED,
            list_task_results,
        )

        rows = []
        for result in list_task_results(q.DRIVE_ROOT, statuses=[STATUS_REQUESTED]):
            marker = result.get("remote_admission")
            if not isinstance(marker, dict) or not str(marker.get("admission_id") or ""):
                continue
            task = {
                key: value
                for key, value in result.items()
                if key not in {
                    "remote_admission", "result", "status", "task_id",
                    "ts", "updated_at", "reason_code",
                }
            }
            task["id"] = str(result.get("task_id") or "")
            rows.append(
                {
                    "id": task["id"],
                    "admission_id": str(marker["admission_id"]),
                    "state": "recovery_required",
                    "requested_at": str(result.get("ts") or ""),
                    "task": task,
                }
            )
        restored, _malformed = restore_requested_admissions(rows)
        return restored
    except Exception:
        q.log.exception("Requested-admission task-result fallback failed")
        return 0


def recover_requested_after_snapshot_error(reason: str) -> int:
    q = _queue_module()
    restored = restore_requested_admissions_from_results()
    if restored:
        q.persist_queue_snapshot(reason=reason)
    return restored


def requested_admission_ids() -> set[str]:
    q = _queue_module()
    with q._queue_lock:
        return set(REMOTE_ADMISSIONS)


def terminalize_pending_after_invalid_acceptance_fences(
    snapshot_pending: List[Dict[str, Any]],
) -> List[str]:
    """Cancel pending rows except IDs recovered as non-runnable admissions."""

    q = _queue_module()
    recovered = requested_admission_ids()
    affected: List[str] = []
    try:
        from ouroboros.task_results import STATUS_CANCELLED, load_task_result, write_task_result

        for task in snapshot_pending:
            task_id = str(task.get("id") or "")
            if not task_id or task_id in recovered:
                continue
            affected.append(task_id)
            existing = load_task_result(q.DRIVE_ROOT, task_id) or {}
            write_task_result(
                q.DRIVE_ROOT,
                task_id,
                STATUS_CANCELLED,
                **q._cancel_result_fields(
                    task,
                    existing=existing,
                    result="Task was not restored because its acceptance-fence snapshot was invalid.",
                ),
            )
    except Exception:
        q.log.warning(
            "Failed to terminalize tasks from invalid acceptance-fence snapshot",
            exc_info=True,
        )
    return affected


def _rollback_admission_transition(
    q: Any,
    task_id: str,
    row: Dict[str, Any],
    *,
    reason: str,
) -> None:
    """Restore requested authority after a pre-commit completion failure."""

    q.PENDING[:] = [
        item for item in q.PENDING
        if str(item.get("id") or "") != task_id
    ]
    task = dict(row.get("task") or {})
    drive_root = pathlib.Path(task.get("budget_drive_root") or q.DRIVE_ROOT)
    try:
        from ouroboros.task_results import (
            STATUS_REQUESTED,
            load_task_result,
            write_task_result,
        )

        try:
            written = write_task_result(
                drive_root,
                task_id,
                STATUS_REQUESTED,
                **_task_result_fields(task),
                remote_admission={
                    "admission_id": str(row.get("admission_id") or ""),
                    "state": str(row.get("state") or "requested"),
                },
                reason_code="",
                result=f"Remote admission remains requested after transition rollback: {reason}",
            )
        except Exception:
            written = load_task_result(drive_root, task_id) or {}
        if str(written.get("status") or "") != STATUS_REQUESTED:
            q.persist_queue_snapshot(reason="remote_admission_terminal_cleanup")
            return
        REMOTE_ADMISSIONS[task_id] = row
        q.persist_queue_snapshot(reason="remote_admission_transition_rollback", required=True)
    except Exception:
        q.log.exception("Remote admission rollback persistence failed for %s", task_id)


def complete_requested_admission(
    task_id: str,
    *,
    admission_id: str,
    admitted_task: Optional[Dict[str, Any]] = None,
    error: str = "",
    reason_code: str = "remote_admission_failed",
) -> Dict[str, Any]:
    """Atomically terminalize or move one admitted task into PENDING."""

    q = _queue_module()
    task_id = str(task_id or "").strip()
    if not task_id:
        return {"ok": False, "status": "error", "error": "missing_task_id"}
    admission_id = str(admission_id or "").strip()
    if not admission_id:
        return {"ok": False, "status": "error", "error": "missing_admission_id"}
    with q._queue_lock:
        row = REMOTE_ADMISSIONS.get(task_id)
        if not isinstance(row, dict):
            if any(str(item.get("id") or "") == task_id for item in q.PENDING):
                return {"ok": False, "status": "stale", "task_id": task_id}
            return {"ok": False, "status": "stale", "task_id": task_id}
        if str(row.get("admission_id") or "") != admission_id:
            return {"ok": False, "status": "stale", "task_id": task_id}
        if (
            any(str(item.get("id") or "") == task_id for item in q.PENDING)
            or task_id in q.RUNNING
        ):
            return {"ok": False, "status": "stale", "task_id": task_id}
        try:
            task = _merge_admission_completion(dict(row.get("task") or {}), admitted_task)
        except ValueError as exc:
            return {
                "ok": False,
                "status": "error",
                "task_id": task_id,
                "error": str(exc),
            }
        task["id"] = task_id
        blocked = ""
        if not error:
            queued = q.enqueue_task(task)
            blocked = str(queued.get("_admission_blocked") or "")
            if not blocked:
                task = queued
        drive_root = pathlib.Path(task.get("budget_drive_root") or q.DRIVE_ROOT)
        if error or blocked:
            REMOTE_ADMISSIONS.pop(task_id, None)
            failure = str(error or f"Remote admission blocked: {blocked}")
            try:
                from ouroboros.task_results import STATUS_FAILED, write_task_result

                written = write_task_result(
                    drive_root,
                    task_id,
                    STATUS_FAILED,
                    **_task_result_fields(task),
                    reason_code=reason_code if error else blocked,
                    result=failure,
                )
                if str(written.get("status") or "") != STATUS_FAILED:
                    q.persist_queue_snapshot(reason="remote_admission_terminal_cleanup")
                    return {"ok": False, "status": "stale", "task_id": task_id}
            except Exception as exc:
                _rollback_admission_transition(
                    q,
                    task_id,
                    row,
                    reason=f"{type(exc).__name__}: {exc}",
                )
                return {
                    "ok": False,
                    "status": "error",
                    "task_id": task_id,
                    "reason_code": "remote_admission_persistence_failed",
                }
            try:
                q.persist_queue_snapshot(reason="remote_admission_failed", required=True)
            except Exception:
                q.log.exception("Failed to persist terminal remote admission %s", task_id)
                return {
                    "ok": False,
                    "status": "failed",
                    "task_id": task_id,
                    "reason_code": "remote_admission_persistence_failed",
                    "snapshot_persistence_degraded": True,
                }
            return {
                "ok": False,
                "status": "failed",
                "task_id": task_id,
                "reason_code": reason_code if error else blocked,
            }
        REMOTE_ADMISSIONS.pop(task_id, None)
        try:
            from ouroboros.task_results import STATUS_SCHEDULED, write_task_result

            written = write_task_result(
                drive_root,
                task_id,
                STATUS_SCHEDULED,
                **_task_result_fields(task),
                result="Remote workspace admitted and queued.",
            )
            if str(written.get("status") or "") != STATUS_SCHEDULED:
                raise RuntimeError("scheduled task-result transition was rejected")
            q.persist_queue_snapshot(reason="remote_admission_scheduled", required=True)
        except Exception as exc:
            _rollback_admission_transition(
                q,
                task_id,
                row,
                reason=f"{type(exc).__name__}: {exc}",
            )
            return {
                "ok": False,
                "status": "error",
                "task_id": task_id,
                "reason_code": "remote_admission_persistence_failed",
            }
    return {"ok": True, "status": "scheduled", "task_id": task_id}


def _cancel_requested_admission(task_id: str) -> bool:
    q = _queue_module()
    with q._queue_lock:
        row = REMOTE_ADMISSIONS.get(task_id)
        if not isinstance(row, dict):
            return False
        task = _durable_copy(row.get("task") or {})
        try:
            from ouroboros.task_results import (
                STATUS_CANCEL_REQUESTED,
                STATUS_CANCELLED,
                write_task_result,
            )

            latched = write_task_result(
                pathlib.Path(task.get("budget_drive_root") or q.DRIVE_ROOT),
                task_id,
                STATUS_CANCEL_REQUESTED,
                _explicit_cancellation=True,
                **_task_result_fields(task),
                remote_admission={
                    "admission_id": str(row.get("admission_id") or ""),
                    "state": "cancel_requested",
                },
                result="Remote workspace admission cancellation requested.",
            )
            if str(latched.get("status") or "") not in {
                STATUS_CANCEL_REQUESTED,
                STATUS_CANCELLED,
            }:
                return False
            REMOTE_ADMISSIONS.pop(task_id, None)
            try:
                q.persist_queue_snapshot(reason="cancel_requested_admission", required=True)
            except Exception:
                q.log.exception(
                    "Requested-admission snapshot removal failed for %s; "
                    "durable cancel latch remains authoritative",
                    task_id,
                )
        except Exception:
            q.log.exception("Failed to latch requested-admission cancellation for %s", task_id)
            return False
    cancel = row.get("_cancel")
    if callable(cancel):
        threading.Thread(
            target=_run_admission_cancel_callback,
            args=(q, task_id, cancel),
            name=f"remote-admission-cancel-{task_id[:32]}",
            daemon=True,
        ).start()
    try:
        from ouroboros.task_results import STATUS_CANCELLED, load_task_result, write_task_result

        write_task_result(
            pathlib.Path(task.get("budget_drive_root") or q.DRIVE_ROOT),
            task_id,
            STATUS_CANCELLED,
            _explicit_cancellation=True,
            **_task_result_fields(task),
            **q._cancel_result_fields(
                task,
                existing=load_task_result(
                    pathlib.Path(task.get("budget_drive_root") or q.DRIVE_ROOT),
                    task_id,
                ) or {},
                result="Remote workspace admission cancelled before scheduling.",
            ),
        )
    except Exception:
        q.log.warning("Failed to persist requested-admission cancellation for %s", task_id, exc_info=True)
    return True


def _run_admission_cancel_callback(
    q: Any,
    task_id: str,
    cancel: Callable[[], Any],
) -> None:
    try:
        cancel()
    except Exception:
        q.log.warning("Requested-admission cancellation failed for %s", task_id, exc_info=True)


def record_scheduled_admission(
    task: Dict[str, Any], admitted: Any, record: Dict[str, Any],
) -> None:
    """Project a cron dispatch refusal into terminal task/schedule state."""
    q = _queue_module()
    block = (
        str(admitted.get("_admission_blocked") or "")
        if isinstance(admitted, dict)
        else ""
    )
    if not block:
        record["failure_count"] = int(record.get("failure_count") or 0)
        record["last_error"] = ""
        return
    detail = f"Scheduled task was not queued: {block}."
    try:
        from ouroboros.task_results import STATUS_FAILED, write_task_result

        write_task_result(
            q.DRIVE_ROOT,
            str(task["id"]),
            STATUS_FAILED,
            result=detail,
            reason_code=block,
            cost_usd=0.0,
        )
    except Exception:
        q.log.warning(
            "Failed to terminalize admission-blocked scheduled task %s",
            task.get("id"),
            exc_info=True,
        )
    record["failure_count"] = int(record.get("failure_count") or 0) + 1
    record["last_error"] = detail


def transition_acceptance_fence(
    *, action: str, token: str, root_task_id: str = "", task_id: str = "", outcome: str = "",
    expected_generation: Optional[int] = None,
) -> Dict[str, Any]:
    """Atomically open, inspect, release, or seal a root admission fence."""
    q = _queue_module()
    action = str(action or "").strip().lower()
    token = str(token or "").strip()
    root_task_id = str(root_task_id or task_id or "").strip()
    if not token or action not in {"begin", "inspect", "end"}:
        return {"ok": False, "status": "error", "error": "invalid acceptance fence event"}
    with q._queue_lock:
        if action == "begin":
            if not root_task_id:
                return {"ok": False, "status": "error", "error": "missing root_task_id"}
            existing = q.ACCEPTANCE_FENCES.get(root_task_id)
            if isinstance(existing, dict) and str(existing.get("token") or "") != token:
                return {
                    "ok": False,
                    "status": "error",
                    "error": f"acceptance fence already active for root {root_task_id}",
                }
            if isinstance(existing, dict):
                row = existing
            else:
                row = q.ACCEPTANCE_FENCES[root_task_id] = {
                    "token": token,
                    "root_task_id": root_task_id,
                    "task_id": str(task_id or root_task_id),
                    "status": "active",
                    "opened_at": utc_now_iso(),
                    "owner_message_generation": 0,
                }
            result = {
                "ok": True,
                "status": "active",
                "root_task_id": root_task_id,
                "token": token,
                "owner_message_generation": int(row.get("owner_message_generation") or 0),
                "queue_descendants": _live_descendants_locked(
                    q, root_task_id, exclude_task_id=str(task_id or root_task_id),
                ),
            }
        else:
            matched_root = next(
                (rid for rid, row in q.ACCEPTANCE_FENCES.items() if str(row.get("token") or "") == token),
                "",
            )
            if not matched_root:
                return {"ok": False, "status": "error", "error": "unknown acceptance fence token"}
            row = q.ACCEPTANCE_FENCES[matched_root]
            if action == "inspect":
                return {
                    "ok": True,
                    "status": str(row.get("status") or "active"),
                    "root_task_id": matched_root,
                    "token": token,
                    "owner_message_generation": int(row.get("owner_message_generation") or 0),
                    "queue_descendants": _live_descendants_locked(
                        q, matched_root, exclude_task_id=str(row.get("task_id") or matched_root),
                    ),
                }
            normalized_outcome = str(outcome or "").strip().lower()
            if normalized_outcome == "revision":
                q.ACCEPTANCE_FENCES.pop(matched_root, None)
                result = {
                    "ok": True,
                    "status": "released",
                    "root_task_id": matched_root,
                    "token": token,
                }
            elif (
                expected_generation is not None
                and int(row.get("owner_message_generation") or 0) != int(expected_generation)
            ):
                current_generation = int(row.get("owner_message_generation") or 0)
                q.ACCEPTANCE_FENCES.pop(matched_root, None)
                result = {
                    "ok": True,
                    "status": "released",
                    "root_task_id": matched_root,
                    "token": token,
                    "generation_mismatch": True,
                    "expected_generation": int(expected_generation),
                    "owner_message_generation": current_generation,
                }
            else:
                row["status"] = "sealed"
                row["outcome"] = normalized_outcome or "terminal"
                row["sealed_at"] = utc_now_iso()
                result = {
                    "ok": True,
                    "status": "sealed",
                    "root_task_id": matched_root,
                    "token": token,
                }
    q.persist_queue_snapshot(reason=f"acceptance_fence_{result['status']}")
    return result


def _live_descendants_locked(
    q: Any, root_task_id: str, *, exclude_task_id: str = "",
) -> List[Dict[str, str]]:
    """Return a compact descendant snapshot while the queue lock is held."""
    rows: List[Dict[str, str]] = []
    for task_id, admission in REMOTE_ADMISSIONS.items():
        task = admission.get("task") if isinstance(admission, dict) else None
        if (
            task_id
            and task_id != exclude_task_id
            and isinstance(task, dict)
            and q._is_descendant_of(task, root_task_id)
        ):
            rows.append(
                {
                    "task_id": task_id,
                    "status": "requested",
                    "source": "supervisor_queue",
                }
            )
    for task in q.PENDING:
        task_id = str(task.get("id") or "") if isinstance(task, dict) else ""
        if task_id and task_id != exclude_task_id and q._is_descendant_of(task, root_task_id):
            rows.append({"task_id": task_id, "status": "pending", "source": "supervisor_queue"})
    for task_id, meta in q.RUNNING.items():
        task = meta.get("task") if isinstance(meta, dict) else None
        if (
            task_id
            and str(task_id) != exclude_task_id
            and isinstance(task, dict)
            and q._is_descendant_of(task, root_task_id)
        ):
            rows.append({"task_id": str(task_id), "status": "running", "source": "supervisor_queue"})
    return rows


def clear_acceptance_fence_for_root(root_task_id: str) -> bool:
    """Release a terminal root's fence after its task_done is queue-visible."""
    q = _queue_module()
    root_task_id = str(root_task_id or "").strip()
    if not root_task_id:
        return False
    with q._queue_lock:
        return q.ACCEPTANCE_FENCES.pop(root_task_id, None) is not None


def finish_remote_task_lease(task: Dict[str, Any], task_id: str) -> None:
    """Best-effort remote cleanup shared by supervisor terminal paths."""

    q = _queue_module()
    try:
        from ouroboros.remote_workspace import finish_remote_task

        finish_remote_task(task, task_id)
    except Exception:
        q.log.warning(
            "Failed to cancel remote task lease for %s", task_id, exc_info=True
        )


def cancel_task_by_id(task_id: str, *, cascade: bool = False) -> bool:
    """Cancel a task and, when requested, its atomically captured live subtree."""
    q = _queue_module()
    task_id = str(task_id or "").strip()
    if not task_id:
        return False
    if not cascade:
        return _cancel_requested_admission(task_id) or q._cancel_task_by_id_single(task_id)
    with q._queue_lock:
        live: Dict[str, Dict[str, Any]] = {
            str(admission_id): dict(row["task"])
            for admission_id, row in REMOTE_ADMISSIONS.items()
            if isinstance(row, dict) and isinstance(row.get("task"), dict)
        }
        live.update({
            str(task["id"]): task
            for task in q.PENDING
            if isinstance(task, dict) and str(task.get("id") or "")
        })
        live.update({
            str(running_id): meta["task"]
            for running_id, meta in q.RUNNING.items()
            if isinstance(meta, dict) and isinstance(meta.get("task"), dict)
        })
        descendants: List[Tuple[int, str]] = []
        for live_id, task in live.items():
            if live_id == task_id:
                continue
            root_id = str(task.get("root_task_id") or "")
            current = task
            distance = 0
            seen: set[str] = set()
            reaches_target = root_id == task_id
            while isinstance(current, dict) and distance < 100:
                parent_id = str(current.get("parent_task_id") or "")
                if not parent_id or parent_id in seen:
                    break
                distance += 1
                if parent_id == task_id:
                    reaches_target = True
                    break
                seen.add(parent_id)
                current = live.get(parent_id)
            if reaches_target:
                try:
                    distance = max(distance, int(task.get("depth") or 0))
                except (TypeError, ValueError):
                    pass
                descendants.append((distance, live_id))
        cancel_order = [item[1] for item in sorted(descendants, reverse=True)] + [task_id]
    q.append_jsonl(
        pathlib.Path(q.DRIVE_ROOT) / "logs" / "supervisor.jsonl",
        {
            "ts": utc_now_iso(),
            "type": "task_cancel_subtree_snapshot",
            "root_task_id": task_id,
            "descendant_task_ids": cancel_order[:-1],
            "descendant_count": len(cancel_order) - 1,
        },
    )
    cancelled = False
    for live_id in cancel_order:
        cancelled = (
            _cancel_requested_admission(live_id)
            or q._cancel_task_by_id_single(live_id)
            or cancelled
        )
    return cancelled


def resume_budget_paused_task(task_id: str) -> Dict[str, Any]:
    """Explicitly resume one zero-dispatch task and, if needed, its root latch."""
    q = _queue_module()
    task_id = str(task_id or "").strip()
    if not task_id:
        return {"ok": False, "error": "missing_task_id"}
    with q._queue_lock:
        task = next((item for item in q.PENDING if str(item.get("id") or "") == task_id), None)
        if task is None:
            return {"ok": False, "error": "task_not_pending"}
        pause = task.get("_budget_pause") if isinstance(task.get("_budget_pause"), dict) else None
        if not pause:
            # A root marker blocks every already-pending sibling without
            # copying pause state onto each task.  An explicit resume request
            # may nominate any genuinely zero-dispatch member of that root.
            candidate_root = str(task.get("root_task_id") or task_id).strip()
            candidate_fence = q.BUDGET_ROOT_FENCES.get(candidate_root)
            if not isinstance(candidate_fence, dict):
                return {"ok": False, "error": "task_not_budget_paused"}
            pause = {
                **candidate_fence,
                "status": "paused_before_dispatch",
                "physical_calls": 0,
                "replay_safe": True,
                "resume_policy": "manual_same_generation",
            }
        root_scope = str(pause.get("scope") or "") == "root"
        root_task_id = str(pause.get("root_task_id") or "").strip()
        fence = q.BUDGET_ROOT_FENCES.get(root_task_id) if root_scope and root_task_id else None
        if root_scope and not isinstance(fence, dict):
            return {"ok": False, "error": "root_budget_fence_missing", "action": "cancel_or_new_run"}
        if root_scope and str(pause.get("fence_id") or "") != str(fence.get("fence_id") or ""):
            return {"ok": False, "error": "replay_unsafe", "action": "cancel_or_new_run"}
        def _pending_member_is_replay_safe(member: Dict[str, Any]) -> tuple[bool, str]:
            member_id = str(member.get("id") or "")
            cost_fields = q.reconstruct_task_cost(
                member_id,
                fields=True,
                drive_root=pathlib.Path(member.get("budget_drive_root") or q.DRIVE_ROOT),
            )
            if cost_fields.get("cost_accounting_status") != "available":
                return False, "accounting_unavailable"
            retry_lineage = bool(
                int(member.get("_attempt") or 1) > 1
                or member.get("original_task_id") or member.get("timeout_retry_from")
            )
            return bool(
                int(cost_fields.get("total_rounds") or 0) == 0
                and not bool(cost_fields.get("ledger_integrity_degraded"))
                and not retry_lineage
            ), "replay_unsafe"

        nominated_safe, nominated_error = _pending_member_is_replay_safe(task)
        nominated_safe = bool(
            nominated_safe
            and pause.get("replay_safe")
            and pause.get("physical_calls") == 0
        )
        if not nominated_safe:
            return {
                "ok": False,
                "error": nominated_error,
                "action": "cancel_or_new_run",
            }
        if root_scope:
            # Clearing one root latch makes every pending member assignable. Check
            # those members together under the existing queue lock; completed
            # historical siblings are deliberately irrelevant.
            unsafe_members: list[str] = []
            for member in q.PENDING:
                member_id = str(member.get("id") or "")
                member_root = str(member.get("root_task_id") or member_id)
                if member_root != root_task_id or member_id == task_id:
                    continue
                member_safe, _member_error = _pending_member_is_replay_safe(member)
                if not member_safe:
                    unsafe_members.append(member_id)
            if unsafe_members:
                return {
                    "ok": False,
                    "error": "root_replay_unsafe",
                    "unsafe_task_ids": unsafe_members,
                    "action": "cancel_or_new_run",
                }

        resumed_at = utc_now_iso()
        prior_pause = dict(pause)
        task.pop("_budget_pause", None)
        task["budget_resumed_at"] = resumed_at
        if root_scope:
            q.BUDGET_ROOT_FENCES.pop(root_task_id, None)
        q.persist_queue_snapshot(
            reason="budget_root_explicit_resume" if root_scope else "budget_pause_explicit_resume",
        )
    try:
        from ouroboros.task_results import STATUS_SCHEDULED, write_task_result

        write_task_result(
            pathlib.Path(task.get("budget_drive_root") or q.DRIVE_ROOT),
            task_id,
            STATUS_SCHEDULED,
            reason_code="",
            resource_limit={
                **prior_pause,
                "status": "resumed",
                "resumed_at": resumed_at,
                "auto_resume": False,
            },
        )
    except Exception:
        q.log.debug("Failed to project explicit budget resume for %s", task_id, exc_info=True)
    q.append_jsonl(
        q.DRIVE_ROOT / "logs" / "events.jsonl",
        {
            "ts": utc_now_iso(),
            "type": "budget_task_explicitly_resumed",
            "task_id": task_id,
            "root_task_id": root_task_id if root_scope else "",
            "same_generation": True,
        },
    )
    return {"ok": True, "task_id": task_id, "same_generation": True}


def _live_project_task_ids(drive_root: object, project_id: str) -> list[str]:
    """Snapshot requested/queued/running tasks associated with one fenced Project."""
    from ouroboros.projects_registry import project_task_bindings

    q = _queue_module()
    with q._queue_lock:
        rows = [
            dict(row["task"])
            for row in REMOTE_ADMISSIONS.values()
            if isinstance(row, dict) and isinstance(row.get("task"), dict)
        ]
        rows.extend(dict(task) for task in q.PENDING if isinstance(task, dict))
        rows.extend(
            dict(meta.get("task"))
            for meta in q.RUNNING.values()
            if isinstance(meta, dict) and isinstance(meta.get("task"), dict)
        )
    bindings = project_task_bindings(drive_root)
    associated: set[str] = set()
    by_id: dict[str, dict] = {}
    for task in rows:
        task_id = str(task.get("id") or task.get("task_id") or "").strip()
        if not task_id:
            continue
        by_id[task_id] = task
        lineage = (task_id, str(task.get("parent_task_id") or ""), str(task.get("root_task_id") or ""))
        if str(task.get("project_id") or "") == project_id or any(
            isinstance(bindings.get(candidate), dict)
            and str(bindings[candidate].get("project_id") or "") == project_id
            for candidate in lineage
            if candidate
        ):
            associated.add(task_id)
    changed = True
    while changed:
        changed = False
        for task_id, task in by_id.items():
            if task_id in associated:
                continue
            if (
                str(task.get("parent_task_id") or "") in associated
                or str(task.get("root_task_id") or "") in associated
            ):
                associated.add(task_id)
                changed = True
    return sorted(
        associated,
        key=lambda task_id: bool(str(by_id.get(task_id, {}).get("parent_task_id") or "")),
        reverse=True,
    )


def _broadcast_projects_changed(project_id: str, chat_id: Any) -> None:
    try:
        from supervisor.message_bus import get_bridge

        get_bridge().broadcast({"type": "projects_changed", "project_id": project_id, "chat_id": chat_id})
    except Exception:
        _queue_module().log.debug("projects_changed broadcast failed for %s", project_id, exc_info=True)


def run_project_deletion(
    drive_root: object,
    project_id: str,
    chat_id: Any,
    worker_key: tuple[str, str] | None = None,
) -> None:
    """Cancel a fenced Project tree and tombstone only after quiescence."""
    from ouroboros.projects_registry import complete_project_deletion, fail_project_deletion

    q = _queue_module()
    try:
        while True:
            live_ids = _live_project_task_ids(drive_root, project_id)
            if not live_ids:
                complete_project_deletion(drive_root, project_id)
                _broadcast_projects_changed(project_id, chat_id)
                return
            errors: list[str] = []
            for task_id in live_ids:
                try:
                    q.cancel_task_by_id(task_id, cascade=True)
                except Exception as exc:
                    errors.append(f"{task_id}: {type(exc).__name__}: {exc}")
            remaining = _live_project_task_ids(drive_root, project_id)
            if not remaining:
                complete_project_deletion(drive_root, project_id)
                _broadcast_projects_changed(project_id, chat_id)
                return
            if set(remaining) >= set(live_ids):
                detail = "; ".join(errors) if errors else "cancel_task_by_id left tasks live"
                raise RuntimeError(f"Project deletion did not quiesce ({', '.join(remaining)}): {detail}")
    except Exception as exc:
        q.log.exception("Project deletion failed for %s", project_id)
        fail_project_deletion(drive_root, project_id, f"{type(exc).__name__}: {exc}")
        _broadcast_projects_changed(project_id, chat_id)
    finally:
        if worker_key is not None:
            with _PROJECT_DELETE_WORKERS_LOCK:
                _PROJECT_DELETE_WORKERS.discard(worker_key)


def start_project_deletion(drive_root: object, project_id: str, chat_id: Any) -> bool:
    """Start one cancellation worker per Project and server generation."""
    key = (str(drive_root), str(project_id))
    with _PROJECT_DELETE_WORKERS_LOCK:
        if key in _PROJECT_DELETE_WORKERS:
            return False
        _PROJECT_DELETE_WORKERS.add(key)
    threading.Thread(
        target=run_project_deletion,
        args=(drive_root, project_id, chat_id, key),
        name=f"project-delete-{project_id}",
        daemon=True,
    ).start()
    return True


def resume_project_deletions(drive_root: object) -> int:
    """Resume interrupted deletion workers from durable registry state."""
    from ouroboros.projects_registry import PROJECT_DELETING, list_sidebar_projects

    started = 0
    for project in list_sidebar_projects(drive_root):
        if str(project.get("lifecycle") or "") != PROJECT_DELETING:
            continue
        started += int(start_project_deletion(
            drive_root,
            str(project.get("id") or ""),
            project.get("chat_id"),
        ))
    return started
