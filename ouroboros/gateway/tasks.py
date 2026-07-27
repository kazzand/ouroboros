"""Headless task gateway endpoints."""

from __future__ import annotations

import asyncio
import inspect
import json
import pathlib
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, StreamingResponse

from ouroboros.contracts.task_contract import (
    attach_task_contract,
    normalize_acceptance_claims,
    normalize_allowed_resources,
    normalize_answer_protocol,
    normalize_bool,
    normalize_disabled_tools,
    normalize_resource_policy,
)
from ouroboros.gateway._helpers import (
    coerce_int,
    json_error,
    json_exception,
    request_drive_root,
    request_json_or,
    request_repo_dir,
)
from ouroboros.headless import (
    ARTIFACT_STATUS_FAILED,
    ARTIFACT_STATUS_FINALIZING,
    ARTIFACT_STATUS_PENDING,
    ARTIFACTS_DIR,
    HEADLESS_TASKS_DIR,
    prepare_task_drive,
    task_artifacts_dir,
    write_workspace_preflight_artifact,
)
from ouroboros.outcomes import public_task_result
from ouroboros.task_results import (
    STATUS_FAILED,
    STATUS_SCHEDULED,
    list_task_results,
    load_task_result,
    validate_task_id,
    write_task_result,
)
from ouroboros.task_status import (
    FINAL_STATUSES,
    effective_task_result,
    find_child_tasks,
    load_effective_task_result,
)
from ouroboros.tool_access import path_is_relative_to, paths_overlap_casefold
from ouroboros.utils import iter_jsonl_objects
from ouroboros.workspace_executor import normalize_executor_ref
from ouroboros.workspace_preflight import (
    collect_workspace_preflight,
    summarize_workspace_preflight,
)

_LOG_SOURCES = (
    ("progress", ("logs", "progress.jsonl")),
    ("chat", ("logs", "chat.jsonl")),
    ("events", ("logs", "events.jsonl")),
    ("tools", ("logs", "tools.jsonl")),
    ("supervisor", ("logs", "supervisor.jsonl")),
)

_RESERVED_METADATA_KEYS = frozenset({
    "task_id",
    "parent_task_id",
    "root_task_id",
    "session_id",
    "actor_id",
    "delegation_role",
    "drive_root",
    "child_drive_root",
    "headless_child_drive_root",
    "budget_drive_root",
    "task_constraint",
    "task_contract",
    "allowed_resources",
    "deadline_at",
    "executor_ref",
    "workspace_executor",
    "workspace_ref",
    "_sealed_workspace_ref",
    "_project_room_workspace_ref",
    "connection_id",
    "remote_root",
    "workspace_id",
    "project_id",
})
_REMOTE_PLACEMENT_INPUT_KEYS = frozenset({
    "workspace_ref",
    "_sealed_workspace_ref",
    "_project_room_workspace_ref",
    "connection_id",
    "remote_root",
    "workspace_id",
})
_REMOTE_SUBMIT_LOCK = threading.Lock()
_REMOTE_SUBMISSIONS: set[tuple[str, str]] = set()


def _external_subagent_label(body: Dict[str, Any], metadata: Dict[str, Any]) -> bool:
    role_values = [
        body.get("delegation_role"),
        metadata.get("delegation_role"),
    ]
    return any(str(value or "").strip().lower() == "subagent" for value in role_values)


def _normalize_deadline_at(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("deadline_at must be an ISO-8601 datetime") from exc
    if parsed.tzinfo is None:
        raise ValueError("deadline_at must include a timezone offset or Z")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _fold_contract_policies(body: Dict[str, Any], raw_metadata: Dict[str, Any], metadata: Dict[str, Any]):
    """Normalize the declarative contract policies from the request body into task
    metadata (extracted from api_tasks_create for the function-size gate; pure).
    Returns (allowed_resources, resource_policy, disabled_tools, acceptance_claims,
    error) — error is non-empty for an invalid service_teardown."""
    allowed_resources = normalize_allowed_resources(body.get("allowed_resources") or raw_metadata.get("allowed_resources") or {})
    if allowed_resources:
        metadata["allowed_resources"] = allowed_resources
    resource_policy = normalize_resource_policy(body.get("resource_policy") or raw_metadata.get("resource_policy") or {})
    if resource_policy:
        metadata["resource_policy"] = resource_policy
    disabled_tools = normalize_disabled_tools(body.get("disabled_tools") or raw_metadata.get("disabled_tools") or [])
    if disabled_tools:
        metadata["disabled_tools"] = disabled_tools
    acceptance_claims = normalize_acceptance_claims(body.get("acceptance_claims") or raw_metadata.get("acceptance_claims") or [])
    if acceptance_claims:
        metadata["acceptance_claims"] = acceptance_claims
    # v6.60.0: adapter-declared answer protocol ("" | "final_answer_line") — flows into
    # the task contract (and to subagents via the normal contract inheritance).
    answer_protocol = normalize_answer_protocol(body.get("answer_protocol") or raw_metadata.get("answer_protocol"))
    if answer_protocol:
        metadata["answer_protocol"] = answer_protocol
    service_teardown = str(body.get("service_teardown") or raw_metadata.get("service_teardown") or "").strip().lower()
    if service_teardown:
        if service_teardown not in {"stop", "keep"}:
            return allowed_resources, resource_policy, disabled_tools, acceptance_claims, "service_teardown must be 'stop' or 'keep'"
        metadata["service_teardown"] = service_teardown
    return allowed_resources, resource_policy, disabled_tools, acceptance_claims, ""


def _admission_rejection_response(
    admitted: Any,
    *,
    drive_root: pathlib.Path,
    task_id: str,
    project_id: str,
    workspace_root: Optional[pathlib.Path],
    child_drive: Optional[pathlib.Path],
) -> Optional[JSONResponse]:
    """Terminalize a typed queue refusal so no scheduled phantom remains."""
    if not (isinstance(admitted, dict) and admitted.get("_admission_blocked")):
        return None
    reason_code = str(admitted.get("_admission_blocked") or "admission_fence")
    detail = "Task was not scheduled because its admission fence is closed."
    admission = {
        "reason_code": reason_code,
        "project_id": str(admitted.get("_project_id") or project_id),
        "project_lifecycle": str(admitted.get("_project_lifecycle") or ""),
        "acceptance_fence_token": str(admitted.get("_acceptance_fence_token") or ""),
        "acceptance_fence_status": str(admitted.get("_acceptance_fence_status") or ""),
    }
    write_task_result(
        drive_root,
        task_id,
        STATUS_FAILED,
        reason_code=reason_code,
        admission=admission,
        artifact_status=ARTIFACT_STATUS_FAILED if workspace_root else "",
        result=detail,
        cost_usd=0.0,
    )
    if child_drive is not None:
        from ouroboros.headless import remove_subagent_task_drive

        removed = remove_subagent_task_drive(drive_root, task_id)
        write_task_result(
            drive_root,
            task_id,
            STATUS_FAILED,
            admission_cleanup={"child_drive_removed": bool(removed)},
        )
    return JSONResponse(
        {
            "error": detail,
            "task_id": task_id,
            "status": STATUS_FAILED,
            "admission": admission,
        },
        status_code=409,
    )


def _has_remote_placement_input(body: Dict[str, Any], metadata: Dict[str, Any]) -> bool:
    return any(key in body or key in metadata for key in _REMOTE_PLACEMENT_INPUT_KEYS)


def _remote_project_workspace(drive_root: object, project_id: str) -> dict | None:
    if not project_id:
        return None
    from ouroboros.projects_registry import get_project
    from ouroboros.workspace_ref import normalize_workspace_ref

    project = get_project(drive_root, project_id)
    if not isinstance(project, dict):
        return None
    workspace_ref = normalize_workspace_ref(project.get("workspace_ref"))
    if workspace_ref is None or workspace_ref["kind"] != "ssh":
        return None
    return workspace_ref


def _remote_admitted_task(result: Any, sealed_ref: dict) -> tuple[dict | None, str, str]:
    """Project an untrusted broker result onto the narrow lifecycle merge contract."""

    if not isinstance(result, dict):
        return None, "remote workspace service returned an invalid response", "remote_service_invalid_response"
    if not result.get("ok"):
        from ouroboros.workspace_diagnostics import sanitize_execution_text

        return (
            None,
            sanitize_execution_text(
                result.get("error") or "remote workspace admission failed"
            )[:2000],
            str(result.get("error_code") or "remote_admission_failed"),
        )
    raw_ref = result.get("workspace_ref")
    if isinstance(raw_ref, dict):
        try:
            from ouroboros.workspace_ref import normalize_workspace_ref

            admitted_ref = normalize_workspace_ref(raw_ref)
        except ValueError as exc:
            return None, str(exc), "remote_service_invalid_response"
        if admitted_ref != sealed_ref:
            return (
                None,
                "remote admission returned a different workspace identity",
                "remote_workspace_identity_changed",
            )
    evidence = result.get("admission_evidence")
    if not isinstance(evidence, dict):
        evidence = {
            key: result[key]
            for key in ("phase", "completion", "platform", "architecture", "build")
            if key in result
        }
    metadata: dict[str, Any] = {
        "_sealed_workspace_ref": dict(sealed_ref),
        "executor_ref": {
            "type": "ssh_exec",
            "id": sealed_ref["connection_id"],
            "network": "host",
            "workspace_id": sealed_ref["workspace_id"],
        },
        "_remote_admission_evidence": evidence,
    }
    admission_git = evidence.get("git") if isinstance(evidence.get("git"), dict) else {}
    metadata["workspace_preflight"] = {
        "schema_version": 1,
        "workspace_root": str(sealed_ref["remote_root"]),
        "git": dict(admission_git),
        "manifests": [],
        "tools": {"available": [], "missing": []},
        "authority": "remote_admission",
    }
    remote_manifest = result.get("attachment_manifest")
    if isinstance(remote_manifest, list):
        metadata["_remote_attachment_manifest"] = remote_manifest
    completion: dict[str, Any] = {"metadata": metadata}
    if isinstance(remote_manifest, list):
        completion["attachments"] = remote_manifest
    return completion, "", ""


def _remote_attachment_upload(task: dict) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    """Read only canonical Home-staged blobs and re-verify their frozen facts."""

    from ouroboros.artifacts import task_artifact_dir_path
    from ouroboros.remote_task_files import (
        RemoteTaskFileError,
        attachment_blob_map,
        canonical_attachment_manifest,
    )

    raw = task.get("attachments")
    if not isinstance(raw, list) or not raw:
        return [], {}
    manifest = canonical_attachment_manifest(raw)
    artifact_dir = task_artifact_dir_path(
        pathlib.Path(str(task.get("drive_root") or "")),
        str(task.get("id") or ""),
        create=False,
    ).resolve(strict=True)
    blobs: dict[str, bytes] = {}
    for entry in manifest:
        source = (artifact_dir / entry["relpath"]).resolve(strict=True)
        try:
            source.relative_to(artifact_dir)
        except ValueError as exc:
            raise RemoteTaskFileError(
                "attachment_home_stage_escape",
                "Canonical Home attachment escaped its task artifact store.",
            ) from exc
        payload = source.read_bytes()
        blobs.setdefault(entry["sha256"], payload)
    return attachment_blob_map(manifest, blobs)


def _stage_api_task_attachments(
    drive_root: object,
    task_id: str,
    raw_attachments: Any,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Stage the Home authority set without growing the task route."""

    from ouroboros.artifacts import stage_task_attachments

    omissions: list[dict[str, Any]] = []
    manifest = stage_task_attachments(
        drive_root,
        task_id,
        _normalize_attachments(raw_attachments),
        diagnostics=omissions,
    )
    images = [item for item in manifest if item.get("is_image")]
    return manifest, images, omissions


def submit_remote_task_admission(
    task: dict,
    *,
    connection: dict,
    service: Any,
) -> dict:
    """Persist REQUESTED, then perform the cancellable broker call off-loop."""

    from supervisor.task_lifecycle import register_requested_admission
    from supervisor.workers import get_event_q

    task_id = str(task.get("id") or "")
    metadata = task.get("metadata") if isinstance(task.get("metadata"), dict) else {}
    sealed_ref = dict(metadata.get("_sealed_workspace_ref") or {})
    admission_id = uuid.uuid4().hex
    cancel_event = threading.Event()

    def cancel() -> None:
        cancel_event.set()
        broker_cancel = getattr(service, "cancel_admission", None)
        if callable(broker_cancel):
            try:
                broker_cancel(task_id)
            except Exception:
                pass

    with _REMOTE_SUBMIT_LOCK:
        registered = register_requested_admission(
            task,
            cancel=cancel,
            admission_id=admission_id,
        )
        if not registered.get("ok"):
            return registered
        admission_id = str(registered.get("admission_id") or admission_id)
        submission_key = (task_id, admission_id)
        if submission_key in _REMOTE_SUBMISSIONS:
            return {**registered, "duplicate": True}
        _REMOTE_SUBMISSIONS.add(submission_key)

    def run() -> None:
        live_fields: dict[str, Any] = {}
        try:
            fn = getattr(service, "admit_workspace", None)
            if not callable(fn):
                raise RuntimeError("remote workspace service is unavailable")
            attachment_manifest, attachment_blobs = _remote_attachment_upload(task)
            admission_kwargs = {
                "remote_root": sealed_ref["remote_root"],
                "project_id": str(task.get("project_id") or ""),
                "workspace_id": sealed_ref["workspace_id"],
                "task_id": task_id,
                "cancel_event": cancel_event,
            }
            if attachment_manifest:
                admission_kwargs.update(
                    attachment_manifest=attachment_manifest,
                    attachment_blobs=attachment_blobs,
                )
            result = fn(connection, **admission_kwargs)
            if inspect.isawaitable(result):
                result = asyncio.run(result)
            from ouroboros.gateway.connections import _public_live_fields

            live_fields = _public_live_fields(result)
            admitted_task, error, reason_code = _remote_admitted_task(
                result, sealed_ref
            )
        except Exception as exc:
            from ouroboros.workspace_diagnostics import sanitize_execution_text

            admitted_task = None
            error = sanitize_execution_text(
                f"{type(exc).__name__}: {exc}"
            )[:2000]
            reason_code = str(
                getattr(exc, "code", None)
                or getattr(exc, "error_code", None)
                or "remote_service_error"
            )
            from ouroboros.gateway.connections import _public_live_fields

            live_fields = _public_live_fields(exc, default_phase="admission")
        get_event_q().put({
            "type": "remote_admission_result",
            **live_fields,
            "task_id": task_id,
            "admission_id": admission_id,
            "connection_id": str(sealed_ref.get("connection_id") or ""),
            "project_id": str(task.get("project_id") or ""),
            "admitted_task": admitted_task,
            "error": error,
            "reason_code": reason_code or "remote_admission_failed",
        })

    threading.Thread(
        target=run,
        name=f"remote-admission-{task_id}",
        daemon=True,
    ).start()
    return {**registered, "submitted": True}


def finish_remote_task_admission(task_id: str, admission_id: str) -> None:
    """Forget process-local in-flight deduplication after queue completion."""

    with _REMOTE_SUBMIT_LOCK:
        _REMOTE_SUBMISSIONS.discard(
            (str(task_id or ""), str(admission_id or ""))
        )


def recover_remote_task_admissions(service: Any = None) -> dict:
    """Nonblocking, idempotent resubmission hook for restored REQUESTED rows.

    The server calls this after queue snapshot restore and broker construction.
    It pulls the global service only when one was not injected and never creates
    another lifecycle store.
    """

    from ouroboros.gateway.connections import get_connection
    from supervisor.task_lifecycle import list_requested_admissions

    if service is None:
        try:
            from ouroboros.remote_workspace import get_remote_workspace_service

            service = get_remote_workspace_service()
        except (ImportError, RuntimeError):
            service = None
    if service is None:
        return {"ok": False, "submitted": 0, "error": "remote_service_unavailable"}
    submitted = 0
    skipped: list[dict[str, str]] = []
    for row in list_requested_admissions(recovery_required_only=True):
        task = row.get("task") if isinstance(row.get("task"), dict) else {}
        metadata = task.get("metadata") if isinstance(task.get("metadata"), dict) else {}
        sealed = metadata.get("_sealed_workspace_ref")
        try:
            from ouroboros.workspace_ref import normalize_workspace_ref

            workspace_ref = normalize_workspace_ref(sealed)
        except ValueError as exc:
            workspace_ref = None
            skipped.append({
                "task_id": str(row.get("task_id") or ""),
                "error": f"invalid_workspace_ref: {exc}",
            })
        if workspace_ref is None or workspace_ref["kind"] != "ssh":
            if not any(item["task_id"] == str(row.get("task_id") or "") for item in skipped):
                skipped.append({
                    "task_id": str(row.get("task_id") or ""),
                    "error": "missing_ssh_workspace_ref",
                })
            continue
        connection = get_connection(workspace_ref["connection_id"])
        if connection is None or connection.get("lifecycle", "active") != "active":
            skipped.append({
                "task_id": str(row.get("task_id") or ""),
                "error": "connection_unavailable",
            })
            continue
        result = submit_remote_task_admission(
            task,
            connection=connection,
            service=service,
        )
        if result.get("ok") and result.get("submitted"):
            submitted += 1
        elif not result.get("ok"):
            skipped.append({
                "task_id": str(row.get("task_id") or ""),
                "error": str(result.get("error") or result.get("status") or "rejected"),
            })
    return {"ok": not skipped, "submitted": submitted, "skipped": skipped}


def _resolve_remote_api_placement(
    request: Request,
    drive_root: object,
    project_id: str,
    workspace_root: Optional[pathlib.Path],
) -> tuple[dict | None, dict | None, Any, JSONResponse | None]:
    workspace_ref = _remote_project_workspace(drive_root, project_id)
    if workspace_ref is None:
        return None, None, None, None
    if workspace_root is not None:
        return None, None, None, json_error(
            "workspace_root cannot override an SSH-bound project workspace",
            400,
        )
    from ouroboros.gateway.connections import (
        _remote_service,
        _request_store_path,
        get_connection,
    )

    connection = get_connection(
        workspace_ref["connection_id"], _request_store_path(request)
    )
    if connection is None:
        return None, None, None, json_error(
            "remote project connection was not found", 404
        )
    if connection.get("lifecycle", "active") != "active":
        return None, None, None, JSONResponse(
            {
                "error": "remote project connection is retired",
                "error_code": "connection_retired",
                "action": "rebind_project",
            },
            status_code=409,
        )
    service = _remote_service(request)
    if service is None:
        return None, None, None, JSONResponse(
            {
                "error": "remote workspace service is unavailable",
                "error_code": "remote_service_unavailable",
                "action": "restart_ouroboros",
            },
            status_code=503,
        )
    return workspace_ref, connection, service, None


def _register_remote_api_task(
    request: Request,
    task: dict,
    *,
    workspace_ref: dict,
    service: Any,
    artifacts: list[dict[str, Any]],
) -> JSONResponse:
    task_id = str(task.get("id") or "")
    project_id = str(task.get("project_id") or "")
    task["artifacts"] = artifacts
    task["artifact_status"] = ARTIFACT_STATUS_PENDING
    from ouroboros.gateway.connections import _request_store_path, get_connection
    from supervisor import queue as supervisor_queue

    with supervisor_queue._queue_lock:
        connection = get_connection(
            workspace_ref["connection_id"],
            _request_store_path(request),
        )
        if (
            connection is None
            or connection.get("lifecycle", "active") != "active"
        ):
            return JSONResponse(
                {
                    "error": "remote project connection became unavailable",
                    "error_code": "connection_retired",
                    "action": "rebind_project",
                },
                status_code=409,
            )
        registered = submit_remote_task_admission(
            task,
            connection=connection,
            service=service,
        )
    if not registered.get("ok"):
        return JSONResponse(
            {
                "error": str(
                    registered.get("error")
                    or registered.get("reason_code")
                    or "remote admission was rejected"
                ),
                "error_code": str(
                    registered.get("reason_code")
                    or registered.get("error")
                    or "remote_admission_rejected"
                ),
                "task_id": task_id,
                "status": str(registered.get("status") or "failed"),
            },
            status_code=409,
        )
    try:
        from ouroboros.gateway.connections import _broadcast_connection_state

        _broadcast_connection_state(
            workspace_ref["connection_id"],
            {
                "status": "connecting",
                "phase": "admission",
                "completion": "requested",
                "task_id": task_id,
                "project_id": project_id,
            },
        )
    except Exception:
        pass
    return JSONResponse(
        {"ok": True, "task_id": task_id, "status": "requested"},
        status_code=202,
    )


def _apply_requested_executor(
    body: dict,
    raw_metadata: dict,
    metadata: dict,
    *,
    workspace_root: Optional[pathlib.Path],
    repo_dir: pathlib.Path,
    drive_root: pathlib.Path,
) -> str:
    if "executor_ref" in raw_metadata or "workspace_executor" in raw_metadata:
        return (
            "metadata.executor_ref/workspace_executor is reserved; "
            "pass executor_ref as a top-level task field"
        )
    if "executor_ref" not in body:
        return ""
    raw = body.get("executor_ref")
    if not isinstance(raw, dict) or not raw:
        return "executor_ref must be a JSON object"
    if workspace_root is None:
        return "executor_ref requires an external workspace_root"
    try:
        normalized = normalize_executor_ref(raw)
    except ValueError as exc:
        return str(exc)
    if normalized is None:
        return ""
    for mapping in normalized.mappings:
        for protected_root, label in (
            (repo_dir, "Ouroboros system repo"),
            (drive_root, "Ouroboros data drive"),
        ):
            if paths_overlap_casefold(mapping.host_path, protected_root):
                return f"executor_ref mapping must not overlap the {label}"
    if not any(
        path_is_relative_to(workspace_root, mapping.host_path)
        for mapping in normalized.mappings
    ):
        return "executor_ref mappings must cover workspace_root"
    metadata["executor_ref"] = {
        "type": normalized.kind,
        "id": normalized.executor_id,
        "network": normalized.network,
        "workspace_host_path": str(normalized.mappings[0].host_path),
        "workspace_backend_path": normalized.mappings[0].backend_path,
        "container_name": normalized.container_name,
        "path_mappings": [
            {
                "host_path": str(mapping.host_path),
                "backend_path": mapping.backend_path,
            }
            for mapping in normalized.mappings
        ],
    }
    return ""


def _requested_deadline(body: dict, raw_metadata: dict) -> tuple[str, str]:
    try:
        deadline_at = _normalize_deadline_at(
            body.get("deadline_at") or raw_metadata.get("deadline_at") or ""
        )
    except ValueError as exc:
        return "", str(exc)
    try:
        timeout_sec = float(body.get("timeout_sec") or body.get("timeout") or 0)
    except (TypeError, ValueError):
        timeout_sec = 0.0
    if not deadline_at and timeout_sec > 0:
        deadline_at = datetime.fromtimestamp(
            time.time() + timeout_sec, timezone.utc
        ).isoformat().replace("+00:00", "Z")
    return deadline_at, ""


async def api_tasks_create(request: Request) -> JSONResponse:
    """POST /api/tasks — enqueue a managed headless task."""

    body = await request_json_or(request, {})
    if not isinstance(body, dict):
        return json_error("request body must be a JSON object", 400)
    description = str(body.get("description") or "").strip()
    if not description:
        return json_error("description is required", 400)

    ready_error = _supervisor_ready_error(request)
    if ready_error:
        return ready_error

    drive_root = request_drive_root(request)
    repo_dir = request_repo_dir(request)
    try:
        task_id = validate_task_id(body.get("task_id") or uuid.uuid4().hex[:8])
    except ValueError as exc:
        return json_error(str(exc), 400)
    if load_task_result(drive_root, task_id):
        return json_error(f"task_id already exists: {task_id}", 409)
    if (drive_root / HEADLESS_TASKS_DIR / task_id).exists() or (drive_root / ARTIFACTS_DIR / task_id).exists():
        return json_error(f"task_id already has headless state: {task_id}", 409)
    try:
        workspace_root = _resolve_workspace_root(
            body.get("workspace_root"),
            system_repo_dir=repo_dir,
            drive_root=drive_root,
        )
    except ValueError as exc:
        return json_error(str(exc), 400)
    workspace_mode = str(body.get("workspace_mode") or ("external" if workspace_root else "")).strip()
    memory_mode = str(body.get("memory_mode") or ("forked" if workspace_root else "shared")).strip().lower()
    if memory_mode not in {"forked", "empty", "shared"}:
        return json_error("memory_mode must be one of forked, empty, shared", 400)
    if workspace_root and memory_mode == "shared":
        return json_error("memory_mode=shared is not allowed for external workspaces; use forked or empty", 400)
    raw_project_id = str(body.get("project_id") or "")
    if raw_project_id:
        from ouroboros.project_facts import explicit_project_id_ok

        # Validate the UNSTRIPPED value so leading/trailing whitespace (which would
        # collapse two inputs into one store) is rejected, not silently normalized.
        if not explicit_project_id_ok(raw_project_id):
            # Fail closed: an explicit project_id must already be filesystem-clean.
            # Reject (rather than silently normalize/empty -> canonical), so two
            # inputs never collapse to one store and isolation is never defeated.
            return json_error(
                "project_id must be filesystem-safe (alphanumeric/_/-/., no spaces or slashes)", 400)
    from ouroboros.project_facts import resolve_project_id as _resolve_pid

    _task_project_id = _resolve_pid({"project_id": raw_project_id, "workspace_root": str(workspace_root or "")})
    # D5 (Option A): keep the RECORDED memory_mode exactly as requested — shared/forked/
    # empty semantics are unchanged. Isolation for a project-scoped `shared` task comes
    # from MATERIALIZING an isolated child drive (data-root isolation), NOT from mutating
    # the recorded mode. The worker uses task['drive_root'] (the child), and a pure
    # --project-id task never shows the memory_mode line, so the recorded mode stays
    # purely informational while post-task writes still land on the isolated child.
    effective_drive_mode = "forked" if (_task_project_id and memory_mode == "shared") else memory_mode
    task_type = str(body.get("type") or "task")
    if task_type in {"evolution", "review", "deep_self_review"}:
        return json_error(
            f"task type {task_type!r} is internal-only and cannot be created via the task API "
            "(use /evolve or /review); evolution additionally requires advanced/pro runtime mode",
            400,
        )
    if workspace_root and task_type != "task":
        return json_error("external workspace tasks must use type='task'", 400)
    try:
        chat_id = int(body.get("chat_id") if body.get("chat_id") is not None else 0)
        depth = int(body.get("depth") or 0)
    except (TypeError, ValueError):
        return json_error("chat_id and depth must be integers", 400)

    raw_metadata = dict(body.get("metadata") or {}) if isinstance(body.get("metadata"), dict) else {}
    if _has_remote_placement_input(body, raw_metadata):
        return json_error(
            "remote workspace placement is inherited from project_id and cannot "
            "be supplied by a task request",
            400,
        )
    (
        remote_workspace_ref,
        _remote_connection,
        remote_service,
        remote_error,
    ) = _resolve_remote_api_placement(
        request, drive_root, _task_project_id, workspace_root
    )
    if remote_error is not None:
        return remote_error
    if remote_workspace_ref is not None:
        workspace_mode = "external"
    if _external_subagent_label(body, raw_metadata):
        return json_error("delegation_role=subagent is only allowed through the internal schedule_subagent tool", 400)
    if str(body.get("parent_task_id") or "").strip() or str(body.get("root_task_id") or "").strip():
        return json_error("parent_task_id and root_task_id are internal lineage fields; external tasks must start as roots", 400)
    if "project_id" in raw_metadata:
        # project_id is a top-level field; silently dropping it from metadata would
        # let a caller believe isolation is active while the task runs unscoped.
        return json_error("project_id must be a top-level field, not metadata", 400)
    metadata = {str(k): v for k, v in raw_metadata.items() if str(k) not in _RESERVED_METADATA_KEYS}
    if remote_workspace_ref is not None:
        metadata["_sealed_workspace_ref"] = dict(remote_workspace_ref)
        metadata["executor_ref"] = {
            "type": "ssh_exec",
            "id": remote_workspace_ref["connection_id"],
            "network": "host",
            "workspace_id": remote_workspace_ref["workspace_id"],
        }
    allowed_resources, resource_policy, disabled_tools, acceptance_claims, policy_error = (
        _fold_contract_policies(body, raw_metadata, metadata)
    )
    if policy_error:
        return json_error(policy_error, 400)
    executor_error = _apply_requested_executor(
        body,
        raw_metadata,
        metadata,
        workspace_root=workspace_root,
        repo_dir=repo_dir,
        drive_root=drive_root,
    )
    if executor_error:
        return json_error(executor_error, 400)
    deadline_at, deadline_error = _requested_deadline(body, raw_metadata)
    if deadline_error:
        return json_error(deadline_error, 400)
    if deadline_at:
        metadata["deadline_at"] = deadline_at
    child_drive = prepare_task_drive(drive_root, task_id, effective_drive_mode, project_id=_task_project_id)
    effective_drive = child_drive or drive_root
    attachment_manifest, attachment_images, attachment_omissions = (
        _stage_api_task_attachments(
            effective_drive,
            task_id,
            body.get("attachments"),
        )
    )
    metadata.setdefault("session_id", str(body.get("session_id") or uuid.uuid4().hex))
    metadata.setdefault("actor_id", str(body.get("actor_id") or "cli"))
    metadata.setdefault("source", str(body.get("source") or "api_task"))
    metadata.setdefault("delegation_role", "root")
    parent_task_id = None
    root_task_id = task_id
    metadata.setdefault("task_id", task_id)
    metadata.setdefault("parent_task_id", parent_task_id or "")
    metadata.setdefault("root_task_id", root_task_id)
    artifacts: List[Dict[str, Any]] = []
    workspace_preflight_summary: Dict[str, Any] = {}
    if workspace_root:
        metadata["workspace_root"] = str(workspace_root)
        try:
            preflight = collect_workspace_preflight(workspace_root)
            workspace_preflight_summary = summarize_workspace_preflight(preflight)
            metadata["workspace_preflight"] = workspace_preflight_summary
            artifacts.append(write_workspace_preflight_artifact(drive_root, task_id, preflight))
        except Exception as exc:
            workspace_preflight_summary = {
                "schema_version": 1,
                "workspace_root": str(workspace_root),
                "error": f"{type(exc).__name__}: {exc}",
            }
            metadata["workspace_preflight"] = workspace_preflight_summary

    task_text = _compose_task_text(
        description,
        workspace_root=workspace_root,
        workspace_mode=workspace_mode,
        memory_mode=memory_mode,
        workspace_preflight=workspace_preflight_summary,
        attachments=attachment_manifest,
        attachment_omissions=attachment_omissions,
    )
    task = {
        "id": task_id,
        "type": task_type,
        "chat_id": chat_id,
        "text": task_text,
        "description": description,
        "context": str(body.get("context") or ""),
        "expected_output": str(body.get("expected_output") or ""),
        "constraints": str(body.get("constraints") or ""),
        "context_requires_self_body_docs": normalize_bool(body.get("context_requires_self_body_docs")),
        "allowed_resources": allowed_resources,
        "resource_policy": resource_policy,
        "disabled_tools": disabled_tools,
        "acceptance_claims": acceptance_claims,
        "deadline_at": deadline_at,
        "depth": depth,
        "parent_task_id": parent_task_id,
        "root_task_id": root_task_id,
        "session_id": metadata["session_id"],
        "actor_id": metadata["actor_id"],
        "delegation_role": metadata["delegation_role"],
        "workspace_root": str(workspace_root) if workspace_root else "",
        "workspace_mode": workspace_mode,
        "memory_mode": memory_mode,
        "project_id": _task_project_id,
        "metadata": metadata,
        # v6.52.0 (P1): the STAGED manifest (root/relpath/mime/is_image), not raw
        # host paths — relpaths resolve against task['drive_root'] at read time.
        "attachments": attachment_manifest,
        "attachment_omissions": attachment_omissions,
        "attachment_images": attachment_images,
        # v6.52.0 (P1): record the effective drive (child when forked/empty, else the shared
        # drive) so build_user_content can resolve staged attachment IMAGES for EVERY task
        # shape — not just child-drive tasks. The child-drive block below re-affirms it.
        "drive_root": str(effective_drive),
    }
    task = attach_task_contract(task)
    if child_drive is not None:
        task["drive_root"] = str(child_drive)
        task["child_drive_root"] = str(child_drive)
        task["budget_drive_root"] = str(drive_root)
        metadata["child_drive_root"] = str(child_drive)
        metadata["budget_drive_root"] = str(drive_root)
    if remote_workspace_ref is not None:
        return _register_remote_api_task(
            request,
            task,
            workspace_ref=remote_workspace_ref,
            service=remote_service,
            artifacts=artifacts,
        )
    write_task_result(
        drive_root,
        task_id,
        STATUS_SCHEDULED,
        parent_task_id=task.get("parent_task_id"),
        root_task_id=task.get("root_task_id"),
        session_id=task.get("session_id"),
        actor_id=task.get("actor_id"),
        delegation_role=task.get("delegation_role"),
        project_id=_task_project_id,
        description=description,
        context=task.get("context"),
        expected_output=task.get("expected_output"),
        constraints=task.get("constraints"),
        allowed_resources=allowed_resources,
        deadline_at=deadline_at,
        task_contract=task.get("task_contract"),
        workspace_root=task.get("workspace_root"),
        workspace_mode=workspace_mode,
        memory_mode=memory_mode,
        child_drive_root=str(child_drive or ""),
        budget_drive_root=str(drive_root) if child_drive is not None else "",
        artifacts=artifacts,
        artifact_status=ARTIFACT_STATUS_PENDING if workspace_root else "",
        metadata=metadata,
        result="Task accepted and scheduled.",
    )
    try:
        from supervisor.queue import enqueue_task, persist_queue_snapshot

        admitted = enqueue_task(task)
        rejection = _admission_rejection_response(
            admitted,
            drive_root=drive_root,
            task_id=task_id,
            project_id=_task_project_id,
            workspace_root=workspace_root,
            child_drive=child_drive,
        )
        if rejection is not None:
            return rejection
        persist_queue_snapshot(reason="api_task_create")
    except Exception as exc:
        write_task_result(
            drive_root,
            task_id,
            "failed",
            parent_task_id=task.get("parent_task_id"),
            root_task_id=task.get("root_task_id"),
            session_id=task.get("session_id"),
            actor_id=task.get("actor_id"),
            project_id=_task_project_id,
            delegation_role=task.get("delegation_role"),
            description=description,
            context=task.get("context"),
            expected_output=task.get("expected_output"),
            constraints=task.get("constraints"),
            allowed_resources=allowed_resources,
            deadline_at=deadline_at,
            task_contract=task.get("task_contract"),
            workspace_root=task.get("workspace_root"),
            workspace_mode=workspace_mode,
            memory_mode=memory_mode,
            child_drive_root=str(child_drive or ""),
            budget_drive_root=str(drive_root) if child_drive is not None else "",
            artifacts=artifacts,
            artifact_status=ARTIFACT_STATUS_FAILED if workspace_root else "",
            metadata=metadata,
            result=f"Failed to enqueue task: {exc}",
        )
        return json_exception(exc, 503)
    return JSONResponse({"ok": True, "task_id": task_id, "status": STATUS_SCHEDULED})


async def api_tasks_list(request: Request) -> JSONResponse:
    statuses = [
        item.strip()
        for item in str(request.query_params.get("status") or "").split(",")
        if item.strip()
    ]
    limit = max(1, min(coerce_int(request.query_params.get("limit"), 50), 500))
    drive_root = request_drive_root(request)
    wanted = {status.lower() for status in statuses}
    rows = [public_task_result(effective_task_result(drive_root, row)) for row in list_task_results(drive_root)]
    if wanted:
        rows = [row for row in rows if str(row.get("status") or "").lower() in wanted]
    rows.sort(key=lambda item: str(item.get("ts") or ""), reverse=True)
    return JSONResponse({"tasks": rows[:limit], "queue": _queue_snapshot(drive_root)})


async def api_task_get(request: Request) -> JSONResponse:
    try:
        task_id = validate_task_id(request.path_params.get("task_id"))
    except ValueError as exc:
        return json_error(str(exc), 400)
    drive_root = request_drive_root(request)
    data = load_effective_task_result(drive_root, task_id)
    if not data:
        return json_error("task not found", 404)
    return JSONResponse(public_task_result(data))


async def api_task_artifact(request: Request):
    try:
        task_id = validate_task_id(request.path_params.get("task_id"))
    except ValueError as exc:
        return json_error(str(exc), 400)
    name = str(request.path_params.get("name") or "").strip()
    if not name or "/" in name or "\\" in name or name in {".", ".."} or ".." in pathlib.PurePosixPath(name).parts:
        return json_error("artifact name must be a simple filename", 400)
    drive_root = request_drive_root(request)
    result = load_effective_task_result(drive_root, task_id)
    if not result:
        return json_error("task not found", 404)
    artifact = _artifact_by_name(result, name)
    if artifact is None:
        return json_error("artifact not found", 404, task_id=task_id, artifact=name)
    base = task_artifacts_dir(drive_root, task_id).resolve(strict=False)
    path = pathlib.Path(str(artifact.get("path") or "")).resolve(strict=False)
    if path.name != name:
        return json_error("artifact metadata path does not match requested name", 500)
    try:
        path.relative_to(base)
    except ValueError:
        return json_error("artifact path is outside task artifact directory", 500)
    if not path.is_file():
        return json_error("artifact file is missing", 404, task_id=task_id, artifact=name)
    return FileResponse(path)


async def api_task_cancel(request: Request) -> JSONResponse:
    try:
        task_id = validate_task_id(request.path_params.get("task_id"))
    except ValueError as exc:
        return json_error(str(exc), 400)
    try:
        from supervisor.queue import cancel_task_by_id

        ok = cancel_task_by_id(task_id)
    except Exception as exc:
        return json_exception(exc, 503)
    if not ok:
        return json_error("task not found or not active", 404, task_id=task_id)
    return JSONResponse({"ok": True, "task_id": task_id})


async def api_task_resume(request: Request) -> JSONResponse:
    """Resume only a replay-safe task paused before its first model dispatch."""
    try:
        task_id = validate_task_id(request.path_params.get("task_id"))
    except ValueError as exc:
        return json_error(str(exc), 400)
    try:
        from supervisor.queue import resume_budget_paused_task

        result = resume_budget_paused_task(task_id)
    except Exception as exc:
        return json_exception(exc, 503)
    if result.get("ok"):
        return JSONResponse(result)
    error = str(result.get("error") or "resume_refused")
    status = 409 if error in {
        "task_not_budget_paused", "replay_unsafe", "root_budget_fence_missing",
    } else 404
    return json_error(error, status, task_id=task_id, **({"action": result["action"]} if result.get("action") else {}))


async def api_task_events(request: Request) -> StreamingResponse:
    try:
        task_id = validate_task_id(request.path_params.get("task_id"))
    except ValueError as exc:
        message = str(exc)
        async def _bad_id():
            yield _sse({"type": "error", "error": message, "seq": 1}, event_id=1)
        return StreamingResponse(_bad_id(), media_type="text/event-stream", status_code=400)
    cursor = max(0, coerce_int(request.query_params.get("cursor"), 0))
    wait_sec = max(0, min(coerce_int(request.query_params.get("wait"), 30), 120))
    drive_root = request_drive_root(request)
    if not load_task_result(drive_root, task_id):
        async def _missing():
            yield _sse({"type": "error", "error": "task not found", "task_id": task_id, "seq": 1}, event_id=1)
        return StreamingResponse(_missing(), media_type="text/event-stream", status_code=404)

    async def _stream():
        nonlocal cursor
        deadline = time.time() + wait_sec
        while True:
            events = [evt for evt in iter_task_events(drive_root, task_id) if int(evt.get("seq") or 0) > cursor]
            emitted_final = False
            for event in events:
                cursor = int(event.get("seq") or cursor)
                if str(event.get("type") or "") == "task_result":
                    data = event.get("data") if isinstance(event.get("data"), dict) else {}
                    emitted_final = str(data.get("status") or "").lower() in FINAL_STATUSES
                yield _sse(event, event_id=cursor)
            if _is_task_final(drive_root, task_id):
                if not emitted_final:
                    result = public_task_result(load_effective_task_result(drive_root, task_id))
                    if result:
                        final_event = {
                            "source": "task_result",
                            "line": 0,
                            "ts": str(result.get("ts") or ""),
                            "type": "task_result",
                            "task_id": task_id,
                            "data": result,
                            "seq": cursor + 1,
                        }
                        cursor = int(final_event["seq"])
                        yield _sse(final_event, event_id=cursor)
                break
            if time.time() >= deadline:
                yield ": heartbeat\n\n"
                break
            await asyncio.sleep(0.5)

    return StreamingResponse(_stream(), media_type="text/event-stream")


def iter_task_events(drive_root: pathlib.Path, task_id: str) -> List[Dict[str, Any]]:
    """Return synthesized replayable events for a task from existing logs."""

    rows: List[Dict[str, Any]] = []
    roots = [pathlib.Path(drive_root)]
    task_filter_ids = {task_id}
    result = load_effective_task_result(drive_root, task_id)
    suppress_task_done = _is_workspace_result(result) and str(result.get("artifact_status") or "").lower() in {
        ARTIFACT_STATUS_PENDING,
        ARTIFACT_STATUS_FINALIZING,
    }
    child = str(result.get("child_drive_root") or result.get("headless_child_drive_root") or "").strip()
    if child:
        child_path = pathlib.Path(child)
        if child_path not in roots:
            roots.append(child_path)
    for child_row in find_child_tasks(drive_root, parent_task_id=task_id, root_task_id=task_id):
        child_id = str(child_row.get("task_id") or child_row.get("id") or "").strip()
        if child_id:
            task_filter_ids.add(child_id)
        child_root = str(child_row.get("child_drive_root") or child_row.get("headless_child_drive_root") or "").strip()
        if child_root:
            child_path = pathlib.Path(child_root)
            if child_path not in roots:
                roots.append(child_path)
    for root in roots:
        for source, parts in _LOG_SOURCES:
            path = root.joinpath(*parts)
            for line_no, entry in enumerate(iter_jsonl_objects(path), 1):
                entry_task = str(entry.get("task_id") or "")
                entry_subagent = str(entry.get("subagent_task_id") or "")
                entry_parent = str(entry.get("parent_task_id") or "")
                entry_root = str(entry.get("root_task_id") or "")
                if (
                    entry_task not in task_filter_ids
                    and entry_subagent not in task_filter_ids
                    and entry_parent != task_id
                    and entry_root != task_id
                ):
                    continue
                event = _event_from_log_entry(source, line_no, entry, root)
                if suppress_task_done and event.get("type") == "task_done":
                    continue
                rows.append(event)
    if result:
        rows.append({
            "source": "task_result",
            "line": 0,
            "ts": str(result.get("ts") or ""),
            "type": "task_result",
            "task_id": task_id,
            "data": public_task_result(result),
        })
    rows.sort(key=lambda item: (str(item.get("ts") or ""), str(item.get("source") or ""), int(item.get("line") or 0)))
    for idx, row in enumerate(rows, 1):
        row["seq"] = idx
    return rows


def _event_from_log_entry(source: str, line_no: int, entry: Dict[str, Any], root: pathlib.Path) -> Dict[str, Any]:
    event_type = str(entry.get("type") or source)
    if source == "progress":
        event_type = "progress"
    elif source == "chat":
        event_type = "message"
    elif source == "tools":
        event_type = "tool_call"
    data = dict(entry)
    data = public_task_result(
        data,
        include_outcome_axes=any(key in data for key in ("status", "outcome_axes", "result_status", "loop_outcome")),
    )
    return {
        "source": source,
        "line": line_no,
        "ts": str(entry.get("ts") or ""),
        "type": event_type,
        "task_id": str(entry.get("task_id") or ""),
        "root": str(root),
        "data": data,
    }


def _sse(event: Dict[str, Any], *, event_id: int) -> str:
    payload = json.dumps(event, ensure_ascii=False)
    return f"id: {event_id}\nevent: task_event\ndata: {payload}\n\n"


def _is_task_final(drive_root: pathlib.Path, task_id: str) -> bool:
    result = load_effective_task_result(drive_root, task_id)
    return str(result.get("status") or "").lower() in FINAL_STATUSES


def _resolve_workspace_root(
    value: Any,
    *,
    system_repo_dir: pathlib.Path,
    drive_root: pathlib.Path,
) -> Optional[pathlib.Path]:
    """Delegates to the admission SSOT (v6.58.0): the gateway and the promote path
    validate a workspace root through ONE function (workspace_admission), so the two
    surfaces can never drift. WorkspaceRootError subclasses ValueError, so existing
    `except ValueError` call sites keep working unchanged."""
    from ouroboros.workspace_admission import validate_workspace_root

    return validate_workspace_root(value, system_repo_dir=system_repo_dir, drive_root=drive_root)


def _normalize_attachments(value: Any) -> List[Dict[str, str]]:
    if not value:
        return []
    if not isinstance(value, list):
        return []
    out: List[Dict[str, str]] = []
    for item in value:
        if isinstance(item, dict):
            path = str(item.get("path") or "").strip()
            label = str(item.get("label") or item.get("display_name") or pathlib.Path(path).name).strip()
        else:
            path = str(item or "").strip()
            label = pathlib.Path(path).name
        if path:
            out.append({"path": path, "label": label})
    return out


def _compose_task_text(
    description: str,
    *,
    workspace_root: Optional[pathlib.Path],
    workspace_mode: str,
    memory_mode: str,
    workspace_preflight: Dict[str, Any],
    attachments: Any,
    attachment_omissions: Any = None,
) -> str:
    parts = [description]
    if workspace_root is not None:
        from ouroboros.workspace_admission import compose_workspace_block

        # SSOT block (v6.58.0): the same [HEADLESS_WORKSPACE] guidance the promote
        # path embeds, so the two admission surfaces render identical context.
        workspace_lines = compose_workspace_block(
            workspace_root=workspace_root,
            workspace_mode=workspace_mode,
            memory_mode=memory_mode,
            workspace_preflight=workspace_preflight,
        )
        if "[HEADLESS_WORKSPACE]" in description and "[END_HEADLESS_WORKSPACE]" in description:
            marker = "[END_HEADLESS_WORKSPACE]"
            idx = description.rfind(marker)
            parts = [description[:idx].rstrip(), "\n", workspace_lines, description[idx:]]
        else:
            parts.append(f"\n\n[HEADLESS_WORKSPACE]\n{workspace_lines}[END_HEADLESS_WORKSPACE]")
    rendered = _render_attachment_lines(attachments)
    if rendered:
        parts.append(f"\n\n[ATTACHMENTS]\n{rendered}\n[END_ATTACHMENTS]")
    if isinstance(attachment_omissions, list) and attachment_omissions:
        rows: list[str] = []
        for item in attachment_omissions[:26]:
            if not isinstance(item, dict):
                continue
            reason = str(item.get("reason") or "omitted")
            count = item.get("omitted_count")
            if isinstance(count, int) and count > 0:
                rows.append(f"- {reason}: {count} additional attachment(s)")
            else:
                label = str(item.get("label") or "attachment")
                rows.append(f"- {label}: {reason}")
        if rows:
            parts.append(
                "\n\n[ATTACHMENT_OMISSIONS]\n"
                + "\n".join(rows)
                + "\n[END_ATTACHMENT_OMISSIONS]"
            )
    return "".join(parts)


def _render_attachment_lines(attachments: Any) -> str:
    """Render READY attachment lines from a staged manifest.

    v6.52.0 (P1): each line is a ready-to-use read_file call against the canonical
    artifact_store root — NEVER a bare absolute host path. ``attachments`` is the
    manifest returned by ``stage_task_attachments`` (entries with root/relpath/mime/
    is_image)."""
    from ouroboros.artifacts import render_task_attachment_lines

    return render_task_attachment_lines(attachments)


def _is_workspace_result(result: Dict[str, Any]) -> bool:
    return bool(str(result.get("workspace_root") or "").strip() or str(result.get("workspace_mode") or "").strip())


def _artifact_by_name(result: Dict[str, Any], name: str) -> Optional[Dict[str, Any]]:
    for artifact in result.get("artifacts") or []:
        if not isinstance(artifact, dict):
            continue
        if str(artifact.get("name") or pathlib.Path(str(artifact.get("path") or "")).name) == name:
            return artifact
    return None


def _queue_snapshot(drive_root: pathlib.Path) -> Dict[str, Any]:
    path = pathlib.Path(drive_root) / "state" / "queue_snapshot.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _supervisor_ready_error(request: Request) -> Optional[JSONResponse]:
    state = getattr(request.app, "state", None)
    ready_event = getattr(state, "supervisor_ready_event", None) if state is not None else None
    if ready_event is not None and not ready_event.is_set():
        return json_error("supervisor is still starting", 503)
    try:
        from supervisor.workers import WORKERS

        if ready_event is not None and not WORKERS:
            return json_error("supervisor has no running workers", 503)
    except Exception:
        pass
    return None


__all__ = [
    "api_task_artifact",
    "api_task_cancel",
    "api_task_resume",
    "api_task_events",
    "api_task_get",
    "api_tasks_create",
    "api_tasks_list",
    "iter_task_events",
]
