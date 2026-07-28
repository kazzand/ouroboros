"""One schedule-fire adapter into local queue or remote REQUESTED admission."""

from __future__ import annotations

import logging
import pathlib
from collections.abc import Callable
from typing import Any

log = logging.getLogger(__name__)


def dispatch_scheduled_task(
    task: dict[str, Any],
    *,
    drive_root: pathlib.Path,
    schedule_id: str,
    schedule_name: str,
    enqueue: Callable[[dict[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    from ouroboros.gateway.tasks import submit_project_task_admission

    admitted = submit_project_task_admission(task, drive_root=drive_root)
    if admitted.get("placement") != "local":
        return admitted
    try:
        from ouroboros.task_results import STATUS_SCHEDULED, write_task_result

        write_task_result(
            drive_root,
            str(task["id"]),
            STATUS_SCHEDULED,
            root_task_id=str(task["id"]),
            actor_id="scheduler",
            delegation_role="root",
            project_id=str(task.get("project_id") or ""),
            description=str(task.get("description") or task.get("text") or ""),
            expected_output=str(task.get("expected_output") or ""),
            constraints=str(task.get("constraints") or ""),
            context=str(task.get("context") or ""),
            allowed_resources=(
                task.get("allowed_resources")
                if isinstance(task.get("allowed_resources"), dict)
                else {}
            ),
            deadline_at=str(task.get("deadline_at") or ""),
            task_contract=(
                task.get("task_contract")
                if isinstance(task.get("task_contract"), dict)
                else {}
            ),
            result="Scheduled task queued.",
            metadata=dict(task.get("metadata") or {}),
            schedule_id=schedule_id,
            schedule_name=schedule_name,
        )
    except Exception:
        log.debug(
            "Failed to persist scheduled task result before enqueue",
            exc_info=True,
        )
    return enqueue(task)
