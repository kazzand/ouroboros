"""Home-side opaque accounting for remote keep-alive services."""

from __future__ import annotations

import threading
from collections.abc import Mapping
from typing import Any

SessionKey = tuple[str, str, str, str]
_SERVICE_PATH_CAP = 64
_SERVICE_PATH_CHARS = 4096


def normalize_remote_service_metadata(
    service_ref: Mapping[str, Any],
) -> dict[str, Any]:
    """Keep bounded non-process service semantics needed after reconnect."""

    result = {
        "keep_alive": bool(service_ref.get("keep_alive", False)),
        "ready": bool(service_ref.get("ready", False)),
    }
    outputs = service_ref.get("outputs")
    if (
        isinstance(outputs, list)
        and len(outputs) <= _SERVICE_PATH_CAP
        and all(
            isinstance(item, str)
            and 0 < len(item) <= _SERVICE_PATH_CHARS
            and "\x00" not in item
            for item in outputs
        )
    ):
        result["outputs"] = list(outputs)
    cwd = service_ref.get("cwd")
    if (
        isinstance(cwd, str)
        and 0 < len(cwd) <= _SERVICE_PATH_CHARS
        and "\x00" not in cwd
    ):
        result["cwd"] = cwd
    before = service_ref.get("declared_outputs_before")
    if (
        isinstance(before, dict)
        and len(before) <= _SERVICE_PATH_CAP
        and all(
            isinstance(key, str)
            and key in result.get("outputs", [])
            and isinstance(value, dict)
            for key, value in before.items()
        )
    ):
        bounded_before: dict[str, dict[str, Any]] = {}
        for key, raw in before.items():
            row: dict[str, Any] = {"exists": bool(raw.get("exists", False))}
            kind = str(raw.get("kind") or "")
            digest = str(raw.get("sha256") or "")
            size = raw.get("size")
            if kind in {"file", "directory"}:
                row["kind"] = kind
            if len(digest) == 64 and all(
                char in "0123456789abcdef" for char in digest
            ):
                row["sha256"] = digest
            if (
                isinstance(size, int)
                and not isinstance(size, bool)
                and size >= 0
            ):
                row["size"] = size
            bounded_before[key] = row
        result["declared_outputs_before"] = bounded_before
    return result


class RemoteServiceLeaseBook:
    """Track service identity without importing remote PID/PGID ownership."""

    def __init__(self) -> None:
        self._rows: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()

    def observe(
        self,
        session_key: SessionKey,
        prepared: Any,
        response: Mapping[str, Any],
        *,
        task_id: str,
    ) -> None:
        if response.get("diagnostic") is not None:
            return
        trace = response.get("trace")
        trace = trace if isinstance(trace, Mapping) else {}
        supplied = prepared.execution_args.get("_service_ref")
        supplied = supplied if isinstance(supplied, Mapping) else {}
        observed = trace.get("service_ref")
        observed = observed if isinstance(observed, Mapping) else {}
        service_id = str(
            observed.get("service_id")
            or supplied.get("service_id")
            or prepared.native_facts.get("service_id")
            or ""
        )
        if prepared.tool == "start_service":
            if bool(prepared.execution_args.get("keep_alive")) and service_id:
                with self._lock:
                    self._rows[service_id] = {
                        "session_key": session_key,
                        "task_id": str(task_id or ""),
                        "name": str(
                            observed.get("name")
                            or prepared.execution_args.get("name")
                            or "service"
                        ),
                        "service_ref": {
                            **normalize_remote_service_metadata(
                                observed or supplied
                            ),
                            "service_id": service_id,
                            "name": str(
                                observed.get("name")
                                or prepared.execution_args.get("name")
                                or "service"
                            ),
                        },
                    }
            return
        dead = (
            prepared.tool == "stop_service"
            or (prepared.tool == "service_status" and trace.get("running") is False)
            or (
                prepared.tool == "service_logs"
                and "SERVICE_NOT_FOUND" in str(response.get("text") or "")
            )
        )
        if dead and service_id:
            with self._lock:
                self._rows.pop(service_id, None)

    def active_for_connection(self, connection_id: str) -> bool:
        with self._lock:
            return any(
                row["session_key"][0] == connection_id
                for row in self._rows.values()
            )

    def discard_session(self, session_key: SessionKey) -> None:
        with self._lock:
            for service_id, row in list(self._rows.items()):
                if row["session_key"] == session_key:
                    self._rows.pop(service_id, None)

    def candidates(self, connection_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return [
                {"service_id": service_id, **row}
                for service_id, row in self._rows.items()
                if row["session_key"][0] == connection_id
            ]

    def discard(self, service_id: str) -> None:
        with self._lock:
            self._rows.pop(str(service_id), None)

    def clear(self) -> None:
        with self._lock:
            self._rows.clear()
