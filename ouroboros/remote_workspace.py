"""Home-owned SSH workspace broker and restricted execd client.

The model-visible tool surface remains owned by :mod:`ouroboros.tools.registry`.
This module is the non-model-facing placement boundary: workers submit one
prepared call through a Pipe proxy, while the server-owned broker alone owns
OpenSSH processes, protocol sessions, leases, bootstrap and reconciliation.
"""

from __future__ import annotations
import concurrent.futures
import dataclasses
import multiprocessing
import os
import pathlib
import queue
import re
import threading
import time
import uuid
import weakref
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from multiprocessing.connection import Connection
from typing import Any, Protocol, runtime_checkable

from ouroboros.config import get_ssh_timeout_sec
from ouroboros.remote_protocol import canonical_json
from ouroboros.remote_service_leases import RemoteServiceLeaseBook
from ouroboros.remote_ssh import OpenSSHExecdTransport
from ouroboros.remote_task_files import (
    remote_task_admission_result,
    stage_remote_task_attachments,
)
from ouroboros.remote_worker_proxy import (
    RemoteWorkspacePipeProxy,
    capability_projection as _capability_projection,
    envelope_from_dict as _envelope_from_dict,
    error_dict as _error_dict,
    execution_wait_timeout as _execution_wait_timeout,
    json_copy as _json_copy,
    opaque as _opaque,
    optional_opaque as _optional_opaque,
    prepared_from_dict as _prepared_from_dict,
    reconnect_failure as _reconnect_failure,
    validated_envelope_dict as _validated_envelope_dict,
    validated_prepared as _validated_prepared,
)
from ouroboros.workspace_diagnostics import (
    ExecutionDiagnostic,
    ToolExecutionEnvelope,
)
from ouroboros.workspace_ref import normalize_workspace_ref

_SSH_ALIAS_RE = re.compile(r"^[^\s\x00-\x20\x7f-][^\s\x00-\x1f\x7f]*$")
_PIPE_QUEUE_LIMIT = 128
_BROKER_MAX_INFLIGHT = 32
_BROKER_IO_WORKERS = 8
_BROKER_POLL_SEC = 0.02
_DEFAULT_REQUEST_TIMEOUT_SEC = 120.0


class RemoteWorkspaceError(RuntimeError):
    """Typed nonsecret broker error suitable for diagnostics and gateway APIs."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        phase: str,
        completion: str = "not_started",
        retryable: bool = False,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        self.code = str(code)
        self.phase = str(phase)
        self.completion = str(completion)
        self.retryable = bool(retryable)
        self.details = dict(details or {})
        super().__init__(str(message))

    def diagnostic(
        self,
        *,
        request_id: str = "",
        operation_id: str = "",
    ) -> ExecutionDiagnostic:
        domain = "transport" if self.phase in {"connect", "bootstrap", "stream"} else "protocol"
        return ExecutionDiagnostic(
            domain=domain,
            code=self.code,
            message=str(self),
            phase=self.phase,
            request_id=request_id,
            operation_id=operation_id,
            completion=self.completion,  # type: ignore[arg-type]
            retryable=self.retryable,
            details=dict(self.details),
        )


@dataclass(frozen=True)
class PreparedRemoteCall:
    """Target-canonical facts awaiting one Home safety authorization."""

    request_id: str
    operation_id: str
    tool: str
    prepared_token: str
    prepared_hash: str
    expires_at_ms: int
    execution_args: dict[str, Any]
    native_facts: dict[str, Any]
    diagnostic: ExecutionDiagnostic | None = None


@dataclass(frozen=True)
class SessionOpenRequest:
    connection: dict[str, Any]
    remote_root: str
    project_id: str
    workspace_id: str
    server_generation: str
    capability_manifest: dict[str, Any]
    drive_root: pathlib.Path
    bundle_dir: pathlib.Path | None = None
    ssh_binary: str | None = None


@runtime_checkable
class RemoteTransport(Protocol):
    """One broker-owned project session; never passed into a worker."""

    handshake: Callable[[], dict[str, Any]]
    prepare: Callable[[Mapping[str, Any], Mapping[str, bytes]], dict[str, Any]]
    execute_prepared: Callable[[Mapping[str, Any]], dict[str, Any]]
    abort_prepared: Callable[[Mapping[str, Any]], bool]
    fetch_blob: Callable[[str, int], bytes]
    reconcile: Callable[[], list[dict[str, Any]]]
    renew_lease: Callable[[Mapping[str, Any]], None]
    cancel: Callable[[Mapping[str, Any]], bool]
    task_lease: Callable[..., bool]
    panic: Callable[[], None]
    close: Callable[[], None]


class RemoteTransportFactory(Protocol):
    __call__: Callable[[SessionOpenRequest], RemoteTransport]


@runtime_checkable
class RemoteWorkspaceService(Protocol):
    """Small public contract consumed by gateway and workspace dispatch lanes."""

    prepare: Callable[..., PreparedRemoteCall]
    execute_prepared: Callable[..., ToolExecutionEnvelope]
    abort_prepared: Callable[..., bool]
    close_project_session: Callable[..., bool]
    fetch_blob: Callable[..., bytes]
    cancel: Callable[..., bool]
    open_browser_forward: Callable[..., dict[str, Any]]
    close_browser_forward: Callable[[str], bool]
    finish_task: Callable[..., bool]


@dataclass(order=True)
class _BrokerRequest:
    priority: int
    sequence: int
    method: str = field(compare=False)
    payload: dict[str, Any] = field(compare=False)
    future: concurrent.futures.Future[Any] = field(compare=False)


@dataclass
class _Session:
    key: tuple[str, str, str, str]
    connection: dict[str, Any]
    remote_root: str
    transport: RemoteTransport
    handshake: dict[str, Any]
    opened_at: float = field(default_factory=time.monotonic)
    last_used_at: float = field(default_factory=time.monotonic)


_SERVICE_LOCK = threading.RLock()
_REMOTE_WORKSPACE_SERVICE: RemoteWorkspaceService | None = None
_LIVE_BROKERS: "weakref.WeakSet[RemoteSessionBroker]" = weakref.WeakSet()


def set_remote_workspace_service(service: RemoteWorkspaceService | None) -> None:
    global _REMOTE_WORKSPACE_SERVICE
    with _SERVICE_LOCK:
        _REMOTE_WORKSPACE_SERVICE = service


def get_remote_workspace_service() -> RemoteWorkspaceService:
    with _SERVICE_LOCK:
        service = _REMOTE_WORKSPACE_SERVICE
    if service is None:
        raise RemoteWorkspaceError(
            "remote_workspace_unavailable",
            "Remote workspace broker is not configured.",
            phase="connect",
        )
    return service


def finish_remote_task(subject: Any, task_id: str) -> bool:
    """End one SSH task lease without closing its reusable project session."""

    from ouroboros.remote_task_files import cleanup_home_media_cache
    from ouroboros.workspace_ref import workspace_ref_for

    cleanup_home_media_cache(subject, task_id)
    ref = workspace_ref_for(subject)
    if ref is None or ref["kind"] != "ssh":
        return False
    return bool(
        get_remote_workspace_service().finish_task(
            ref,
            task_id=_opaque(task_id, "task_id"),
        )
    )


class RemoteSessionBroker:
    """Server-generation owner of all OpenSSH sessions and worker proxies."""

    def __init__(
        self,
        drive_root: pathlib.Path,
        server_generation: str,
        capability_manifest: Mapping[str, Any],
        *,
        transport_factory: RemoteTransportFactory | None = None,
        bundle_dir: pathlib.Path | None = None,
        ssh_binary: str | None = None,
    ) -> None:
        self.drive_root = pathlib.Path(drive_root).resolve(strict=False)
        self.server_generation = _opaque(server_generation, "server_generation")
        # Public model schemas may legitimately contain JSON numbers such as
        # ``5.0`` defaults.  They are hashed on Home, but never cross the execd
        # wire.  Canonicalize only the integer/string proof that is uploaded.
        self.capability_projection = _capability_projection(capability_manifest)
        self.bundle_dir = pathlib.Path(bundle_dir).resolve(strict=False) if bundle_dir is not None else None
        self.ssh_binary = str(ssh_binary or "").strip() or None
        self._transport_factory = transport_factory or OpenSSHExecdTransport
        from ouroboros.remote_browser_forward import SSHBrowserForwardManager

        self._browser_forwards = SSHBrowserForwardManager(
            self.drive_root,
            ssh_binary=self.ssh_binary or "ssh",
        )
        self._requests: queue.PriorityQueue[_BrokerRequest] = queue.PriorityQueue(maxsize=_PIPE_QUEUE_LIMIT)
        self._request_sequence = 0
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._sessions: dict[tuple[str, str, str, str], _Session] = {}
        self._task_sessions: dict[str, tuple[str, str, str, str]] = {}
        self._service_leases = RemoteServiceLeaseBook()
        self._connections: dict[str, dict[str, Any]] = {}
        self._worker_endpoints: list[Connection] = []
        self._worker_send_locks: dict[int, threading.Lock] = {}
        self._admission_cancels: dict[str, threading.Event] = {}
        self._admission_transports: dict[str, tuple[RemoteTransport, bool]] = {}
        # Panic reads these append-only custody snapshots without waiting for
        # the ordinary broker lock.
        self._panic_transports: list[RemoteTransport] = []
        self._panic_events: list[threading.Event] = []
        self._admission_key_locks: dict[tuple[str, str, str], threading.Lock] = {}
        self._state_lock = threading.RLock()
        self._io_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=_BROKER_IO_WORKERS,
            thread_name_prefix="remote-broker-io",
        )
        self._inflight = threading.BoundedSemaphore(_BROKER_MAX_INFLIGHT)
        self._started = False
        _LIVE_BROKERS.add(self)

    def start(self) -> None:
        with self._state_lock:
            if self._started:
                return
            if self._stop.is_set():
                raise RemoteWorkspaceError(
                    "broker_closed",
                    "Remote workspace broker cannot restart after close.",
                    phase="connect",
                )
            self._started = True
            self._thread = threading.Thread(
                target=self._run,
                name=f"remote-session-broker-{self.server_generation[:12]}",
                daemon=True,
            )
            self._thread.start()

    def create_worker_pipe_proxy(self) -> RemoteWorkspacePipeProxy:
        self.start()
        broker_endpoint, worker_endpoint = multiprocessing.Pipe(duplex=True)
        with self._state_lock:
            self._worker_endpoints.append(broker_endpoint)
            self._worker_send_locks[id(broker_endpoint)] = threading.Lock()
        return RemoteWorkspacePipeProxy(worker_endpoint)

    def recover(self) -> list[dict[str, Any]]:
        return list(self._submit("recover", {}, priority=5))

    def status(self, connection_id: str | None = None) -> dict[str, Any]:
        with self._state_lock:
            rows = []
            for key, session in self._sessions.items():
                if connection_id is not None and key[0] != connection_id:
                    continue
                health = getattr(session.transport, "health", None)
                if not callable(health):
                    transport_state = {"status": "ready", "phase": "ready"}
                else:
                    try:
                        observed = health()
                        transport_state = (
                            dict(observed)
                            if isinstance(observed, Mapping)
                            else {"status": "unknown", "phase": "connect"}
                        )
                    except Exception:
                        transport_state = {
                            "status": "disconnected",
                            "phase": "connect",
                        }
                rows.append(
                    {
                        "id": key[0],
                        "connection_id": key[0],
                        "project_id": key[1],
                        "workspace_id": key[2],
                        "server_generation": key[3],
                        **transport_state,
                        "opened_at_monotonic": session.opened_at,
                        "last_used_at_monotonic": session.last_used_at,
                        "active_task_count": sum(1 for task_key in self._task_sessions.values() if task_key == key),
                    }
                )
        return {"connections": rows}

    health = status

    def reconnect_connection(
        self,
        connection: Mapping[str, Any],
        *,
        timeout_sec: float = _DEFAULT_REQUEST_TIMEOUT_SEC,
    ) -> dict[str, Any]:
        row = _json_copy(connection, "connection")
        connection_id = _opaque(row.get("id"), "connection_id")
        try:
            return dict(
                self._submit(
                    "reconnect_connection",
                    {"connection": row, "timeout_sec": max(1.0, float(timeout_sec))},
                    priority=0,
                    timeout_sec=max(1.0, float(timeout_sec)) + 5.0,
                )
            )
        except Exception as exc:
            return _reconnect_failure(connection_id, exc)

    def test_connection(
        self,
        connection: Mapping[str, Any],
        *,
        timeout_sec: float = 10.0,
    ) -> dict[str, Any]:
        request = self._session_request(connection, "", "", "")
        transport = self._new_transport(request)
        try:
            probe = getattr(transport, "probe", None)
            return dict(probe(timeout_sec=timeout_sec) if callable(probe) else transport.handshake())
        finally:
            transport.close()

    def bootstrap(
        self,
        connection: Mapping[str, Any],
        *,
        timeout_sec: float = 30.0,
    ) -> dict[str, Any]:
        request = self._session_request(connection, "", "", "")
        transport = self._new_transport(request)
        try:
            bootstrap = getattr(transport, "bootstrap", None)
            if not callable(bootstrap):
                raise RemoteWorkspaceError(
                    "bootstrap_unsupported",
                    "Remote transport does not expose bootstrap.",
                    phase="bootstrap",
                )
            return dict(bootstrap(timeout_sec=timeout_sec))
        finally:
            transport.close()

    def list_directories(
        self,
        connection: Mapping[str, Any],
        *,
        remote_root: str = "",
        timeout_sec: float = 10.0,
    ) -> dict[str, Any]:
        request = self._session_request(connection, remote_root, "", "")
        transport = self._new_transport(request)
        try:
            list_directories = getattr(transport, "list_directories", None)
            if not callable(list_directories):
                raise RemoteWorkspaceError(
                    "directory_listing_unsupported",
                    "Remote transport does not expose directory listing.",
                    phase="connect",
                )
            return dict(list_directories(remote_root=remote_root, timeout_sec=timeout_sec))
        finally:
            transport.close()
    def admit_workspace(
        self,
        connection: Mapping[str, Any],
        *,
        remote_root: str,
        project_id: str,
        workspace_id: str = "",
        task_id: str = "",
        cancel_event: threading.Event | None = None,
        attachment_manifest: list[dict[str, Any]] | None = None,
        attachment_blobs: Mapping[str, bytes] | None = None,
    ) -> dict[str, Any]:
        project_id = _opaque(project_id, "project_id")
        task_id = _optional_opaque(task_id, "task_id")
        owned_cancel = threading.Event()
        self._panic_events.append(owned_cancel)
        if task_id:
            with self._state_lock:
                self._admission_cancels[task_id] = owned_cancel
        try:
            result = self._submit(
                "admit",
                {
                    "connection": dict(connection),
                    "remote_root": str(remote_root),
                    "project_id": project_id,
                    "workspace_id": workspace_id,
                    "task_id": task_id,
                    "cancel": owned_cancel,
                    "external_cancel": cancel_event,
                    "attachment_manifest": list(attachment_manifest or []),
                    "attachment_blobs": dict(attachment_blobs or {}),
                },
                priority=5,
                timeout_sec=float(get_ssh_timeout_sec("admission")),
            )
            return dict(result)
        except BaseException:
            owned_cancel.set()
            raise
        finally:
            if task_id:
                with self._state_lock:
                    self._admission_cancels.pop(task_id, None)
                    self._admission_transports.pop(task_id, None)
    def prepare(
        self,
        workspace_ref: Mapping[str, Any],
        *,
        request_id: str,
        operation_id: str,
        tool: str,
        args: Mapping[str, Any],
        blobs: Mapping[str, bytes] | None = None,
        deadline_ms: int | None = None,
        task_id: str = "",
        parent_task_id: str = "", project_id: str = "",
    ) -> PreparedRemoteCall:
        result = self._submit(
            "prepare",
            {
                "workspace_ref": dict(workspace_ref),
                "request_id": request_id,
                "operation_id": operation_id,
                "tool": tool,
                "args": dict(args),
                "blobs": dict(blobs or {}),
                "deadline_ms": deadline_ms,
                "task_id": task_id,
                "parent_task_id": parent_task_id, "project_id": project_id,
            },
            priority=10,
        )
        return _prepared_from_dict(result)
    def execute_prepared(
        self,
        workspace_ref: Mapping[str, Any],
        prepared: PreparedRemoteCall,
        *,
        canonical_args: Mapping[str, Any],
        task_id: str = "",
        timeout_sec: float | None = None,
    ) -> ToolExecutionEnvelope:
        return _envelope_from_dict(
            self._submit(
                "execute_prepared",
                {
                    "workspace_ref": dict(workspace_ref),
                    "prepared": dataclasses.asdict(prepared),
                    "canonical_args": dict(canonical_args),
                    "task_id": task_id,
                    "timeout_sec": timeout_sec,
                },
                priority=10,
                timeout_sec=_execution_wait_timeout(canonical_args, timeout_sec),
            )
        )
    def abort_prepared(
        self,
        workspace_ref: Mapping[str, Any],
        prepared: PreparedRemoteCall,
        *,
        task_id: str = "",
        reason: str = "denied",
    ) -> bool:
        return bool(
            self._submit(
                "abort_prepared",
                {
                    "workspace_ref": dict(workspace_ref),
                    "prepared": dataclasses.asdict(prepared),
                    "task_id": task_id,
                    "reason": str(reason)[:1000],
                },
                priority=0,
            )
        )
    def fetch_blob(
        self,
        workspace_ref: Mapping[str, Any],
        blob_id: str,
        *,
        max_bytes: int,
        task_id: str,
    ) -> bytes:
        return bytes(
            self._submit(
                "fetch_blob",
                {
                    "workspace_ref": dict(workspace_ref),
                    "blob_id": blob_id,
                    "max_bytes": int(max_bytes),
                    "task_id": task_id,
                },
                priority=20,
            )
        )
    def open_browser_forward(
        self,
        workspace_ref: Mapping[str, Any],
        *,
        remote_port: int,
        task_id: str,
    ) -> dict[str, Any]:
        session = self._session_for_ref(workspace_ref, task_id=_opaque(task_id, "task_id"))
        return dataclasses.asdict(
            self._browser_forwards.open(
                session.connection,
                remote_port=int(remote_port),
                task_id=task_id,
            )
        )
    def close_browser_forward(self, forward_id: str) -> bool:
        return self._browser_forwards.close(str(forward_id))
    def cancel(
        self,
        workspace_ref: Mapping[str, Any],
        *,
        task_id: str = "",
        request_id: str = "",
        operation_id: str = "",
    ) -> bool:
        if not task_id and not (request_id and operation_id):
            raise ValueError("cancel requires task_id or request_id+operation_id")
        # Cancellation must not sit behind a blocked ordinary request on the
        # broker queue.  Transport implementations provide an independent
        # control writer and must kill the selected group before ACK.
        session = self._session_for_ref(workspace_ref, task_id=task_id)
        cancelled = bool(
            session.transport.cancel(
                {
                    "task_id": _optional_opaque(task_id, "task_id"),
                    "request_id": _optional_opaque(request_id, "request_id"),
                    "operation_id": _optional_opaque(operation_id, "operation_id"),
                }
            )
        )
        if task_id:
            with self._state_lock:
                self._task_sessions.pop(task_id, None)
            self._browser_forwards.close_task(task_id)
        return cancelled
    def cancel_admission(self, task_id: str) -> bool:
        task_id = _opaque(task_id, "task_id")
        with self._state_lock:
            event = self._admission_cancels.get(task_id)
        if event is None:
            return False
        event.set()
        with self._state_lock:
            ownership = self._admission_transports.get(task_id)
        if ownership is not None:
            transport, exclusive = ownership
            try:
                if exclusive:
                    transport.close()
                else:
                    transport.cancel({"task_id": task_id, "request_id": "", "operation_id": ""})
            except Exception:
                pass
        self._browser_forwards.close_task(task_id)
        return True
    def finish_task(
        self,
        workspace_ref: Mapping[str, Any],
        *,
        task_id: str,
    ) -> bool:
        """Idempotently end a task lease while preserving its project session."""

        task_id = _opaque(task_id, "task_id")
        ref = normalize_workspace_ref(dict(workspace_ref))
        if ref is None or ref.get("kind") != "ssh":
            raise ValueError("finish_task requires an SSH workspace ref")
        with self._state_lock:
            key = self._task_sessions.get(task_id)
            if key is not None and (key[0], key[2]) != (
                ref["connection_id"],
                ref["workspace_id"],
            ):
                raise RemoteWorkspaceError(
                    "task_session_mismatch",
                    "Task completion refers to another remote workspace.",
                    phase="authorize",
                )
            session = self._sessions.get(key) if key is not None else None
        if session is None:
            return False
        try:
            return bool(
                session.transport.cancel(
                    {"task_id": task_id, "request_id": "", "operation_id": ""}
                )
            )
        finally:
            task_lease = getattr(session.transport, "task_lease", None)
            if callable(task_lease):
                task_lease(task_id, forget=True)
            with self._state_lock:
                if self._task_sessions.get(task_id) == key:
                    self._task_sessions.pop(task_id, None)
            self._browser_forwards.close_task(task_id)
    def close_project_session(
        self,
        workspace_ref: Mapping[str, Any],
        *,
        project_id: str,
    ) -> bool:
        """Close only the exact project/workspace admission session."""

        payload = {
            "workspace_ref": dict(workspace_ref),
            "project_id": _opaque(project_id, "project_id"),
        }
        return bool(self._submit("close_project_session", payload, priority=0))
    def cancel_connection(self, connection_id: str) -> int:
        return int(
            self._submit(
                "cancel_connection",
                {"connection_id": _opaque(connection_id, "connection_id")},
                priority=0,
            )
        )
    def has_active_lease(self, connection_id: str) -> bool:
        connection_id = _opaque(connection_id, "connection_id")
        with self._state_lock:
            has_task = any(
                key[0] == connection_id for key in self._task_sessions.values()
            )
        if has_task:
            return True
        self._refresh_service_leases(connection_id)
        return self._service_leases.active_for_connection(connection_id)
    def panic(self) -> None:
        self._stop.set()
        panic_forwards = getattr(self._browser_forwards, "panic_close_all", None)
        if callable(panic_forwards):
            panic_forwards()
        transports = tuple(self._panic_transports)
        admission_events = tuple(self._panic_events)
        if self._state_lock.acquire(blocking=False):
            try:
                self._sessions.clear()
                self._task_sessions.clear()
                self._service_leases = RemoteServiceLeaseBook()
                self._admission_transports.clear()
                self._admission_cancels.clear()
            finally:
                self._state_lock.release()
        for event in admission_events:
            event.set()
        seen: set[int] = set()
        for transport in transports:
            if id(transport) in seen:
                continue
            seen.add(id(transport))
            try:
                transport.panic()
            except Exception:
                pass
    @classmethod
    def panic_close_all(cls) -> None:
        for broker in list(_LIVE_BROKERS):
            try:
                broker.panic()
            except Exception:
                pass

    def close(self, timeout_sec: float | None = None) -> None:
        if self._stop.is_set() and not self._started:
            return
        self._stop.set()
        self._browser_forwards.close_all()
        self.panic()
        with self._state_lock:
            endpoints = list(self._worker_endpoints)
            self._worker_endpoints.clear()
        for endpoint in endpoints:
            try:
                endpoint.close()
            except (OSError, EOFError):
                pass
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, float(timeout_sec or 0.0)))
        self._started = False
        self._io_executor.shutdown(wait=False, cancel_futures=True)
        _LIVE_BROKERS.discard(self)
    def _detach_after_fork_child(self) -> None:
        """Drop inherited broker/SSH descriptors without signalling the parent."""

        self._stop.set()
        for endpoint in list(self._worker_endpoints):
            try:
                endpoint.close()
            except (OSError, EOFError):
                pass
        for transport in tuple(self._panic_transports):
            detach = getattr(transport, "detach_after_fork", None)
            if callable(detach):
                try:
                    detach()
                except Exception:
                    pass
        self._worker_endpoints = []
        self._worker_send_locks = {}
        self._sessions = {}
        self._task_sessions = {}
        self._service_leases.clear()
        self._admission_transports = {}
        self._panic_transports = []
        self._panic_events = []
        self._thread = None
        self._started = False
    def _submit(
        self,
        method: str,
        payload: dict[str, Any],
        *,
        priority: int,
        timeout_sec: float = _DEFAULT_REQUEST_TIMEOUT_SEC,
    ) -> Any:
        self.start()
        if self._stop.is_set():
            raise RemoteWorkspaceError(
                "broker_closed",
                "Remote workspace broker is closed.",
                phase="stream",
            )
        future: concurrent.futures.Future[Any] = concurrent.futures.Future()
        with self._state_lock:
            self._request_sequence += 1
            sequence = self._request_sequence
        try:
            self._requests.put_nowait(_BrokerRequest(priority, sequence, method, payload, future))
        except queue.Full as exc:
            raise RemoteWorkspaceError(
                "broker_overloaded",
                "Remote workspace broker queue is full.",
                phase="stream",
                retryable=True,
            ) from exc
        try:
            return future.result(timeout=timeout_sec)
        except concurrent.futures.TimeoutError as exc:
            raise RemoteWorkspaceError(
                "remote_request_timeout",
                "Remote workspace request exceeded its Home deadline.",
                phase="stream",
                completion="unknown",
                retryable=True,
            ) from exc
    def _new_transport(self, request: SessionOpenRequest) -> RemoteTransport:
        transport = self._transport_factory(request)
        self._panic_transports.append(transport)
        if self._stop.is_set():
            self.panic()
            raise RemoteWorkspaceError("broker_closed", "Remote workspace broker is closed.", phase="stream")
        return transport
    def _run(self) -> None:
        while not self._stop.is_set():
            self._poll_worker_endpoints()
            try:
                request = self._requests.get(timeout=_BROKER_POLL_SEC)
            except queue.Empty:
                continue
            if request.future.cancelled():
                continue
            if not self._inflight.acquire(blocking=False):
                request.future.set_exception(
                    RemoteWorkspaceError(
                        "broker_overloaded",
                        "Remote workspace broker has too many in-flight requests.",
                        phase="stream",
                        retryable=True,
                    )
                )
                continue
            submitted = self._io_executor.submit(
                self._dispatch,
                request.method,
                request.payload,
            )
            submitted.add_done_callback(
                lambda completed, target=request.future: self._complete_request(target, completed)
            )
    def _poll_worker_endpoints(self) -> None:
        with self._state_lock:
            endpoints = list(self._worker_endpoints)
        dead: list[Connection] = []
        for endpoint in endpoints:
            try:
                if not endpoint.poll(0):
                    continue
                message = endpoint.recv()
                if not self._inflight.acquire(blocking=False):
                    endpoint.send(
                        {
                            "correlation_id": (
                                str(message.get("correlation_id") or "") if isinstance(message, dict) else ""
                            ),
                            "ok": False,
                            "error": {
                                "code": "broker_overloaded",
                                "message": "Remote broker has too many in-flight requests.",
                                "phase": "stream",
                                "completion": "not_started",
                                "retryable": True,
                                "details": {},
                            },
                        }
                    )
                    continue
                submitted = self._io_executor.submit(
                    self._dispatch_pipe_message,
                    message,
                )
                submitted.add_done_callback(lambda completed, target=endpoint: self._complete_pipe(target, completed))
            except (EOFError, OSError):
                dead.append(endpoint)
        if dead:
            with self._state_lock:
                self._worker_endpoints = [endpoint for endpoint in self._worker_endpoints if endpoint not in dead]
                for endpoint in dead:
                    self._worker_send_locks.pop(id(endpoint), None)
            for endpoint in dead:
                try:
                    endpoint.close()
                except (OSError, EOFError):
                    pass
    def _complete_request(
        self,
        target: concurrent.futures.Future[Any],
        completed: concurrent.futures.Future[Any],
    ) -> None:
        self._inflight.release()
        if target.cancelled():
            return
        try:
            target.set_result(completed.result())
        except BaseException as exc:
            target.set_exception(exc)
    def _complete_pipe(
        self,
        endpoint: Connection,
        completed: concurrent.futures.Future[dict[str, Any]],
    ) -> None:
        self._inflight.release()
        try:
            response = completed.result()
        except BaseException as exc:
            response = {
                "correlation_id": "",
                "ok": False,
                "error": _error_dict(exc),
            }
        with self._state_lock:
            lock = self._worker_send_locks.get(id(endpoint))
        if lock is None:
            return
        try:
            with lock:
                endpoint.send(response)
        except (EOFError, OSError):
            return
    def _dispatch_pipe_message(self, message: Any) -> dict[str, Any]:
        correlation_id = str(message.get("correlation_id") or "") if isinstance(message, dict) else ""
        try:
            if not isinstance(message, dict):
                raise ValueError("worker broker message must be an object")
            method = str(message.get("method") or "")
            payload = message.get("payload")
            if not isinstance(payload, dict):
                raise ValueError("worker broker payload must be an object")
            result = self._dispatch(method, payload)
            if isinstance(result, (PreparedRemoteCall, ToolExecutionEnvelope)):
                result = dataclasses.asdict(result)
            return {"correlation_id": correlation_id, "ok": True, "result": result}
        except Exception as exc:
            return {
                "correlation_id": correlation_id,
                "ok": False,
                "error": _error_dict(exc),
            }
    def _dispatch(self, method: str, payload: dict[str, Any]) -> Any:
        handlers: dict[str, Callable[[dict[str, Any]], Any]] = {
            "prepare": self._prepare_on_broker,
            "execute_prepared": self._execute_on_broker,
            "abort_prepared": self._abort_on_broker,
            "fetch_blob": self._fetch_blob_on_broker,
            "cancel": self._cancel_on_broker,
            "cancel_connection": self._cancel_connection_on_broker,
            "close_project_session": self._close_project_session_on_broker,
            "recover": self._recover_on_broker,
            "reconnect_connection": self._reconnect_connection_on_broker,
            "admit": self._admit_on_broker,
            "open_browser_forward": self._open_browser_forward_on_broker,
            "close_browser_forward": self._close_browser_forward_on_broker,
        }
        handler = handlers.get(method)
        if handler is None:
            raise ValueError(f"unsupported broker method: {method}")
        return handler(payload)
    def _open_browser_forward_on_broker(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self.open_browser_forward(
            payload["workspace_ref"],
            remote_port=int(payload["remote_port"]),
            task_id=_opaque(payload["task_id"], "task_id"),
        )

    def _close_browser_forward_on_broker(self, payload: dict[str, Any]) -> bool:
        return self.close_browser_forward(str(payload.get("forward_id") or ""))
    def _session_request(
        self,
        connection: Mapping[str, Any],
        remote_root: str,
        project_id: str,
        workspace_id: str,
    ) -> SessionOpenRequest:
        row = _json_copy(connection, "connection")
        connection_id = _opaque(row.get("id"), "connection_id")
        alias = str(row.get("ssh_alias") or "")
        if not _SSH_ALIAS_RE.fullmatch(alias):
            raise ValueError("ssh_alias is invalid")
        row["id"] = connection_id
        return SessionOpenRequest(
            connection=row,
            remote_root=str(remote_root),
            project_id=str(project_id),
            workspace_id=str(workspace_id),
            server_generation=self.server_generation,
            capability_manifest=dict(self.capability_projection),
            drive_root=self.drive_root,
            bundle_dir=self.bundle_dir,
            ssh_binary=self.ssh_binary,
        )
    def _admit_on_broker(self, payload: dict[str, Any]) -> dict[str, Any]:
        connection = payload.get("connection")
        connection = connection if isinstance(connection, Mapping) else {}
        lock_key = (
            _opaque(connection.get("id"), "connection_id"),
            _opaque(payload.get("project_id"), "project_id"),
            str(payload.get("workspace_id") or payload.get("remote_root") or ""),
        )
        with self._state_lock:
            lock = self._admission_key_locks.setdefault(lock_key, threading.Lock())
        with lock:
            return self._admit_locked(payload)

    def _admit_locked(self, payload: dict[str, Any]) -> dict[str, Any]:
        request = self._session_request(
            payload["connection"],
            payload["remote_root"],
            payload["project_id"],
            payload.get("workspace_id") or "",
        )
        raw_task_id = str(payload.get("task_id") or "")
        task_id = "" if raw_task_id.startswith("project:") else raw_task_id
        cancel = payload["cancel"]
        external_cancel = payload.get("external_cancel")
        if cancel.is_set() or (external_cancel is not None and external_cancel.is_set()):
            raise RemoteWorkspaceError("admission_cancelled", "Remote admission was cancelled.", phase="connect")
        if not request.workspace_id:
            with self._state_lock:
                root_match = next(
                    (
                        session
                        for key, session in self._sessions.items()
                        if key[0] == request.connection["id"]
                        and key[1] == request.project_id
                        and key[3] == self.server_generation
                        and session.remote_root.rstrip("/") == request.remote_root.rstrip("/")
                    ),
                    None,
                )
            if root_match is not None:
                request = dataclasses.replace(
                    request,
                    workspace_id=root_match.key[2],
                )
        if request.workspace_id:
            existing_key = (
                request.connection["id"],
                request.project_id,
                request.workspace_id,
                self.server_generation,
            )
            with self._state_lock:
                existing = self._sessions.get(existing_key)
            if existing is not None:
                if task_id:
                    with self._state_lock:
                        self._admission_transports[task_id] = (existing.transport, False)
                try:
                    staged = stage_remote_task_attachments(
                        existing,
                        task_id,
                        payload.get("attachment_manifest"),
                        payload.get("attachment_blobs"),
                    )
                    if cancel.is_set() or (external_cancel is not None and external_cancel.is_set()):
                        existing.transport.cancel({"task_id": task_id, "request_id": "", "operation_id": ""})
                        raise RemoteWorkspaceError(
                            "admission_cancelled",
                            "Remote admission was cancelled.",
                            phase="connect",
                        )
                except BaseException:
                    if task_id:
                        try:
                            existing.transport.cancel(
                                {
                                    "task_id": task_id,
                                    "request_id": "",
                                    "operation_id": "",
                                }
                            )
                        except Exception:
                            pass
                    raise
                if task_id:
                    with self._state_lock:
                        self._task_sessions[task_id] = existing_key
                return remote_task_admission_result(
                    existing,
                    staged,
                )
        transport = self._new_transport(request)
        if task_id:
            with self._state_lock:
                self._admission_transports[task_id] = (transport, True)
        try:
            facts = transport.handshake()
            if cancel.is_set() or (external_cancel is not None and external_cancel.is_set()):
                raise RemoteWorkspaceError("admission_cancelled", "Remote admission was cancelled.", phase="connect")
            observed_host = _opaque(facts.get("host_id"), "host_id")
            expected_host = str(request.connection.get("expected_host_id") or "")
            if expected_host and expected_host != observed_host:
                raise RemoteWorkspaceError(
                    "host_identity_mismatch",
                    "Remote host identity changed; explicit re-trust is required.",
                    phase="bootstrap",
                )
            observed_workspace = _opaque(facts.get("workspace_id"), "workspace_id")
            if request.workspace_id and request.workspace_id != observed_workspace:
                raise RemoteWorkspaceError(
                    "workspace_identity_mismatch", "Remote workspace identity changed.", phase="bootstrap"
                )
            if facts.get("capability_hash") != self.capability_projection["manifest_sha256"]:
                raise RemoteWorkspaceError(
                    "capability_mismatch", "Remote execd capabilities differ from Home.", phase="bootstrap"
                )
            if str(facts.get("canonical_root") or "") != request.remote_root.rstrip("/"):
                raise RemoteWorkspaceError(
                    "workspace_root_mismatch",
                    "Remote canonical git root differs from the selected path.",
                    phase="bootstrap",
                )
            identity = getattr(transport, "artifact_identity", None)
            expected_artifact = identity() if callable(identity) else {}
            if expected_artifact and any(
                facts.get(field) != value
                for field, value in expected_artifact.items()
                if field != "artifact_size" and value
            ):
                raise RemoteWorkspaceError(
                    "execd_artifact_mismatch",
                    "Remote execd artifact identity differs from Home selection.",
                    phase="bootstrap",
                )
            key = (request.connection["id"], request.project_id, observed_workspace, self.server_generation)
            session = _Session(key, request.connection, request.remote_root, transport, dict(facts))
            inserted = False
            with self._state_lock:
                existing = self._sessions.get(key)
                if existing is None:
                    self._sessions[key] = session
                    selected = session
                    inserted = True
                else:
                    selected = existing
                self._connections[request.connection["id"]] = request.connection
            if selected is not session:
                transport.close()
                session = selected
                if task_id:
                    with self._state_lock:
                        self._admission_transports[task_id] = (session.transport, False)
            elif task_id:
                with self._state_lock:
                    self._admission_transports[task_id] = (session.transport, False)
            try:
                staged = stage_remote_task_attachments(
                    session,
                    task_id,
                    payload.get("attachment_manifest"),
                    payload.get("attachment_blobs"),
                )
                if cancel.is_set() or (external_cancel is not None and external_cancel.is_set()):
                    session.transport.cancel({"task_id": task_id, "request_id": "", "operation_id": ""})
                    raise RemoteWorkspaceError(
                        "admission_cancelled",
                        "Remote admission was cancelled.",
                        phase="connect",
                    )
            except BaseException:
                if task_id:
                    try:
                        session.transport.cancel(
                            {
                                "task_id": task_id,
                                "request_id": "",
                                "operation_id": "",
                            }
                        )
                    except Exception:
                        pass
                if inserted:
                    with self._state_lock:
                        if self._sessions.get(key) is session:
                            self._sessions.pop(key, None)
                    session.transport.close()
                raise
            if task_id:
                with self._state_lock:
                    self._task_sessions[task_id] = key
            return remote_task_admission_result(
                session,
                staged,
            )
        except BaseException:
            transport.close()
            raise

    def _session_for_ref(
        self,
        raw_ref: Mapping[str, Any],
        *,
        task_id: str = "",
        parent_task_id: str = "", project_id: str = "",
    ) -> _Session:
        ref = normalize_workspace_ref(dict(raw_ref))
        if ref.get("kind") != "ssh":
            raise ValueError("remote broker requires an SSH workspace ref")
        connection_id = str(ref["connection_id"])
        workspace_id = str(ref["workspace_id"])
        with self._state_lock:
            key = self._task_sessions.get(task_id) if task_id else None
            if key is None and task_id and parent_task_id:
                key = self._task_sessions.get(parent_task_id)
            if key is None and task_id and project_id:
                key = (
                    connection_id,
                    project_id,
                    workspace_id,
                    self.server_generation,
                )
            if key is None and task_id:
                raise RemoteWorkspaceError(
                    "task_session_unbound",
                    "Task is not bound to a remote workspace session.",
                    phase="authorize",
                )
            if key is not None and ((key[0], key[2]) != (connection_id, workspace_id)
                                    or (project_id and key[1] != project_id)):
                raise RemoteWorkspaceError(
                    "task_session_mismatch",
                    "Task is bound to another remote workspace session.",
                    phase="authorize",
                )
            candidates = [candidate for candidate in self._sessions
                          if (candidate[0], candidate[2]) == (connection_id, workspace_id)]
            if key is None:
                if len(candidates) > 1:
                    raise RemoteWorkspaceError(
                        "remote_session_ambiguous",
                        "Remote workspace is bound to multiple projects; task identity is required.",
                        phase="authorize",
                    )
                key = candidates[0] if candidates else None
            session = self._sessions.get(key) if key is not None else None
            if session is not None and task_id:
                self._task_sessions.setdefault(task_id, key)
        if session is None:
            raise RemoteWorkspaceError(
                "remote_session_disconnected",
                "Remote workspace session is not connected.",
                phase="connect",
                retryable=True,
                details={"connection_id": connection_id, "workspace_id": workspace_id},
            )
        session.last_used_at = time.monotonic()
        return session

    def _prepare_on_broker(self, payload: dict[str, Any]) -> dict[str, Any]:
        task_id = _optional_opaque(payload.get("task_id"), "task_id")
        parent_task_id = _optional_opaque(payload.get("parent_task_id"), "parent_task_id")
        project_id = _optional_opaque(payload.get("project_id"), "project_id")
        session = self._session_for_ref(
            payload["workspace_ref"], task_id=task_id,
            parent_task_id=parent_task_id, project_id=project_id,
        )
        request_id = _opaque(payload.get("request_id"), "request_id")
        operation_id = _opaque(payload.get("operation_id"), "operation_id")
        tool = str(payload.get("tool") or "")
        args = _json_copy(payload.get("args"), "args")
        blobs = payload.get("blobs") if isinstance(payload.get("blobs"), dict) else {}
        bounded_blobs = {
            _opaque(blob_id, "blob_id"): bytes(value)
            for blob_id, value in blobs.items()
            if isinstance(value, (bytes, bytearray, memoryview))
        }
        response = session.transport.prepare(
            {
                "request_id": request_id,
                "operation_id": operation_id,
                "tool": tool,
                "args": args,
                "task_id": task_id,
                "workspace_id": session.key[2],
                "deadline_ms": payload.get("deadline_ms"),
            },
            bounded_blobs,
        )
        return _validated_prepared(response)

    def _execute_on_broker(self, payload: dict[str, Any]) -> dict[str, Any]:
        task_id = _optional_opaque(payload.get("task_id"), "task_id")
        session = self._session_for_ref(payload["workspace_ref"], task_id=task_id)
        prepared = _prepared_from_dict(payload.get("prepared"))
        canonical_args = _json_copy(payload.get("canonical_args"), "canonical_args")
        if canonical_json(canonical_args) != canonical_json(prepared.execution_args):
            raise RemoteWorkspaceError(
                "prepared_arguments_mismatch",
                "Home authorization does not match target-prepared arguments.",
                phase="authorize",
            )
        response_timeout = _execution_wait_timeout(
            canonical_args,
            payload.get("timeout_sec"),
        )

        response = _validated_envelope_dict(
            session.transport.execute_prepared(
                {
                    "request_id": prepared.request_id,
                    "operation_id": prepared.operation_id,
                    "prepared_hash": prepared.prepared_hash,
                    "prepared_token": prepared.prepared_token,
                    "task_id": task_id,
                    "_home_import_kind": "task_result_v1",
                    "_home_import_context": {},
                    "_response_timeout_sec": response_timeout,
                }
            )
        )
        self._service_leases.observe(session.key, prepared, response, task_id=task_id)
        return response

    def _abort_on_broker(self, payload: dict[str, Any]) -> bool:
        task_id = _optional_opaque(payload.get("task_id"), "task_id")
        session = self._session_for_ref(payload["workspace_ref"], task_id=task_id)
        prepared = _prepared_from_dict(payload.get("prepared"))
        return bool(
            session.transport.abort_prepared(
                {
                    "request_id": prepared.request_id,
                    "operation_id": prepared.operation_id,
                    "prepared_hash": prepared.prepared_hash,
                    "prepared_token": prepared.prepared_token,
                    "reason": str(payload.get("reason") or "denied")[:1000],
                }
            )
        )

    def _fetch_blob_on_broker(self, payload: dict[str, Any]) -> bytes:
        session = self._session_for_ref(
            payload["workspace_ref"],
            task_id=_opaque(payload.get("task_id"), "task_id"),
        )
        blob_id = _opaque(payload.get("blob_id"), "blob_id")
        max_bytes = int(payload.get("max_bytes") or 0)
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        return session.transport.fetch_blob(blob_id, max_bytes)

    def _cancel_on_broker(self, payload: dict[str, Any]) -> bool:
        task_id = _optional_opaque(payload.get("task_id"), "task_id")
        session = self._session_for_ref(payload["workspace_ref"], task_id=task_id)
        cancelled = bool(
            session.transport.cancel(
                {
                    "task_id": task_id,
                    "request_id": _optional_opaque(payload.get("request_id"), "request_id"),
                    "operation_id": _optional_opaque(payload.get("operation_id"), "operation_id"),
                }
            )
        )
        if task_id:
            with self._state_lock:
                self._task_sessions.pop(task_id, None)
            self._browser_forwards.close_task(task_id)
        return cancelled

    def _cancel_connection_on_broker(self, payload: dict[str, Any]) -> int:
        connection_id = _opaque(payload.get("connection_id"), "connection_id")
        with self._state_lock:
            victims = [(key, session) for key, session in self._sessions.items() if key[0] == connection_id]
            for key, _session in victims:
                self._sessions.pop(key, None)
                for task_id, task_key in list(self._task_sessions.items()):
                    if task_key == key:
                        self._task_sessions.pop(task_id, None)
                self._service_leases.discard_session(key)
        for _key, session in victims:
            try:
                session.transport.cancel({"task_id": "", "request_id": "", "operation_id": ""})
            except Exception:
                pass
            session.transport.close()
        self._browser_forwards.close_connection(connection_id)
        return len(victims)

    def _close_project_session_on_broker(
        self,
        payload: dict[str, Any],
    ) -> bool:
        ref = normalize_workspace_ref(dict(payload.get("workspace_ref") or {}))
        if ref is None or ref.get("kind") != "ssh":
            raise ValueError("close_project_session requires an SSH workspace ref")
        key = (str(ref["connection_id"]), _opaque(
            payload.get("project_id"), "project_id"
        ), str(ref["workspace_id"]), self.server_generation)
        with self._state_lock:
            session = self._sessions.pop(key, None)
            task_ids = [task_id for task_id, task_key
                        in self._task_sessions.items() if task_key == key]
            for task_id in task_ids:
                self._task_sessions.pop(task_id, None)
            self._service_leases.discard_session(key)
        if session is None:
            return False
        for task_id in task_ids:
            task_lease = getattr(session.transport, "task_lease", None)
            if callable(task_lease):
                task_lease(task_id, forget=True)
            self._browser_forwards.close_task(task_id)
        session.transport.close()
        return True

    def _refresh_service_leases(self, connection_id: str) -> None:
        refresh_deadline = time.monotonic() + 5.0
        for candidate in self._service_leases.candidates(connection_id)[:128]:
            remaining = refresh_deadline - time.monotonic()
            if remaining <= 0:
                break
            key = candidate["session_key"]
            with self._state_lock:
                session = self._sessions.get(key)
            if session is None:
                # Observable session teardown owns lease removal.  If a
                # session is merely unavailable to this refresh, retain the
                # fence rather than claiming an unproven service is dead.
                continue
            task_id = str(candidate.get("task_id") or "")
            task_lease = getattr(session.transport, "task_lease", None)
            was_tracked = bool(
                callable(task_lease) and task_lease(task_id)
            )
            request_id = f"service_refresh_{uuid.uuid4().hex}"
            operation_id = f"service_refresh_{uuid.uuid4().hex}"
            try:
                raw = session.transport.prepare(
                    {
                        "request_id": request_id,
                        "operation_id": operation_id,
                        "tool": "service_status",
                        "args": {
                            "name": str(candidate.get("name") or "service"),
                            "_service_ref": dict(
                                candidate.get("service_ref") or {}
                            ),
                        },
                        "task_id": task_id,
                        "workspace_id": session.key[2],
                        "deadline_ms": int(time.time() * 1000) + 5_000,
                        "_response_timeout_sec": remaining,
                    },
                    {},
                )
                prepared = _prepared_from_dict(_validated_prepared(raw))
                response = _validated_envelope_dict(
                    session.transport.execute_prepared(
                        {
                            "request_id": prepared.request_id,
                            "operation_id": prepared.operation_id,
                            "prepared_hash": prepared.prepared_hash,
                            "prepared_token": prepared.prepared_token,
                            "task_id": task_id,
                            "_home_import_kind": "task_result_v1",
                            "_home_import_context": {},
                            "_response_timeout_sec": max(
                                0.1,
                                refresh_deadline - time.monotonic(),
                            ),
                        }
                    )
                )
                self._service_leases.observe(
                    session.key,
                    prepared,
                    response,
                    task_id=task_id,
                )
            except Exception:
                # Lifecycle checks fail closed: an unproven-dead service keeps
                # its owner fence until a later authoritative refresh.
                continue
            finally:
                if callable(task_lease) and not was_tracked:
                    task_lease(task_id, forget=True)
    def _recover_on_broker(self, _payload: dict[str, Any]) -> list[dict[str, Any]]:
        from ouroboros.remote_pending_operations import recover_pending_on_broker

        return recover_pending_on_broker(self)
    def _reconnect_connection_on_broker(self, payload: dict[str, Any]) -> dict[str, Any]:
        connection = _json_copy(payload.get("connection"), "connection")
        connection_id = _opaque(connection.get("id"), "connection_id")
        timeout_sec = max(1.0, float(payload.get("timeout_sec") or 0))
        with self._state_lock:
            sessions = [session for key, session in self._sessions.items() if key[0] == connection_id]
        if not sessions:
            return _reconnect_failure(connection_id)
        recovered: list[dict[str, Any]] = []
        reconciliation: list[dict[str, Any]] = []
        for session in sessions:
            reconnect = getattr(session.transport, "reconnect", None)
            if not callable(reconnect):
                raise RemoteWorkspaceError(
                    "reconnect_unsupported",
                    "Remote transport does not support reconnect.",
                    phase="connect",
                )
            row = dict(reconnect(timeout_sec=timeout_sec))
            facts = row.get("handshake")
            if isinstance(facts, dict):
                prior = session.handshake
                stable = ("host_id", "workspace_id", "canonical_root", "capability_hash")
                if any(facts.get(field) != prior.get(field) for field in stable):
                    raise RemoteWorkspaceError(
                        "reconnect_identity_mismatch",
                        "Reconnected execd session changed its admitted identity.",
                        phase="bootstrap",
                    )
                session.handshake = dict(facts)
            recovered.append({"workspace_id": session.key[2], **row})
            reconciliation.extend(item for item in list(row.get("reconciliation") or []) if isinstance(item, dict))
        return {
            "status": "ready",
            "phase": "ready",
            "completion": "completed",
            "error_code": "",
            "action": "",
            "diagnostic": "",
            "log_refs": [],
            "connection_id": connection_id,
            "sessions": recovered,
            "reconciliation": reconciliation,
        }

RemoteWorkspaceBroker = RemoteSessionBroker


def _after_fork_child() -> None:
    global _REMOTE_WORKSPACE_SERVICE
    for broker in list(_LIVE_BROKERS):
        broker._detach_after_fork_child()
    _REMOTE_WORKSPACE_SERVICE = None
    _LIVE_BROKERS.clear()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_child)
