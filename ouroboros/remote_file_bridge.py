"""Task-scoped loopback static origin for a stable remote file snapshot."""

from __future__ import annotations

import functools
import http.server
import mimetypes
import pathlib
import secrets
import threading
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote, urlparse

from ouroboros.workspace_executor import materialize_remote_workspace_snapshot
from ouroboros.workspace_ref import workspace_ref_for

_MAX_ASSET_BYTES = 25 * 1024 * 1024
_MAX_BRIDGE_BYTES = 64 * 1024 * 1024


class RemoteFileBridgeError(RuntimeError):
    pass


@dataclass
class RemoteFileBridge:
    """One immutable snapshot served behind an unguessable loopback path."""

    origin: str
    url: str
    token: str
    _server: http.server.ThreadingHTTPServer
    _thread: threading.Thread

    @classmethod
    def open(cls, subject: Any, remote_url: str) -> "RemoteFileBridge":
        workspace_ref = workspace_ref_for(subject)
        if workspace_ref is None or workspace_ref["kind"] != "ssh":
            raise RemoteFileBridgeError("remote file bridge requires an SSH workspace")
        relative = _remote_relative_path(
            remote_url,
            str(workspace_ref["remote_root"]),
        )
        snapshot = materialize_remote_workspace_snapshot(subject)
        try:
            target = snapshot.root.joinpath(*relative.parts)
            resolved = target.resolve(strict=True)
            resolved.relative_to(snapshot.root.resolve(strict=True))
            if not resolved.is_file():
                raise RemoteFileBridgeError("remote file target is not a file")
            assets = _load_assets(snapshot.root)
            if relative.as_posix() not in assets:
                raise RemoteFileBridgeError("remote file target exceeds bridge limits")
        finally:
            snapshot.close()
        token = secrets.token_urlsafe(32)
        handler = _handler_factory(assets, token)
        try:
            server = http.server.ThreadingHTTPServer(
                ("127.0.0.1", 0),
                handler,
            )
        except Exception:
            raise
        server.daemon_threads = True
        port = int(server.server_address[1])
        origin = f"http://127.0.0.1:{port}"
        path = "/".join(relative.parts)
        thread = threading.Thread(
            target=lambda: server.serve_forever(poll_interval=0.05),
            name=f"remote-file-bridge-{token[:10]}",
            daemon=True,
        )
        thread.start()
        return cls(
            origin=origin,
            url=f"{origin}/{token}/{path}",
            token=token,
            _server=server,
            _thread=thread,
        )

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not threading.current_thread():
            self._thread.join(timeout=2)


def _remote_relative_path(remote_url: str, remote_root: str) -> pathlib.PurePosixPath:
    parsed = urlparse(str(remote_url))
    if parsed.scheme != "file" or parsed.netloc not in {"", "localhost"}:
        raise RemoteFileBridgeError("remote file URL must use file:/// or file://localhost/")
    decoded = unquote(parsed.path)
    if "\x00" in decoded:
        raise RemoteFileBridgeError("remote file URL contains NUL")
    path = pathlib.PurePosixPath(decoded)
    root = pathlib.PurePosixPath(str(remote_root))
    if not path.is_absolute():
        raise RemoteFileBridgeError("remote file URL must be absolute")
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise RemoteFileBridgeError(
            "remote file URL escapes the admitted workspace"
        ) from exc
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise RemoteFileBridgeError("remote file URL path is unsafe")
    return relative


def _handler_factory(
    assets: dict[str, tuple[bytes, str]],
    token: str,
) -> type[http.server.BaseHTTPRequestHandler]:
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "OuroborosRemoteFile/1"
        sys_version = ""

        def _reject_write(self) -> None:
            self.send_error(405)

        do_POST = _reject_write
        do_PUT = _reject_write
        do_DELETE = _reject_write

        def log_message(self, _format: str, *args: Any) -> None:
            del args

        def _serve(self, *, include_body: bool) -> None:
            parsed = urlparse(self.path)
            parts = [part for part in unquote(parsed.path).split("/") if part]
            if not parts or not secrets.compare_digest(parts[0], token):
                self.send_error(404)
                return
            relative = parts[1:]
            if not relative or any(part in {".", ".."} for part in relative):
                self.send_error(404)
                return
            item = assets.get("/".join(relative))
            if item is None:
                self.send_error(404)
                return
            data, mime = item
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.end_headers()
            if include_body:
                self.wfile.write(data)

        do_GET = functools.partialmethod(_serve, include_body=True)
        do_HEAD = functools.partialmethod(_serve, include_body=False)

    return Handler


def _load_assets(root: pathlib.Path) -> dict[str, tuple[bytes, str]]:
    assets: dict[str, tuple[bytes, str]] = {}
    total = 0
    resolved_root = root.resolve(strict=True)
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(resolved_root)
            if not resolved.is_file():
                continue
            size = resolved.stat().st_size
            if size > _MAX_ASSET_BYTES:
                continue
            data = resolved.read_bytes()
        except (OSError, ValueError):
            continue
        total += len(data)
        if total > _MAX_BRIDGE_BYTES:
            raise RemoteFileBridgeError("remote file bridge exceeds its byte limit")
        rel = path.relative_to(root).as_posix()
        mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        assets[rel] = (data, mime)
    return assets
