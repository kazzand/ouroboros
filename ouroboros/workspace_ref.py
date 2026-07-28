"""Dependency-light project/task workspace placement contract."""

from __future__ import annotations

import pathlib
import posixpath
from collections.abc import Mapping
from typing import Any

try:
    from typing import Literal, NotRequired, Required, TypedDict  # type: ignore[attr-defined]
except ImportError:  # Python 3.10
    from typing_extensions import Literal, NotRequired, Required, TypedDict  # type: ignore[assignment]


class LocalWorkspaceRef(TypedDict):
    kind: Required[Literal["local"]]
    local_root: Required[str]


class SshWorkspaceRef(TypedDict):
    kind: Required[Literal["ssh"]]
    connection_id: Required[str]
    remote_root: Required[str]
    workspace_id: Required[str]


class WorkspaceRef(TypedDict, total=False):
    kind: Required[Literal["local", "ssh"]]
    local_root: NotRequired[str]
    connection_id: NotRequired[str]
    remote_root: NotRequired[str]
    workspace_id: NotRequired[str]


class RemoteWorkspacePathError(ValueError):
    """Raised when Home code asks an SSH workspace for a native Home path."""


def _clean_identity(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"workspace_ref.{field} is required")
    if any(ord(char) < 32 or ord(char) == 127 for char in text):
        raise ValueError(f"workspace_ref.{field} contains a control character")
    return text


def _normalize_remote_root(value: Any) -> str:
    text = _clean_identity(value, "remote_root").replace("\\", "/")
    if not text.startswith("/"):
        raise ValueError("workspace_ref.remote_root must be an absolute POSIX path")
    if any(part in {".", ".."} for part in text.split("/") if part):
        raise ValueError("workspace_ref.remote_root must not contain traversal segments")
    normalized = posixpath.normpath(text)
    if normalized in {"", ".", "/"}:
        raise ValueError("workspace_ref.remote_root must name a git worktree root")
    return normalized


def normalize_workspace_ref(raw: Any) -> WorkspaceRef | None:
    """Return a strict normalized ref, or ``None`` for an absent ref."""

    if raw in (None, "") or raw == {}:
        return None
    if not isinstance(raw, dict):
        raise ValueError("workspace_ref must be an object")
    kind = str(raw.get("kind") or "").strip().lower()
    if kind == "local":
        unknown = set(raw) - {"kind", "local_root"}
        if unknown:
            raise ValueError(f"workspace_ref.local has unknown fields: {sorted(unknown)}")
        root_text = _clean_identity(raw.get("local_root"), "local_root")
        root = pathlib.Path(root_text).expanduser()
        if not root.is_absolute():
            raise ValueError("workspace_ref.local_root must be an absolute path")
        return {"kind": "local", "local_root": str(root.resolve(strict=False))}
    if kind == "ssh":
        unknown = set(raw) - {"kind", "connection_id", "remote_root", "workspace_id"}
        if unknown:
            raise ValueError(f"workspace_ref.ssh has unknown fields: {sorted(unknown)}")
        return {
            "kind": "ssh",
            "connection_id": _clean_identity(raw.get("connection_id"), "connection_id"),
            "remote_root": _normalize_remote_root(raw.get("remote_root")),
            "workspace_id": _clean_identity(raw.get("workspace_id"), "workspace_id"),
        }
    raise ValueError("workspace_ref.kind must be 'local' or 'ssh'")


def _field(source: Any, name: str, default: Any = None) -> Any:
    if isinstance(source, Mapping):
        return source.get(name, default)
    return getattr(source, name, default)


def workspace_ref_for(ctx: Any, *, include_room_lens: bool = False) -> WorkspaceRef | None:
    """Read sealed placement from a live context or durable task/result record."""

    metadata_sources = (
        _field(ctx, "task_metadata"),
        _field(ctx, "metadata"),
    )
    raw = None
    for metadata in metadata_sources:
        if isinstance(metadata, Mapping):
            raw = metadata.get("_sealed_workspace_ref")
        if raw not in (None, "", {}):
            break
    if raw in (None, "", {}) and include_room_lens:
        for metadata in metadata_sources:
            if isinstance(metadata, Mapping):
                raw = metadata.get("_project_room_workspace_ref")
            if raw not in (None, "", {}):
                break
    return normalize_workspace_ref(raw)


def has_workspace(ctx: Any) -> bool:
    ref = workspace_ref_for(ctx)
    if ref is not None:
        return True
    root = _field(ctx, "workspace_root")
    if not root:
        for metadata in (_field(ctx, "task_metadata"), _field(ctx, "metadata")):
            if isinstance(metadata, Mapping):
                root = metadata.get("workspace_root")
            if root:
                break
    return bool(str(root or "").strip())


def is_remote_workspace(ctx: Any) -> bool:
    ref = workspace_ref_for(ctx)
    return bool(ref and ref["kind"] == "ssh")


def local_workspace_path_for(ctx: Any) -> pathlib.Path:
    """Return the native Home path or fail loudly for an SSH placement."""

    ref = workspace_ref_for(ctx)
    if ref is not None:
        if ref["kind"] == "ssh":
            raise RemoteWorkspacePathError(
                "SSH workspace has no native Home path; route the operation through its executor"
            )
        return pathlib.Path(ref["local_root"])
    root = _field(ctx, "workspace_root")
    if not root:
        for metadata in (_field(ctx, "task_metadata"), _field(ctx, "metadata")):
            if isinstance(metadata, Mapping):
                root = metadata.get("workspace_root")
            if root:
                break
    if not str(root or "").strip():
        raise ValueError("task has no workspace")
    return pathlib.Path(root)
