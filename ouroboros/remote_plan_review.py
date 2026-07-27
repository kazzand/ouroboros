"""Verified remote snapshot lifecycle for Home-owned plan review."""

from __future__ import annotations

import functools
import pathlib
import subprocess
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

_T = TypeVar("_T")


def materialized_plan_roots(ctx: Any) -> tuple[pathlib.Path, pathlib.Path] | None:
    """Return Home governance plus one verified SSH subject mirror, when needed."""

    from ouroboros.workspace_ref import is_remote_workspace

    if not is_remote_workspace(ctx):
        return None
    from ouroboros.workspace_executor import materialize_remote_workspace_snapshot

    snapshot = getattr(ctx, "_remote_plan_review_snapshot", None)
    if snapshot is None:
        snapshot = materialize_remote_workspace_snapshot(ctx)
        ctx._remote_plan_review_snapshot = snapshot
    governance = pathlib.Path(
        getattr(ctx, "system_repo_dir", None) or ctx.repo_dir
    ).resolve(strict=False)
    return governance, pathlib.Path(snapshot.root).resolve(strict=False)


def close_materialized_plan_snapshot(ctx: Any) -> None:
    snapshot = getattr(ctx, "_remote_plan_review_snapshot", None)
    if snapshot is None:
        return
    try:
        snapshot.close()
    finally:
        try:
            delattr(ctx, "_remote_plan_review_snapshot")
        except AttributeError:
            pass


def remote_snapshot_lifecycle(
    function: Callable[..., Awaitable[_T]],
) -> Callable[..., Awaitable[_T]]:
    """Close a verified remote mirror after either review success or failure."""

    @functools.wraps(function)
    async def wrapped(ctx: Any, *args: Any, **kwargs: Any) -> _T:
        try:
            return await function(ctx, *args, **kwargs)
        finally:
            close_materialized_plan_snapshot(ctx)

    return wrapped


def verified_snapshot_result(
    repo_dir: pathlib.Path,
    relative_path: str,
) -> subprocess.CompletedProcess[bytes]:
    """Read one confined file from a previously verified materialization."""

    root = pathlib.Path(repo_dir).resolve(strict=False)
    candidate = (root / relative_path).resolve(strict=False)
    candidate.relative_to(root)
    if candidate.is_file():
        return subprocess.CompletedProcess(
            ["verified-filesystem-snapshot", relative_path],
            0,
            stdout=candidate.read_bytes(),
            stderr=b"",
        )
    return subprocess.CompletedProcess(
        ["verified-filesystem-snapshot", relative_path],
        128,
        stdout=b"",
        stderr=b"path does not exist in verified snapshot",
    )
