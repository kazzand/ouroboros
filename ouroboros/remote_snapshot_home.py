"""Home materialization of integrity-complete remote snapshot manifests."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import tempfile
from typing import Any

from ouroboros.workspace_native import path_is_relative_to

_POLICY_EXCLUSION_REASONS = frozenset(
    {"protected_artifact", "sensitive_file"}
)


def _canonical_manifest_path(
    value: Any,
    error_type: type[Exception],
) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise error_type("remote snapshot path is not canonical")
    candidate = pathlib.PurePosixPath(value)
    if (
        candidate.is_absolute()
        or value != candidate.as_posix()
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise error_type("remote snapshot path is not canonical")
    return value


def _has_path_ancestor(
    path: str,
    candidates: set[str],
    *,
    include_self: bool = True,
) -> bool:
    parts = path.split("/")
    stop = len(parts) + 1 if include_self else len(parts)
    return any(
        "/".join(parts[:index]) in candidates
        for index in range(1, stop)
    )


def _manifest_count(
    manifest: dict[str, Any],
    key: str,
    error_type: type[Exception],
) -> int:
    value = manifest.get(key)
    if type(value) is not int or value < 0:
        raise error_type(f"remote snapshot {key} is invalid")
    return value


def _validate_manifest_contract(
    manifest: dict[str, Any],
    error_type: type[Exception],
) -> None:
    entries = manifest.get("entries")
    exclusions = manifest.get("exclusions")
    failures = manifest.get("failures")
    policy_exclusions = manifest.get("policy_exclusions")
    protected_paths = manifest.get("protected_paths")
    if manifest.get("schema_version") != 3:
        raise error_type("remote snapshot schema is unsupported")
    if not all(
        isinstance(value, list)
        for value in (
            entries,
            exclusions,
            failures,
            policy_exclusions,
            protected_paths,
        )
    ):
        raise error_type("remote snapshot integrity declaration is invalid")
    assert isinstance(entries, list)
    assert isinstance(exclusions, list)
    assert isinstance(failures, list)
    assert isinstance(policy_exclusions, list)
    assert isinstance(protected_paths, list)
    if (
        manifest.get("unstable") is not False
        or manifest.get("integrity_complete") is not True
        or manifest.get("materializable") is not True
        or failures
        or _manifest_count(manifest, "failure_count", error_type)
        != len(failures)
    ):
        raise error_type(
            "remote snapshot is partial or unstable; refusing local review/finalization"
        )

    def policy_rows(raw_rows: list[Any]) -> list[tuple[str, str]]:
        rows: list[tuple[str, str]] = []
        for row in raw_rows:
            if not isinstance(row, dict):
                raise error_type("remote snapshot policy exclusions are invalid")
            path = _canonical_manifest_path(row.get("path"), error_type)
            reason = str(row.get("reason") or "")
            if reason not in _POLICY_EXCLUSION_REASONS:
                raise error_type("remote snapshot policy exclusions are invalid")
            rows.append((path, reason))
        if len(set(rows)) != len(rows):
            raise error_type("remote snapshot policy exclusions are invalid")
        return sorted(rows)

    policy = policy_rows(policy_exclusions)
    if policy_rows(exclusions) != policy:
        raise error_type("remote snapshot exclusion declarations disagree")
    if (
        _manifest_count(manifest, "policy_excluded_count", error_type)
        != len(policy)
        or _manifest_count(manifest, "excluded_count", error_type)
        != len(policy)
    ):
        raise error_type("remote snapshot exclusion count is invalid")
    expected_scope = "policy_filtered" if policy else "full"
    if manifest.get("policy_scope") != expected_scope:
        raise error_type("remote snapshot policy scope is invalid")
    expected_complete = expected_scope == "full"
    if manifest.get("complete") is not expected_complete:
        raise error_type("remote snapshot completeness declaration is invalid")
    _manifest_count(manifest, "total_bytes", error_type)

    entry_paths: set[str] = set()
    for row in entries:
        if not isinstance(row, dict):
            raise error_type("remote snapshot row is invalid")
        path = _canonical_manifest_path(row.get("path"), error_type)
        if path in entry_paths or _has_path_ancestor(path, entry_paths):
            raise error_type("remote snapshot entry topology is ambiguous")
        entry_paths.add(path)
    if any(
        _has_path_ancestor(path, entry_paths, include_self=False)
        for path in entry_paths
    ):
        raise error_type("remote snapshot entry topology is ambiguous")
    policy_paths = {path for path, _reason in policy}
    if any(
        _has_path_ancestor(path, policy_paths)
        for path in entry_paths
    ) or any(
        _has_path_ancestor(path, entry_paths)
        for path in policy_paths
    ):
        raise error_type("remote snapshot entries overlap policy exclusions")

    canonical_protected = [
        _canonical_manifest_path(path, error_type)
        for path in protected_paths
    ]
    if len(set(canonical_protected)) != len(canonical_protected):
        raise error_type("remote snapshot protected paths are invalid")


def materialize_snapshot(
    subject: Any,
    *,
    max_files: int,
    max_bytes: int,
):
    from ouroboros.remote_workspace import get_remote_workspace_service
    from ouroboros.workspace_executor import (
        RemoteWorkspaceOperationError,
        RemoteWorkspaceSnapshot,
        _subject_task_id,
        execute_remote_system_operation,
    )
    from ouroboros.workspace_ref import workspace_ref_for

    workspace_ref = workspace_ref_for(subject)
    if workspace_ref is None or workspace_ref["kind"] != "ssh":
        raise ValueError("remote snapshot requires a sealed SSH workspace")
    envelope = execute_remote_system_operation(
        subject,
        "snapshot_manifest_and_blob_export",
        {},
    )
    trace = getattr(envelope, "trace", {})
    manifest = trace.get("snapshot") if isinstance(trace, dict) else None
    if not isinstance(manifest, dict):
        raise RemoteWorkspaceOperationError("remote snapshot omitted its manifest")
    _validate_manifest_contract(manifest, RemoteWorkspaceOperationError)
    entries = manifest.get("entries")
    policy_exclusions = manifest.get("policy_exclusions")
    assert isinstance(entries, list)
    assert isinstance(policy_exclusions, list)
    if len(entries) > max(1, int(max_files)):
        raise RemoteWorkspaceOperationError("remote snapshot exceeds the file limit")
    declared_total = int(manifest.get("total_bytes") or 0)
    if declared_total > max(1, int(max_bytes)):
        raise RemoteWorkspaceOperationError("remote snapshot exceeds the byte limit")
    service = get_remote_workspace_service()
    if service is None:
        raise RemoteWorkspaceOperationError("remote workspace broker is unavailable")
    temp_root = pathlib.Path(tempfile.mkdtemp(prefix="ouroboros-remote-snapshot-"))
    materialized = temp_root / "workspace"
    materialized.mkdir()
    consumed = 0
    canonical_entries: list[dict[str, Any]] = []
    try:
        for raw in entries:
            if not isinstance(raw, dict):
                raise RemoteWorkspaceOperationError("remote snapshot row is invalid")
            rel = str(raw.get("path") or "").replace("\\", "/")
            parts = [part for part in rel.split("/") if part not in {"", "."}]
            if not parts or any(part == ".." for part in parts):
                raise RemoteWorkspaceOperationError("remote snapshot path is unsafe")
            target = materialized.joinpath(*parts)
            if not path_is_relative_to(
                target.parent.resolve(strict=False),
                materialized,
            ):
                raise RemoteWorkspaceOperationError(
                    "remote snapshot path escapes materialization"
                )
            digest = str(raw.get("sha256") or "")
            size = int(raw.get("size") or 0)
            if not digest or size < 0:
                raise RemoteWorkspaceOperationError(
                    "remote snapshot blob declaration is invalid"
                )
            consumed += size
            if consumed > max(1, int(max_bytes)):
                raise RemoteWorkspaceOperationError(
                    "remote snapshot exceeds the byte limit"
                )
            data = service.fetch_blob(
                workspace_ref,
                digest,
                max_bytes=size,
                task_id=_subject_task_id(subject),
            )
            if not isinstance(data, bytes) or len(data) != size:
                raise RemoteWorkspaceOperationError(
                    "remote snapshot blob size mismatch"
                )
            if hashlib.sha256(data).hexdigest() != digest:
                raise RemoteWorkspaceOperationError(
                    "remote snapshot blob digest mismatch"
                )
            kind = str(raw.get("kind") or "file")
            if kind == "symlink":
                target.parent.mkdir(parents=True, exist_ok=True)
                link_target = data.decode(
                    "utf-8",
                    errors="surrogateescape",
                )
                if pathlib.Path(link_target).is_absolute() or not path_is_relative_to(
                    (target.parent / link_target).resolve(strict=False),
                    materialized,
                ):
                    raise RemoteWorkspaceOperationError(
                        "remote snapshot symlink escapes materialization"
                    )
                os.symlink(link_target, target)
            elif kind == "file":
                _atomic_materialized_write(target, data)
                try:
                    os.chmod(target, int(raw.get("mode") or 0o600) & 0o777)
                except OSError:
                    pass
            else:
                raise RemoteWorkspaceOperationError(
                    "remote snapshot file kind is invalid"
                )
            canonical_entries.append({
                "path": "/".join(parts),
                "kind": kind,
                "sha256": digest,
                "size": size,
                "mode": int(raw.get("mode") or 0) & 0o777,
            })
        canonical_entries.sort(key=lambda row: row["path"])
        if consumed != declared_total:
            raise RemoteWorkspaceOperationError(
                "remote snapshot byte total mismatch"
            )
        encoded = json.dumps(
            canonical_entries,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        if hashlib.sha256(encoded).hexdigest() != str(
            manifest.get("content_fingerprint") or ""
        ):
            raise RemoteWorkspaceOperationError(
                "remote snapshot content fingerprint mismatch"
            )
        canonical_policy = sorted(
            {
                (
                    str(row.get("path") or ""),
                    str(row.get("reason") or ""),
                )
                for row in policy_exclusions
                if isinstance(row, dict)
            }
        )
        if len(canonical_policy) != len(policy_exclusions):
            raise RemoteWorkspaceOperationError(
                "remote snapshot policy exclusions are invalid"
            )
        entry_paths = {row["path"] for row in canonical_entries}
        if entry_paths & {path for path, _reason in canonical_policy}:
            raise RemoteWorkspaceOperationError(
                "remote snapshot entries overlap policy exclusions"
            )
        protected_paths = sorted(
            str(item)
            for item in list(manifest.get("protected_paths") or [])
            if str(item or "")
        )
        overall = hashlib.sha256(
            json.dumps(
                {
                    "entries": canonical_entries,
                    "git": manifest.get("git"),
                    "policy_exclusions": [
                        {"path": path, "reason": reason}
                        for path, reason in canonical_policy
                    ],
                    "protected_paths": protected_paths,
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        if overall != str(manifest.get("fingerprint") or ""):
            raise RemoteWorkspaceOperationError(
                "remote snapshot overall fingerprint mismatch"
            )
        return RemoteWorkspaceSnapshot(
            root=materialized,
            manifest=dict(manifest),
            _cleanup_root=temp_root,
        )
    except Exception:
        shutil.rmtree(temp_root, ignore_errors=True)
        raise


def _atomic_materialized_write(path: pathlib.Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
