"""Stable snapshot and conflict-safe patch primitives for the execd kernel."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import stat
import subprocess
import threading
from collections.abc import Mapping
from typing import Any

from ouroboros.workspace_diagnostics import ToolExecutionEnvelope
from ouroboros.workspace_native_contract import NativeOperationResult

_EXCLUDED_DIRS = frozenset({".git", ".ouroboros", "__pycache__", ".pytest_cache", ".mypy_cache"})
MAX_SNAPSHOT_FILES = 25_000
MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024
_SENSITIVE_NAMES = frozenset(
    {
        ".env",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "credentials",
        "credentials.json",
        "secrets.json",
        "token.json",
        "tokens.json",
    }
)
_LOCKS_GUARD = threading.Lock()
_ROOT_LOCKS: dict[str, threading.Lock] = {}
_MATERIALIZABLE_EXCLUSION_REASONS = frozenset(
    {"excluded_directory", "protected_artifact", "sensitive_file"}
)


def snapshot_workspace(
    root: pathlib.Path,
    *,
    protected_paths: tuple[str, ...] = (),
) -> tuple[dict[str, Any], dict[str, bytes]]:
    """Return blobs only after two exact content/git manifest observations."""

    previous: dict[str, Any] | None = None
    previous_blobs: dict[str, bytes] = {}
    for attempt in range(2):
        manifest, blobs = _snapshot_once(root, protected_paths=protected_paths)
        manifest["attempt"] = attempt + 1
        if previous is not None and previous["fingerprint"] == manifest["fingerprint"]:
            return manifest, blobs
        previous, previous_blobs = manifest, blobs
    assert previous is not None
    previous["complete"] = False
    previous["materializable"] = False
    previous["integrity_complete"] = False
    previous["unstable"] = True
    failures = list(previous.get("failures") or [])
    failures.append({"path": "", "reason": "unstable_observation"})
    previous["failures"] = failures
    previous["failure_count"] = len(failures)
    return previous, previous_blobs


def snapshot_operation(
    root: pathlib.Path,
    *,
    protected_paths: tuple[str, ...] = (),
) -> NativeOperationResult:
    """Project a stable snapshot into the native operation wire contract."""

    manifest, blobs = snapshot_workspace(root, protected_paths=protected_paths)
    state = "complete" if manifest["complete"] else "partial"
    return NativeOperationResult(
        ToolExecutionEnvelope(
            text=json.dumps(manifest, sort_keys=True),
            artifacts=tuple(
                {
                    "path": row["path"],
                    "blob_id": row["sha256"],
                    "sha256": row["sha256"],
                    "size": row["size"],
                    "mode": row["mode"],
                    "kind": row["kind"],
                }
                for row in manifest["entries"]
            ),
            trace={"snapshot": manifest, "completion": state},
        ),
        blobs,
    )


def guarded_patch_apply(
    root: pathlib.Path,
    args: Mapping[str, Any],
    blobs: Mapping[str, bytes],
    *,
    protected_paths: tuple[str, ...] = (),
) -> ToolExecutionEnvelope:
    """Check all preconditions, apply once, and restore exact originals on failure."""

    with _root_lock(root):
        current, current_blobs = snapshot_workspace(
            root,
            protected_paths=protected_paths,
        )
        if not snapshot_integrity_ready(current):
            return ToolExecutionEnvelope(
                text=(
                    "⚠️ REMOTE_SNAPSHOT_INTEGRITY_FAILED: guarded apply "
                    "requires an integrity-complete source snapshot."
                ),
                trace={"completion": "not_started", "snapshot": current},
            )
        expected = str(args.get("expected_fingerprint") or "")
        if not expected or current["fingerprint"] != expected:
            return _conflict_envelope(expected, current)
        expected_head = str(args.get("expected_head") or "")
        expected_index = str(args.get("expected_index_sha256") or "")
        git_facts = current.get("git") if isinstance(current.get("git"), dict) else {}
        if expected_head and expected_head != str(git_facts.get("head") or ""):
            return _conflict_envelope(expected, current, "HEAD changed")
        if expected_index and expected_index != str(git_facts.get("index_sha256") or ""):
            return _conflict_envelope(expected, current, "index changed")
        patch = _patch_blob(args, blobs)
        changes = _validated_changes(args.get("changes"), current)
        declared_paths = {str(change["path"]) for change in changes}
        touched_paths = _patch_numstat_paths(root, patch, reverse=False)
        touched_paths.update(_patch_numstat_paths(root, patch, reverse=True))
        if not touched_paths:
            raise ValueError("cannot prove patch paths: patch touched no paths")
        if touched_paths != declared_paths:
            missing = sorted(touched_paths - declared_paths)
            extra = sorted(declared_paths - touched_paths)
            raise ValueError("patch paths do not exactly match declared changes " f"(missing={missing}, extra={extra})")
        check = _git_apply(root, patch, check=True)
        if check.returncode:
            return ToolExecutionEnvelope(
                text=("⚠️ REMOTE_PATCH_CHECK_FAILED: " + check.stderr.decode("utf-8", errors="replace")),
                trace={"completion": "not_started", "snapshot": current},
            )
        rollback = _rollback_rows(changes, current, current_blobs)
        try:
            applied = _git_apply(root, patch, check=False)
            if applied.returncode:
                raise RuntimeError(applied.stderr.decode("utf-8", errors="replace") or "git apply failed")
            after, _ = snapshot_workspace(
                root,
                protected_paths=protected_paths,
            )
            if not snapshot_integrity_ready(after):
                raise RuntimeError(
                    "remote post-state snapshot is partial or unstable"
                )
            expected_content = str(args.get("expected_content_fingerprint") or "")
            if (
                (expected_content and after.get("content_fingerprint") != expected_content)
                or (expected_head and str(after.get("git", {}).get("head") or "") != expected_head)
                or (expected_index and str(after.get("git", {}).get("index_sha256") or "") != expected_index)
            ):
                raise RuntimeError("remote post-state does not match the reviewed mirror")
        except Exception as exc:
            rollback_errors = _restore_rows(root, rollback)
            message = f"{type(exc).__name__}: {exc}"
            if rollback_errors:
                return ToolExecutionEnvelope(
                    text=(
                        "⚠️ ROLLBACK_FAILED: guarded remote apply failed and "
                        f"rollback was incomplete: {message}; {rollback_errors}"
                    ),
                    trace={
                        "completion": "unknown",
                        "rollback_failed": rollback_errors,
                    },
                )
            return ToolExecutionEnvelope(
                text=f"⚠️ REMOTE_PATCH_ROLLED_BACK: {message}",
                trace={"completion": "not_started", "rollback": "complete"},
            )
        return ToolExecutionEnvelope(
            text="OK: guarded remote patch applied.",
            trace={
                "completion": "complete",
                "before": current,
                "after": after,
                "changed": len(changes),
            },
        )


def _snapshot_once(
    root: pathlib.Path,
    *,
    protected_paths: tuple[str, ...] = (),
) -> tuple[dict[str, Any], dict[str, bytes]]:
    entries: list[dict[str, Any]] = []
    blobs: dict[str, bytes] = {}
    policy_exclusions: list[dict[str, str]] = []
    failures: list[dict[str, str]] = []
    total = 0
    protected = tuple(
        sorted(
            {
                pathlib.PurePosixPath(str(item).replace("\\", "/")).as_posix().strip("/")
                for item in protected_paths
                if str(item or "").strip() not in {"", "."}
                and ".." not in pathlib.PurePosixPath(
                    str(item).replace("\\", "/")
                ).parts
            }
        )
    )
    protected_inodes: set[tuple[int, int]] = set()

    def record_failure(path: str, reason: str) -> None:
        row = {"path": path, "reason": reason}
        if row not in failures:
            failures.append(row)

    def walk_error(exc: OSError) -> None:
        raw = pathlib.Path(str(getattr(exc, "filename", "") or root))
        try:
            rel = raw.relative_to(root).as_posix()
        except ValueError:
            rel = ""
        record_failure(rel, "walk_error")

    # Explicit protected paths may live below a directory omitted from ordinary
    # snapshot traversal. Seed their identities directly so an outside hardlink
    # cannot export the protected inode under an otherwise harmless name.
    for rel in protected:
        try:
            target_stat = root.joinpath(*rel.split("/")).stat()
        except FileNotFoundError:
            continue
        except OSError:
            record_failure(rel, "protected_identity_unverified")
            continue
        protected_inodes.add((target_stat.st_dev, target_stat.st_ino))

    # Resolve every direct policy path before reading any ordinary entry. This
    # prevents a lexically-earlier hardlink/symlink alias from exporting the
    # inode of a later `.env` or protected artifact.
    for dirpath, dirnames, filenames in os.walk(
        root,
        followlinks=False,
        onerror=walk_error,
    ):
        current = pathlib.Path(dirpath)
        dirnames[:] = [
            name for name in sorted(dirnames)
            if name not in _EXCLUDED_DIRS
        ]
        for name in sorted([*dirnames, *filenames]):
            path = current / name
            rel = path.relative_to(root).as_posix()
            parts = [part.casefold() for part in rel.split("/") if part]
            folded_name = parts[-1]
            direct_policy_path = (
                folded_name in _SENSITIVE_NAMES
                or folded_name.startswith(".env.")
                or folded_name.startswith(("id_rsa", "id_ed25519"))
                or any(part in {".ssh", ".aws", ".gnupg"} for part in parts)
                or any(
                    rel == item or rel.startswith(item + "/")
                    for item in protected
                )
            )
            if not direct_policy_path:
                continue
            try:
                target_stat = path.stat()
            except FileNotFoundError:
                continue
            except OSError:
                record_failure(rel, "protected_identity_unverified")
                continue
            protected_inodes.add((target_stat.st_dev, target_stat.st_ino))

    for dirpath, dirnames, filenames in os.walk(
        root,
        followlinks=False,
        onerror=walk_error,
    ):
        current = pathlib.Path(dirpath)
        kept_dirs: list[str] = []
        for name in sorted(dirnames):
            path = current / name
            rel = path.relative_to(root).as_posix()
            if any(rel == item or rel.startswith(item + "/") for item in protected):
                policy_exclusions.append(
                    {"path": rel, "reason": "protected_artifact"}
                )
            elif name in _EXCLUDED_DIRS:
                continue
            elif path.is_symlink():
                filenames.append(name)
            else:
                kept_dirs.append(name)
        dirnames[:] = kept_dirs
        for name in sorted(filenames):
            path = current / name
            rel = path.relative_to(root).as_posix()
            if len(entries) + len(policy_exclusions) >= MAX_SNAPSHOT_FILES:
                record_failure(rel, "file_limit_exceeded")
                break
            parts = [part.casefold() for part in rel.split("/") if part]
            folded_name = parts[-1]
            if (
                folded_name in _SENSITIVE_NAMES
                or folded_name.startswith(".env.")
                or folded_name.startswith(("id_rsa", "id_ed25519"))
                or any(part in {".ssh", ".aws", ".gnupg"} for part in parts)
            ):
                policy_exclusions.append({"path": rel, "reason": "sensitive_file"})
                continue
            protected_match = any(
                rel == item or rel.startswith(item + "/") for item in protected
            )
            if not protected_match and protected_inodes:
                try:
                    candidate_stat = path.stat()
                    protected_match = (
                        candidate_stat.st_dev,
                        candidate_stat.st_ino,
                    ) in protected_inodes
                except OSError:
                    pass
            if protected_match:
                policy_exclusions.append(
                    {"path": rel, "reason": "protected_artifact"}
                )
                continue
            try:
                row, data = _read_stable_entry(path, rel, root)
            except RuntimeError:
                record_failure(rel, "changed_during_read")
                continue
            except OSError as exc:
                reason = (
                    "unsafe_symlink"
                    if "symlink escapes" in str(exc)
                    else (
                        "unsupported_file_kind"
                        if "unsupported file kind" in str(exc)
                        else "entry_read_error"
                    )
                )
                record_failure(rel, reason)
                continue
            total += len(data)
            if total > MAX_SNAPSHOT_BYTES:
                record_failure(rel, "byte_limit_exceeded")
                break
            entries.append(row)
            blobs.setdefault(row["sha256"], data)
        if failures:
            break
    entries.sort(key=lambda row: row["path"])
    policy_exclusions = sorted(
        {(
            str(row["path"]),
            str(row["reason"]),
        ) for row in policy_exclusions}
    )
    policy_rows = [
        {"path": path, "reason": reason}
        for path, reason in policy_exclusions
    ]
    integrity_complete = not failures
    policy_scope = "policy_filtered" if policy_rows else "full"
    complete = integrity_complete and policy_scope == "full"
    git_facts = _git_facts(root)
    content_fingerprint = hashlib.sha256(
        json.dumps(
            entries,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    fingerprint = hashlib.sha256(
        json.dumps(
            {
                "entries": entries,
                "git": git_facts,
                "policy_exclusions": policy_rows,
                "protected_paths": list(protected),
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return (
        {
            "schema_version": 3,
            "entries": entries,
            "fingerprint": fingerprint,
            "content_fingerprint": content_fingerprint,
            "git": git_facts,
            "complete": complete,
            "materializable": integrity_complete,
            "integrity_complete": integrity_complete,
            "policy_scope": policy_scope,
            "unstable": False,
            "protected_paths": list(protected),
            "policy_exclusions": policy_rows,
            "policy_excluded_count": len(policy_rows),
            "exclusions": policy_rows,
            "excluded_count": len(policy_rows),
            "failures": failures,
            "failure_count": len(failures),
            "total_bytes": total,
        },
        blobs,
    )


def _read_stable_entry(
    path: pathlib.Path,
    rel: str,
    root: pathlib.Path,
) -> tuple[dict[str, Any], bytes]:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode):
        link_target = os.readlink(path)
        resolved_target = (path.parent / link_target).resolve(strict=False)
        if pathlib.Path(link_target).is_absolute() or not _path_inside(
            resolved_target,
            root,
        ):
            raise OSError("symlink escapes workspace")
        data = link_target.encode("utf-8", errors="surrogateescape")
        kind = "symlink"
    elif stat.S_ISREG(before.st_mode):
        data = path.read_bytes()
        kind = "file"
    else:
        raise OSError("unsupported file kind")
    after = path.lstat()
    if (
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ino,
    ) != (
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ino,
    ):
        raise RuntimeError("file changed during snapshot")
    return (
        {
            "path": rel,
            "kind": kind,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "mode": stat.S_IMODE(before.st_mode),
        },
        data,
    )


def _git_facts(root: pathlib.Path) -> dict[str, str]:
    head = _git_bytes(
        root,
        ["rev-parse", "--verify", "HEAD"],
        allow_failure=True,
    )
    index = _git_bytes(
        root,
        ["ls-files", "--stage", "-z"],
        allow_failure=True,
    )
    status = _git_bytes(
        root,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        allow_failure=True,
    )
    return {
        "head": head.decode("utf-8", errors="replace").strip(),
        "unborn": "true" if not head else "false",
        "index_sha256": hashlib.sha256(index).hexdigest(),
        "status_sha256": hashlib.sha256(status).hexdigest(),
    }

def _validated_changes(
    raw: Any,
    current: Mapping[str, Any],
) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise ValueError("changes must be a list")
    current_rows = {
        str(row.get("path") or ""): row for row in list(current.get("entries") or []) if isinstance(row, dict)
    }
    changes: list[dict[str, Any]] = []
    seen: set[str] = set()
    excluded_paths = tuple(
        str(row.get("path") or "")
        for row in list(current.get("exclusions") or [])
        if isinstance(row, dict)
        and str(row.get("reason") or "") in _MATERIALIZABLE_EXCLUSION_REASONS
        and str(row.get("path") or "")
    )
    protected_paths = tuple(
        str(item)
        for item in list(current.get("protected_paths") or [])
        if str(item or "")
    )
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("change rows must be objects")
        path = _safe_relpath(item.get("path"))
        if _policy_exclusion_reason(path, protected_paths, excluded_paths):
            raise ValueError(f"change targets an omitted policy path: {path}")
        if path in seen:
            raise ValueError(f"duplicate change path: {path}")
        seen.add(path)
        before = item.get("before")
        after = item.get("after")
        if before is not None and not isinstance(before, dict):
            raise ValueError("change before state must be an object or null")
        if after is not None and not isinstance(after, dict):
            raise ValueError("change after state must be an object or null")
        if current_rows.get(path) != before:
            raise ValueError(f"change precondition mismatch: {path}")
        changes.append({"path": path, "before": before, "after": after})
    return changes


def _policy_exclusion_reason(
    path: str,
    protected_paths: tuple[str, ...],
    excluded_paths: tuple[str, ...] = (),
) -> str:
    parts = [part.casefold() for part in path.split("/") if part]
    folded_name = parts[-1] if parts else ""
    if any(part in _EXCLUDED_DIRS for part in parts):
        return "excluded_directory"
    if (
        folded_name in _SENSITIVE_NAMES
        or folded_name.startswith(".env.")
        or folded_name.startswith(("id_rsa", "id_ed25519"))
        or any(part in {".ssh", ".aws", ".gnupg"} for part in parts)
    ):
        return "sensitive_file"
    for protected in (*protected_paths, *excluded_paths):
        if path == protected or path.startswith(protected + "/"):
            return "protected_artifact"
    return ""


def snapshot_integrity_ready(manifest: Mapping[str, Any]) -> bool:
    failures = manifest.get("failures")
    failure_count = manifest.get("failure_count")
    return (
        manifest.get("integrity_complete") is True
        and manifest.get("materializable") is True
        and manifest.get("unstable") is False
        and isinstance(failures, list)
        and not failures
        and type(failure_count) is int
        and failure_count == 0
    )


def _rollback_rows(
    changes: list[dict[str, Any]],
    current: Mapping[str, Any],
    blobs: Mapping[str, bytes],
) -> list[dict[str, Any]]:
    del current
    rows: list[dict[str, Any]] = []
    for change in changes:
        before = change["before"]
        data = None if before is None else blobs.get(str(before.get("sha256") or ""))
        if before is not None and data is None:
            raise ValueError(f"rollback blob is unavailable: {change['path']}")
        rows.append({"path": change["path"], "before": before, "data": data})
    return rows


def _restore_rows(root: pathlib.Path, rows: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    for row in rows:
        try:
            target = root.joinpath(*row["path"].split("/"))
            before = row["before"]
            if before is None:
                _remove_path(target)
                continue
            _remove_path(target)
            target.parent.mkdir(parents=True, exist_ok=True)
            data = bytes(row["data"])
            if before["kind"] == "symlink":
                os.symlink(data.decode("utf-8", errors="surrogateescape"), target)
            else:
                target.write_bytes(data)
                os.chmod(target, int(before["mode"]) & 0o777)
        except Exception as exc:
            errors.append(f"{row['path']}: {type(exc).__name__}: {exc}")
    return errors


def _patch_blob(args: Mapping[str, Any], blobs: Mapping[str, bytes]) -> bytes:
    blob_id = str(args.get("patch_blob_id") or "")
    if not blob_id:
        raise ValueError("patch_blob_id is required")
    patch = blobs.get(blob_id)
    if patch is None or hashlib.sha256(patch).hexdigest() != blob_id:
        raise ValueError("declared patch blob is unavailable or invalid")
    return bytes(patch)


def _git_apply(
    root: pathlib.Path,
    patch: bytes,
    *,
    check: bool,
) -> subprocess.CompletedProcess[bytes]:
    command = ["git", "apply"]
    if check:
        command.append("--check")
    command.append("-")
    return subprocess.run(
        command,
        cwd=str(root),
        input=patch,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
    )


def _patch_numstat_paths(
    root: pathlib.Path,
    patch: bytes,
    *,
    reverse: bool,
) -> set[str]:
    command = ["git", "apply", "--numstat", "-z"]
    if reverse:
        command.append("--reverse")
    command.append("-")
    proc = subprocess.run(
        command,
        cwd=str(root),
        input=patch,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
    )
    if proc.returncode:
        error = proc.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"cannot prove patch paths: {error or 'git rejected patch'}")
    raw = bytes(proc.stdout)
    if not raw or not raw.endswith(b"\0"):
        raise ValueError("cannot prove patch paths: malformed Git numstat output")
    records = raw.split(b"\0")
    records.pop()
    paths: set[str] = set()
    index = 0
    while index < len(records):
        fields = records[index].split(b"\t", 2)
        index += 1
        if len(fields) != 3 or not all(value == b"-" or value.isdigit() for value in fields[:2]):
            raise ValueError("cannot prove patch paths: malformed Git numstat record")
        encoded_path = fields[2]
        if encoded_path:
            paths.add(_safe_relpath(os.fsdecode(encoded_path)))
            continue
        if index + 1 >= len(records):
            raise ValueError("cannot prove patch paths: incomplete rename record")
        old_path, new_path = records[index : index + 2]
        index += 2
        if not old_path or not new_path:
            raise ValueError("cannot prove patch paths: empty rename path")
        paths.add(_safe_relpath(os.fsdecode(old_path)))
        paths.add(_safe_relpath(os.fsdecode(new_path)))
    return paths


def _git_bytes(
    root: pathlib.Path,
    args: list[str],
    *,
    allow_failure: bool,
) -> bytes:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(root),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )
    if proc.returncode and not allow_failure:
        raise RuntimeError(proc.stderr.decode("utf-8", errors="replace"))
    return bytes(proc.stdout) if proc.returncode == 0 else b""


def _safe_relpath(value: Any) -> str:
    text = str(value or "").replace("\\", "/")
    parts = [part for part in text.split("/") if part not in {"", "."}]
    if not parts or any(part == ".." for part in parts):
        raise ValueError("unsafe change path")
    return "/".join(parts)


def _root_lock(root: pathlib.Path) -> threading.Lock:
    key = str(root.resolve(strict=False))
    with _LOCKS_GUARD:
        return _ROOT_LOCKS.setdefault(key, threading.Lock())


def _remove_path(path: pathlib.Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.is_dir():
        shutil.rmtree(path)


def _path_inside(path: pathlib.Path, root: pathlib.Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except (OSError, ValueError):
        return False


def _conflict_envelope(
    expected: str,
    current: Mapping[str, Any],
    reason: str = "workspace changed",
) -> ToolExecutionEnvelope:
    return ToolExecutionEnvelope(
        text=(
            "⚠️ SNAPSHOT_FINGERPRINT_MISMATCH: "
            f"{reason} (expected={expected or '<missing>'}, "
            f"actual={current.get('fingerprint') or '<missing>'})."
        ),
        trace={"completion": "not_started", "snapshot": dict(current)},
    )
