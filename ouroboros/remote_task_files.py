"""Restricted task-file staging shared by Home admission and remote execd.

The cache is execution transport, never workspace content or durable Home
memory.  Execd owns its paths and accepts only the canonical attachment
manifest plus content-addressed blobs; callers cannot nominate a remote
destination.
"""

from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import pathlib
import re
import shutil
import tempfile
import uuid
from collections.abc import Mapping
from typing import Any

from ouroboros.remote_protocol import canonical_json

ATTACHMENT_STAGE_OPERATION = "_stage_task_attachments"
MEDIA_EXPORT_OPERATION = "_export_task_media"
INTERNAL_TASK_FILE_OPERATIONS = frozenset(
    {ATTACHMENT_STAGE_OPERATION, MEDIA_EXPORT_OPERATION}
)

MAX_ATTACHMENT_COUNT = 25
MAX_ATTACHMENT_BYTES = 50 * 1024 * 1024
MAX_ATTACHMENT_TOTAL_BYTES = 512 * 1024 * 1024
MAX_MEDIA_EXPORT_BYTES = 25 * 1024 * 1024

_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_OPAQUE_RE = re.compile(
    r"^[A-Za-z0-9_:@-](?:[A-Za-z0-9_.:@-]{0,254}[A-Za-z0-9_:@-])?$"
)
_SAFE_SUFFIX_RE = re.compile(r"^\.[A-Za-z0-9]{1,16}$")


class RemoteTaskFileError(RuntimeError):
    """Typed internal cache error translated at the execd boundary."""

    def __init__(self, code: str, message: str) -> None:
        self.code = str(code)
        super().__init__(str(message))


def cleanup_home_media_cache(subject: Any, task_id: str) -> bool:
    """Remove only one task's ephemeral Home import cache."""

    task = _opaque(task_id, "task_id")
    if isinstance(subject, Mapping):
        drive_root = subject.get("drive_root")
    else:
        drive_root = getattr(subject, "drive_root", None)
    if not drive_root:
        return False
    target = (
        pathlib.Path(str(drive_root))
        / "task_drives"
        / task
        / "remote_media_cache"
    )
    if not target.exists():
        return False
    shutil.rmtree(target)
    return True


def _opaque(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not _OPAQUE_RE.fullmatch(text):
        raise RemoteTaskFileError(
            "attachment_manifest_invalid",
            f"{field} must be a file-safe opaque ID.",
        )
    return text


def _safe_label(value: Any) -> str:
    label = " ".join(
        "".join(character for character in str(value or "") if character.isprintable()).split()
    )[:120]
    if not label:
        raise RemoteTaskFileError(
            "attachment_manifest_invalid",
            "Attachment label is empty.",
        )
    return label


def _safe_relpath(value: Any) -> str:
    text = str(value or "").replace("\\", "/").strip()
    path = pathlib.PurePosixPath(text)
    if (
        path.is_absolute()
        or len(path.parts) != 2
        or path.parts[0] != "attachments"
        or path.parts[1] in {"", ".", ".."}
    ):
        raise RemoteTaskFileError(
            "attachment_manifest_invalid",
            "Attachment relpath must name one canonical artifact-store attachment.",
        )
    return path.as_posix()


def canonical_attachment_manifest(value: Any) -> list[dict[str, Any]]:
    """Validate and copy the Home-authoritative ready attachment set."""

    if not isinstance(value, list) or len(value) > MAX_ATTACHMENT_COUNT:
        raise RemoteTaskFileError(
            "attachment_manifest_invalid",
            "Attachment manifest count exceeds the admission limit.",
        )
    result: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    total = 0
    for raw in value:
        if not isinstance(raw, Mapping):
            raise RemoteTaskFileError(
                "attachment_manifest_invalid",
                "Attachment manifest entries must be objects.",
            )
        attachment_id = _opaque(raw.get("attachment_id"), "attachment_id")
        if attachment_id in seen_ids:
            raise RemoteTaskFileError(
                "attachment_manifest_invalid",
                "Attachment IDs must be unique.",
            )
        seen_ids.add(attachment_id)
        digest = str(raw.get("sha256") or "")
        if not _HASH_RE.fullmatch(digest):
            raise RemoteTaskFileError(
                "attachment_manifest_invalid",
                "Attachment SHA-256 is invalid.",
            )
        size = raw.get("size")
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or size > MAX_ATTACHMENT_BYTES
        ):
            raise RemoteTaskFileError(
                "attachment_manifest_invalid",
                "Attachment size exceeds the admission limit.",
            )
        total += size
        if total > MAX_ATTACHMENT_TOTAL_BYTES:
            raise RemoteTaskFileError(
                "attachment_manifest_invalid",
                "Attachment set exceeds the aggregate admission limit.",
            )
        mime = str(raw.get("mime") or "application/octet-stream").strip()[:255]
        if not mime or any(character.isspace() for character in mime):
            raise RemoteTaskFileError(
                "attachment_manifest_invalid",
                "Attachment MIME is invalid.",
            )
        is_image = raw.get("is_image")
        if not isinstance(is_image, bool) or is_image != mime.startswith("image/"):
            raise RemoteTaskFileError(
                "attachment_manifest_invalid",
                "Attachment image fact does not match its MIME.",
            )
        if str(raw.get("root") or "") != "artifact_store":
            raise RemoteTaskFileError(
                "attachment_manifest_invalid",
                "Attachment root must remain artifact_store.",
            )
        if str(raw.get("stage_status") or "") != "ready":
            raise RemoteTaskFileError(
                "attachment_manifest_invalid",
                "Only ready Home-staged attachments may be admitted.",
            )
        result.append(
            {
                "attachment_id": attachment_id,
                "label": _safe_label(raw.get("label")),
                "root": "artifact_store",
                "relpath": _safe_relpath(raw.get("relpath")),
                "mime": mime,
                "is_image": is_image,
                "size": size,
                "sha256": digest,
                "stage_status": "ready",
            }
        )
    return result


def attachment_blob_map(
    manifest: Any,
    blobs: Mapping[str, bytes],
) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    """Require one exact content-addressed blob for every authoritative entry."""

    canonical = canonical_attachment_manifest(manifest)
    required = {entry["sha256"] for entry in canonical}
    if set(str(key) for key in blobs) != required:
        raise RemoteTaskFileError(
            "attachment_blob_set_mismatch",
            "Remote attachment upload must contain every and only authoritative blob.",
        )
    verified: dict[str, bytes] = {}
    for digest in required:
        payload = bytes(blobs[digest])
        if hashlib.sha256(payload).hexdigest() != digest:
            raise RemoteTaskFileError(
                "attachment_hash_mismatch",
                "Remote attachment upload failed SHA-256 verification.",
            )
        expected_sizes = {
            int(entry["size"]) for entry in canonical if entry["sha256"] == digest
        }
        if expected_sizes != {len(payload)}:
            raise RemoteTaskFileError(
                "attachment_size_mismatch",
                "Remote attachment upload failed exact-size verification.",
            )
        verified[digest] = payload
    return canonical, verified


def validate_staged_attachment_envelope(
    manifest: list[dict[str, Any]],
    raw_envelope: Mapping[str, Any],
    fetched: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Validate the closed attachment import contract without a closure."""

    from ouroboros.remote_workspace import (
        RemoteWorkspaceError,
        _envelope_from_dict,
    )

    fetched = fetched or {}
    if fetched.get("externalized_envelope") or fetched.get("process_blobs"):
        raise RemoteWorkspaceError(
            "attachment_manifest_invalid",
            "Attachment staging returned unexpected external result blobs.",
            phase="import",
        )
    envelope = _envelope_from_dict(raw_envelope)
    if envelope.diagnostic is not None:
        raise RemoteWorkspaceError(
            envelope.diagnostic.code,
            envelope.diagnostic.message,
            phase=envelope.diagnostic.phase,
            completion=envelope.diagnostic.completion,
            retryable=envelope.diagnostic.retryable,
            details=envelope.diagnostic.details,
        )
    staged = envelope.trace.get("attachment_manifest")
    if not isinstance(staged, list) or len(staged) != len(manifest):
        raise RemoteWorkspaceError(
            "attachment_manifest_invalid",
            "Execd returned an invalid staged attachment manifest.",
            phase="finalize",
        )
    validated: list[dict[str, Any]] = []
    for expected, remote in zip(manifest, staged):
        if not isinstance(remote, dict):
            raise RemoteWorkspaceError(
                "attachment_manifest_invalid",
                "Execd returned an invalid staged attachment entry.",
                phase="finalize",
            )
        source_facts = {key: remote.get(key) for key in expected}
        if canonical_json(source_facts) != canonical_json(expected):
            raise RemoteWorkspaceError(
                "attachment_manifest_changed",
                "Execd changed authoritative attachment facts.",
                phase="finalize",
            )
        execution_path = str(remote.get("execution_path") or "")
        if (
            not execution_path.startswith("/")
            or len(execution_path) > 4096
            or any(ord(character) < 32 for character in execution_path)
        ):
            raise RemoteWorkspaceError(
                "attachment_execution_path_invalid",
                "Execd returned an invalid attachment execution path.",
                phase="finalize",
            )
        validated.append({
            **expected,
            "execution_path": execution_path,
            "abs_path": execution_path,
        })
    return validated


def stage_remote_task_attachments(
    session: Any,
    task_id: str,
    raw_manifest: Any,
    raw_blobs: Any,
) -> list[dict[str, Any]] | None:
    """Home broker half of all-or-nothing task attachment staging."""

    if not isinstance(raw_manifest, list) or not raw_manifest:
        return None
    from ouroboros.remote_workspace import (
        RemoteWorkspaceError,
        _validated_prepared,
    )

    if not task_id:
        raise RemoteWorkspaceError(
            "attachment_task_id_missing",
            "Remote attachment staging requires a task identity.",
            phase="prepare",
        )
    try:
        manifest, blobs = attachment_blob_map(
            raw_manifest,
            raw_blobs if isinstance(raw_blobs, Mapping) else {},
        )
    except RemoteTaskFileError as exc:
        raise RemoteWorkspaceError(
            exc.code,
            str(exc),
            phase="prepare",
        ) from exc
    request_id = uuid.uuid4().hex
    operation_id = uuid.uuid4().hex
    prepared = _validated_prepared(
        session.transport.prepare(
            {
                "request_id": request_id,
                "operation_id": operation_id,
                "tool": ATTACHMENT_STAGE_OPERATION,
                "args": {"manifest": manifest},
                "task_id": task_id,
                "workspace_id": session.key[2],
            },
            blobs,
        )
    )
    if canonical_json(prepared["execution_args"]) != canonical_json(
        {"manifest": manifest}
    ):
        session.transport.abort_prepared(
            {
                "request_id": request_id,
                "operation_id": operation_id,
                "prepared_hash": prepared["prepared_hash"],
                "prepared_token": prepared["prepared_token"],
                "reason": "attachment_manifest_changed",
            }
        )
        raise RemoteWorkspaceError(
            "attachment_manifest_changed",
            "Execd prepared a different attachment manifest.",
            phase="authorize",
        )
    imported = session.transport.execute_prepared(
        {
            "request_id": request_id,
            "operation_id": operation_id,
            "prepared_hash": prepared["prepared_hash"],
            "prepared_token": prepared["prepared_token"],
            "task_id": task_id,
            "_home_import_kind": "attachment_stage_v1",
            "_home_import_context": {
                "expected_manifest": manifest,
            },
        }
    )
    return validate_staged_attachment_envelope(manifest, imported)


def remote_task_admission_result(
    session: Any,
    attachment_manifest: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    """Project one admitted session and its optional staged input set."""

    facts = session.handshake
    raw_git = facts.get("git") if isinstance(facts.get("git"), Mapping) else {}
    git = {
        "head": str(raw_git.get("head") or ""),
        "head_present": bool(raw_git.get("head_present")),
        "branch": str(raw_git.get("branch") or ""),
        "index_present": bool(raw_git.get("index_present")),
        "index_sha256": str(raw_git.get("index_sha256") or ""),
        "status_sha256": str(raw_git.get("status_sha256") or ""),
        "dirty": bool(raw_git.get("dirty")),
        "status_count": int(raw_git.get("status_count") or 0),
    }
    evidence = {
        "host_id": str(facts.get("host_id") or ""),
        "execd_build": str(facts.get("build") or ""),
        "capability_hash": str(facts.get("capability_hash") or ""),
        "canonical_root": str(facts.get("canonical_root") or ""),
        "git": git,
    }
    result = {
        "ok": True,
        "workspace_ref": {
            "kind": "ssh",
            "connection_id": session.key[0],
            "remote_root": session.remote_root.rstrip("/"),
            "workspace_id": session.key[2],
        },
        "executor_ref": {
            "type": "ssh_exec",
            "id": session.key[0],
            "workspace_id": session.key[2],
            "network": "host",
        },
        "evidence": evidence,
        "admission_evidence": evidence,
    }
    if attachment_manifest is not None:
        result["attachment_manifest"] = attachment_manifest
    return result


class RemoteTaskFileCache:
    """Execd-owned, private cache for one connection/server generation."""

    def __init__(
        self,
        state_root: pathlib.Path,
        *,
        connection_id: str,
        server_generation: str,
    ) -> None:
        connection = _opaque(connection_id, "connection_id")
        generation = _opaque(server_generation, "server_generation")
        self.connection_root = (
            pathlib.Path(state_root) / "task_files" / connection
        )
        self.generation_root = self.connection_root / generation
        self.generation_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.connection_root.parent, 0o700)
        os.chmod(self.connection_root, 0o700)
        os.chmod(self.generation_root, 0o700)
        self._prune_stale_generations(generation)

    def stage_attachments(
        self,
        task_id: str,
        manifest: Any,
        blobs: Mapping[str, bytes],
    ) -> list[dict[str, Any]]:
        """Atomically publish the entire verified task attachment set."""

        task = _opaque(task_id, "task_id")
        canonical, verified = attachment_blob_map(manifest, blobs)
        task_root = self.generation_root / task
        expected_identity = hashlib.sha256(canonical_json(canonical)).hexdigest()
        existing = self._existing_manifest(task_root, expected_identity)
        if existing is not None:
            return existing
        if task_root.exists():
            raise RemoteTaskFileError(
                "attachment_task_cache_conflict",
                "Task attachment cache already contains a different manifest.",
            )
        temporary = pathlib.Path(
            tempfile.mkdtemp(prefix=f".{task}.", dir=str(self.generation_root))
        )
        try:
            os.chmod(temporary, 0o700)
            published: list[dict[str, Any]] = []
            for entry in canonical:
                digest = entry["sha256"]
                suffix = pathlib.PurePosixPath(entry["relpath"]).suffix.lower()
                safe_suffix = suffix if _SAFE_SUFFIX_RE.fullmatch(suffix) else ""
                target = temporary / f"{digest}{safe_suffix}"
                if not target.exists():
                    self._write_private_file(target, verified[digest])
                remote = {
                    **entry,
                    "execution_path": str(target),
                    "abs_path": str(target),
                }
                published.append(remote)
            self._write_private_file(
                temporary / "manifest.json",
                canonical_json(
                    {
                        "_schema_version": 1,
                        "identity_sha256": expected_identity,
                        "attachments": published,
                    }
                ),
            )
            os.replace(temporary, task_root)
            self._fsync_directory(self.generation_root)
            # The temp absolute prefix changed after rename; publish canonical
            # paths from the final execd-owned root.
            return self._existing_manifest(task_root, expected_identity) or []
        except BaseException:
            shutil.rmtree(temporary, ignore_errors=True)
            raise

    def cleanup_task(self, task_id: str) -> bool:
        task = _opaque(task_id, "task_id")
        target = self.generation_root / task
        if not target.exists():
            return False
        shutil.rmtree(target)
        self._fsync_directory(self.generation_root)
        return True

    def export_workspace_file(
        self,
        workspace_root: pathlib.Path,
        relative_path: str,
        *,
        max_bytes: int,
        expected_sha256: str = "",
        expected_size: int | None = None,
    ) -> tuple[dict[str, Any], bytes]:
        """Read one symlink-confined regular workspace file with exact facts."""

        root = pathlib.Path(workspace_root).resolve(strict=True)
        relative = str(relative_path or "").replace("\\", "/").strip()
        pure = pathlib.PurePosixPath(relative)
        if not relative or pure.is_absolute() or any(
            part in {"", ".", ".."} for part in pure.parts
        ):
            raise RemoteTaskFileError(
                "remote_media_path_invalid",
                "Remote media path must be a non-traversing workspace-relative file.",
            )
        target = root.joinpath(*pure.parts).resolve(strict=True)
        try:
            target.relative_to(root)
        except ValueError as exc:
            raise RemoteTaskFileError(
                "remote_media_path_escape",
                "Remote media path escapes the admitted workspace.",
            ) from exc
        if not target.is_file():
            raise RemoteTaskFileError(
                "remote_media_not_file",
                "Remote media source is not a regular file.",
            )
        limit = int(max_bytes)
        if limit <= 0 or limit > MAX_MEDIA_EXPORT_BYTES:
            raise RemoteTaskFileError(
                "remote_media_limit_invalid",
                "Remote media import limit is invalid.",
            )
        size = target.stat().st_size
        if size > limit:
            raise RemoteTaskFileError(
                "remote_media_too_large",
                "Remote media source exceeds the Home import limit.",
            )
        payload = target.read_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        if len(payload) != size:
            raise RemoteTaskFileError(
                "remote_media_changed",
                "Remote media source changed while it was imported.",
            )
        if expected_size is not None and size != int(expected_size):
            raise RemoteTaskFileError(
                "remote_media_changed",
                "Remote media source size changed after preparation.",
            )
        if expected_sha256 and digest != expected_sha256:
            raise RemoteTaskFileError(
                "remote_media_changed",
                "Remote media source hash changed after preparation.",
            )
        return (
            {
                "relative_path": pure.as_posix(),
                "size": size,
                "sha256": digest,
                "mime": mimetypes.guess_type(target.name)[0]
                or "application/octet-stream",
                "name": target.name,
            },
            payload,
        )

    def export_task_attachment(
        self,
        task_id: str,
        attachment_id: str,
        *,
        max_bytes: int,
        expected_sha256: str = "",
        expected_size: int | None = None,
    ) -> tuple[dict[str, Any], bytes]:
        """Read one exact manifest-bound attachment from the current task cache."""

        task = _opaque(task_id, "task_id")
        wanted = _opaque(attachment_id, "attachment_id")
        manifest_path = self.generation_root / task / "manifest.json"
        try:
            raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RemoteTaskFileError(
                "attachment_task_cache_unavailable",
                "Remote task attachment cache is unavailable.",
            ) from exc
        entries = raw.get("attachments") if isinstance(raw, dict) else None
        entry = next(
            (
                item
                for item in entries
                if isinstance(item, dict)
                and str(item.get("attachment_id") or "") == wanted
            ),
            None,
        ) if isinstance(entries, list) else None
        if entry is None:
            raise RemoteTaskFileError(
                "attachment_not_found",
                "Attachment is not present in the current task manifest.",
            )
        size = int(entry.get("size") or 0)
        limit = int(max_bytes)
        if limit <= 0 or limit > MAX_MEDIA_EXPORT_BYTES or size > limit:
            raise RemoteTaskFileError(
                "remote_media_too_large",
                "Remote attachment exceeds the Home media import limit.",
            )
        digest = str(entry.get("sha256") or "")
        suffix = pathlib.PurePosixPath(str(entry.get("relpath") or "")).suffix.lower()
        safe_suffix = suffix if _SAFE_SUFFIX_RE.fullmatch(suffix) else ""
        target = self.generation_root / task / f"{digest}{safe_suffix}"
        try:
            payload = target.read_bytes()
        except OSError as exc:
            raise RemoteTaskFileError(
                "attachment_task_cache_unavailable",
                "Remote task attachment blob is unavailable.",
            ) from exc
        observed = hashlib.sha256(payload).hexdigest()
        if (
            len(payload) != size
            or observed != digest
            or (expected_size is not None and len(payload) != int(expected_size))
            or (expected_sha256 and observed != expected_sha256)
        ):
            raise RemoteTaskFileError(
                "attachment_task_cache_corrupt",
                "Remote task attachment failed exact size/hash verification.",
            )
        return (
            {
                "attachment_id": wanted,
                "size": size,
                "sha256": digest,
                "mime": str(entry.get("mime") or "application/octet-stream"),
                "name": pathlib.PurePosixPath(
                    str(entry.get("relpath") or "")
                ).name,
            },
            payload,
        )

    def _existing_manifest(
        self,
        task_root: pathlib.Path,
        identity: str,
    ) -> list[dict[str, Any]] | None:
        path = task_root / "manifest.json"
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RemoteTaskFileError(
                "attachment_task_cache_corrupt",
                "Existing remote task attachment cache is corrupt.",
            ) from exc
        if (
            not isinstance(raw, dict)
            or raw.get("identity_sha256") != identity
            or not isinstance(raw.get("attachments"), list)
        ):
            return None
        result: list[dict[str, Any]] = []
        for entry in raw["attachments"]:
            if not isinstance(entry, dict):
                raise RemoteTaskFileError(
                    "attachment_task_cache_corrupt",
                    "Existing remote task attachment manifest is corrupt.",
                )
            digest = str(entry.get("sha256") or "")
            suffix = pathlib.PurePosixPath(str(entry.get("relpath") or "")).suffix.lower()
            safe_suffix = suffix if _SAFE_SUFFIX_RE.fullmatch(suffix) else ""
            target = task_root / f"{digest}{safe_suffix}"
            try:
                payload = target.read_bytes()
            except OSError as exc:
                raise RemoteTaskFileError(
                    "attachment_task_cache_corrupt",
                    "Existing remote task attachment blob is unavailable.",
                ) from exc
            if (
                len(payload) != int(entry.get("size") or 0)
                or hashlib.sha256(payload).hexdigest() != digest
            ):
                raise RemoteTaskFileError(
                    "attachment_task_cache_corrupt",
                    "Existing remote task attachment blob failed verification.",
                )
            result.append(
                {
                    **entry,
                    "execution_path": str(target),
                    "abs_path": str(target),
                }
            )
        return result

    def _prune_stale_generations(self, current: str) -> None:
        for child in self.connection_root.iterdir():
            if child.name == current or not child.is_dir() or child.is_symlink():
                continue
            shutil.rmtree(child, ignore_errors=True)

    @staticmethod
    def _write_private_file(path: pathlib.Path, payload: bytes) -> None:
        descriptor = os.open(
            str(path),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(path, 0o600)

    @staticmethod
    def _fsync_directory(path: pathlib.Path) -> None:
        descriptor = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
