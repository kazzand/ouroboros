"""Target-native reviewed payload and declared artifact handling."""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import inspect
import json
import os
import pathlib
import shutil
import sys
import tempfile
import uuid
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable

from ouroboros.workspace_diagnostics import ToolExecutionEnvelope
from ouroboros.workspace_native_contract import (
    DECLARED_OUTPUT_FILE_CAP,
    DECLARED_OUTPUT_TOTAL_BYTES,
    REVIEWED_PAYLOAD_FILE_BYTES,
    REVIEWED_PAYLOAD_FILE_CAP,
    REVIEWED_PAYLOAD_TOTAL_BYTES,
    NativeOperationResult,
)

_SENSITIVE_OUTPUT_NAMES = frozenset(
    {".env", ".env.local", "credentials.json", "secrets.json", "token.json"}
)
_SENSITIVE_OUTPUT_SUFFIXES = (".key", ".pem", ".p12", ".pfx")
_SENSITIVE_OUTPUT_MARKERS = (
    "api_key",
    "apikey",
    "access_token",
    "bearer_token",
    "credential",
    "password",
    "refresh_token",
    "secret",
)
_SENSITIVE_OUTPUT_COMPONENT_NAMES = _SENSITIVE_OUTPUT_NAMES | frozenset(
    {"secret", "secrets", "credential", "credentials", "token", "tokens"}
)


def sensitive_output_name(name: str) -> bool:
    text = str(name or "")
    lowered = text.lower()
    return (
        text.startswith(".")
        or lowered in _SENSITIVE_OUTPUT_NAMES
        or lowered.endswith(_SENSITIVE_OUTPUT_SUFFIXES)
        or any(marker in lowered for marker in _SENSITIVE_OUTPUT_MARKERS)
    )


def sensitive_output_component_reason(parts: tuple[str, ...]) -> str:
    for part in parts:
        text = str(part or "")
        if not text:
            continue
        lowered = text.lower()
        if text.startswith("."):
            return (
                f"hidden/control output path component {text} "
                "is not a deliverable artifact"
            )
        if (
            lowered in _SENSITIVE_OUTPUT_COMPONENT_NAMES
            or lowered.endswith(_SENSITIVE_OUTPUT_SUFFIXES)
            or any(marker in lowered for marker in _SENSITIVE_OUTPUT_MARKERS)
        ):
            return (
                f"credential-like output path component {text} "
                "is not a deliverable artifact"
            )
    return ""


def attach_remote_verification_facts(
    workspace_root: pathlib.Path,
    args: Mapping[str, Any],
    checked: NativeOperationResult,
) -> NativeOperationResult:
    """Probe typed comparison/lifecycle facts immediately after a target check."""

    root = pathlib.Path(workspace_root).resolve(strict=True)
    declared = [
        str(path).strip().replace("\\", "/")
        for path in args.get("artifact_paths") or []
        if str(path or "").strip()
    ][:20]
    raw_cwd = str(args.get("cwd") or "").strip()
    try:
        work_dir = pathlib.Path(raw_cwd) if raw_cwd else root
        if not work_dir.is_absolute():
            work_dir = root / work_dir
        work_dir = work_dir.resolve(strict=False)
        work_dir.relative_to(root)
    except (OSError, ValueError):
        work_dir = None
    resolved: list[pathlib.Path | None] = []
    for raw in declared:
        pure = pathlib.PurePosixPath(raw)
        candidate: pathlib.Path | None = None
        if work_dir is not None and not pure.is_absolute() and ".." not in pure.parts:
            try:
                candidate = work_dir.joinpath(*pure.parts).resolve(strict=False)
                candidate.relative_to(root)
            except (OSError, ValueError):
                candidate = None
        resolved.append(candidate)
    facts: dict[str, Any] = {}
    if str(args.get("expected_match") or "") == "bytes_equal":
        if len(declared) != 2:
            raise ValueError("bytes_equal requires exactly two artifact paths")
        comparable = (
            len(resolved) == 2
            and all(path is not None and path.is_file() for path in resolved)
        )
        matched = False
        unavailable = next(
            (
                declared[index]
                for index, path in enumerate(resolved)
                if path is None or not path.is_file()
            ),
            declared[0],
        )
        detail = (
            f"bytes_equal: file not found or unavailable: "
            f"{unavailable}"
        )
        if comparable:
            a_path, b_path = resolved
            assert a_path is not None and b_path is not None
            a_size, b_size = a_path.stat().st_size, b_path.stat().st_size
            offset = 0
            first_diff = -1
            with a_path.open("rb") as a_stream, b_path.open("rb") as b_stream:
                while True:
                    a_chunk = a_stream.read(64 * 1024)
                    b_chunk = b_stream.read(64 * 1024)
                    if not a_chunk and not b_chunk:
                        break
                    if a_chunk != b_chunk:
                        common = min(len(a_chunk), len(b_chunk))
                        first_diff = next(
                            (
                                offset + index
                                for index in range(common)
                                if a_chunk[index] != b_chunk[index]
                            ),
                            offset + common,
                        )
                        break
                    offset += len(a_chunk)
            matched = first_diff < 0 and a_size == b_size
            if matched:
                detail = (
                    f"bytes_equal: {declared[0]} == {declared[1]} "
                    f"({a_size} bytes)"
                )
            else:
                if first_diff < 0:
                    first_diff = min(a_size, b_size)
                window_start = max(0, first_diff - 16)
                try:
                    with a_path.open("rb") as stream:
                        stream.seek(window_start)
                        a_hex = stream.read(48).hex(" ")
                except OSError:
                    a_hex = "(unreadable)"
                try:
                    with b_path.open("rb") as stream:
                        stream.seek(window_start)
                        b_hex = stream.read(48).hex(" ")
                except OSError:
                    b_hex = "(unreadable)"
                detail = (
                    f"bytes differ at offset {first_diff} "
                    f"(sizes {a_size} vs {b_size}).\n"
                    f"{declared[0]} @{window_start}: {a_hex}\n"
                    f"{declared[1]} @{window_start}: {b_hex}"
                )
        facts["bytes_equal"] = {"matched": matched, "detail": detail}
    lifecycle: list[dict[str, Any]] = []
    missing: list[str] = []
    for raw, path in zip(declared, resolved):
        exists: bool | None = None
        surface = "remote_target"
        try:
            if path is None:
                raise ValueError("path is outside workspace")
            path.lstat()
            exists = True
        except FileNotFoundError:
            exists = False
        except (OSError, ValueError):
            surface = "unavailable"
        lifecycle.append(
            {
                "path": raw[:300],
                "exists_after": exists,
                "check_surface": surface,
            }
        )
        if exists is False:
            missing.append(raw[:300])
    if lifecycle:
        facts["artifact_lifecycle"] = lifecycle
    if missing:
        facts["artifacts_missing_after"] = missing
    envelope = checked.envelope
    return NativeOperationResult(
        ToolExecutionEnvelope(
            text=envelope.text,
            diagnostic=envelope.diagnostic,
            process=envelope.process,
            artifacts=envelope.artifacts,
            trace={**envelope.trace, "verification": facts},
        ),
        checked.blobs,
    )


def validate_reviewed_payload(
    args: Mapping[str, Any],
    blobs: Mapping[str, bytes],
) -> tuple[dict[str, Any], dict[str, Any]]:
    execution_args = {str(key): value for key, value in args.items()}
    payload = execution_args.get("payload")
    invocation = execution_args.get("invocation")
    if (
        execution_args.get("schema_version") != 1
        or not isinstance(payload, Mapping)
        or not isinstance(invocation, Mapping)
    ):
        raise ValueError("reviewed payload package schema is invalid")
    kind = str(execution_args.get("kind") or "")
    if kind not in {"script", "extension_tool"}:
        raise ValueError("reviewed payload kind is invalid")
    expected_hash = str(payload.get("content_hash") or "")
    skill_name = str(payload.get("skill_name") or "")
    if (
        len(expected_hash) != 64
        or any(char not in "0123456789abcdef" for char in expected_hash)
        or not skill_name
        or len(skill_name) > 64
        or any(
            not ((char.isascii() and char.isalnum()) or char in "_-")
            for char in skill_name
        )
    ):
        raise ValueError("reviewed payload identity is invalid")
    files = payload.get("files")
    if not isinstance(files, list) or not files or len(files) > REVIEWED_PAYLOAD_FILE_CAP:
        raise ValueError("reviewed payload file manifest is invalid")
    aggregate = hashlib.sha256()
    total = 0
    seen: set[str] = set()
    canonical_files: list[dict[str, Any]] = []
    for raw in files:
        if not isinstance(raw, Mapping):
            raise ValueError("reviewed payload file entry is invalid")
        rel = str(raw.get("path") or "").replace("\\", "/")
        pure = pathlib.PurePosixPath(rel)
        if not rel or pure.is_absolute() or ".." in pure.parts or rel.casefold() in seen:
            raise ValueError("reviewed payload path is unsafe or colliding")
        seen.add(rel.casefold())
        digest = str(raw.get("sha256") or "")
        size = raw.get("size")
        mode = raw.get("mode", 0o600)
        if (
            len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or size > REVIEWED_PAYLOAD_FILE_BYTES
            or not isinstance(mode, int)
            or isinstance(mode, bool)
            or mode & ~0o755
            or mode & 0o022
        ):
            raise ValueError("reviewed payload file metadata is invalid")
        data = blobs.get(digest)
        if (
            not isinstance(data, bytes)
            or len(data) != size
            or hashlib.sha256(data).hexdigest() != digest
        ):
            raise ValueError("reviewed payload blob is absent or mismatched")
        total += size
        if total > REVIEWED_PAYLOAD_TOTAL_BYTES:
            raise ValueError("reviewed payload exceeds aggregate byte limit")
        aggregate.update(rel.encode("utf-8"))
        aggregate.update(b"\0")
        aggregate.update(bytes.fromhex(digest))
        canonical_files.append(
            {"path": rel, "sha256": digest, "size": size, "mode": mode}
        )
    if set(blobs) != {row["sha256"] for row in canonical_files}:
        raise ValueError("reviewed payload contains undeclared blobs")
    if aggregate.hexdigest() != expected_hash:
        raise ValueError("reviewed payload content hash does not match review")
    invocation = dict(invocation)
    timeout = invocation.get("timeout_sec", 60)
    if (
        not isinstance(timeout, int)
        or isinstance(timeout, bool)
        or timeout < 1
        or timeout > 300
    ):
        raise ValueError("reviewed payload timeout is invalid")
    if kind == "script":
        entry = str(invocation.get("entry") or "").replace("\\", "/")
        argv = invocation.get("argv")
        if (
            not entry
            or pathlib.PurePosixPath(entry).is_absolute()
            or ".." in pathlib.PurePosixPath(entry).parts
            or entry.casefold() not in seen
            or not isinstance(argv, list)
            or len(argv) > 256
            or any(not isinstance(item, str) or len(item) > 8192 for item in argv)
            or sum(len(item) for item in argv) > 64 * 1024
        ):
            raise ValueError("reviewed script invocation is invalid")
    else:
        entry = str(payload.get("entry") or "").replace("\\", "/")
        surface = str(invocation.get("surface") or "")
        call_args = invocation.get("args")
        if (
            not entry
            or pathlib.PurePosixPath(entry).is_absolute()
            or ".." in pathlib.PurePosixPath(entry).parts
            or entry.casefold() not in seen
            or not surface
            or len(surface) > 64
            or any(
                not ((char.isascii() and char.isalnum()) or char in "_-")
                for char in surface
            )
            or not isinstance(call_args, Mapping)
        ):
            raise ValueError("reviewed extension invocation is invalid")
        try:
            encoded = json.dumps(
                call_args,
                ensure_ascii=False,
                sort_keys=True,
                allow_nan=False,
            ).encode()
        except (TypeError, ValueError) as exc:
            raise ValueError("reviewed extension args are not JSON") from exc
        if len(encoded) > 1024 * 1024:
            raise ValueError("reviewed extension args exceed the size limit")
    canonical_payload = dict(payload)
    canonical_payload["files"] = canonical_files
    execution_args["payload"] = canonical_payload
    execution_args["invocation"] = invocation
    return execution_args, {
        "payload_content_hash": expected_hash,
        "payload_file_count": len(canonical_files),
        "payload_total_bytes": total,
    }


@dataclass(frozen=True)
class ReviewedPayloadStage:
    command: list[str]
    env: dict[str, str]
    result_path: pathlib.Path | None = None


@contextmanager
def stage_reviewed_payload(
    workspace_root: pathlib.Path,
    args: Mapping[str, Any],
    blobs: Mapping[str, bytes],
    native_facts: Mapping[str, Any],
):
    canonical, facts = validate_reviewed_payload(args, blobs)
    if facts["payload_content_hash"] != native_facts.get("payload_content_hash"):
        raise PermissionError("reviewed payload facts changed after authorization")
    payload = canonical["payload"]
    invocation = canonical["invocation"]
    runtime = str(native_facts.get("resolved_runtime") or "")
    if not runtime or not pathlib.Path(runtime).is_file():
        raise FileNotFoundError("reviewed payload runtime is unavailable on target")
    stage_root = pathlib.Path(tempfile.mkdtemp(prefix="ouroboros-reviewed-"))
    os.chmod(stage_root, 0o700)
    skill_name = str(payload["skill_name"])
    skill_dir = stage_root / skill_name
    try:
        for row in payload["files"]:
            destination = skill_dir.joinpath(*pathlib.PurePosixPath(row["path"]).parts)
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            destination.write_bytes(blobs[row["sha256"]])
            os.chmod(destination, int(row["mode"]) or 0o600)
        rehash = hashlib.sha256()
        for row in payload["files"]:
            data = skill_dir.joinpath(
                *pathlib.PurePosixPath(row["path"]).parts
            ).read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            if digest != row["sha256"]:
                raise PermissionError("reviewed payload changed while staging")
            rehash.update(row["path"].encode())
            rehash.update(b"\0")
            rehash.update(bytes.fromhex(digest))
        if rehash.hexdigest() != payload["content_hash"]:
            raise PermissionError("reviewed payload hash changed before spawn")
        safe_env = {
            key: str(os.environ[key])
            for key in (
                "PATH", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR",
            )
            if os.environ.get(key)
        }
        private_home = stage_root / "home"
        private_home.mkdir(mode=0o700)
        safe_env["HOME"] = str(private_home)
        safe_env["PYTHONDONTWRITEBYTECODE"] = "1"
        result_path = None
        if canonical["kind"] == "script":
            entry = skill_dir.joinpath(
                *pathlib.PurePosixPath(str(invocation["entry"])).parts
            )
            command = [runtime, str(entry), *map(str, invocation.get("argv") or [])]
        else:
            drive_root = stage_root / "drive"
            state_dir = drive_root / "state" / "skills" / skill_name
            state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            (state_dir / "enabled.json").write_text('{"enabled":true}')
            (state_dir / "review.json").write_text(json.dumps({
                "status": "clean",
                "content_hash": payload["content_hash"],
                "findings": [],
            }))
            input_path = stage_root / "extension-call.json"
            result_path = stage_root / "extension-result.json"
            input_path.write_text(json.dumps({
                "mode": "tool",
                "skill_name": skill_name,
                "entry": str(payload["entry"]),
                "surface": str(invocation["surface"]),
                "args": dict(invocation.get("args") or {}),
                "ctx": {
                    "task_id": str(native_facts.get("task_id") or ""),
                    "repo_dir": str(workspace_root),
                    "workspace_root": str(workspace_root),
                    "workspace_mode": "external",
                },
                "drive_root": str(drive_root),
                "repo_dir": str(workspace_root),
                "skills_repo_path": str(stage_root),
                "result_path": str(result_path),
            }, ensure_ascii=False))
            safe_env.update({
                "OUROBOROS_DATA_DIR": str(drive_root),
                "OUROBOROS_REPO_DIR": str(workspace_root),
                "OUROBOROS_EXTENSION_PROCESS_CHILD": "1",
                "PYTHONUNBUFFERED": "1",
            })
            kernel_root = pathlib.Path(__file__).resolve().parent.parent
            command = [
                runtime,
                "-I",
                "-B",
                "-c",
                (
                    "import runpy,sys;"
                    "sys.path.insert(0,sys.argv.pop(1));"
                    "runpy.run_module('ouroboros.workspace_payload_native',"
                    "run_name='__main__')"
                ),
                str(kernel_root),
                str(input_path),
            ]
        yield ReviewedPayloadStage(command, safe_env, result_path)
    finally:
        shutil.rmtree(stage_root, ignore_errors=True)


def execute_reviewed_payload(
    workspace_root: pathlib.Path,
    args: Mapping[str, Any],
    *,
    native_facts: Mapping[str, Any],
    blobs: Mapping[str, bytes],
    control: Any,
    process_runner: Callable[..., NativeOperationResult],
) -> NativeOperationResult:
    """Stage and execute one exact Home-reviewed payload on the target."""

    invocation = args.get("invocation")
    process_args = {
        "cwd": str(workspace_root),
        "timeout_sec": (
            invocation.get("timeout_sec", 60)
            if isinstance(invocation, Mapping)
            else 60
        ),
    }
    with stage_reviewed_payload(
        workspace_root,
        args,
        blobs,
        native_facts,
    ) as stage:
        result = process_runner(
            workspace_root,
            process_args,
            cmd=stage.command,
            control=control,
            env=stage.env,
        )
        if stage.result_path is None or result.envelope.process is None:
            return result
        if result.envelope.process.returncode:
            return result
        if (
            not stage.result_path.is_file()
            or stage.result_path.stat().st_size > 2 * 1024 * 1024
        ):
            raise RuntimeError("remote extension omitted its bounded result")
        payload = json.loads(stage.result_path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or not payload.get("ok"):
            error = payload.get("error") if isinstance(payload, dict) else ""
            raise RuntimeError(str(error or "remote extension failed"))
        return NativeOperationResult(
            ToolExecutionEnvelope(
                text=str(payload.get("result") or ""),
                process=result.envelope.process,
                artifacts=result.envelope.artifacts,
                trace={
                    **result.envelope.trace,
                    "reviewed_payload": native_facts.get(
                        "payload_content_hash"
                    ),
                },
            ),
            result.blobs,
        )


def execute_inline_script(
    workspace_root: pathlib.Path,
    args: Mapping[str, Any],
    *,
    native_facts: Mapping[str, Any],
    control: Any,
    process_runner: Callable[..., NativeOperationResult],
    atomic_write: Callable[[pathlib.Path, bytes], None],
) -> NativeOperationResult:
    """Execute a bounded inline script through the shared process runner."""

    body = str(args.get("script") or "")
    if not body.strip():
        raise ValueError("script is required")
    interpreter = str(args.get("interpreter") or "python3")
    suffix = ".py" if "python" in pathlib.PurePath(interpreter).name else ".sh"
    temp_dir = workspace_root / ".ouroboros" / "tmp_scripts"
    temp_dir.mkdir(parents=True, exist_ok=True)
    path = temp_dir / f"script_{uuid.uuid4().hex}{suffix}"
    atomic_write(path, body.encode("utf-8"))
    try:
        os.chmod(path, 0o600)
        command = [
            interpreter,
            str(path),
            *[str(item) for item in args.get("args") or []],
        ]
        result = process_runner(
            workspace_root,
            args,
            cmd=command,
            control=control,
            native_facts=native_facts,
        )
        return NativeOperationResult(
            ToolExecutionEnvelope(
                text=f"# script_path={path}\n{result.envelope.text}",
                process=result.envelope.process,
                artifacts=result.envelope.artifacts,
                trace=result.envelope.trace,
            ),
            result.blobs,
        )
    finally:
        path.unlink(missing_ok=True)


def _confined_path(
    workspace_root: pathlib.Path,
    cwd: pathlib.Path,
    raw: Any,
) -> pathlib.Path:
    text = str(raw or "").strip()
    if not text:
        raise ValueError("declared path is blank")
    candidate = pathlib.Path(text)
    target = (candidate if candidate.is_absolute() else cwd / candidate).resolve(
        strict=False
    )
    target.relative_to(workspace_root)
    target.relative_to(cwd)
    return target


def snapshot_declared_outputs(
    workspace_root: pathlib.Path,
    args: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    cwd = pathlib.Path(str(args.get("cwd") or workspace_root)).resolve(strict=True)
    before: dict[str, dict[str, Any]] = {}
    outputs = args.get("outputs") or []
    if not isinstance(outputs, list) or len(outputs) > 64:
        raise ValueError("outputs must be an array of at most 64 paths")
    for raw in outputs:
        target = _confined_path(workspace_root, cwd, raw)
        if not target.exists():
            before[str(raw)] = {"exists": False}
        elif target.is_file() and not target.is_symlink():
            data = target.read_bytes()
            before[str(raw)] = {
                "exists": True,
                "kind": "file",
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
        elif target.is_dir() and not target.is_symlink():
            digest = hashlib.sha256()
            count = size = 0
            for child in sorted(target.rglob("*")):
                if child.is_symlink() or not child.is_file():
                    continue
                rel = child.relative_to(target).as_posix()
                data = child.read_bytes()
                digest.update(rel.encode())
                digest.update(b"\0")
                digest.update(hashlib.sha256(data).digest())
                count += 1
                size += len(data)
                if count > DECLARED_OUTPUT_FILE_CAP or size > DECLARED_OUTPUT_TOTAL_BYTES:
                    raise ValueError("declared output directory exceeds limits")
            before[str(raw)] = {
                "exists": True,
                "kind": "directory",
                "sha256": digest.hexdigest(),
                "size": size,
            }
        else:
            raise ValueError("declared output is not a regular file or directory")
    return before


def validate_declared_output_context(
    workspace_root: pathlib.Path,
    service_ref: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate persisted semantic service metadata before target-native reuse."""

    raw_cwd = str(service_ref.get("cwd") or "")
    if not raw_cwd:
        return {"cwd": workspace_root.as_posix(), "outputs": [], "before": {}}
    cwd = pathlib.Path(raw_cwd).resolve(strict=True)
    cwd.relative_to(workspace_root)
    if not cwd.is_dir():
        raise NotADirectoryError(str(cwd))
    outputs = service_ref.get("outputs") or []
    if (
        not isinstance(outputs, list)
        or len(outputs) > 64
        or any(not isinstance(item, str) for item in outputs)
    ):
        raise ValueError("persisted service outputs are invalid")
    for raw in outputs:
        _confined_path(workspace_root, cwd, raw)
    raw_before = service_ref.get("declared_outputs_before") or {}
    if not isinstance(raw_before, Mapping) or set(raw_before) - set(outputs):
        raise ValueError("persisted declared-output snapshot is invalid")
    before: dict[str, dict[str, Any]] = {}
    for label in outputs:
        row = raw_before.get(label, {"exists": False})
        if not isinstance(row, Mapping) or not isinstance(row.get("exists"), bool):
            raise ValueError("persisted declared-output snapshot row is invalid")
        normalized: dict[str, Any] = {"exists": bool(row["exists"])}
        if normalized["exists"]:
            kind = str(row.get("kind") or "")
            digest = str(row.get("sha256") or "")
            size = row.get("size")
            if (
                kind not in {"file", "directory"}
                or len(digest) != 64
                or any(char not in "0123456789abcdef" for char in digest)
                or not isinstance(size, int)
                or isinstance(size, bool)
                or size < 0
                or size > DECLARED_OUTPUT_TOTAL_BYTES
            ):
                raise ValueError("persisted declared-output snapshot row is invalid")
            normalized.update({"kind": kind, "sha256": digest, "size": size})
        before[label] = normalized
    return {"cwd": cwd.as_posix(), "outputs": list(outputs), "before": before}


def collect_declared_outputs(
    workspace_root: pathlib.Path,
    args: Mapping[str, Any],
    before: Mapping[str, Any],
) -> tuple[dict[str, bytes], list[dict[str, Any]], list[str], bool]:
    cwd = pathlib.Path(str(args.get("cwd") or workspace_root)).resolve(strict=True)
    blobs: dict[str, bytes] = {}
    artifacts: list[dict[str, Any]] = []
    notes: list[str] = []
    failed = False
    total = count = 0
    for raw in args.get("outputs") or []:
        label = str(raw)
        target = _confined_path(workspace_root, cwd, raw)
        members = [target] if target.is_file() else (
            sorted(path for path in target.rglob("*") if path.is_file())
            if target.is_dir() and not target.is_symlink()
            else []
        )
        if not members:
            notes.append(f"missing output: {label}")
            failed = True
            continue
        current_digest = hashlib.sha256()
        rows: list[tuple[pathlib.Path, str, bytes]] = []
        for path in members:
            if path.is_symlink():
                failed = True
                notes.append(f"blocked symlink output: {path}")
                rows = []
                break
            rel_parts = (
                path.relative_to(target).parts
                if target.is_dir()
                else (path.name,)
            )
            component_reason = sensitive_output_component_reason(rel_parts)
            if component_reason:
                failed = True
                notes.append(f"blocked sensitive output: {path}: {component_reason}")
                rows = []
                break
            data = path.read_bytes()
            rel = path.relative_to(target).as_posix() if target.is_dir() else path.name
            digest = hashlib.sha256(data).hexdigest()
            current_digest.update(rel.encode())
            current_digest.update(b"\0")
            current_digest.update(bytes.fromhex(digest))
            rows.append((path, digest, data))
        prior = before.get(label) if isinstance(before.get(label), Mapping) else {}
        after_digest = (
            rows[0][1]
            if target.is_file() and rows
            else current_digest.hexdigest()
        )
        if prior.get("exists") and prior.get("sha256") == after_digest:
            notes.append(f"unchanged output (cosmetic): {label}")
            continue
        for path, digest, data in rows:
            total += len(data)
            count += 1
            if total > DECLARED_OUTPUT_TOTAL_BYTES or count > DECLARED_OUTPUT_FILE_CAP:
                raise ValueError("declared outputs exceed remote import limits")
            blobs[digest] = data
            member = path.relative_to(target).as_posix() if target.is_dir() else path.name
            artifacts.append({
                "name": path.name,
                "kind": "declared_output",
                "declared_as": label,
                "member_path": member,
                "blob_id": digest,
                "sha256": digest,
                "size": len(data),
                "mime": "application/octet-stream",
            })
        if target.is_file() and rows:
            notes.append(
                f"registered output {target} -> artifact_store:{target.name} "
                f"sha256={rows[0][1][:12]}"
            )
        else:
            names = ", ".join(path.name for path, _digest, _data in rows)
            notes.append(
                f"registered directory output {target} -> artifact_store:{names}"
            )
    return blobs, artifacts, notes, failed


def scratch_fingerprints(
    workspace_root: pathlib.Path,
    args: Mapping[str, Any],
) -> dict[str, str]:
    cwd = pathlib.Path(str(args.get("cwd") or workspace_root)).resolve(strict=True)
    scratch = args.get("scratch") or []
    if not isinstance(scratch, list) or len(scratch) > 64:
        raise ValueError("scratch must be an array of at most 64 paths")
    result: dict[str, str] = {}
    for raw in scratch:
        target = _confined_path(workspace_root, cwd, raw)
        if target.is_dir():
            raise ValueError("scratch paths must be files, not directories")
        if target.is_file() and not target.is_symlink():
            result[str(target)] = hashlib.sha256(target.read_bytes()).hexdigest()
    return result


class _WorkspaceExtensionAPI:
    """Minimal target-only PluginAPI projection for workspace-affine tools."""

    def __init__(
        self,
        *,
        skill_name: str,
        workspace_root: pathlib.Path,
        state_dir: pathlib.Path,
    ) -> None:
        self.skill_name = skill_name
        self.workspace_root = workspace_root
        self.state_dir = state_dir
        self.tools: dict[str, tuple[Any, bool]] = {}

    def register_tool(
        self,
        name: str,
        handler: Any,
        *,
        description: str,
        schema: Mapping[str, Any],
        timeout_sec: int = 60,
    ) -> None:
        del description, schema, timeout_sec
        short = str(name or "").strip()
        if (
            not short
            or len(short) > 24
            or any(
                not ((char.isascii() and char.isalnum()) or char == "_")
                for char in short
            )
            or not callable(handler)
        ):
            raise ValueError("extension registered an invalid tool")
        safe_skill = "".join(
            char
            if char.isascii() and (char.isalnum() or char in "-_")
            else "_"
            for char in self.skill_name
        )
        safe_skill = "_".join(
            part for part in safe_skill.split("_") if part
        ).strip("_-")
        if (
            safe_skill
            and safe_skill == self.skill_name
            and len(safe_skill) <= 30
        ):
            token = f"r_{safe_skill}"
        else:
            digest = hashlib.sha1(
                self.skill_name.encode("utf-8", errors="replace")
            ).hexdigest()[:10]
            prefix = (safe_skill or "skill")[:19].strip("_-") or "skill"
            token = f"h_{prefix}_{digest}"
        full = f"ext_{len(token)}_{token}_{short}"
        if full in self.tools:
            raise ValueError(f"extension tool already registered: {short}")
        try:
            parameters = list(inspect.signature(handler).parameters.values())
        except (TypeError, ValueError):
            wants_context = True
        else:
            wants_context = bool(parameters) and (
                parameters[0].kind == parameters[0].VAR_POSITIONAL
                or (
                    parameters[0].kind
                    in (
                        parameters[0].POSITIONAL_ONLY,
                        parameters[0].POSITIONAL_OR_KEYWORD,
                    )
                    and parameters[0].name
                    in {"ctx", "context", "_ctx", "tool_context"}
                )
            )
        self.tools[full] = (handler, wants_context)

    def _ignore_registration(self, *args: Any, **kwargs: Any) -> None:
        """Ignore Home-only registrations in the target tool-only projection."""

        del args, kwargs

    register_route = _ignore_registration
    register_ws_handler = _ignore_registration
    register_ui_tab = _ignore_registration
    register_settings_section = _ignore_registration
    register_supervised_task = _ignore_registration
    register_companion_process = _ignore_registration
    on_unload = _ignore_registration

    def subscribe_event(self, *args: Any, **kwargs: Any) -> str:
        del args, kwargs
        return ""

    def _deny_home_access(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs
        raise PermissionError(
            "remote workspace extension has no Home settings, token, or control channel"
        )

    send_ws_message = _deny_home_access
    get_skill_token = _deny_home_access
    get_settings = _deny_home_access

    def get_state_dir(self) -> str:
        return str(self.state_dir)

    def skill_job_dir(self, job_id: str) -> pathlib.Path:
        safe = str(job_id or "")
        if (
            not safe
            or len(safe) > 80
            or any(
                not ((char.isascii() and char.isalnum()) or char in "._-")
                for char in safe
            )
        ):
            raise ValueError("extension job id is invalid")
        target = self.state_dir / "jobs" / safe
        for name in ("assets", "output", "tmp"):
            (target / name).mkdir(parents=True, exist_ok=True, mode=0o700)
        return target

    def get_runtime_info(self) -> dict[str, Any]:
        return {
            "plugin_api_version": 1,
            "execution_mode": "workspace_remote",
            "workspace_root": str(self.workspace_root),
            "available_capabilities": ["tool"],
        }

    def log(self, level: str, message: str, **fields: Any) -> None:
        del fields
        print(f"[extension:{str(level)}] {str(message)}", file=sys.stderr)


def _json_safe(value: Any) -> Any:
    try:
        json.dumps(value, ensure_ascii=False, allow_nan=False)
        return value
    except (TypeError, ValueError):
        if isinstance(value, Mapping):
            return {str(key): _json_safe(item) for key, item in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [_json_safe(item) for item in value]
        return str(value)


def _write_extension_result(path: pathlib.Path, payload: Mapping[str, Any]) -> None:
    data = json.dumps(
        dict(payload),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if len(data) > 2 * 1024 * 1024:
        data = json.dumps(
            {"ok": False, "error": "remote extension result exceeded safety cap"}
        ).encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def _run_extension_call(input_path: pathlib.Path) -> None:
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    result_path = pathlib.Path(str(payload["result_path"]))
    try:
        skill_name = str(payload["skill_name"])
        workspace_root = pathlib.Path(str(payload["repo_dir"])).resolve(
            strict=True
        )
        skills_root = pathlib.Path(str(payload["skills_repo_path"])).resolve(
            strict=True
        )
        skill_dir = (skills_root / skill_name).resolve(strict=True)
        skill_dir.relative_to(skills_root)
        entry = skill_dir.joinpath(
            *pathlib.PurePosixPath(str(payload["entry"])).parts
        ).resolve(strict=True)
        entry.relative_to(skill_dir)
        state_dir = pathlib.Path(str(payload["drive_root"])).resolve(
            strict=True
        ) / "state" / "skills" / skill_name
        state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        api = _WorkspaceExtensionAPI(
            skill_name=skill_name,
            workspace_root=workspace_root,
            state_dir=state_dir,
        )
        module_name = f"_ouroboros_remote_extension_{uuid.uuid4().hex}"
        spec = importlib.util.spec_from_file_location(module_name, entry)
        if spec is None or spec.loader is None:
            raise RuntimeError("extension entry cannot be imported")
        module = importlib.util.module_from_spec(spec)
        sys.path.insert(0, str(skill_dir))
        try:
            spec.loader.exec_module(module)
            register = getattr(module, "register", None)
            if not callable(register):
                raise RuntimeError("extension entry omitted register(api)")
            register(api)
            surface = str(payload.get("surface") or "")
            registered = api.tools.get(surface)
            if registered is None:
                raise RuntimeError(f"extension tool is not registered: {surface}")
            handler, wants_context = registered
            ctx_payload = payload.get("ctx")
            ctx_payload = (
                dict(ctx_payload) if isinstance(ctx_payload, Mapping) else {}
            )
            context = type("WorkspaceExtensionContext", (), {})()
            context.task_id = str(ctx_payload.get("task_id") or "")
            context.repo_dir = workspace_root
            context.workspace_root = str(workspace_root)
            context.workspace_mode = "external"
            context.drive_root = state_dir
            args = payload.get("args")
            args = dict(args) if isinstance(args, Mapping) else {}
            value = (
                handler(context, **args)
                if wants_context
                else handler(**args)
            )
            result = asyncio.run(value) if inspect.isawaitable(value) else value
        finally:
            try:
                sys.path.remove(str(skill_dir))
            except ValueError:
                pass
        _write_extension_result(
            result_path,
            {"ok": True, "result": _json_safe(result)},
        )
    except BaseException as exc:
        _write_extension_result(
            result_path,
            {"ok": False, "error": f"{type(exc).__name__}: {exc}"},
        )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(
            "usage: python -m ouroboros.workspace_payload_native <payload.json>"
        )
    _run_extension_call(pathlib.Path(sys.argv[1]))
