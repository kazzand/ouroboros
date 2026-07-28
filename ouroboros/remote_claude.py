"""Home-side Claude Code mirror for an admitted SSH workspace.

Claude and its credentials never leave Home.  The remote workspace is exposed
to the SDK only through a verified, task-scoped snapshot; the resulting binary
patch is applied remotely only while the source fingerprint still matches.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import stat
import subprocess
from dataclasses import dataclass
from typing import Any

from ouroboros.workspace_executor import (
    RemoteWorkspaceOperationError,
    execute_remote_system_operation,
    materialize_remote_workspace_snapshot,
)

_PATCH_MAX_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class RemoteClaudeOutcome:
    result: Any
    source_fingerprint: str
    changed_files: tuple[str, ...]
    diff_stat: str
    apply_trace: dict[str, Any]
    validation_summary: str = ""


def run_remote_claude_edit(
    ctx: Any,
    *,
    prompt: str,
    budget: float,
    validate: bool,
    system_prompt: str,
) -> RemoteClaudeOutcome:
    """Run the existing Claude edit path on Home and guard its remote import."""

    from ouroboros.gateways.claude_code import (
        DEFAULT_CLAUDE_CODE_MAX_TURNS,
        resolve_claude_code_model,
        run_edit,
    )

    with materialize_remote_workspace_snapshot(ctx) as snapshot:
        mirror = snapshot.root
        source_fingerprint = str(snapshot.manifest.get("fingerprint") or "")
        if not source_fingerprint:
            raise RemoteWorkspaceOperationError(
                "remote snapshot omitted its source fingerprint"
            )
        _git(mirror, ["init", "-q"])
        _git(mirror, ["config", "user.name", "Ouroboros Snapshot"])
        _git(mirror, ["config", "user.email", "snapshot@ouroboros.invalid"])
        _git(mirror, ["add", "-A"])
        _git(mirror, ["commit", "-qm", "remote snapshot", "--allow-empty"])
        before = _content_manifest(mirror)
        omission_note = _snapshot_omission_note(snapshot.manifest)
        result = run_edit(
            prompt=prompt,
            cwd=str(mirror),
            model=resolve_claude_code_model(),
            max_turns=DEFAULT_CLAUDE_CODE_MAX_TURNS,
            budget=budget,
            system_prompt=system_prompt,
            repo_root=str(mirror),
            protect_runtime_paths=False,
        )
        if not result.success:
            return RemoteClaudeOutcome(
                result=result,
                source_fingerprint=source_fingerprint,
                changed_files=(),
                diff_stat="",
                apply_trace={"completion": "not_started"},
            )
        _assert_mirror_head_unchanged(mirror)
        after = _content_manifest(mirror)
        changes = _change_manifest(before["entries"], after["entries"])
        patch = _binary_patch(mirror)
        changed_files = tuple(row["path"] for row in changes)
        diff_stat = _git_text(mirror, ["diff", "--stat", "HEAD", "--"])
        apply_trace: dict[str, Any] = {"completion": "complete", "changed": 0}
        if changes:
            if not patch:
                raise RemoteWorkspaceOperationError(
                    "Claude changed the mirror but no exact binary patch was produced"
                )
            if len(patch) > _PATCH_MAX_BYTES:
                raise RemoteWorkspaceOperationError(
                    "Claude patch exceeds the remote apply limit"
                )
            patch_id = hashlib.sha256(patch).hexdigest()
            envelope = execute_remote_system_operation(
                ctx,
                "guarded_patch_apply",
                {
                    "expected_fingerprint": source_fingerprint,
                    "expected_content_fingerprint": after["content_fingerprint"],
                    "expected_head": str(
                        snapshot.manifest.get("git", {}).get("head") or ""
                    ),
                    "expected_index_sha256": str(
                        snapshot.manifest.get("git", {}).get("index_sha256") or ""
                    ),
                    "patch_blob_id": patch_id,
                    "changes": changes,
                    "_protected_paths": list(
                        snapshot.manifest.get("protected_paths") or []
                    ),
                },
                blobs={patch_id: patch},
            )
            apply_trace = dict(getattr(envelope, "trace", {}) or {})
            if apply_trace.get("completion") != "complete":
                raise RemoteWorkspaceOperationError(
                    str(getattr(envelope, "text", "") or "guarded remote apply failed"),
                    envelope=envelope,
                )
        validation_summary = _remote_validation(ctx) if validate else ""
        if omission_note:
            validation_summary = "\n".join(
                part for part in (omission_note, validation_summary) if part
            )
        return RemoteClaudeOutcome(
            result=result,
            source_fingerprint=source_fingerprint,
            changed_files=changed_files,
            diff_stat=diff_stat,
            apply_trace=apply_trace,
            validation_summary=validation_summary,
        )


def _snapshot_omission_note(manifest: dict[str, Any]) -> str:
    exclusions = [
        row
        for row in list(manifest.get("exclusions") or [])
        if isinstance(row, dict)
        and str(row.get("reason") or "")
        in {"protected_artifact", "sensitive_file"}
    ]
    if not exclusions:
        return ""
    rendered = ", ".join(
        f"{row.get('path')} ({row.get('reason')})"
        for row in exclusions[:20]
    )
    suffix = (
        f"; +{len(exclusions) - 20} more"
        if len(exclusions) > 20
        else ""
    )
    return (
        "NOTICE: remote review used a policy-filtered snapshot; omitted "
        f"{rendered}{suffix}."
    )

def _assert_mirror_head_unchanged(root: pathlib.Path) -> None:
    if _git_text(root, ["rev-list", "--count", "HEAD"]) != "1":
        raise RemoteWorkspaceOperationError(
            "Claude moved the mirror HEAD; refusing an ambiguous remote patch"
        )


def _binary_patch(root: pathlib.Path) -> bytes:
    untracked = [
        row
        for row in _git_bytes(
            root, ["ls-files", "-z", "--others", "--exclude-standard"]
        ).split(b"\0")
        if row
    ]
    if untracked:
        _git(root, ["add", "-N", "--", *[os.fsdecode(row) for row in untracked]])
    return _git_bytes(
        root,
        [
            "diff",
            "--binary",
            "--full-index",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            "HEAD",
            "--",
        ],
    )


def _content_manifest(root: pathlib.Path) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(name for name in dirnames if name != ".git")
        for name in sorted(filenames):
            path = pathlib.Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            before = path.lstat()
            if stat.S_ISLNK(before.st_mode):
                data = os.readlink(path).encode("utf-8", errors="surrogateescape")
                kind = "symlink"
            elif stat.S_ISREG(before.st_mode):
                data = path.read_bytes()
                kind = "file"
            else:
                continue
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
                raise RemoteWorkspaceOperationError(
                    f"Claude mirror changed while it was being inspected: {rel}"
                )
            entries.append(
                {
                    "path": rel,
                    "kind": kind,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size": len(data),
                    "mode": stat.S_IMODE(before.st_mode),
                }
            )
    entries.sort(key=lambda row: row["path"])
    encoded = json.dumps(
        entries, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()
    return {
        "entries": entries,
        "content_fingerprint": hashlib.sha256(encoded).hexdigest(),
    }


def _change_manifest(
    before_rows: list[dict[str, Any]],
    after_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    before = {row["path"]: row for row in before_rows}
    after = {row["path"]: row for row in after_rows}
    changed: list[dict[str, Any]] = []
    for path in sorted(before.keys() | after.keys()):
        if before.get(path) == after.get(path):
            continue
        changed.append(
            {
                "path": path,
                "before": before.get(path),
                "after": after.get(path),
            }
        )
    return changed


def _remote_validation(ctx: Any) -> str:
    try:
        envelope = execute_remote_system_operation(
            ctx,
            "run_command",
            {
                "cmd": [
                    "python3",
                    "-m",
                    "pytest",
                    "tests/",
                    "--tb=line",
                    "-q",
                ],
                "cwd": ".",
                "timeout_sec": 60,
            },
        )
    except Exception as exc:
        return f"ERROR: remote validation failed: {type(exc).__name__}: {exc}"
    process = getattr(envelope, "process", None)
    if process is None:
        return f"ERROR: remote validation omitted process facts: {envelope.text}"
    if process.returncode == 0:
        return "PASS: all remote tests passed"
    output = (process.stdout or process.stderr or "")[-500:]
    return f"FAIL: remote tests failed (exit {process.returncode})\n{output}"


def _git(root: pathlib.Path, args: list[str]) -> None:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(root),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    if proc.returncode:
        raise RemoteWorkspaceOperationError(
            proc.stderr.decode("utf-8", errors="replace")
            or f"git {' '.join(args)} failed"
        )


def _git_bytes(root: pathlib.Path, args: list[str]) -> bytes:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(root),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    if proc.returncode:
        raise RemoteWorkspaceOperationError(
            proc.stderr.decode("utf-8", errors="replace")
            or f"git {' '.join(args)} failed"
        )
    return bytes(proc.stdout)


def _git_text(root: pathlib.Path, args: list[str]) -> str:
    return _git_bytes(root, args).decode("utf-8", errors="replace").strip()
