#!/usr/bin/env python3
"""Hermetic functional smoke for an assembled execd stage."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import pathlib
import subprocess
import sys
import tempfile
from typing import Any


def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_stage_hashes(root: pathlib.Path) -> None:
    manifest = root / "stage-files.sha256"
    declared: dict[str, str] = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        digest, separator, relative = line.partition("  ")
        if (
            separator != "  "
            or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
            or not relative
            or relative in declared
        ):
            raise RuntimeError("stage checksum manifest is malformed")
        path = pathlib.PurePosixPath(relative)
        if path.is_absolute() or ".." in path.parts:
            raise RuntimeError("stage checksum manifest contains an unsafe path")
        declared[relative] = digest
    observed: dict[str, pathlib.Path] = {}
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise RuntimeError(f"stage contains a link: {relative}")
        if path.is_file() and path != manifest:
            observed[relative] = path
    if set(declared) != set(observed):
        raise RuntimeError("stage checksum manifest does not match the artifact tree")
    for relative, expected in declared.items():
        if _sha256(observed[relative]) != expected:
            raise RuntimeError(f"stage checksum mismatch: {relative}")


def _service_smoke(root: pathlib.Path) -> None:
    from ouroboros.execd import ExecdService
    from ouroboros.execd_state import initialize_continuity_host_id
    from ouroboros.workspace_native import MANDATORY_REMOTE_NATIVE_OPERATIONS

    with tempfile.TemporaryDirectory(prefix="execd-service-smoke-") as temporary:
        base = pathlib.Path(temporary)
        workspace = base / "workspace"
        workspace.mkdir()
        for command in (
            ["git", "init", "-q"],
            ["git", "config", "user.email", "execd-smoke@example.invalid"],
            ["git", "config", "user.name", "Execd Smoke"],
        ):
            subprocess.run(
                command,
                cwd=workspace,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=30,
                check=True,
            )
        (workspace / "README.md").write_text("bootstrap\n", encoding="utf-8")
        for command in (
            ["git", "add", "README.md"],
            ["git", "commit", "-qm", "fixture"],
        ):
            subprocess.run(
                command,
                cwd=workspace,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=30,
                check=True,
            )
        manifest = {
            "manifest_sha256": "a" * 64,
            "native_operations": sorted(MANDATORY_REMOTE_NATIVE_OPERATIONS),
        }
        initialize_continuity_host_id(base / "state")
        service = ExecdService(
            base / "state",
            workspace,
            connection_id="connection-smoke",
            project_id="project-smoke",
            server_generation="generation-smoke",
            capability_manifest=manifest,
            release_id="smoke-release",
            artifact_sha256="b" * 64,
        )
        try:
            service.renew_lease(15_000, "task-smoke")
            handshake = service.handshake(manifest["manifest_sha256"])
            if (
                handshake["capability_hash"] != manifest["manifest_sha256"]
                or handshake["canonical_root"] != str(workspace.resolve())
                or not handshake["workspace_id"]
                or not handshake["host_id"]
                or not handshake["git"].get("head")
            ):
                raise RuntimeError(f"execd handshake facts are incomplete: {handshake}")

            operation_index = 0

            def execute(tool: str, args: dict[str, Any]) -> dict[str, Any]:
                nonlocal operation_index
                operation_index += 1
                operation_id = f"operation-{operation_index}"
                prepared = service.prepare(
                    request_id=f"request-{operation_index}",
                    operation_id=operation_id,
                    tool=tool,
                    args=args,
                    task_id="task-smoke",
                )
                result = service.continue_prepared(
                    request_id=f"request-{operation_index}",
                    operation_id=operation_id,
                    prepared_hash=prepared["prepared_hash"],
                    prepared_token=prepared["prepared_token"],
                )
                if result.get("completion") != "completed":
                    raise RuntimeError(f"execd operation did not complete: {result}")
                service.acknowledge(
                    "task-smoke",
                    operation_id,
                    prepared["prepared_hash"],
                )
                return result

            written = execute(
                "write_file",
                {"path": "native-smoke.txt", "content": "written-remotely\n"},
            )
            if written["envelope"].get("diagnostic") is not None:
                raise RuntimeError(f"execd write failed: {written}")
            read = execute("read_file", {"path": "native-smoke.txt"})
            if "written-remotely" not in read["envelope"].get("text", ""):
                raise RuntimeError(f"execd read did not observe the write: {read}")
            command = execute(
                "run_command",
                {
                    "cmd": ["sh", "-c", "printf native-run"],
                    "cwd": str(workspace),
                },
            )
            process = command["envelope"].get("process") or {}
            if process.get("returncode") != 0 or process.get("stdout") != "native-run":
                raise RuntimeError(f"execd process result is invalid: {command}")
            failed = execute("read_file", {"path": "absent-smoke.txt"})
            diagnostic = failed["envelope"].get("diagnostic") or {}
            if (
                not diagnostic.get("code")
                or diagnostic.get("domain") != "filesystem"
                or diagnostic.get("phase") != "execute"
            ):
                raise RuntimeError(f"execd typed error was lost: {failed}")
        finally:
            service.close()


def main(stage: pathlib.Path) -> int:
    root = stage.resolve(strict=True)
    _verify_stage_hashes(root)
    sys.path.insert(0, str(root / "lib"))
    provenance = json.loads(
        (root / "stage-provenance.json").read_text(encoding="utf-8")
    )
    for module in provenance["kernel_modules"]:
        importlib.import_module(module)

    from tree_sitter_language_pack import get_parser

    tree = get_parser("go").parse(b"package main\nfunc Serve() int { return 1 }\n")
    if tree.root_node.has_error:
        raise RuntimeError("bundled tree-sitter Go grammar failed")

    video = provenance["video_helper"]
    ffmpeg = root.joinpath(*pathlib.PurePosixPath(video["path"]).parts)
    if _sha256(ffmpeg) != video["sha256"]:
        raise RuntimeError("bundled ffmpeg digest differs from stage provenance")
    subprocess.run(
        [str(ffmpeg), "-version"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=30,
        check=True,
    )

    from ouroboros.workspace_query_native import query_workspace

    with tempfile.TemporaryDirectory(prefix="execd-stage-smoke-") as temporary:
        workspace = pathlib.Path(temporary)
        (workspace / "main.go").write_text(
            "package main\nfunc Serve() int { return 1 }\n",
            encoding="utf-8",
        )
        result = query_workspace(
            workspace,
            {
                "op": "structural",
                "query": "function_declaration",
                "lang": "go",
            },
        )
        if "main.go:2 function_declaration" not in result.text:
            raise RuntimeError(f"bundled structural query failed: {result.text}")
    _service_smoke(root)
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", type=pathlib.Path)
    arguments = parser.parse_args()
    raise SystemExit(main(arguments.stage))
