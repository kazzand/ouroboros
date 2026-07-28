from __future__ import annotations

import hashlib
import io
import json
import os
import pathlib
import signal
import subprocess
import sys
import tarfile
import threading
import time
import types
from typing import Any

import pytest

import ouroboros.execd as execd_module
import ouroboros.execd_state as state_module
import ouroboros.workspace_native as native_module
from ouroboros.execd import ExecdProtocolServer, ExecdService
from ouroboros.execd_state import (
    CASBlobStore,
    ExecdError,
    LeaseCustody,
    OperationJournal,
    continuity_host_id,
    initialize_continuity_host_id,
    read_json,
)
from ouroboros.remote_protocol import (
    MAX_CONTROL_BYTES,
    MAX_JSON_STRING_BYTES,
    ProtocolError,
    canonical_json,
    encode_control,
    read_frame,
)
from ouroboros.remote_ssh import OpenSSHExecdTransport, _validate_archive
from ouroboros.workspace_diagnostics import ToolExecutionEnvelope
from ouroboros.workspace_native import (
    MANDATORY_REMOTE_NATIVE_OPERATIONS,
    NativeOperationResult,
    execute_native_operation,
)
from scripts.assemble_execd_stage import LAUNCHER
from scripts.build_execd_bundle import build as build_execd_bundle


def _capability_manifest() -> dict[str, Any]:
    return {
        "manifest_sha256": "a" * 64,
        "native_operations": sorted(MANDATORY_REMOTE_NATIVE_OPERATIONS),
    }


def _git_workspace(path: pathlib.Path) -> pathlib.Path:
    path.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "execd-tests@example.invalid"],
        cwd=path,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Execd Tests"],
        cwd=path,
        check=True,
    )
    (path / "README.md").write_text("remote-only\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=path, check=True)
    subprocess.run(["git", "commit", "-qm", "fixture"], cwd=path, check=True)
    return path


def _service(
    tmp_path: pathlib.Path,
    *,
    generation: str = "generation-a",
    connection_id: str = "connection-a",
    project_id: str = "project-a",
) -> ExecdService:
    workspace = tmp_path / "workspace"
    if not workspace.exists():
        _git_workspace(workspace)
    initialize_continuity_host_id(tmp_path / "state")
    return ExecdService(
        tmp_path / "state",
        workspace,
        connection_id=connection_id,
        project_id=project_id,
        server_generation=generation,
        release_id="test-release",
        artifact_sha256="f" * 64,
        capability_manifest=_capability_manifest(),
    )


def test_continuity_identity_read_is_non_mutating_and_bootstrap_is_explicit(
    tmp_path,
    capsys,
):
    state_root = tmp_path / "state"

    with pytest.raises(ExecdError) as missing:
        continuity_host_id(state_root)
    assert missing.value.code == "host_identity_missing"
    assert not state_root.exists()

    with pytest.raises(ExecdError) as cli_missing:
        execd_module._main([
            "--state-root",
            str(state_root),
            "--print-host-id",
        ])
    assert cli_missing.value.code == "host_identity_missing"
    assert not state_root.exists()

    assert execd_module._main([
        "--state-root",
        str(state_root),
        "--initialize-host-id",
    ]) == 0
    initialized = capsys.readouterr().out.strip()
    assert initialized == continuity_host_id(state_root)

    assert execd_module._main([
        "--state-root",
        str(state_root),
        "--print-host-id",
    ]) == 0
    assert capsys.readouterr().out.strip() == initialized
    assert initialize_continuity_host_id(state_root) == initialized


@pytest.mark.parametrize(
    ("release_id", "artifact_sha256", "code"),
    [
        ("", "f" * 64, "release_identity_invalid"),
        ("../mutable", "f" * 64, "release_identity_invalid"),
        ("release-a", "F" * 64, "artifact_identity_invalid"),
        ("release-a", "f" * 63, "artifact_identity_invalid"),
    ],
)
def test_release_attestation_is_strict(release_id, artifact_sha256, code):
    with pytest.raises(ExecdError) as invalid:
        state_module.release_attestation(release_id, artifact_sha256)
    assert invalid.value.code == code


def test_handshake_attests_exact_release_and_prepared_binding(tmp_path):
    service = _service(tmp_path)
    writer = io.BytesIO()
    server = ExecdProtocolServer(service, io.BytesIO(), writer)

    server._receive_control({"kind": "handshake"})
    label, response = read_frame(io.BytesIO(writer.getvalue()))

    assert label == "control"
    assert response["kind"] == "handshake_ok"
    assert response["optional"]["artifact"] == {
        "release_id": "test-release",
        "sha256": "f" * 64,
    }
    service.prepare(
        request_id="request-release",
        operation_id="operation-release",
        tool="read_file",
        args={"path": "README.md"},
    )
    binding = service._prepared[
        ("request-release", "operation-release")
    ].prepared
    assert binding["release_id"] == "test-release"
    assert binding["artifact_sha256"] == "f" * 64


def test_execd_admission_supports_pre_2_5_git_facts(tmp_path, monkeypatch):
    workspace = _git_workspace(tmp_path / "workspace")
    real_run = subprocess.run
    observed: list[list[str]] = []

    def legacy_run(command, *args, **kwargs):
        argv = [str(item) for item in command]
        observed.append(argv)
        if argv == ["git", "rev-parse", "--git-common-dir"]:
            return subprocess.CompletedProcess(argv, 0, "--git-common-dir\n", "")
        if argv == ["git", "rev-parse", "--git-path", "index"]:
            return subprocess.CompletedProcess(argv, 0, b"--git-path\nindex\n", b"")
        if argv == [
            "git",
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ]:
            return subprocess.CompletedProcess(argv, 129, b"", b"unsupported option")
        return real_run(command, *args, **kwargs)

    monkeypatch.setattr(execd_module.subprocess, "run", legacy_run)
    initialize_continuity_host_id(tmp_path / "state")
    service = ExecdService(
        tmp_path / "state",
        workspace,
        connection_id="connection-a",
        project_id="project-a",
        server_generation="generation-a",
        release_id="test-release",
        artifact_sha256="f" * 64,
        capability_manifest=_capability_manifest(),
    )

    assert service.git_facts["common_dir"] == str(workspace / ".git")
    assert service.git_facts["index_present"] is True
    assert all("-C" not in argv for argv in observed)
    assert [
        "git",
        "-c",
        "diff.ignoreSubmodules=none",
        "status",
        "--porcelain",
        "--untracked-files=all",
    ] in observed


def test_continue_revalidates_target_facts_before_journal_or_effect(tmp_path):
    service = _service(tmp_path)
    first = service.workspace_root / "first"
    second = service.workspace_root / "second"
    first.mkdir()
    second.mkdir()
    selected = service.workspace_root / "selected"
    selected.symlink_to(first, target_is_directory=True)
    prepared = service.prepare(
        request_id="request-target",
        operation_id="operation-target",
        tool="run_command",
        args={
            "cmd": [sys.executable, "-c", "open('effect', 'w').write('ran')"],
            "cwd": "selected",
        },
        task_id="task-target",
    )
    selected.unlink()
    selected.symlink_to(second, target_is_directory=True)

    with pytest.raises(ExecdError) as changed:
        service.continue_prepared(
            request_id="request-target",
            operation_id="operation-target",
            prepared_hash=prepared["prepared_hash"],
            prepared_token=prepared["prepared_token"],
        )

    assert changed.value.code == "prepared_target_changed"
    assert changed.value.phase == "authorize"
    assert service.journal.list_records() == []
    assert not (first / "effect").exists()
    assert not (second / "effect").exists()


def test_reviewed_payload_prepare_and_revalidation_receive_staged_blobs(
    tmp_path,
    monkeypatch,
):
    operation = "execute_reviewed_payload"
    payload = b"print('reviewed payload')\n"
    digest = hashlib.sha256(payload).hexdigest()
    content_hash = hashlib.sha256(
        b"main.py\0" + bytes.fromhex(digest)
    ).hexdigest()
    service = _service(tmp_path)
    executed: list[dict[str, bytes]] = []

    def execute(*_args, blobs=None, **_kwargs):
        executed.append(dict(blobs or {}))
        return NativeOperationResult(ToolExecutionEnvelope(text="ok"))

    monkeypatch.setattr(execd_module, "execute_native_operation", execute)
    prepared = service.prepare(
        request_id="request-reviewed",
        operation_id="operation-reviewed",
        tool=operation,
        args={
            "schema_version": 1,
            "kind": "script",
            "payload": {
                "content_hash": content_hash,
                "skill_name": "reviewed",
                "runtime": "python3",
                "files": [{
                    "path": "main.py",
                    "sha256": digest,
                    "size": len(payload),
                    "mode": 0o600,
                }],
            },
            "invocation": {
                "entry": "main.py",
                "argv": [],
                "timeout_sec": 10,
            },
        },
        task_id="task-reviewed",
        blobs={digest: payload},
    )
    result = service.continue_prepared(
        request_id="request-reviewed",
        operation_id="operation-reviewed",
        prepared_hash=prepared["prepared_hash"],
        prepared_token=prepared["prepared_token"],
    )

    assert result["completion"] == "completed"
    assert prepared["native_facts"]["payload_content_hash"] == content_hash
    assert executed == [{digest: payload}]


def _fake_bundle_stage(path: pathlib.Path, architecture: str) -> pathlib.Path:
    (path / "bin").mkdir(parents=True)
    launcher = path / "bin" / "ouroboros-execd"
    launcher.write_text(f"#!/bin/sh\necho {architecture}\n", encoding="utf-8")
    launcher.chmod(0o755)
    ripgrep = path / "bin" / "rg"
    ripgrep.write_bytes(f"rg-{architecture}".encode())
    ripgrep.chmod(0o755)
    lock = json.loads(
        (
            pathlib.Path(__file__).resolve().parents[1]
            / "scripts"
            / "execd_dependency_lock.json"
        ).read_text(encoding="utf-8")
    )
    provenance = path / "stage-provenance.json"
    provenance.write_text(
        json.dumps(
            {
                "architecture": architecture,
                "python_build_standalone": lock["python_build_standalone"][
                    "architectures"
                ][architecture],
                "ripgrep": lock["ripgrep"]["architectures"][architecture],
                "video_helper": lock["video_helper"]["architectures"][
                    architecture
                ],
                "python_wheels": lock["python_wheels"][architecture],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (path / "stage-files.sha256").write_text(
        "\n".join(
            f"{hashlib.sha256(item.read_bytes()).hexdigest()}  "
            f"{item.relative_to(path).as_posix()}"
            for item in (launcher, ripgrep, provenance)
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def test_execd_bundle_builder_is_deterministic_and_dual_arch(tmp_path):
    stages = {
        architecture: _fake_bundle_stage(tmp_path / architecture, architecture)
        for architecture in ("x86_64", "aarch64")
    }
    lock = json.loads(
        (
            pathlib.Path(__file__).resolve().parents[1]
            / "scripts"
            / "execd_dependency_lock.json"
        ).read_text(encoding="utf-8")
    )
    first = tmp_path / "first"
    second = tmp_path / "second"
    one = build_execd_bundle(
        version="9.9.9",
        stages=stages,
        output_dir=first,
        dependency_lock=lock,
    )
    two = build_execd_bundle(
        version="9.9.9",
        stages=stages,
        output_dir=second,
        dependency_lock=lock,
    )
    assert one == two
    assert (first / "manifest.json").read_bytes() == (
        second / "manifest.json"
    ).read_bytes()
    for asset in one["assets"].values():
        assert (first / asset["archive"]).read_bytes() == (
            second / asset["archive"]
        ).read_bytes()
        assert asset["glibc_min"] == "2.17"
        assert asset["files"]
        with tarfile.open(first / asset["archive"], "r:gz") as archive:
            modes = {member.name: member.mode for member in archive.getmembers()}
        assert modes["bin/ouroboros-execd"] & 0o111
        assert modes["bin/rg"] & 0o111


def test_execd_launcher_self_smoke_does_not_mutate_stage(tmp_path):
    stage = tmp_path / "stage"
    launcher = stage / "bin" / "ouroboros-execd"
    runtime = stage / "runtime" / "bin" / "python3"
    package = stage / "lib" / "ouroboros"
    launcher.parent.mkdir(parents=True)
    runtime.parent.mkdir(parents=True)
    package.mkdir(parents=True)
    runtime.symlink_to(sys.executable)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "execd.py").write_text(
        'print("ouroboros-execd synthetic")\n',
        encoding="utf-8",
    )
    launcher.write_text(
        LAUNCHER.replace("@FFMPEG_SHA256@", "a" * 64),
        encoding="utf-8",
    )
    launcher.chmod(0o755)
    before = {
        path.relative_to(stage).as_posix(): (
            path.is_dir(),
            path.is_symlink(),
            hashlib.sha256(path.read_bytes()).hexdigest()
            if path.is_file() and not path.is_symlink()
            else "",
        )
        for path in stage.rglob("*")
    }

    subprocess.run([str(launcher), "--version"], check=True, timeout=30)

    after = {
        path.relative_to(stage).as_posix(): (
            path.is_dir(),
            path.is_symlink(),
            hashlib.sha256(path.read_bytes()).hexdigest()
            if path.is_file() and not path.is_symlink()
            else "",
        )
        for path in stage.rglob("*")
    }
    assert after == before


def test_execd_bundle_builder_rejects_links_and_home_modules(tmp_path):
    stages = {
        architecture: _fake_bundle_stage(tmp_path / architecture, architecture)
        for architecture in ("x86_64", "aarch64")
    }
    (stages["x86_64"] / "escape").symlink_to("/etc/passwd")
    with pytest.raises(ValueError, match="links are forbidden"):
        build_execd_bundle(
            version="9.9.9",
            stages=stages,
            output_dir=tmp_path / "out",
            dependency_lock=json.loads(
                (
                    pathlib.Path(__file__).resolve().parents[1]
                    / "scripts"
                    / "execd_dependency_lock.json"
                ).read_text(encoding="utf-8")
            ),
        )


def test_bootstrap_archive_validator_rejects_duplicate_members(tmp_path):
    archive_path = tmp_path / "duplicate.tar.gz"
    payload = b"verified"
    with tarfile.open(archive_path, "w:gz") as archive:
        for _index in range(2):
            info = tarfile.TarInfo("bin/ouroboros-execd")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    declared = {
        "bin/ouroboros-execd": {
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
    }

    with pytest.raises(Exception) as rejected:
        _validate_archive(archive_path, declared)

    assert getattr(rejected.value, "code", "") == "execd_bundle_invalid"


def test_bootstrap_archive_validator_accepts_empty_and_rejects_digest_mismatch(
    tmp_path,
):
    empty_path = tmp_path / "empty.tar.gz"
    with tarfile.open(empty_path, "w:gz") as archive:
        info = tarfile.TarInfo("lib/empty")
        info.size = 0
        archive.addfile(info, io.BytesIO())
    _validate_archive(
        empty_path,
        {
            "lib/empty": {
                "size": 0,
                "sha256": hashlib.sha256(b"").hexdigest(),
            }
        },
    )

    archive_path = tmp_path / "mismatch.tar.gz"
    payload = b"tampered"
    with tarfile.open(archive_path, "w:gz") as archive:
        info = tarfile.TarInfo("bin/ouroboros-execd")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    declared = {
        "bin/ouroboros-execd": {
            "size": len(payload),
            "sha256": hashlib.sha256(b"expected").hexdigest(),
        }
    }

    with pytest.raises(Exception) as rejected:
        _validate_archive(archive_path, declared)

    assert getattr(rejected.value, "code", "") == "execd_bundle_invalid"


def test_musl_platform_fails_before_bundle_upload(tmp_path):
    probe = object.__new__(OpenSSHExecdTransport)
    probe._run_remote = lambda *args, **kwargs: subprocess.CompletedProcess(
        args,
        0,
        stdout=b"Linux\tx86_64\t\n",
        stderr=b"",
    )
    assert probe._platform_probe(1)["libc"] == "unknown"

    bundle = tmp_path / "bundle"
    bundle.mkdir()
    payload = b"binary"
    archive_path = bundle / "execd.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        info = tarfile.TarInfo("bin/ouroboros-execd")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    (bundle / "manifest.json").write_text(
        json.dumps(
            {
                "build": "test",
                "assets": {
                    "linux-x86_64": {
                        "archive": archive_path.name,
                        "sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                        "size": archive_path.stat().st_size,
                        "loader": "/lib64/ld-linux-x86-64.so.2",
                        "glibc_min": "2.17",
                        "files": [
                            {
                                "path": "bin/ouroboros-execd",
                                "size": len(payload),
                                "sha256": hashlib.sha256(payload).hexdigest(),
                            }
                        ],
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    transport = object.__new__(OpenSSHExecdTransport)
    transport.request = types.SimpleNamespace(bundle_dir=bundle)
    transport._platform_probe = lambda _timeout: {
        "system": "Linux",
        "machine": "x86_64",
        "libc": "unknown",
        "libc_version": "",
    }
    remote_calls = []
    transport._run_remote = lambda *args, **kwargs: remote_calls.append((args, kwargs))

    with pytest.raises(Exception) as rejected:
        transport.bootstrap(timeout_sec=1)

    assert getattr(rejected.value, "code", "") == "remote_libc_unsupported"
    assert remote_calls == []


def test_bootstrap_reuses_only_exact_verified_content_addressed_release(tmp_path):
    import inspect

    stages = {
        architecture: _fake_bundle_stage(tmp_path / architecture, architecture)
        for architecture in ("x86_64", "aarch64")
    }
    lock = json.loads(
        (
            pathlib.Path(__file__).resolve().parents[1]
            / "scripts"
            / "execd_dependency_lock.json"
        ).read_text(encoding="utf-8")
    )
    bundle = tmp_path / "bundle"
    manifest = build_execd_bundle(
        version="9.9.9",
        stages=stages,
        output_dir=bundle,
        dependency_lock=lock,
    )
    archive = bundle / manifest["assets"]["linux-x86_64"]["archive"]
    capability = {
        "manifest_sha256": "a" * 64,
        "native_operations": sorted(MANDATORY_REMOTE_NATIVE_OPERATIONS),
    }
    outcomes = []
    for current_is_valid in (True, False):
        calls = []
        host_calls = []
        transport = object.__new__(OpenSSHExecdTransport)
        transport.request = types.SimpleNamespace(
            bundle_dir=bundle,
            capability_manifest=capability,
            connection={"expected_host_id": "host-a"},
        )
        transport._platform_probe = lambda _timeout: {
            "system": "Linux",
            "machine": "x86_64",
            "libc": "glibc",
            "libc_version": "2.17",
        }
        transport._run_remote = lambda command, **kwargs: (
            calls.append((command, kwargs))
            or subprocess.CompletedProcess(
                command,
                0,
                stdout=(
                    b"READY\n"
                    if current_is_valid and "READY" in str(command) and "MISS" in str(command)
                    else b"MISS\n"
                    if "READY" in str(command) and "MISS" in str(command)
                    else b""
                ),
                stderr=b"",
            )
        )
        transport._installed_host_id = lambda _timeout, required, selected: (
            host_calls.append(required) or "host-a"
        )

        result = transport.bootstrap(timeout_sec=1)

        archive_uploads = [
            kwargs.get("input_path")
            for _command, kwargs in calls
            if kwargs.get("input_path") == archive
        ]
        assert bool(archive_uploads) is not current_is_valid
        assert any(
            kwargs.get("input_bytes") == canonical_json(capability)
            for _command, kwargs in calls
        )
        assert host_calls == [True]
        outcomes.append(result["completion"])
    assert outcomes == ["already_installed", "installed"]

    source = inspect.getsource(OpenSSHExecdTransport._start_session)
    assert '--project-id "$5"' in source
    assert "self.request.project_id" in source
    assert "select.select" not in source
    assert "process.stdout.read" in source


def _journal(tmp_path: pathlib.Path) -> OperationJournal:
    blobs = CASBlobStore(tmp_path / "blobs")
    return OperationJournal(
        tmp_path / "operations",
        connection_id="connection-a",
        workspace_id="workspace-a",
        spool=CASBlobStore(tmp_path / "spool"),
        blobs=blobs,
    )


def _begin(
    journal: OperationJournal,
    *,
    task_id: str = "task-a",
    operation_id: str = "operation-a",
    request_hash: str = "b" * 64,
) -> tuple[str, dict[str, Any] | None]:
    return journal.begin(
        task_id=task_id,
        operation_id=operation_id,
        request_hash=request_hash,
        binding={"task_id": task_id, "operation_id": operation_id},
    )


def _process_group_exists(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_group_gone(pgid: int, timeout: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _process_group_exists(pgid):
            return True
        time.sleep(0.05)
    return not _process_group_exists(pgid)


def test_new_custody_state_is_durable_before_custodian_spawn(tmp_path, monkeypatch):
    service = _service(tmp_path)
    observed: dict[str, Any] = {}

    class _FakeProcess:
        def poll(self):
            return None

        def terminate(self):
            return None

    def fake_popen(command, **kwargs):
        del kwargs
        state_path = pathlib.Path(command[command.index("--custodian") + 1])
        observed["command"] = list(command)
        observed["state"] = read_json(state_path, required=True)
        return _FakeProcess()

    monkeypatch.setattr(execd_module.subprocess, "Popen", fake_popen)
    process = service._spawn_custodian()

    assert process.poll() is None
    assert observed["state"]["server_generation"] == "generation-a"
    assert observed["state"]["groups"] == []
    assert observed["state"]["server_expiry_ms"] > int(time.time() * 1000)
    assert observed["state"]["custodian_id"]
    assert observed["state"]["custodian_close_requested"] is False
    assert observed["command"][-2:] == [
        "--custodian-id",
        observed["state"]["custodian_id"],
    ]


def test_service_close_durably_stops_exact_custodian(tmp_path, monkeypatch):
    service = _service(tmp_path)

    class _FakeProcess:
        def __init__(self):
            self.terminated = False

        def poll(self):
            return None

        def terminate(self):
            self.terminated = True

    process = _FakeProcess()
    monkeypatch.setattr(
        execd_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )
    service._custodian_process = service._spawn_custodian()
    identity = service._custodian_id

    service.close(kill_owned=True)

    state = service.custody.refresh_snapshot()
    assert state["custodian_id"] == identity
    assert state["custodian_close_requested"] is True
    assert state["server_expiry_ms"] == 0
    assert process.terminated is True
    with pytest.raises(ExecdError) as closing:
        service.renew_lease(10_000)
    assert closing.value.code == "generation_closing"


def test_frozen_execd_reenters_itself_without_python_module_mode(tmp_path, monkeypatch):
    service = _service(tmp_path)
    commands: list[list[str]] = []

    class _FakeProcess:
        def poll(self):
            return None

    monkeypatch.delenv("OUROBOROS_EXECD_SELF", raising=False)
    monkeypatch.setattr(execd_module.sys, "frozen", True, raising=False)
    monkeypatch.setattr(execd_module.sys, "executable", "/opt/exe/ouroboros-execd")
    monkeypatch.setattr(
        execd_module.subprocess,
        "Popen",
        lambda command, **kwargs: (
            commands.append(list(command)) or _FakeProcess()
        ),
    )

    service._spawn_custodian()

    assert commands
    assert commands[0][0] == "/opt/exe/ouroboros-execd"
    assert commands[0][1] == "--custodian"
    assert "-m" not in commands[0]


def test_configured_execd_self_is_the_bundle_reentry_authority(tmp_path, monkeypatch):
    service = _service(tmp_path)
    commands: list[list[str]] = []

    class _FakeProcess:
        def poll(self):
            return None

    monkeypatch.setenv("OUROBOROS_EXECD_SELF", "/bundle/current/ouroboros-execd")
    monkeypatch.setattr(
        execd_module.subprocess,
        "Popen",
        lambda command, **kwargs: (
            commands.append(list(command)) or _FakeProcess()
        ),
    )

    service._spawn_custodian()

    assert commands[0][:2] == [
        "/bundle/current/ouroboros-execd",
        "--custodian",
    ]


def test_custodian_survives_empty_expired_lease_until_explicit_close(tmp_path):
    custody = LeaseCustody(tmp_path / "custody.json", "generation-a")
    identity = custody.claim_custodian()
    custody.renew(ttl_ms=50)
    outcomes: list[int] = []
    thread = threading.Thread(
        target=lambda: outcomes.append(
            state_module.run_custodian(
                custody.state_path,
                "generation-a",
                identity,
            )
        ),
        daemon=True,
    )
    thread.start()

    time.sleep(0.35)
    assert thread.is_alive()
    assert custody.refresh_snapshot()["groups"] == []

    assert custody.request_custodian_close(identity) is True
    thread.join(timeout=1)
    assert not thread.is_alive()
    assert outcomes == [0]


def test_replacement_custodian_waits_for_previous_identity_to_close(tmp_path):
    custody = LeaseCustody(tmp_path / "custody.json", "generation-a")
    first = custody.claim_custodian()
    outcomes: list[int] = []
    thread = threading.Thread(
        target=lambda: outcomes.append(
            state_module.run_custodian(
                custody.state_path,
                "generation-a",
                first,
            )
        ),
        daemon=True,
    )
    thread.start()
    with pytest.raises(ExecdError) as active:
        custody.claim_custodian()
    assert active.value.code == "generation_active"
    assert custody.request_custodian_close(first) is True
    second = custody.claim_custodian()

    thread.join(timeout=1)
    assert not thread.is_alive()
    assert outcomes == [0]
    assert custody.refresh_snapshot()["custodian_id"] == second
    assert custody.request_custodian_close(first) is False


def test_custody_refuses_processes_without_required_live_leases(tmp_path, monkeypatch):
    fingerprint = {
        "boot_id": "boot",
        "pid_namespace": "pid:[1]",
        "leader_pid": 12345,
        "pgrp": 12345,
        "session": 12345,
        "start_ticks": 1,
    }
    monkeypatch.setattr(state_module, "_process_fingerprint", lambda _pid: fingerprint)
    custody = LeaseCustody(tmp_path / "custody.json", "generation-a")

    with pytest.raises(ExecdError) as no_generation:
        custody.register(
            pgid=12345,
            task_id="task-a",
            keep_alive=True,
            service_id="service-a",
        )
    assert no_generation.value.code == "server_lease_expired"
    assert custody.snapshot()["groups"] == []

    custody.renew(ttl_ms=10_000)
    with pytest.raises(ExecdError) as no_task:
        custody.register(
            pgid=12345,
            task_id="task-a",
            keep_alive=False,
            service_id="",
        )
    assert no_task.value.code == "task_lease_expired"
    assert custody.snapshot()["groups"] == []

    custody.register(
        pgid=12345,
        task_id="task-a",
        keep_alive=True,
        service_id="service-a",
    )
    assert custody.snapshot()["groups"][0]["service_id"] == "service-a"


def test_failed_group_kill_retains_durable_authority_for_retry(tmp_path, monkeypatch):
    fingerprint = {
        "boot_id": "boot",
        "pid_namespace": "pid:[1]",
        "leader_pid": 12345,
        "pgrp": 12345,
        "session": 12345,
        "start_ticks": 1,
    }
    monkeypatch.setattr(state_module, "_process_fingerprint", lambda _pid: fingerprint)
    custody = LeaseCustody(tmp_path / "custody.json", "generation-a")
    custody.renew(ttl_ms=10_000, task_id="task-a")
    custody.register(
        pgid=12345,
        task_id="task-a",
        keep_alive=False,
        service_id="",
    )
    attempts = 0

    def flaky_group_kill(pgid, *, checked=False):
        nonlocal attempts
        assert pgid == 12345
        assert checked is True
        attempts += 1
        if attempts == 1:
            raise PermissionError("temporarily denied")
        return True

    monkeypatch.setattr(
        state_module,
        "kill_process_group_id",
        flaky_group_kill,
    )

    assert custody.cancel_task("task-a") == 0
    assert [row["pgid"] for row in custody.snapshot()["groups"]] == [12345]
    assert LeaseCustody(
        tmp_path / "custody.json", "generation-a"
    ).snapshot()["groups"][0]["pgid"] == 12345

    assert custody.kill_generation() == 1
    assert custody.snapshot()["groups"] == []


def test_release_and_service_identity_survive_custody_reopen(tmp_path, monkeypatch):
    fingerprint = {
        "boot_id": "boot",
        "pid_namespace": "pid:[1]",
        "leader_pid": 12345,
        "pgrp": 12345,
        "session": 12345,
        "start_ticks": 1,
    }
    monkeypatch.setattr(state_module, "_process_fingerprint", lambda _pid: fingerprint)
    path = tmp_path / "custody.json"
    custody = LeaseCustody(path, "generation-a")
    custody.renew(ttl_ms=10_000)
    custody.register(
        pgid=12345,
        task_id="task-a",
        keep_alive=True,
        service_id="service-a",
    )

    reopened = LeaseCustody(path, "generation-a")
    recovered = reopened.recover_service(service_id="service-a", task_id="task-a")
    assert recovered is not None
    assert recovered["pgid"] == 12345

    with pytest.raises(ExecdError):
        reopened.release(pgid=12345, service_id="service-other")
    reopened.release(pgid=12345, service_id="service-a")
    assert LeaseCustody(path, "generation-a").snapshot()["groups"] == []


def test_custody_fingerprint_mismatch_prunes_without_signalling(tmp_path, monkeypatch):
    recorded = {
        "boot_id": "boot-a",
        "pid_namespace": "pid:[1]",
        "leader_pid": 12345,
        "pgrp": 12345,
        "session": 12345,
        "start_ticks": 10,
    }
    current = {**recorded, "start_ticks": 11}
    monkeypatch.setattr(state_module, "_process_fingerprint", lambda _pid: recorded)
    custody = LeaseCustody(tmp_path / "custody.json", "generation-a")
    custody.renew(ttl_ms=10_000)
    custody.register(
        pgid=12345,
        task_id="task-a",
        keep_alive=True,
        service_id="service-a",
    )
    monkeypatch.setattr(state_module, "_process_fingerprint", lambda _pid: current)
    calls: list[int] = []
    monkeypatch.setattr(
        state_module,
        "kill_process_group_id",
        lambda pgid, *, checked=False: calls.append(pgid) or checked,
    )

    assert custody.kill_generation() == 1
    assert calls == []
    assert custody.refresh_snapshot()["groups"] == []


def test_zero_generation_expiry_retries_retained_keepalive_kill(tmp_path, monkeypatch):
    fingerprint = {
        "boot_id": "boot",
        "pid_namespace": "pid:[1]",
        "leader_pid": 12345,
        "pgrp": 12345,
        "session": 12345,
        "start_ticks": 1,
    }
    monkeypatch.setattr(state_module, "_process_fingerprint", lambda _pid: fingerprint)
    custody = LeaseCustody(tmp_path / "custody.json", "generation-a")
    custody.renew(ttl_ms=10_000)
    custody.register(
        pgid=12345,
        task_id="task-a",
        keep_alive=True,
        service_id="service-a",
    )
    attempts = 0

    def flaky(pgid, *, checked=False):
        nonlocal attempts
        assert checked is True
        attempts += 1
        if attempts == 1:
            raise PermissionError("transient")
        return True

    monkeypatch.setattr(state_module, "kill_process_group_id", flaky)
    assert custody.kill_generation() == 0
    assert custody.refresh_snapshot()["groups"]
    assert custody.expire() == 1
    assert attempts == 2
    assert custody.refresh_snapshot()["groups"] == []


def test_broker_blocked_session_does_not_block_other_session_or_cancel(tmp_path):
    from ouroboros.remote_workspace import RemoteSessionBroker

    release = threading.Event()
    entered = threading.Event()

    class Transport:
        def __init__(self, request):
            self.request = request

        def handshake(self):
            return {
                "host_id": f"host-{self.request.connection['id']}",
                "workspace_id": f"workspace-{self.request.connection['id']}",
                "canonical_root": self.request.remote_root,
                "capability_hash": "a" * 64,
                "build": "test",
            }

        def prepare(self, message, blobs):
            return {
                "request_id": message["request_id"],
                "operation_id": message["operation_id"],
                "tool": message["tool"],
                "prepared_token": "token-a",
                "prepared_hash": "c" * 64,
                "expires_at_ms": int(time.time() * 1000) + 10_000,
                "execution_args": dict(message["args"]),
                "native_facts": {},
            }

        def execute_prepared(self, message):
            if self.request.connection["id"] == "connection-a":
                entered.set()
                assert release.wait(5)
            return {
                "text": "done",
                "diagnostic": None,
                "process": None,
                "artifacts": [],
                "trace": {},
            }

        def abort_prepared(self, message):
            return True

        def fetch_blob(self, blob_id, max_bytes):
            return b""

        def reconcile(self):
            return []

        def renew_lease(self, message):
            return None

        def cancel(self, message):
            release.set()
            return True

        def panic(self):
            release.set()

        def close(self):
            release.set()

    manifest = {
        "schema_version": 1,
        "manifest_sha256": "a" * 64,
        "public_schema_sha256": "b" * 64,
        "native_operations": [
            {"name": name} for name in sorted(MANDATORY_REMOTE_NATIVE_OPERATIONS)
        ],
        "native_kernel_modules": [],
        "native_import_modules": [],
        "native_import_edges": {},
    }
    broker = RemoteSessionBroker(
        tmp_path,
        "generation-a",
        manifest,
        transport_factory=Transport,
    )
    try:
        refs = {}
        for suffix in ("a", "b"):
            admitted = broker.admit_workspace(
                {
                    "id": f"connection-{suffix}",
                    "ssh_alias": f"host-{suffix}",
                },
                remote_root=f"/srv/{suffix}",
                project_id=f"project-{suffix}",
                task_id=f"task-{suffix}",
            )
            refs[suffix] = admitted["workspace_ref"]
        prepared_a = broker.prepare(
            refs["a"],
            request_id="request-a",
            operation_id="operation-a",
            tool="read_file",
            args={"path": "a"},
            task_id="task-a",
        )
        result: list[Any] = []
        worker = threading.Thread(
            target=lambda: result.append(
                broker.execute_prepared(
                    refs["a"],
                    prepared_a,
                    canonical_args=prepared_a.execution_args,
                    task_id="task-a",
                )
            )
        )
        worker.start()
        assert entered.wait(2)
        started = time.monotonic()
        prepared_b = broker.prepare(
            refs["b"],
            request_id="request-b",
            operation_id="operation-b",
            tool="read_file",
            args={"path": "b"},
            task_id="task-b",
        )
        assert time.monotonic() - started < 1
        assert prepared_b.execution_args == {"path": "b"}
        assert broker.cancel(refs["a"], task_id="task-a")
        worker.join(timeout=2)
        assert result and result[0].text == "done"
    finally:
        broker.close(timeout_sec=2)


def test_generation_mismatch_cannot_adopt_another_generation_state(tmp_path):
    path = tmp_path / "custody.json"
    LeaseCustody(path, "generation-a")

    with pytest.raises(ExecdError) as mismatch:
        LeaseCustody(path, "generation-b")

    assert mismatch.value.code == "custody_state_mismatch"
    assert read_json(path, required=True)["server_generation"] == "generation-a"


def test_panic_kill_isolated_to_exact_server_generation(tmp_path, monkeypatch):
    def fingerprint(pid):
        return {
            "boot_id": "boot",
            "pid_namespace": "pid:[1]",
            "leader_pid": pid,
            "pgrp": pid,
            "session": pid,
            "start_ticks": pid * 10,
        }

    monkeypatch.setattr(state_module, "_process_fingerprint", fingerprint)
    killed: list[int] = []
    monkeypatch.setattr(
        state_module.os,
        "killpg",
        lambda pgid, sig: (
            killed.append(pgid)
            if sig == signal.SIGKILL
            else pytest.fail(f"unexpected signal: {sig}")
        ),
    )
    first = LeaseCustody(tmp_path / "generation-a.json", "generation-a")
    second = LeaseCustody(tmp_path / "generation-b.json", "generation-b")
    first.renew(ttl_ms=10_000)
    second.renew(ttl_ms=10_000)
    first.register(
        pgid=11111,
        task_id="task-a",
        keep_alive=True,
        service_id="service-a",
    )
    second.register(
        pgid=22222,
        task_id="task-b",
        keep_alive=True,
        service_id="service-b",
    )

    assert first.kill_generation() == 1

    assert killed == [11111]
    assert first.refresh_snapshot()["groups"] == []
    assert [row["pgid"] for row in second.refresh_snapshot()["groups"]] == [
        22222
    ]


def test_journal_is_task_bound_even_when_operation_id_and_hash_match(tmp_path):
    journal = _journal(tmp_path)
    assert _begin(journal) == ("started", None)

    with pytest.raises(ExecdError):
        _begin(journal, task_id="task-b")

    reopened = _journal(tmp_path)
    with pytest.raises(ExecdError):
        reopened.reconcile("task-b", "operation-a", "b" * 64)

    with pytest.raises(ExecdError):
        reopened.acknowledge("task-b", "operation-a", "b" * 64)


def test_journal_duplicate_completion_and_unknown_started_are_reconciled(tmp_path):
    journal = _journal(tmp_path)
    _begin(journal)

    assert journal.reconcile("task-a", "operation-a", "b" * 64) == {
        "completion": "unknown"
    }
    result = {"completion": "completed", "answer": "ok"}
    journal.complete(
        task_id="task-a",
        operation_id="operation-a",
        request_hash="b" * 64,
        result=result,
    )

    assert _begin(journal) == ("completed", result)
    assert journal.reconcile("task-a", "operation-a", "b" * 64) == {
        "completion": "completed",
        "result": result,
        "result_unavailable": False,
    }
    with pytest.raises(ExecdError) as conflict:
        _begin(journal, request_hash="c" * 64)
    assert conflict.value.code == "operation_id_conflict"


def test_journal_start_write_failure_is_fail_closed(tmp_path, monkeypatch):
    journal = _journal(tmp_path)
    original = state_module.durable_json

    def fail_start(path, payload):
        if payload.get("state") == "started":
            raise OSError("disk full")
        return original(path, payload)

    monkeypatch.setattr(state_module, "durable_json", fail_start)
    with pytest.raises(ExecdError) as failure:
        _begin(journal)

    assert failure.value.code == "journal_start_failed"
    assert journal.reconcile("task-a", "operation-a", "b" * 64) == {
        "completion": "not_started"
    }


def test_missing_spooled_result_is_unavailable_and_never_reruns(tmp_path, monkeypatch):
    monkeypatch.setattr(state_module, "MAX_RESULT_BYTES", 32)
    journal = _journal(tmp_path)
    _begin(journal)
    journal.complete(
        task_id="task-a",
        operation_id="operation-a",
        request_hash="b" * 64,
        result={"completion": "completed", "payload": "x" * 1000},
    )
    record = journal.list_records()[0]
    spool_path = journal.spool.path_for(record["result_blob_id"])
    spool_path.unlink()

    reconciled = journal.reconcile("task-a", "operation-a", "b" * 64)
    assert reconciled == {
        "completion": "completed",
        "result": None,
        "result_unavailable": True,
    }
    assert _begin(journal) == ("completed", None)


def test_ack_prunes_only_old_acknowledged_records(tmp_path, monkeypatch):
    monkeypatch.setattr(state_module, "MAX_RETAINED_ACKED_OPERATIONS", 2)
    monkeypatch.setattr(state_module, "ACKED_BLOB_EXPORT_GRACE_MS", 0)
    journal = _journal(tmp_path)
    for index in range(4):
        operation_id = f"operation-{index}"
        request_hash = hashlib.sha256(operation_id.encode()).hexdigest()
        _begin(
            journal,
            operation_id=operation_id,
            request_hash=request_hash,
        )
        journal.complete(
            task_id="task-a",
            operation_id=operation_id,
            request_hash=request_hash,
            result={"completion": "completed", "index": index},
        )
        journal.acknowledge("task-a", operation_id, request_hash)
        time.sleep(0.002)

    rows = journal.list_records()
    assert len(rows) == 2
    assert {row["operation_id"] for row in rows} == {
        "operation-2",
        "operation-3",
    }


def test_journal_live_capacity_ignores_bounded_acknowledged_rows(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(state_module, "MAX_LIVE_OPERATIONS", 1)
    monkeypatch.setattr(state_module, "MAX_TOTAL_OPERATION_RECORDS", 3)
    journal = _journal(tmp_path)
    _begin(journal, operation_id="operation-acked", request_hash="3" * 64)
    journal.complete(
        task_id="task-a",
        operation_id="operation-acked",
        request_hash="3" * 64,
        result={"completion": "completed"},
    )
    journal.acknowledge("task-a", "operation-acked", "3" * 64)

    assert _begin(
        journal,
        operation_id="operation-live",
        request_hash="4" * 64,
    ) == ("started", None)
    with pytest.raises(ExecdError, match="capacity"):
        _begin(
            journal,
            operation_id="operation-blocked",
            request_hash="5" * 64,
        )


def test_blob_gc_preserves_every_unacknowledged_journal_reference(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(state_module, "MAX_RESULT_BYTES", 32)
    journal = _journal(tmp_path)
    assert journal.blobs is not None
    input_blob = journal.blobs.put(b"prepared input")
    output_blob = journal.blobs.put(b"unfetched output")
    request_hash = "d" * 64
    journal.begin(
        task_id="task-live",
        operation_id="operation-live",
        request_hash=request_hash,
        binding={"blob_hashes": {"upload": input_blob}},
    )
    journal.complete(
        task_id="task-live",
        operation_id="operation-live",
        request_hash=request_hash,
        result={
            "completion": "completed",
            "payload": "x" * 1000,
            "output_blobs": {output_blob: output_blob},
        },
    )
    live = journal.list_records()[0]
    spooled_result = str(live["result_blob_id"])

    _begin(
        journal,
        task_id="task-acked",
        operation_id="operation-acked",
        request_hash="e" * 64,
    )
    journal.complete(
        task_id="task-acked",
        operation_id="operation-acked",
        request_hash="e" * 64,
        result={"completion": "completed"},
    )
    monkeypatch.setattr(state_module, "MAX_CAS_STORE_BLOBS", 0)
    monkeypatch.setattr(state_module, "MAX_CAS_STORE_BYTES", 0)
    monkeypatch.setattr(state_module, "CAS_ORPHAN_RETENTION_SECONDS", 0)
    journal.acknowledge("task-acked", "operation-acked", "e" * 64)

    assert journal.blobs.path_for(input_blob).exists()
    assert journal.blobs.path_for(output_blob).exists()
    assert journal.spool.path_for(spooled_result).exists()
    with pytest.raises(ExecdError) as full:
        journal.blobs.put(b"new blob")
    assert full.value.code == "blob_capacity_exhausted"


def test_blob_gc_reclaims_acked_result_and_staged_orphans(tmp_path, monkeypatch):
    monkeypatch.setattr(state_module, "MAX_RESULT_BYTES", 32)
    journal = _journal(tmp_path)
    assert journal.blobs is not None
    output_blob = journal.blobs.put(b"already imported output")
    staged_blob = journal.blobs.put(b"staged upload")
    journal.blobs.pin(staged_blob)
    request_hash = "f" * 64
    journal.begin(
        task_id="task-acked",
        operation_id="operation-acked",
        request_hash=request_hash,
        binding={},
    )
    journal.complete(
        task_id="task-acked",
        operation_id="operation-acked",
        request_hash=request_hash,
        result={
            "completion": "completed",
            "payload": "x" * 1000,
            "output_blobs": {output_blob: output_blob},
        },
    )
    spooled_result = str(journal.list_records()[0]["result_blob_id"])
    monkeypatch.setattr(state_module, "MAX_CAS_STORE_BLOBS", 0)
    monkeypatch.setattr(state_module, "MAX_CAS_STORE_BYTES", 0)
    monkeypatch.setattr(state_module, "CAS_ORPHAN_RETENTION_SECONDS", 0)
    monkeypatch.setattr(state_module, "ACKED_BLOB_EXPORT_GRACE_MS", 0)
    monkeypatch.setattr(
        state_module,
        "MAX_RETAINED_ACKED_OPERATION_AGE_MS",
        0,
    )

    journal.acknowledge("task-acked", "operation-acked", request_hash)

    assert journal.list_records() == []
    assert not journal.blobs.path_for(output_blob).exists()
    assert not journal.spool.path_for(spooled_result).exists()
    assert journal.blobs.path_for(staged_blob).exists()
    journal.blobs.unpin(staged_blob)
    journal.blobs.collect_garbage(set())
    assert not journal.blobs.path_for(staged_blob).exists()


def test_blob_gc_keeps_recent_acked_exports_until_bounded_grace_expires(
    tmp_path,
    monkeypatch,
):
    journal = _journal(tmp_path)
    assert journal.blobs is not None
    output_blob = journal.blobs.put(b"pending Home export")
    request_hash = "1" * 64
    journal.begin(
        task_id="task-export",
        operation_id="operation-export",
        request_hash=request_hash,
        binding={},
    )
    journal.complete(
        task_id="task-export",
        operation_id="operation-export",
        request_hash=request_hash,
        result={"output_blobs": {output_blob: output_blob}},
    )
    monkeypatch.setattr(state_module, "MAX_CAS_STORE_BLOBS", 0)
    monkeypatch.setattr(state_module, "MAX_CAS_STORE_BYTES", 0)
    monkeypatch.setattr(state_module, "CAS_ORPHAN_RETENTION_SECONDS", 0)
    journal.acknowledge("task-export", "operation-export", request_hash)
    assert len(journal.list_records()) == 1
    assert journal.blobs.path_for(output_blob).exists()

    monkeypatch.setattr(state_module, "ACKED_BLOB_EXPORT_GRACE_MS", 0)
    _begin(
        journal,
        task_id="task-trigger",
        operation_id="operation-trigger",
        request_hash="2" * 64,
    )
    journal.complete(
        task_id="task-trigger",
        operation_id="operation-trigger",
        request_hash="2" * 64,
        result={"completion": "completed"},
    )
    journal.acknowledge("task-trigger", "operation-trigger", "2" * 64)
    assert not journal.blobs.path_for(output_blob).exists()


def test_cas_reserves_the_full_snapshot_transaction_above_4096_blobs(tmp_path):
    store = CASBlobStore(tmp_path / "blobs")
    for index in range(4100):
        payload = index.to_bytes(4, "big")
        store.path_for(hashlib.sha256(payload).hexdigest()).write_bytes(payload)

    collected = store.collect_garbage(set())

    assert state_module.MAX_CAS_ATOMIC_BLOB_RESERVE == max(
        state_module.MAX_SNAPSHOT_FILES + 1,
        state_module.MAX_ATTACHMENT_COUNT,
    )
    assert state_module.MAX_CAS_STORE_BLOBS >= 32_768
    assert collected["removed_count"] == 0
    assert store.put(b"next snapshot blob")


def test_project_scoped_transport_state_prevents_cross_process_gc(tmp_path):
    first = _service(tmp_path, project_id="project-a")
    second = _service(tmp_path, project_id="project-b")
    digest = first.cas.put(b"project-a staged blob")
    first.cas.pin(digest)

    assert first.cas.root != second.cas.root
    assert first.spool.root != second.spool.root
    assert first.journal.root != second.journal.root
    assert first.custody.state_path != second.custody.state_path
    second.cas.collect_garbage(set())
    assert first.cas.path_for(digest).exists()


def test_cas_persistent_pin_is_visible_to_another_store_instance(
    tmp_path,
    monkeypatch,
):
    root = tmp_path / "shared-cas"
    owner = CASBlobStore(root)
    collector = CASBlobStore(root)
    digest = owner.put(b"cross-process staged blob")
    owner.pin(digest)
    monkeypatch.setattr(state_module, "MAX_CAS_STORE_BLOBS", 0)
    monkeypatch.setattr(state_module, "MAX_CAS_STORE_BYTES", 0)
    monkeypatch.setattr(state_module, "CAS_ORPHAN_RETENTION_SECONDS", 0)

    collector.collect_garbage(set())
    assert owner.path_for(digest).exists()

    owner.unpin(digest)
    collector.collect_garbage(set())
    assert not owner.path_for(digest).exists()


def test_cas_rejects_wrong_hash_and_detects_corruption(tmp_path):
    store = CASBlobStore(tmp_path / "blobs")
    payload = b"bounded remote blob"
    digest = store.put(payload)
    assert store.read(digest, max_bytes=len(payload)) == payload

    with pytest.raises(ExecdError) as mismatch:
        store.put(payload, expected_sha256="0" * 64)
    assert mismatch.value.code == "blob_hash_mismatch"

    store.path_for(digest).write_bytes(b"corrupt")
    with pytest.raises(ExecdError) as corrupt:
        store.read(digest, max_bytes=1024)
    assert corrupt.value.code == "blob_store_corrupt"


@pytest.mark.serial
def test_native_registration_failure_kills_the_newborn_process_group(tmp_path):
    class _RejectCustody:
        pgid = 0

        def cancelled(self):
            return False

        def register_process(self, *, pgid, **kwargs):
            del kwargs
            self.pgid = pgid
            raise OSError("custody ledger unavailable")

        def release_process(self, **kwargs):
            del kwargs

        def recover_service(self, **kwargs):
            del kwargs
            return None

    control = _RejectCustody()
    result = execute_native_operation(
        tmp_path,
        "run_command",
        {
            "cmd": [sys.executable, "-c", "import time; time.sleep(60)"],
            "cwd": str(tmp_path),
            "timeout_sec": 60,
        },
        control=control,
    )

    assert control.pgid > 0
    assert result.envelope.diagnostic is not None
    assert "custody ledger unavailable" in result.envelope.diagnostic.message
    assert _wait_group_gone(control.pgid)


def test_protocol_eof_and_panic_both_close_owned_groups_without_ack():
    class _Service:
        def __init__(self):
            self.close_calls: list[bool] = []

        def close(self, *, kill_owned=True):
            self.close_calls.append(kill_owned)

    service = _Service()
    reader = __import__("io").BytesIO()
    writer = __import__("io").BytesIO()
    server = ExecdProtocolServer(service, reader, writer)

    server.serve()
    assert service.close_calls == [True]
    assert writer.getvalue() == b""

    service.close_calls.clear()
    server._receive_control(
        {
            "kind": "panic",
            "seq": 0,
            "server_generation": "generation-a",
        }
    )
    assert service.close_calls == [True]
    assert writer.getvalue() == b""


@pytest.mark.serial
def test_protocol_panic_exits_control_loop_without_waiting_for_transport_eof():
    class _Service:
        def __init__(self):
            self.closed = threading.Event()

        def close(self, *, kill_owned=True):
            assert kill_owned is True
            self.closed.set()

    read_fd, write_fd = os.pipe()
    reader = os.fdopen(read_fd, "rb", buffering=0)
    transport_writer = os.fdopen(write_fd, "wb", buffering=0)
    protocol_output = __import__("io").BytesIO()
    service = _Service()
    server = ExecdProtocolServer(service, reader, protocol_output)
    thread = threading.Thread(target=server.serve, daemon=True)
    thread.start()
    try:
        transport_writer.write(
            encode_control(
                {
                    "kind": "panic",
                    "seq": 0,
                    "server_generation": "generation-a",
                }
            )
        )
        transport_writer.flush()

        assert service.closed.wait(timeout=1)
        thread.join(timeout=1)
        assert not thread.is_alive()
        assert protocol_output.getvalue() == b""
    finally:
        transport_writer.close()
        reader.close()
        thread.join(timeout=2)


def test_completed_operation_reconciles_after_new_execd_instance(tmp_path):
    first = _service(tmp_path)
    prepared = first.prepare(
        request_id="request-a",
        operation_id="operation-a",
        tool="read_file",
        args={"path": "README.md"},
        task_id="task-a",
    )
    result = first.continue_prepared(
        request_id="request-a",
        operation_id="operation-a",
        prepared_hash=prepared["prepared_hash"],
        prepared_token=prepared["prepared_token"],
    )
    assert result["completion"] == "completed"

    second = _service(tmp_path)
    reconciled = second.reconcile(
        "request-a",
        "operation-a",
        prepared["prepared_hash"],
    )

    assert reconciled["completion"] == "completed"
    assert reconciled["result"]["prepared_hash"] == prepared["prepared_hash"]


@pytest.mark.serial
def test_keepalive_service_is_recovered_by_new_execd_instance(tmp_path):
    first = _service(tmp_path)
    first.renew_lease(10_000, "task-a")
    prepared = first.prepare(
        request_id="request-start",
        operation_id="operation-start",
        tool="start_service",
        args={
            "name": "worker",
            "cmd": [
                sys.executable,
                "-c",
                (
                    "from pathlib import Path; import time; "
                    "Path('service-output.bin').write_bytes(b'\\x00remote-output'); "
                    "print('ready', flush=True); time.sleep(60)"
                ),
            ],
            "cwd": str(first.workspace_root),
            "keep_alive": True,
            "readiness": {"stdout_contains": "ready", "timeout_sec": 5},
            "outputs": ["service-output.bin"],
        },
        task_id="task-a",
    )
    started = first.continue_prepared(
        request_id="request-start",
        operation_id="operation-start",
        prepared_hash=prepared["prepared_hash"],
        prepared_token=prepared["prepared_token"],
    )
    service_ref = started["envelope"]["trace"]["service_ref"]
    native_module._SERVICES_BY_ID.clear()
    native_module._SERVICES_BY_TASK_NAME.clear()

    second = _service(tmp_path)
    status_prepared = second.prepare(
        request_id="request-status",
        operation_id="operation-status",
        tool="service_status",
        args={"name": "worker", "_service_ref": service_ref},
        task_id="task-a",
    )
    status = second.continue_prepared(
        request_id="request-status",
        operation_id="operation-status",
        prepared_hash=status_prepared["prepared_hash"],
        prepared_token=status_prepared["prepared_token"],
    )

    assert status["envelope"]["trace"]["running"] is True
    observed_ref = status["envelope"]["trace"]["service_ref"]
    assert {
        key: observed_ref[key] for key in ("kind", "service_id", "name")
    } == {
        key: service_ref[key] for key in ("kind", "service_id", "name")
    }
    assert status["envelope"]["trace"]["keep_alive"] is True
    assert status["envelope"]["trace"]["ready"] is True
    assert status["envelope"]["trace"]["outputs"] == ["service-output.bin"]

    stop_prepared = second.prepare(
        request_id="request-stop",
        operation_id="operation-stop",
        tool="stop_service",
        args={"name": "worker", "_service_ref": service_ref},
        task_id="task-a",
    )
    stopped = second.continue_prepared(
        request_id="request-stop",
        operation_id="operation-stop",
        prepared_hash=stop_prepared["prepared_hash"],
        prepared_token=stop_prepared["prepared_token"],
    )
    output = b"\x00remote-output"
    digest = hashlib.sha256(output).hexdigest()
    assert stopped["output_blobs"] == {digest: digest}
    assert second.cas.read(digest, max_bytes=len(output)) == output
    native_module._SERVICES_BY_ID.clear()
    native_module._SERVICES_BY_TASK_NAME.clear()


def test_protocol_ack_marks_task_bound_completed_operation(tmp_path):
    service = _service(tmp_path)
    prepared = service.prepare(
        request_id="request-a",
        operation_id="operation-a",
        tool="read_file",
        args={"path": "README.md"},
        task_id="task-a",
    )
    service.continue_prepared(
        request_id="request-a",
        operation_id="operation-a",
        prepared_hash=prepared["prepared_hash"],
        prepared_token=prepared["prepared_token"],
    )
    server = ExecdProtocolServer(
        service,
        __import__("io").BytesIO(),
        __import__("io").BytesIO(),
    )

    server._receive_control(
        {
            "kind": "ack",
            "seq": 0,
            "request_id": "request-a",
            "operation_id": "operation-a",
            "optional": {"prepared_hash": prepared["prepared_hash"]},
        }
    )

    records = service.journal.list_records()
    assert len(records) == 1
    assert records[0]["acked"] is True


def test_second_blob_manifest_is_rejected_while_upload_is_active(tmp_path):
    service = _service(tmp_path)
    server = ExecdProtocolServer(
        service,
        __import__("io").BytesIO(),
        __import__("io").BytesIO(),
    )
    first = {
        "kind": "blob_manifest",
        "seq": 0,
        "request_id": "request-a",
        "operation_id": "operation-a",
        "blob_id": "blob-a",
        "size": 10,
        "sha256": hashlib.sha256(b"a" * 10).hexdigest(),
    }
    second = {
        "kind": "blob_manifest",
        "seq": 1,
        "request_id": "request-b",
        "operation_id": "operation-b",
        "blob_id": "blob-b",
        "size": 5,
        "sha256": hashlib.sha256(b"b" * 5).hexdigest(),
    }

    server._receive_control(first)
    with pytest.raises(ProtocolError):
        server._receive_control(second)

    assert server._incoming_blob is not None
    assert server._incoming_blob["request_id"] == "request-a"
    assert bytes(server._incoming_blob["data"]) == b""


def test_transport_serializes_concurrent_prepare_uploads_without_blocking_cancel():
    transport = object.__new__(OpenSSHExecdTransport)
    transport._upload_lock = threading.Lock()
    transport._active_tasks = set()
    transport._known_operations = {}
    transport._ensure_session = lambda: None
    transport._renew_lease = lambda _task_id: None
    transport._raise_diagnostic = lambda _response: None

    first_upload_started = threading.Event()
    release_first_upload = threading.Event()
    order: list[tuple[str, str]] = []
    order_lock = threading.Lock()

    def upload(
        request_id: str,
        _operation_id: str,
        blob_id: str,
        _payload: bytes,
    ) -> None:
        with order_lock:
            order.append(("upload-start", blob_id))
        if request_id == "request-a":
            first_upload_started.set()
            assert release_first_upload.wait(timeout=2)
        with order_lock:
            order.append(("upload-end", blob_id))

    def send(kind: str, **fields: Any) -> int:
        label = str(fields.get("request_id") or fields.get("task_id") or "")
        with order_lock:
            order.append((kind, label))
        return 77 if kind == "cancel" else len(order)

    def wait_control(predicate, timeout_sec=120):
        del timeout_sec
        candidates = [
            {"kind": "ack", "ack_seq": 77},
            {
                "kind": "prepared",
                "request_id": "request-a",
                "operation_id": "operation-a",
                "prepared_hash": "hash-a",
                "expires_ms": 1,
                "prepared": {
                    "tool": "write_file",
                    "prepared_token": "token-a",
                    "execution_args": {},
                    "native_facts": {},
                },
            },
            {
                "kind": "prepared",
                "request_id": "request-b",
                "operation_id": "operation-b",
                "prepared_hash": "hash-b",
                "expires_ms": 1,
                "prepared": {
                    "tool": "write_file",
                    "prepared_token": "token-b",
                    "execution_args": {},
                    "native_facts": {},
                },
            },
        ]
        return next(row for row in candidates if predicate(row))

    transport._upload_blob = upload
    transport._send = send
    transport._wait_control = wait_control

    def prepare(label: str) -> None:
        transport.prepare(
            {
                "request_id": f"request-{label}",
                "operation_id": f"operation-{label}",
                "tool": "write_file",
                "args": {"path": f"{label}.txt"},
                "task_id": f"task-{label}",
            },
            {f"blob-{label}": label.encode()},
        )

    first = threading.Thread(target=prepare, args=("a",))
    second = threading.Thread(target=prepare, args=("b",))
    first.start()
    assert first_upload_started.wait(timeout=2)
    second.start()

    # Cancel uses only the frame send lock and remains responsive while the
    # independent upload transaction is deliberately paused.
    assert transport.cancel({"task_id": "task-cancel"}) is True
    with order_lock:
        assert ("upload-start", "blob-b") not in order
        assert any(kind == "cancel" for kind, _label in order)

    release_first_upload.set()
    first.join(timeout=2)
    second.join(timeout=2)
    assert not first.is_alive()
    assert not second.is_alive()

    with order_lock:
        stream = [
            row
            for row in order
            if row[0] in {"upload-start", "upload-end", "prepare"}
        ]
    assert stream == [
        ("upload-start", "blob-a"),
        ("upload-end", "blob-a"),
        ("prepare", "request-a"),
        ("upload-start", "blob-b"),
        ("upload-end", "blob-b"),
        ("prepare", "request-b"),
    ]


def test_oversized_native_result_is_spooled_before_result_frame_and_reconciles(
    tmp_path,
):
    service = _service(tmp_path)
    payload = "x" * (MAX_CONTROL_BYTES * 2)
    (service.workspace_root / "huge.txt").write_text(payload, encoding="utf-8")
    prepared = service.prepare(
        request_id="request-huge",
        operation_id="operation-huge",
        tool="read_file",
        args={"path": "huge.txt", "max_lines": 1},
        task_id="task-huge",
    )
    writer = __import__("io").BytesIO()
    server = ExecdProtocolServer(
        service,
        __import__("io").BytesIO(),
        writer,
    )

    server._continue_and_send(
        {
            "kind": "continue",
            "seq": 0,
            "request_id": "request-huge",
            "operation_id": "operation-huge",
            "prepared_hash": prepared["prepared_hash"],
            "optional": {"prepared_token": prepared["prepared_token"]},
        }
    )

    frame = writer.getvalue()
    assert len(frame) <= MAX_CONTROL_BYTES + 5
    label, message = read_frame(__import__("io").BytesIO(frame))
    assert label == "control"
    assert message["kind"] == "result"
    assert message["completion"] == "completed"
    result = message["result"]
    envelope = result["envelope"]
    assert len(envelope["text"].encode("utf-8")) <= MAX_JSON_STRING_BYTES
    references = list(result.get("output_blobs") or {})
    references.extend(
        str(row.get("blob_id") or "")
        for row in envelope.get("artifacts") or []
        if isinstance(row, dict)
    )
    assert any(reference for reference in references)

    reconciled = service.reconcile(
        "request-huge",
        "operation-huge",
        prepared["prepared_hash"],
    )
    assert reconciled["completion"] == "completed"
    assert reconciled["result_unavailable"] is False


def test_custodian_fence_rejects_overlap_and_stale_generation_kill(
    tmp_path,
    monkeypatch,
):
    def fingerprint(pid):
        return {
            "boot_id": "boot",
            "pid_namespace": "pid:[1]",
            "leader_pid": pid,
            "pgrp": pid,
            "session": pid,
            "start_ticks": pid * 10,
        }

    monkeypatch.setattr(state_module, "_process_fingerprint", fingerprint)
    monkeypatch.setattr(
        state_module,
        "kill_process_group_id",
        lambda _pgid, *, checked=False: checked,
    )
    path = tmp_path / "custody.json"
    first = LeaseCustody(path, "generation-a")
    first_id = first.claim_custodian()
    first.renew(ttl_ms=10_000)
    first.register(
        pgid=11111,
        task_id="task-a",
        keep_alive=True,
        service_id="service-a",
    )
    second = LeaseCustody(path, "generation-a")
    with pytest.raises(ExecdError) as active:
        second.claim_custodian()
    assert active.value.code == "generation_active"

    assert first.kill_generation(first_id) == 1
    second_id = second.claim_custodian()
    second.renew(ttl_ms=10_000)
    second.register(
        pgid=22222,
        task_id="task-b",
        keep_alive=True,
        service_id="service-b",
    )

    assert first.kill_generation(first_id) == 0
    snapshot = second.refresh_snapshot()
    assert snapshot["custodian_id"] == second_id
    assert [row["pgid"] for row in snapshot["groups"]] == [22222]


def test_finish_task_forgets_local_lease_even_when_remote_cancel_fails():
    from ouroboros.remote_workspace import RemoteSessionBroker

    class Transport:
        def __init__(self):
            self.forgotten = []

        def cancel(self, _message):
            raise RuntimeError("remote EOF")

        def task_lease(self, task_id, *, forget=False):
            if forget:
                self.forgotten.append(task_id)
            return True

    class BrowserForwards:
        def __init__(self):
            self.closed = []

        def close_task(self, task_id):
            self.closed.append(task_id)

    broker = object.__new__(RemoteSessionBroker)
    broker._state_lock = threading.RLock()
    broker._task_sessions = {}
    broker._sessions = {}
    broker._browser_forwards = BrowserForwards()
    key = ("connection-a", "project-a", "workspace-a", "generation-a")
    transport = Transport()
    broker._sessions[key] = types.SimpleNamespace(transport=transport)
    broker._task_sessions["task-a"] = key
    workspace_ref = {
        "kind": "ssh",
        "connection_id": "connection-a",
        "remote_root": "/srv/project",
        "workspace_id": "workspace-a",
    }

    with pytest.raises(RuntimeError, match="remote EOF"):
        broker.finish_task(workspace_ref, task_id="task-a")

    assert "task-a" not in broker._task_sessions
    assert transport.forgotten == ["task-a"]
    assert broker._browser_forwards.closed == ["task-a"]


def test_close_project_session_does_not_close_sibling_project():
    from ouroboros.remote_service_leases import RemoteServiceLeaseBook
    from ouroboros.remote_workspace import RemoteSessionBroker

    class Transport:
        def __init__(self):
            self.closed = False
            self.forgotten = []

        def close(self):
            self.closed = True

        def task_lease(self, task_id, *, forget=False):
            if forget:
                self.forgotten.append(task_id)
            return True

    class BrowserForwards:
        def __init__(self):
            self.closed = []

        def close_task(self, task_id):
            self.closed.append(task_id)

    broker = object.__new__(RemoteSessionBroker)
    broker.server_generation = "generation-a"
    broker._state_lock = threading.RLock()
    broker._task_sessions = {}
    broker._sessions = {}
    broker._service_leases = RemoteServiceLeaseBook()
    broker._browser_forwards = BrowserForwards()
    key_a = ("connection-a", "project-a", "workspace-a", "generation-a")
    key_b = ("connection-a", "project-b", "workspace-a", "generation-a")
    transport_a = Transport()
    transport_b = Transport()
    broker._sessions[key_a] = types.SimpleNamespace(transport=transport_a)
    broker._sessions[key_b] = types.SimpleNamespace(transport=transport_b)
    broker._task_sessions = {"task-a": key_a, "task-b": key_b}

    closed = broker._close_project_session_on_broker(
        {
            "workspace_ref": {
                "kind": "ssh",
                "connection_id": "connection-a",
                "remote_root": "/srv/project",
                "workspace_id": "workspace-a",
            },
            "project_id": "project-a",
        }
    )

    assert closed is True
    assert key_a not in broker._sessions
    assert key_b in broker._sessions
    assert transport_a.closed is True
    assert transport_b.closed is False
    assert broker._task_sessions == {"task-b": key_b}
    assert broker._browser_forwards.closed == ["task-a"]


def test_lifecycle_fence_refresh_discards_dead_keepalive(tmp_path):
    from ouroboros.remote_service_leases import RemoteServiceLeaseBook
    from ouroboros.remote_workspace import RemoteSessionBroker

    key = ("connection-a", "project-a", "workspace-a", "generation-a")

    class Transport:
        def __init__(self):
            self.forgotten = []

        def prepare(self, message, _blobs):
            return {
                "request_id": message["request_id"],
                "operation_id": message["operation_id"],
                "tool": message["tool"],
                "prepared_token": "token-a",
                "prepared_hash": "b" * 64,
                "expires_at_ms": int(time.time() * 1000) + 10_000,
                "execution_args": dict(message["args"]),
                "native_facts": {"service_id": "service-a"},
            }

        def execute_prepared(self, _message):
            return {
                "text": "stopped",
                "diagnostic": None,
                "process": None,
                "artifacts": [],
                "trace": {"running": False},
            }

        def task_lease(self, task_id, *, forget=False):
            if forget:
                self.forgotten.append(task_id)
            return task_id == "task-a"

    broker = object.__new__(RemoteSessionBroker)
    broker.drive_root = tmp_path
    broker._state_lock = threading.RLock()
    broker._task_sessions = {}
    broker._sessions = {}
    broker._service_leases = RemoteServiceLeaseBook()
    transport = Transport()
    broker._sessions[key] = types.SimpleNamespace(key=key, transport=transport)
    started = types.SimpleNamespace(
        tool="start_service",
        execution_args={"name": "worker", "keep_alive": True},
        native_facts={"service_id": "service-a"},
    )
    broker._service_leases.observe(
        key,
        started,
        {
            "diagnostic": None,
            "trace": {
                "service_ref": {
                    "service_id": "service-a",
                    "name": "worker",
                    "keep_alive": True,
                }
            },
        },
        task_id="task-a",
    )

    assert broker.has_active_lease("connection-a") is False
    assert transport.forgotten == []


def test_reconcile_imports_completed_result_then_confirms_ack():
    transport = object.__new__(OpenSSHExecdTransport)
    key = ("request-a", "operation-a")
    transport._known_operations = {key: "a" * 64}
    imported = []
    transport._operation_contexts = {
        key: {
            "task_id": "task-a",
            "validator": lambda _result, envelope, _fetched: (
                imported.append(envelope) or envelope
            ),
        }
    }
    sent = []

    def send(kind, **fields):
        sent.append((kind, fields))
        return len(sent)

    responses = iter(
        [
            {
                "kind": "reconcile_result",
                "seq": 8,
                "request_id": "request-a",
                "operation_id": "operation-a",
                "result": {
                    "completion": "completed",
                    "result": {
                        "prepared_hash": "a" * 64,
                        "envelope": {
                            "text": "done",
                            "diagnostic": None,
                            "process": None,
                            "artifacts": [],
                            "trace": {},
                        },
                        "output_blobs": {},
                    },
                    "result_unavailable": False,
                },
            },
            {
                "kind": "ack",
                "seq": 9,
                "ack_seq": 2,
                "request_id": "request-a",
                "operation_id": "operation-a",
            },
        ]
    )
    transport._send = send
    transport._wait_control = lambda _predicate, **_kwargs: next(responses)
    transport.fetch_blob = lambda _blob_id, _max_bytes: b""

    from ouroboros.remote_finalization import reconcile_remote_operations

    rows = reconcile_remote_operations(
        transport,
        ack_timeout_sec=5.0,
        retention_cap=512,
    )

    assert rows[0]["imported"] is True
    assert imported[0]["text"] == "done"
    assert [kind for kind, _fields in sent] == ["reconcile", "ack"]
    assert transport._known_operations == {}


def test_protocol_ssh_neutralizes_alias_forwarding_but_browser_rejects_it(
    monkeypatch,
):
    import ouroboros.remote_ssh as remote_ssh

    raw = (
        "remotecommand none\n"
        "requesttty false\n"
        "tunnel false\n"
        "localforward 127.0.0.1:8080 127.0.0.1:80\n"
    )
    neutralized = (
        raw
        + "clearallforwardings yes\n"
        + "tunnel false\n"
    )

    def run(command, **_kwargs):
        is_final = any(
            str(item) == "ClearAllForwardings=yes" for item in command
        )
        return types.SimpleNamespace(
            returncode=0,
            stdout=neutralized if is_final else raw,
            stderr="",
        )

    monkeypatch.setattr(remote_ssh.subprocess, "run", run)
    command = remote_ssh.validated_ssh_base_command(
        "configured-host",
        "/usr/bin/ssh",
    )
    assert "ClearAllForwardings=yes" in command
    assert "Tunnel=no" in command

    with pytest.raises(Exception) as blocked:
        remote_ssh.validated_ssh_base_command(
            "configured-host",
            "/usr/bin/ssh",
            forwarding=True,
        )
    assert getattr(blocked.value, "code", "") == "unsafe_ssh_forwarding"

    request = types.SimpleNamespace(
        connection={"id": "connection-a", "ssh_alias": "configured-host"},
        ssh_binary="/usr/bin/ssh",
    )
    transport = OpenSSHExecdTransport(request)
    health = transport.health()
    assert health["warnings"] == [
        {
            "code": "ssh_alias_forwarding_neutralized",
            "directives": ["localforward"],
        }
    ]


def test_ssh_operational_settings_drive_openssh_argv(
    monkeypatch,
):
    import ouroboros.remote_ssh as remote_ssh

    monkeypatch.setenv("OUROBOROS_SSH_CONNECT_TIMEOUT_SEC", "41")
    monkeypatch.setenv("OUROBOROS_SSH_KEEPALIVE_INTERVAL_SEC", "7")
    monkeypatch.setenv("OUROBOROS_SSH_KEEPALIVE_COUNT", "4")
    rendered = (
        "remotecommand none\n"
        "requesttty false\n"
        "clearallforwardings yes\n"
        "tunnel false\n"
    )
    calls = []

    def run(command, **kwargs):
        calls.append((list(command), dict(kwargs)))
        return types.SimpleNamespace(
            returncode=0,
            stdout=rendered,
            stderr="",
        )

    monkeypatch.setattr(remote_ssh.subprocess, "run", run)
    command = remote_ssh.validated_ssh_base_command(
        "configured-host",
        "/usr/bin/ssh",
    )

    assert "ConnectTimeout=41" in command
    assert "ServerAliveInterval=7" in command
    assert "ServerAliveCountMax=4" in command
    assert all(call[1]["timeout"] == 41 for call in calls)


def test_broker_panic_does_not_wait_for_held_state_lock(monkeypatch):
    from ouroboros.remote_service_leases import RemoteServiceLeaseBook
    from ouroboros.remote_workspace import RemoteSessionBroker

    class Transport:
        def __init__(self):
            self.panicked = threading.Event()

        def panic(self):
            self.panicked.set()

    class BrowserForwards:
        def __init__(self):
            self.panicked = threading.Event()

        def panic_close_all(self):
            self.panicked.set()

    broker = object.__new__(RemoteSessionBroker)
    broker._stop = threading.Event()
    broker._state_lock = threading.RLock()
    broker._browser_forwards = BrowserForwards()
    transport = Transport()
    broker._panic_transports = [transport]
    broker._panic_events = [threading.Event()]
    broker._sessions = {}
    broker._task_sessions = {}
    broker._service_leases = RemoteServiceLeaseBook()
    broker._admission_transports = {}
    broker._admission_cancels = {}
    entered = threading.Event()
    release = threading.Event()

    def hold_lock():
        with broker._state_lock:
            entered.set()
            release.wait(2)

    holder = threading.Thread(target=hold_lock)
    holder.start()
    assert entered.wait(1)
    started = time.monotonic()
    broker.panic()
    elapsed = time.monotonic() - started
    release.set()
    holder.join(1)

    assert elapsed < 0.2
    assert transport.panicked.is_set()
    assert broker._browser_forwards.panicked.is_set()
    assert broker._panic_events[0].is_set()

    class PanicProcess:
        def __init__(self):
            self.pid = 987654
            self.stdin = io.BytesIO()
            self.stdout = None
            self.stderr = None
            self.killed = False

        def poll(self):
            return None

        def kill(self):
            self.killed = True

    process = PanicProcess()
    wire = object.__new__(OpenSSHExecdTransport)
    wire.request = types.SimpleNamespace(server_generation="generation-a")
    wire._stop = threading.Event()
    wire._process = process
    wire._helper_process = None
    wire._send_lock = threading.Lock()
    wire._send_lock.acquire()
    monkeypatch.setattr(
        state_module.os,
        "getpgid",
        lambda _pid: (_ for _ in ()).throw(ProcessLookupError()),
    )
    started = time.monotonic()
    wire.panic()
    elapsed = time.monotonic() - started
    wire._send_lock.release()

    assert elapsed < 0.2
    assert process.killed is True


def test_result_unavailable_is_fixed_on_home_before_ack(tmp_path):
    transport = object.__new__(OpenSSHExecdTransport)
    key = ("request-a", "operation-a")
    transport._known_operations = {key: "a" * 64}
    transport._operation_contexts = {
        key: {
            "task_id": "task-a",
            "validator": lambda _result, envelope, _fetched: envelope,
        }
    }
    transport.request = types.SimpleNamespace(
        connection={"id": "connection-a"},
        project_id="project-a",
        workspace_id="workspace-a",
        drive_root=tmp_path,
    )
    sent = []

    def send(kind, **fields):
        sent.append((kind, fields))
        return len(sent)

    responses = iter(
        [
            {
                "kind": "reconcile_result",
                "seq": 8,
                "request_id": "request-a",
                "operation_id": "operation-a",
                "result": {
                    "completion": "completed",
                    "result": None,
                    "result_unavailable": True,
                },
            },
            {
                "kind": "ack",
                "seq": 9,
                "ack_seq": 2,
                "request_id": "request-a",
                "operation_id": "operation-a",
            },
        ]
    )
    transport._send = send
    transport._wait_control = lambda _predicate, **_kwargs: next(responses)

    from ouroboros.remote_finalization import reconcile_remote_operations

    rows = reconcile_remote_operations(
        transport,
        ack_timeout_sec=5.0,
        retention_cap=512,
    )

    assert rows[0]["result_unavailable"] is True
    assert rows[0]["envelope"]["diagnostic"]["code"] == (
        "remote_result_unavailable"
    )
    assert (tmp_path / rows[0]["evidence_ref"]).is_file()
    assert [kind for kind, _fields in sent] == ["reconcile", "ack"]
    assert transport._known_operations == {}
