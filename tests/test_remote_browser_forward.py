from __future__ import annotations

import io
import subprocess
import threading
import urllib.error
import urllib.request
from types import SimpleNamespace
from urllib.parse import urljoin, urlparse

import pytest

from ouroboros.remote_browser_forward import (
    BrowserForwardError,
    SSHBrowserForwardManager,
)
from ouroboros.remote_workspace import set_remote_workspace_service
from ouroboros.tools.browser import (
    _is_remote_workspace_browser_blocked_url,
    _remote_browser_url,
    cleanup_browser,
)
from ouroboros.tools.registry import BrowserState

_SAFE_CONFIG = b"""
hostname example.invalid
user deploy
tunnel false
remotecommand none
permitlocalcommand no
controlmaster auto
controlpersist 600
sendenv LANG
sendenv LC_*
"""


def _config_for_command(command):
    forward = command[command.index("-L") + 1].split(":")
    local_host, local_port, remote_host, remote_port = forward
    return _SAFE_CONFIG + (
        f"localforward [{local_host}]:{local_port} "
        f"[{remote_host}]:{remote_port}\n"
    ).encode()


class _Connection:
    def close(self):
        return None


class _Process:
    _next_pid = 9000

    def __init__(self, *, returncode=None, stderr=b""):
        type(self)._next_pid += 1
        self.pid = type(self)._next_pid
        self.returncode = returncode
        self.stderr = io.BytesIO(stderr)
        self.killed = False

    def poll(self):
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout=None):
        del timeout
        return self.returncode


def test_forward_uses_required_custody_exact_loopback_and_no_multiplexing(
    tmp_path,
):
    spawned = []
    config_calls = []

    def _spawn(command, **kwargs):
        spawned.append((command, kwargs))
        return _Process()

    def _config(command, child_env):
        config_calls.append((command, dict(child_env)))
        return _config_for_command(command)

    manager = SSHBrowserForwardManager(
        tmp_path,
        config_runner=_config,
        process_spawner=_spawn,
        connector=lambda *args, **kwargs: _Connection(),
    )
    record = manager.open(
        {"id": "connection", "ssh_alias": "safe-alias"},
        remote_port=4321,
        task_id="task",
    )

    command, kwargs = spawned[0]
    assert kwargs["required_custody"] is True
    assert kwargs["new_process_group"] is True
    assert kwargs["owner_task_id"] == "task"
    assert "-N" in command and "-T" in command and "-S" in command
    assert command[command.index("-S") + 1] == "none"
    assert command.count("-L") == 1
    assert not any(part == "-D" for part in command)
    assert command[-1] == "safe-alias"
    assert (
        command[command.index("-L") + 1]
        == f"127.0.0.1:{record.local_port}:127.0.0.1:4321"
    )
    assert record.origin == f"http://127.0.0.1:{record.local_port}"
    assert record.url == record.origin + "/"
    assert record.task_token
    assert len(config_calls) == 2
    assert all(
        config_command == [command[0], "-G", *command[1:]]
        for config_command, _child_env in config_calls
    )
    assert all(
        config_env == kwargs["env"]
        for _config_command, config_env in config_calls
    )
    assert manager.close(record.forward_id) is True


@pytest.mark.parametrize(
    "line",
    [
        b"localforward 127.0.0.1:1 127.0.0.1:2\n",
        b"remoteforward 1 127.0.0.1:2\n",
        b"dynamicforward 1080\n",
        b"tunnel point-to-point\n",
        b"remotecommand touch /tmp/pwned\n",
        b"localcommand touch /tmp/pwned\n",
        b"permitlocalcommand yes\n",
        b"setenv SECRET=value\n",
    ],
)
def test_hostile_effective_alias_is_rejected_before_spawn(tmp_path, line):
    spawned = []
    manager = SSHBrowserForwardManager(
        tmp_path,
        config_runner=lambda command, _child_env: _config_for_command(command) + line,
        process_spawner=lambda *args, **kwargs: spawned.append((args, kwargs)),
    )
    with pytest.raises(BrowserForwardError, match="forbidden"):
        manager.open(
            {"id": "connection", "ssh_alias": "hostile"},
            remote_port=8080,
            task_id="task",
        )
    assert spawned == []


def test_standard_or_unretained_sendenv_patterns_are_allowed(tmp_path):
    spawned = []

    def _spawn(command, **kwargs):
        spawned.append((command, kwargs))
        return _Process()

    manager = SSHBrowserForwardManager(
        tmp_path,
        config_runner=lambda command, _child_env: (
            _config_for_command(command) + b"sendenv UNRETAINED_*\n"
        ),
        process_spawner=_spawn,
        connector=lambda *args, **kwargs: _Connection(),
    )
    record = manager.open(
        {"id": "connection", "ssh_alias": "safe"},
        remote_port=8080,
        task_id="task",
    )
    assert spawned
    assert manager.close(record.forward_id) is True


@pytest.mark.parametrize("retained_name", ["HOME", "PATH", "SSH_AUTH_SOCK"])
def test_sendenv_matching_retained_child_env_is_rejected(
    tmp_path,
    monkeypatch,
    retained_name,
):
    monkeypatch.setenv(retained_name, f"/retained/{retained_name.lower()}")
    spawned = []
    manager = SSHBrowserForwardManager(
        tmp_path,
        config_runner=lambda command, _child_env: (
            _config_for_command(command)
            + f"sendenv {retained_name}\n".encode()
        ),
        process_spawner=lambda *args, **kwargs: spawned.append((args, kwargs)),
    )
    with pytest.raises(BrowserForwardError, match="sendenv"):
        manager.open(
            {"id": "connection", "ssh_alias": "unsafe-sendenv"},
            remote_port=8080,
            task_id="task",
        )
    assert spawned == []


@pytest.mark.parametrize(
    "alias",
    [
        "-oProxyCommand=evil",
        "safe alias",
        "safe\nHost evil",
        "",
        "../unsafe",
    ],
)
def test_option_shaped_or_hostile_alias_is_rejected(tmp_path, alias):
    config_calls = []
    manager = SSHBrowserForwardManager(
        tmp_path,
        config_runner=lambda command, _child_env: (
            config_calls.append(command) or _config_for_command(command)
        ),
    )
    with pytest.raises(BrowserForwardError, match="ssh_alias"):
        manager.open(
            {"id": "connection", "ssh_alias": alias},
            remote_port=8080,
            task_id="task",
        )
    assert config_calls == []


def test_config_digest_change_between_probe_and_spawn_fails_closed(tmp_path):
    config_calls = 0

    def _changing_config(command, _child_env):
        nonlocal config_calls
        config_calls += 1
        return _config_for_command(command) + (
            b"user changed\n" if config_calls == 2 else b""
        )

    spawned = []
    manager = SSHBrowserForwardManager(
        tmp_path,
        config_runner=_changing_config,
        process_spawner=lambda *args, **kwargs: spawned.append((args, kwargs)),
    )
    with pytest.raises(BrowserForwardError, match="config changed"):
        manager.open(
            {"id": "connection", "ssh_alias": "safe"},
            remote_port=8080,
            task_id="task",
        )
    assert spawned == []


def test_ephemeral_bind_race_is_retried_and_only_ready_url_is_published(
    tmp_path,
    monkeypatch,
):
    processes = [
        _Process(
            returncode=255,
            stderr=b"bind [127.0.0.1]: Address already in use\n",
        ),
        _Process(),
    ]
    spawned = []

    def _spawn(command, **kwargs):
        spawned.append((command, kwargs))
        return processes[len(spawned) - 1]

    monkeypatch.setattr(
        "ouroboros.remote_browser_forward.kill_process_tree",
        lambda process: process.kill(),
    )
    manager = SSHBrowserForwardManager(
        tmp_path,
        config_runner=lambda command, _child_env: _config_for_command(command),
        process_spawner=_spawn,
        connector=lambda *args, **kwargs: _Connection(),
    )
    ports = iter([41001, 41002])

    class _Probe:
        def close(self):
            return None

    monkeypatch.setattr(
        manager,
        "_reserve_loopback_port",
        lambda: (next(ports), _Probe()),
    )
    record = manager.open(
        {"id": "connection", "ssh_alias": "safe"},
        remote_port=8080,
        task_id="task",
    )
    first_port = int(spawned[0][0][spawned[0][0].index("-L") + 1].split(":")[1])
    assert len(spawned) == 2
    assert processes[0].killed is True
    assert first_port == 41001
    assert record.local_port == 41002


def test_task_connection_and_global_cleanup_terminate_owned_children(
    tmp_path,
    monkeypatch,
):
    processes = []

    def _spawn(*args, **kwargs):
        del args, kwargs
        process = _Process()
        processes.append(process)
        return process

    monkeypatch.setattr(
        "ouroboros.remote_browser_forward.kill_process_tree",
        lambda process: process.kill(),
    )
    manager = SSHBrowserForwardManager(
        tmp_path,
        config_runner=lambda command, _child_env: _config_for_command(command),
        process_spawner=_spawn,
        connector=lambda *args, **kwargs: _Connection(),
    )
    manager.open(
        {"id": "one", "ssh_alias": "safe-one"},
        remote_port=8001,
        task_id="task-a",
    )
    manager.open(
        {"id": "one", "ssh_alias": "safe-one"},
        remote_port=8002,
        task_id="task-b",
    )
    manager.open(
        {"id": "two", "ssh_alias": "safe-two"},
        remote_port=8003,
        task_id="task-c",
    )

    assert manager.close_task("task-a") == 1
    assert manager.close_connection("one") == 1
    assert manager.close_all() == 1
    assert all(process.killed for process in processes)
    assert manager.records() == []


def test_panic_cleanup_kills_a_forward_still_in_startup(tmp_path, monkeypatch):
    process = _Process()
    entered = threading.Event()
    release = threading.Event()
    outcome = []

    monkeypatch.setattr(
        "ouroboros.remote_browser_forward.kill_process_tree",
        lambda child: child.kill(),
    )
    monkeypatch.setattr(
        "ouroboros.remote_browser_forward.os.getpgid",
        lambda _pid: (_ for _ in ()).throw(ProcessLookupError()),
    )
    manager = SSHBrowserForwardManager(
        tmp_path,
        config_runner=lambda command, _child_env: _config_for_command(command),
        process_spawner=lambda *args, **kwargs: process,
    )

    def _blocked_ready(child, port):
        del child, port
        entered.set()
        release.wait(2)
        return False, "closed"

    monkeypatch.setattr(manager, "_await_ready", _blocked_ready)

    def _open():
        try:
            manager.open(
                {"id": "connection", "ssh_alias": "safe"},
                remote_port=8080,
                task_id="task",
            )
        except Exception as exc:
            outcome.append(exc)

    thread = threading.Thread(target=_open)
    thread.start()
    assert entered.wait(1)
    assert manager.panic_close_all() == 1
    assert process.killed is True
    release.set()
    thread.join(2)
    assert outcome and isinstance(outcome[0], BrowserForwardError)
    assert manager.records() == []


def test_panic_cleanup_does_not_wait_for_held_manager_lock(tmp_path):
    manager = SSHBrowserForwardManager(tmp_path)
    process = _Process()
    manager._panic_processes.append(process)
    entered = threading.Event()
    release = threading.Event()

    def hold_lock():
        with manager._lock:
            entered.set()
            release.wait(2)

    holder = threading.Thread(target=hold_lock)
    holder.start()
    assert entered.wait(1)
    started = __import__("time").monotonic()
    assert manager.panic_close_all() == 1
    elapsed = __import__("time").monotonic() - started
    release.set()
    holder.join(1)

    assert elapsed < 0.2
    assert process.killed is True


def test_process_returned_after_panic_is_killed_before_registration(tmp_path):
    process = _Process()
    manager = None

    def spawn(*_args, **_kwargs):
        assert manager is not None
        manager.panic_close_all()
        return process

    manager = SSHBrowserForwardManager(
        tmp_path,
        config_runner=lambda command, _child_env: _config_for_command(command),
        process_spawner=spawn,
    )

    with pytest.raises(BrowserForwardError, match="closed during startup"):
        manager.open(
            {"id": "connection", "ssh_alias": "safe"},
            remote_port=8080,
            task_id="task",
        )
    assert process.killed is True
    assert manager.records() == []


def test_real_config_runner_surfaces_ssh_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "ouroboros.remote_browser_forward.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=args,
            returncode=255,
            stdout=b"",
            stderr=b"bad config",
        ),
    )
    manager = SSHBrowserForwardManager(tmp_path)
    with pytest.raises(BrowserForwardError, match="bad config"):
        manager._run_config(["ssh", "-G", "bad"], {"HOME": str(tmp_path)})


def test_browser_tool_transparently_rewrites_only_remote_loopback_origin():
    class _Service:
        def __init__(self):
            self.opened = []
            self.closed = []

        def open_browser_forward(self, workspace_ref, **kwargs):
            self.opened.append((workspace_ref, kwargs))
            return {
                "forward_id": "unguessable-forward",
                "local_port": 45678,
                "task_token": "unguessable-task-token",
            }

        def close_browser_forward(self, forward_id):
            self.closed.append(forward_id)
            return True

    service = _Service()
    ctx = SimpleNamespace(
        task_id="remote-task",
        browser_state=BrowserState(),
        task_metadata={
            "_sealed_workspace_ref": {
                "kind": "ssh",
                "connection_id": "connection",
                "remote_root": "/srv/project",
                "workspace_id": "workspace",
            }
        },
    )
    set_remote_workspace_service(service)
    try:
        rewritten = _remote_browser_url(
            ctx,
            "http://127.0.0.1:3000/path?q=1#fragment",
        )
        cached = _remote_browser_url(ctx, "http://localhost:3000/other")
        external = _remote_browser_url(ctx, "https://example.com/page")
        assert rewritten == "http://127.0.0.1:45678/path?q=1#fragment"
        assert cached == "http://127.0.0.1:45678/other"
        assert external == "https://example.com/page"
        assert len(service.opened) == 1
        assert service.opened[0][1] == {
            "remote_port": 3000,
            "task_id": "remote-task",
        }
        assert not _is_remote_workspace_browser_blocked_url(rewritten, ctx)
        assert _is_remote_workspace_browser_blocked_url(
            "http://127.0.0.1:8765/api/settings",
            ctx,
        )
        assert _is_remote_workspace_browser_blocked_url(
            "http://10.0.0.2/private",
            ctx,
        )
        assert _is_remote_workspace_browser_blocked_url(
            "file:///Users/owner/.ssh/id_ed25519",
            ctx,
        )
        cleanup_browser(ctx)
        assert service.closed == ["unguessable-forward"]
    finally:
        set_remote_workspace_service(None)


def test_remote_browser_userinfo_is_rejected_before_broker_call():
    ctx = SimpleNamespace(
        task_id="remote-task",
        browser_state=BrowserState(),
        task_metadata={
            "_sealed_workspace_ref": {
                "kind": "ssh",
                "connection_id": "connection",
                "remote_root": "/srv/project",
                "workspace_id": "workspace",
            }
        },
    )
    with pytest.raises(ValueError, match="userinfo"):
        _remote_browser_url(ctx, "http://user:pass@127.0.0.1:3000/")


def test_remote_file_bridge_serves_relative_assets_with_token_and_nosniff(
    tmp_path,
    monkeypatch,
):
    snapshot_root = tmp_path / "snapshot"
    web = snapshot_root / "web"
    web.mkdir(parents=True)
    (web / "index.html").write_text(
        '<link rel="stylesheet" href="style.css"><h1>Remote</h1>'
    )
    (web / "style.css").write_text("h1 { color: green; }")
    (web / "escape").symlink_to("/etc/passwd")

    class _Snapshot:
        root = snapshot_root
        closed = False

        def close(self):
            self.closed = True

    snapshot = _Snapshot()
    monkeypatch.setattr(
        "ouroboros.remote_file_bridge.materialize_remote_workspace_snapshot",
        lambda _subject: snapshot,
    )
    ctx = SimpleNamespace(
        task_id="remote-task",
        browser_state=BrowserState(),
        task_metadata={
            "_sealed_workspace_ref": {
                "kind": "ssh",
                "connection_id": "connection",
                "remote_root": "/srv/project",
                "workspace_id": "workspace",
            }
        },
    )

    bridged = _remote_browser_url(
        ctx,
        "file:///srv/project/web/index.html?mode=test#section",
    )
    parsed = urlparse(bridged)
    assert parsed.hostname == "127.0.0.1"
    assert parsed.query == "mode=test"
    assert parsed.fragment == "section"
    assert snapshot.closed is True
    with urllib.request.urlopen(bridged, timeout=2) as response:
        assert b"<h1>Remote</h1>" in response.read()
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers.get("Set-Cookie") is None
    with urllib.request.urlopen(urljoin(bridged, "style.css"), timeout=2) as response:
        assert response.read() == b"h1 { color: green; }"
        assert response.headers["Content-Type"].startswith("text/css")
    with pytest.raises(urllib.error.HTTPError) as wrong_token:
        urllib.request.urlopen(
            f"{parsed.scheme}://{parsed.netloc}/wrong/web/index.html",
            timeout=2,
        )
    assert wrong_token.value.code == 404
    token = parsed.path.split("/")[1]
    with pytest.raises(urllib.error.HTTPError) as listing:
        urllib.request.urlopen(
            f"{parsed.scheme}://{parsed.netloc}/{token}/web/",
            timeout=2,
        )
    assert listing.value.code == 404
    with pytest.raises(urllib.error.HTTPError) as escape:
        urllib.request.urlopen(
            f"{parsed.scheme}://{parsed.netloc}/{token}/web/escape",
            timeout=2,
        )
    assert escape.value.code == 404
    assert not _is_remote_workspace_browser_blocked_url(bridged, ctx)
    assert _is_remote_workspace_browser_blocked_url(
        "http://127.0.0.1:8765/api/settings",
        ctx,
    )
    cleanup_browser(ctx)
    assert snapshot.closed is True
    with pytest.raises(OSError):
        urllib.request.urlopen(bridged, timeout=0.2)


def test_remote_file_bridge_rejects_outside_workspace_before_snapshot(
    tmp_path,
    monkeypatch,
):
    materialized = []
    monkeypatch.setattr(
        "ouroboros.remote_file_bridge.materialize_remote_workspace_snapshot",
        lambda _subject: materialized.append(True),
    )
    ctx = SimpleNamespace(
        task_id="remote-task",
        browser_state=BrowserState(),
        task_metadata={
            "_sealed_workspace_ref": {
                "kind": "ssh",
                "connection_id": "connection",
                "remote_root": "/srv/project",
                "workspace_id": "workspace",
            }
        },
    )
    with pytest.raises(Exception, match="escapes"):
        _remote_browser_url(ctx, "file:///etc/passwd")
    assert materialized == []


def test_remote_route_policy_does_not_change_ordinary_home_localhost():
    ctx = SimpleNamespace(
        browser_state=BrowserState(),
        task_metadata={},
    )
    assert not _is_remote_workspace_browser_blocked_url(
        "http://127.0.0.1:3000/",
        ctx,
    )
