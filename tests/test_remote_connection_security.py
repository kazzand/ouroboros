import json
import os
from concurrent.futures import ThreadPoolExecutor

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from ouroboros.gateway.connections import (
    add_connection,
    api_connection_bootstrap,
    api_connection_dirs,
    api_connection_reconnect,
    api_connection_retire,
    api_connection_retrust,
    api_connection_test,
    api_connections_add,
    api_connections_list,
    get_connection,
    is_connection_store_path,
    list_connections,
    normalize_ssh_alias,
    pin_connection_host,
    retire_connection,
    retrust_connection,
)


@pytest.mark.parametrize("alias", ["", "-host", "two words", "bad\nhost", "\x00host"])
def test_connection_alias_rejects_argv_injection(alias):
    with pytest.raises(ValueError):
        normalize_ssh_alias(alias)


def test_connection_store_is_atomic_owner_only_nonsecret_and_soft_retired(tmp_path):
    path = tmp_path / "state" / "remote_connections.json"
    added = add_connection(name="Build host", ssh_alias="build-host", path=path)
    assert added["lifecycle"] == "active"
    assert list_connections(path) == [added]
    assert not any(
        key in added
        for key in ("password", "private_key", "ssh_options", "health", "session")
    )
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600

    pinned = pin_connection_host(added["id"], "host-a", path=path)
    assert pinned["expected_host_id"] == "host-a"
    with pytest.raises(ValueError, match="retrust"):
        pin_connection_host(added["id"], "host-b", path=path)
    with pytest.raises(ValueError, match="active task"):
        retrust_connection(
            added["id"],
            "host-b",
            path=path,
            has_active_lease=True,
        )
    trusted = retrust_connection(added["id"], "host-b", path=path)
    assert trusted["expected_host_id"] == "host-b"
    assert trusted["host_id_history"][0]["superseded_at"]
    assert trusted["host_id_history"][1]["superseded_at"] is None

    retired = retire_connection(added["id"], path=path)
    assert retired["lifecycle"] == "retired"
    assert list_connections(path) == []
    assert get_connection(added["id"], path) == retired


def test_connection_store_locked_updates_do_not_lose_rows(tmp_path):
    path = tmp_path / "state" / "remote_connections.json"

    def add(index):
        return add_connection(
            name=f"Host {index}",
            ssh_alias=f"host-{index}",
            path=path,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        rows = list(pool.map(add, range(12)))

    assert len(rows) == 12
    assert len(list_connections(path)) == 12
    assert len({row["id"] for row in rows}) == 12
    assert not path.with_name(path.name + ".lock").exists()


def test_connection_store_rejects_malformed_existing_state(tmp_path):
    path = tmp_path / "state" / "remote_connections.json"
    path.parent.mkdir(parents=True)
    path.write_text("{broken", encoding="utf-8")

    with pytest.raises(ValueError, match="malformed"):
        list_connections(path)
    with pytest.raises(ValueError, match="malformed"):
        add_connection(name="Host", ssh_alias="host", path=path)
    assert path.read_text(encoding="utf-8") == "{broken"


def test_connection_state_predicate_covers_store_lock_temp_and_hardlink(tmp_path):
    path = tmp_path / "state" / "remote_connections.json"
    add_connection(name="Host", ssh_alias="host", path=path)
    assert is_connection_store_path(path, store_path=path)
    assert is_connection_store_path(
        path.with_name(path.name + ".lock"),
        store_path=path,
    )
    assert is_connection_store_path(
        path.with_name(f".{path.name}.tmp.1.deadbeef"),
        store_path=path,
    )
    hardlink = path.with_name("alias.json")
    os.link(path, hardlink)
    assert is_connection_store_path(hardlink, store_path=path)
    assert json.loads(path.read_text(encoding="utf-8"))["_schema_version"] == 1


def test_live_connection_projection_bounds_and_scrubs_diagnostics():
    from ouroboros.gateway.connections import _public_live_fields

    projected = _public_live_fields({
        "status": "degraded",
        "diagnostic": {
            "message": "api_key=secret " + ("x" * 9000),
            "details": {"stderr": "permission denied"},
        },
        "log_refs": [
            {"stream": "stderr", "blob_id": f"log-{index}"}
            for index in range(100)
        ],
        "warnings": [
            {
                "code": "ssh_alias_forwarding_neutralized",
                "directives": ["localforward"],
            }
            for _index in range(100)
        ],
    })

    assert projected["status"] == "degraded"
    assert "[REDACTED]" in projected["diagnostic"]["message"]
    assert len(projected["diagnostic"]["message"]) == 4000
    assert projected["diagnostic"]["details"]["stderr"] == "permission denied"
    assert len(projected["log_refs"]) == 32
    assert len(projected["warnings"]) == 32
    assert projected["warnings"][0]["code"] == "ssh_alias_forwarding_neutralized"


def test_remote_error_details_are_recursively_redacted():
    from ouroboros.remote_worker_proxy import error_dict
    from ouroboros.remote_workspace import RemoteWorkspaceError

    error = RemoteWorkspaceError(
        "ssh_command_failed",
        "Remote command failed.",
        phase="connect",
        details={
            "stderr": {
                "lines": [
                    "api_key=visible-secret",
                    "Authorization: Bearer visible-token",
                ]
            }
        },
    )

    projected = json.dumps(error_dict(error))
    assert "visible-secret" not in projected
    assert "visible-token" not in projected
    assert "REDACTED" in projected


def test_bootstrap_rejects_asset_without_top_level_size(tmp_path):
    from types import SimpleNamespace

    from ouroboros.remote_ssh_bootstrap import select_and_install

    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "manifest.json").write_text(
        json.dumps(
            {
                "build": "test",
                "assets": {
                    "linux-x86_64": {
                        "archive": "execd.tar.gz",
                        "sha256": "a" * 64,
                        "files": [],
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(Exception) as rejected:
        select_and_install(
            SimpleNamespace(bundle_dir=bundle),
            run_remote=lambda *args, **kwargs: pytest.fail(
                "invalid asset must fail before remote mutation"
            ),
            platform_probe=lambda _timeout: {
                "machine": "x86_64",
                "libc": "glibc",
                "libc_version": "2.17",
            },
            timeout_sec=1,
        )

    assert getattr(rejected.value, "code", "") == "execd_bundle_invalid"


def test_bootstrap_recognizes_an_exact_installed_tree(tmp_path):
    import hashlib
    import shutil
    import subprocess

    from ouroboros.remote_ssh_bootstrap import SelectedRelease, _installed

    selected = SelectedRelease("smoke", "a" * 64, 1)
    home = tmp_path / "home"
    target = home / selected.target_rel
    executable = target / "bin" / "ouroboros-execd"
    executable.parent.mkdir(parents=True)
    executable.write_text("#!/bin/sh\nprintf 'ouroboros-execd 1\\n'\n", encoding="utf-8")
    executable.chmod(0o755)
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    tree_manifest = target / "stage-files.sha256"
    tree_manifest.write_text(
        f"{digest}  bin/ouroboros-execd\n",
        encoding="utf-8",
    )
    current = home / ".local" / "share" / "ouroboros" / "execd" / "current"
    current.symlink_to(target)
    tool_path = os.environ.get("PATH", "/usr/bin:/bin")
    if shutil.which("sha256sum") is None:
        tools = tmp_path / "tools"
        tools.mkdir()
        sha256sum = tools / "sha256sum"
        sha256sum.write_text(
            "#!/bin/sh\nexec /usr/bin/shasum -a 256 \"$@\"\n",
            encoding="utf-8",
        )
        sha256sum.chmod(0o755)
        tool_path = f"{tools}:{tool_path}"

    def run_remote(argv, *, timeout_sec):
        return subprocess.run(
            argv,
            env={"HOME": str(home), "PATH": tool_path},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_sec,
            check=True,
        )

    assert _installed(
        run_remote,
        selected,
        hashlib.sha256(tree_manifest.read_bytes()).hexdigest(),
        tree_manifest.stat().st_size,
        5,
    )


class _FakeRemoteService:
    def __init__(self):
        self.host_id = "host-a"
        self.cancelled = []
        self.reconnects = 0

    def status(self, connection_id=None):
        return {"connections": []}

    def test_connection(self, connection, timeout_sec=10):
        return {
            "ok": True,
            "status": "ready",
            "phase": "connect",
            "host_id": self.host_id,
            "system": "Linux",
            "machine": "x86_64",
        }

    def bootstrap(self, connection, timeout_sec=30):
        return {
            "ok": True,
            "status": "ready",
            "phase": "bootstrap",
            "completion": "installed",
            "host_id": self.host_id,
            "system": "Linux",
            "machine": "x86_64",
            "build": "execd-test-build",
        }

    def reconnect_connection(self, connection, timeout_sec=120):
        self.reconnects += 1
        return {
            "ok": True,
            "status": "ready",
            "phase": "reconcile",
            "completion": "reconciled",
            "host_id": self.host_id,
            "sessions": 1,
            "reconciliation": [],
        }

    def list_directories(self, connection, remote_root="", timeout_sec=10):
        return {
            "ok": True,
            "path": remote_root or "/srv",
            "parent": "/" if remote_root else "",
            "dirs": [{"name": "repo", "path": "/srv/repo", "is_git": True}],
        }

    def has_active_lease(self, connection_id):
        return False

    def cancel_connection(self, connection_id):
        self.cancelled.append(connection_id)
        return 0


def _connection_app(tmp_path, service):
    app = Starlette(routes=[
        Route("/api/owner/connections", api_connections_list, methods=["GET"]),
        Route("/api/owner/connections", api_connections_add, methods=["POST"]),
        Route("/api/owner/connections/{connection_id}/test", api_connection_test, methods=["POST"]),
        Route("/api/owner/connections/{connection_id}/bootstrap", api_connection_bootstrap, methods=["POST"]),
        Route("/api/owner/connections/{connection_id}/reconnect", api_connection_reconnect, methods=["POST"]),
        Route("/api/owner/connections/{connection_id}/retrust", api_connection_retrust, methods=["POST"]),
        Route("/api/owner/connections/{connection_id}/dirs", api_connection_dirs, methods=["GET"]),
        Route("/api/owner/connections/{connection_id}", api_connection_retire, methods=["DELETE"]),
    ])
    app.state.remote_connections_path = tmp_path / "remote_connections.json"
    app.state.remote_workspace_service = service
    return app


def test_eight_connection_routes_keep_metadata_and_live_state_separate(tmp_path):
    service = _FakeRemoteService()
    client = TestClient(_connection_app(tmp_path, service))
    added = client.post(
        "/api/owner/connections",
        json={"name": "Build host", "ssh_alias": "build"},
    )
    assert added.status_code == 201
    connection_id = added.json()["connection"]["id"]

    # A broker projection is not allowed to manufacture the Home-owned
    # process-local Bootstrap/health evidence used by the Project picker.
    service.status = lambda requested_id=None, _cid=connection_id: {
        "connections": [{
            "connection_id": _cid,
            "status": "ready",
            "bootstrap_compatible": True,
            "health_fresh": True,
        }]
    }
    unbootstrapped = client.get("/api/owner/connections").json()["connections"]
    assert unbootstrapped[0]["bootstrap_compatible"] is False
    assert unbootstrapped[0]["health_fresh"] is False

    tested = client.post(f"/api/owner/connections/{connection_id}/test")
    assert tested.status_code == 200
    assert tested.json()["status"] == "ready"
    assert tested.json()["platform"] == "Linux"
    assert tested.json()["architecture"] == "x86_64"
    assert tested.json()["bootstrap_compatible"] is False
    assert tested.json()["health_fresh"] is False
    assert get_connection(
        connection_id, tmp_path / "remote_connections.json"
    )["expected_host_id"] == ""

    bootstrapped = client.post(
        f"/api/owner/connections/{connection_id}/bootstrap"
    )
    assert bootstrapped.status_code == 200
    assert bootstrapped.json()["completion"] == "installed"
    assert bootstrapped.json()["bootstrap_compatible"] is True
    assert bootstrapped.json()["health_fresh"] is True
    assert get_connection(
        connection_id, tmp_path / "remote_connections.json"
    )["expected_host_id"] == "host-a"
    reconnected = client.post(
        f"/api/owner/connections/{connection_id}/reconnect"
    )
    assert reconnected.status_code == 200
    assert reconnected.json()["completion"] == "reconciled"
    assert service.reconnects == 1
    dirs = client.get(
        f"/api/owner/connections/{connection_id}/dirs?path=%2Fsrv"
    )
    assert dirs.status_code == 200
    assert dirs.json()["dirs"][0]["path"] == "/srv/repo"
    listed = client.get("/api/owner/connections").json()["connections"]
    assert listed[0]["ssh_alias"] == "build"
    assert listed[0]["bootstrap_compatible"] is True
    assert listed[0]["health_fresh"] is True
    assert listed[0]["status"] == "ready"
    assert "password" not in json.dumps(listed)

    service.host_id = "host-b"
    retrusted = client.post(
        f"/api/owner/connections/{connection_id}/retrust",
        json={
            "confirm": True,
            "old_host_id": "host-a",
            "new_host_id": "host-b",
        },
    )
    assert retrusted.status_code == 200
    assert retrusted.json()["connection"]["expected_host_id"] == "host-b"
    assert retrusted.json()["bootstrap_compatible"] is False
    assert retrusted.json()["health_fresh"] is False
    retired = client.delete(f"/api/owner/connections/{connection_id}")
    assert retired.status_code == 200
    assert retired.json()["connection"]["lifecycle"] == "retired"
    assert service.cancelled == [connection_id]
    retrust_retired = client.post(
        f"/api/owner/connections/{connection_id}/retrust",
        json={
            "confirm": True,
            "old_host_id": "host-b",
            "new_host_id": "host-c",
        },
    )
    assert retrust_retired.status_code == 409
    assert retrust_retired.json()["error_code"] == "connection_retired"


def test_connection_failure_keeps_typed_stderr_and_completion(tmp_path):
    from ouroboros.remote_workspace import RemoteWorkspaceError

    class BrokenService(_FakeRemoteService):
        def test_connection(self, connection, timeout_sec=10):
            raise RemoteWorkspaceError(
                "ssh_command_failed",
                "Remote SSH operation failed.",
                phase="connect",
                completion="not_started",
                retryable=True,
                details={"stderr": "Permission denied (publickey)."},
            )

    client = TestClient(_connection_app(tmp_path, BrokenService()))
    connection_id = client.post(
        "/api/owner/connections",
        json={"name": "Build host", "ssh_alias": "build"},
    ).json()["connection"]["id"]

    failed = client.post(f"/api/owner/connections/{connection_id}/test")

    assert failed.status_code == 503
    payload = failed.json()
    assert payload["status"] == "degraded"
    assert payload["error_code"] == "ssh_command_failed"
    assert payload["completion"] == "not_started"
    assert (
        payload["diagnostic"]["details"]["stderr"]
        == "Permission denied (publickey)."
    )


def test_reconnect_without_known_project_session_is_typed_failure(tmp_path):
    class DisconnectedService(_FakeRemoteService):
        def reconnect_connection(self, connection, timeout_sec=120):
            return {
                "ok": False,
                "status": "disconnected",
                "phase": "reconcile",
                "completion": "not_started",
                "error_code": "remote_session_disconnected",
                "action": "readmit_project",
            }

    client = TestClient(_connection_app(tmp_path, DisconnectedService()))
    connection_id = client.post(
        "/api/owner/connections",
        json={"name": "Build host", "ssh_alias": "build"},
    ).json()["connection"]["id"]

    failed = client.post(
        f"/api/owner/connections/{connection_id}/reconnect"
    )

    assert failed.status_code == 503
    assert failed.json()["status"] == "disconnected"
    assert failed.json()["action"] == "readmit_project"


@pytest.mark.parametrize(
    "path",
    [
        "/api/owner/connections",
        "/api/owner/connections/conn-1/test",
        "/api%2Fowner%2Fconnections%2Fconn-1%2Fdirs",
        "%252Fapi%252Fowner%252Fconnections%252Fconn-1",
        "http://127.0.0.1:8765/api/owner/connections",
    ],
)
def test_owner_connections_path_predicate_decodes_bounded_aliases(path):
    from ouroboros.server_auth import is_owner_connections_path

    assert is_owner_connections_path(path)


@pytest.mark.parametrize(
    "path",
    [
        "/api/owner/connectionsevil",
        "/api/owner/connections-archive",
        "/api/owner/skills/connections",
    ],
)
def test_owner_connections_path_predicate_rejects_lookalikes(path):
    from ouroboros.server_auth import is_owner_connections_path

    assert not is_owner_connections_path(path)


def test_agent_browser_blocks_every_owner_connections_method_and_evaluate():
    from ouroboros.tools.browser import (
        _block_owner_connections_request,
        _blocks_owner_connections_js,
    )

    for method in ("GET", "POST", "DELETE", "PATCH"):
        events = []
        route = type("Route", (), {})()
        route.request = type("Request", (), {
            "url": (
                "http://127.0.0.1:8765/"
                "api%2Fowner%2Fconnections%2Fconn-1"
            ),
            "method": method,
        })()
        route.abort = lambda: events.append("abort")
        route.fallback = lambda: events.append("fallback")
        _block_owner_connections_request(route)
        assert events == ["abort"]
        route.request.url = (
            "http://127.0.0.1:8765/api/owner/connectionsevil"
        )
        _block_owner_connections_request(route)
        assert events == ["abort", "fallback"]
    assert _blocks_owner_connections_js(
        "fetch('%252Fapi%252Fowner%252Fconnections%252Fconn-1%252Fbootstrap')"
    )
    assert not _blocks_owner_connections_js(
        "fetch('/api/owner/connectionsevil')"
    )


def test_agent_shell_blocks_owner_connections_http_and_cli_but_allows_source_reads(
    tmp_path,
):
    from ouroboros.tools.registry import ToolContext, ToolRegistry

    repo = tmp_path / "repo"
    drive = tmp_path / "data"
    repo.mkdir()
    drive.mkdir()
    registry = ToolRegistry(repo_dir=repo, drive_root=drive)
    registry.set_context(ToolContext(repo_dir=repo, drive_root=drive))

    blocked = (
        "curl http://127.0.0.1:8765/api/owner/connections",
        (
            "python -c \"import urllib.request; "
            "urllib.request.urlopen('http://127.0.0.1:8765/"
            "%252Fapi%252Fowner%252Fconnections%252Fconn-1%252Fbootstrap')\""
        ),
        "ouroboros connections list",
        "python -m ouroboros.cli connections bootstrap conn-1",
    )
    for command in blocked:
        result = registry._run_shell_safety_check({"cmd": command}, "advanced")
        assert "OWNER_CONNECTIONS_SELF_CALL_BLOCKED" in (result or ""), command

    for command in (
        "rg -n '/api/owner/connections' ouroboros",
        "git grep -n '/api/owner/connections'",
        "curl http://127.0.0.1:8765/api/owner/connectionsevil",
    ):
        assert (
            registry._run_shell_safety_check({"cmd": command}, "advanced") is None
        ), command


def test_owner_connection_namespace_requires_auth_even_on_loopback(monkeypatch):
    import ouroboros.server_auth as server_auth

    inner = Starlette(routes=[
        Route(
            "/api/owner/connections",
            lambda request: JSONResponse({"ok": True}),
        ),
        Route(
            "/api/owner/connectionsevil",
            lambda request: JSONResponse({"lookalike": True}),
        ),
    ])
    app = server_auth.NetworkAuthGate(inner)
    client = TestClient(app, client=("127.0.0.1", 12345))

    monkeypatch.setattr(server_auth, "get_configured_network_password", lambda: "")
    missing = client.get("/api/owner/connections")
    assert missing.status_code == 503
    assert missing.json()["error_code"] == "owner_auth_not_configured"
    assert client.get("/api/owner/connectionsevil").status_code == 200

    monkeypatch.setattr(
        server_auth, "get_configured_network_password", lambda: "owner-secret"
    )
    required = client.get("/api/owner/connections")
    assert required.status_code == 401
    assert required.json()["error_code"] == "owner_auth_required"
    wrong = client.get(
        "/api/owner/connections",
        headers={"X-Ouroboros-Password": "wrong"},
    )
    assert wrong.status_code == 401
    assert wrong.json() == required.json()
    malformed = client.post(
        "/api/owner/connections",
        content=b"{not-json",
        headers={"content-type": "application/json"},
    )
    assert malformed.status_code == 401
    assert malformed.json() == required.json()
    accepted = client.get(
        "/api/owner/connections",
        headers={"X-Ouroboros-Password": "owner-secret"},
    )
    assert accepted.status_code == 200
