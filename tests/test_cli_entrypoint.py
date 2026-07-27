from __future__ import annotations

import json
import sys
from types import SimpleNamespace

import pytest


def test_server_subcommand_sanitizes_argv(monkeypatch):
    from ouroboros import cli

    seen = {}

    class FakeServer:
        @staticmethod
        def main():
            seen["argv"] = list(sys.argv)
            return 0

    monkeypatch.setitem(sys.modules, "server", FakeServer)
    monkeypatch.setattr(sys, "argv", ["ouroboros", "server", "--host", "127.0.0.1", "--port", "9000"])

    result = cli._server_command(SimpleNamespace(host="127.0.0.1", port=9000, no_ui=True))

    assert result == 0
    assert seen["argv"] == ["ouroboros"]
    assert json.loads(__import__("os").environ["OUROBOROS_SERVER_REEXEC_ARGV_JSON"]) == [
        "-m",
        "ouroboros.cli",
        "server",
        "--host",
        "127.0.0.1",
        "--port",
        "9000",
    ]
    assert sys.argv == ["ouroboros", "server", "--host", "127.0.0.1", "--port", "9000"]


def test_settings_context_mode_posts_owner_endpoint(monkeypatch):
    from ouroboros import cli

    seen = {}

    class FakeClient:
        def request(self, method, path, body=None):
            seen["request"] = (method, path, body)
            return {"ok": True, "context_mode": body["mode"]}

    monkeypatch.setattr(cli, "_client", lambda _args, **_kwargs: FakeClient())

    result = cli._owner_context_mode_command(SimpleNamespace(mode="low"))

    assert result == 0
    assert seen["request"] == ("POST", "/api/owner/context-mode", {"mode": "low"})


def test_connections_cli_prompts_before_request_and_never_uses_environment(
    monkeypatch,
    capsys,
):
    from ouroboros import cli

    seen = []
    monkeypatch.setenv("OUROBOROS_NETWORK_PASSWORD", "must-not-be-read")
    monkeypatch.setattr(
        cli, "_read_owner_password", lambda: seen.append("prompt") or "typed-secret"
    )

    class FakeClient:
        def __init__(self, base_url="", timeout=30.0, *, owner_password=""):
            seen.append(("client", owner_password))

        def request(self, method, path, body=None, **kwargs):
            seen.append((method, path, body))
            return {
                "connections": [
                    {
                        "id": "conn-1",
                        "name": "Build",
                        "ssh_alias": "build",
                        "lifecycle": "active",
                        "status": "ready",
                    }
                ]
            }

    monkeypatch.setattr(cli, "OuroborosHTTPClient", FakeClient)
    assert cli.main(["connections", "list", "--json"]) == 0
    assert seen[0] == "prompt"
    assert seen[1] == ("client", "typed-secret")
    assert "must-not-be-read" not in json.dumps(seen)
    assert '"conn-1"' in capsys.readouterr().out


def test_connections_cli_has_stable_owner_and_conflict_exit_codes(
    monkeypatch,
    capsys,
):
    from ouroboros import cli

    monkeypatch.setattr(cli, "_read_owner_password", lambda: "typed-secret")

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, *args, **kwargs):
            raise cli.GatewayHTTPError(
                503,
                {
                    "error": "Owner authentication is not configured.",
                    "error_code": "owner_auth_not_configured",
                    "action": "configure_network_password",
                },
            )

    monkeypatch.setattr(cli, "OuroborosHTTPClient", FakeClient)
    assert cli.main(["connections", "list", "--json"]) == 3
    payload = json.loads(capsys.readouterr().out)
    assert payload["error_code"] == "owner_auth_not_configured"

    class ConflictClient(FakeClient):
        def request(self, *args, **kwargs):
            raise cli.GatewayHTTPError(
                409,
                {"error": "active", "error_code": "active_lease"},
            )

    monkeypatch.setattr(cli, "OuroborosHTTPClient", ConflictClient)
    assert cli.main(["connections", "retire", "conn-1", "--json"]) == 5


def test_owner_password_refuses_piped_stdin_without_controlling_tty(monkeypatch):
    from ouroboros import cli

    monkeypatch.setattr(cli.os, "name", "posix")

    def no_tty(*args, **kwargs):
        raise OSError("no controlling tty")

    monkeypatch.setattr(cli.os, "open", no_tty)
    try:
        cli._read_owner_password()
    except cli.CLIError as exc:
        assert "controlling terminal" in str(exc)
    else:
        raise AssertionError("piped stdin must not be accepted for owner password")


def test_connections_json_reports_non_tty_auth_without_request(
    monkeypatch,
    capsys,
):
    from ouroboros import cli

    monkeypatch.setattr(
        cli,
        "_read_owner_password",
        lambda: (_ for _ in ()).throw(cli.CLIError("controlling terminal required")),
    )
    monkeypatch.setattr(
        cli,
        "OuroborosHTTPClient",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("no request is allowed without TTY authentication")
        ),
    )
    assert cli.main(["connections", "list", "--json"]) == 3
    payload = json.loads(capsys.readouterr().out)
    assert payload["error_code"] == "owner_auth_required"
    assert payload["action"] == "run_from_controlling_terminal"


def test_connections_add_requires_named_flags():
    from ouroboros import cli

    parsed = cli.build_parser().parse_args([
        "connections",
        "add",
        "--name",
        "Build",
        "--ssh-alias",
        "build",
    ])
    assert parsed.name == "Build"
    assert parsed.ssh_alias == "build"
    with pytest.raises(SystemExit) as exc:
        cli.build_parser().parse_args(["connections", "add", "Build", "build"])
    assert exc.value.code == 2


def test_connections_parser_exposes_exactly_six_admin_commands(capsys):
    from ouroboros import cli

    parser = cli.build_parser()
    root_subparsers = next(
        action for action in parser._actions
        if getattr(action, "dest", None) == "command"
    )
    connections_parser = root_subparsers.choices["connections"]
    connection_subparsers = next(
        action for action in connections_parser._actions
        if getattr(action, "dest", None) == "connections_command"
    )
    assert set(connection_subparsers.choices) == {
        "list",
        "add",
        "test",
        "bootstrap",
        "retrust",
        "retire",
    }
    for forbidden in ("status", "remove", "delete", "run", "reconnect", "cancel"):
        with pytest.raises(SystemExit) as exc:
            parser.parse_args(["connections", forbidden])
        assert exc.value.code == 2
    capsys.readouterr()


def test_connections_cli_incompatible_exit_and_human_action(monkeypatch, capsys):
    from ouroboros import cli

    monkeypatch.setattr(cli, "_read_owner_password", lambda: "typed-secret")

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, *args, **kwargs):
            raise cli.GatewayHTTPError(
                503,
                {
                    "error": "remote executor protocol is incompatible",
                    "error_code": "incompatible_protocol",
                    "phase": "handshake",
                    "action": "bootstrap",
                },
            )

    monkeypatch.setattr(cli, "OuroborosHTTPClient", FakeClient)
    assert cli.main(["connections", "test", "conn-1"]) == 4
    stderr = capsys.readouterr().err
    assert "phase=handshake" in stderr
    assert "action=bootstrap" in stderr


def test_connections_cli_human_result_exposes_ssh_alias_warning(capsys):
    from ouroboros import cli

    cli._print_connection_result(
        {
            "connection_id": "conn-1",
            "status": "ready",
            "warnings": [{
                "code": "ssh_alias_forwarding_neutralized",
                "directives": ["localforward"],
            }],
        },
        as_json=False,
    )

    captured = capsys.readouterr()
    assert "status=ready" in captured.out
    assert "ssh_alias_forwarding_neutralized" in captured.err


@pytest.mark.parametrize(
    "error_code",
    [
        "unsupported_ssh_client",
        "remote_platform_unsupported",
        "remote_libc_unsupported",
        "remote_glibc_too_old",
        "execd_preamble_invalid",
        "execd_release_unselected",
        "execd_bundle_unavailable",
        "execd_bundle_invalid",
        "execd_artifact_mismatch",
        "capability_mismatch",
        "incompatible_protocol",
    ],
)
def test_connections_cli_all_incompatibility_codes_exit_four(error_code, capsys):
    from ouroboros import cli

    error = cli.GatewayHTTPError(
        503,
        {
            "error": "remote target is incompatible",
            "error_code": error_code,
        },
    )
    assert cli._connection_error_exit(error, as_json=True) == 4
    assert json.loads(capsys.readouterr().out)["error_code"] == error_code


def test_connections_retrust_requires_explicit_tty_confirmation_before_post(
    monkeypatch,
):
    from ouroboros import cli

    calls = []
    confirmations = []
    monkeypatch.setattr(cli, "_read_owner_password", lambda: "typed-secret")
    monkeypatch.setattr(
        cli,
        "_confirm_host_retrust",
        lambda old, new: confirmations.append((old, new)) or False,
    )

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, method, path, body=None, **kwargs):
            calls.append((method, path, body))
            if path == "/api/owner/connections":
                return {
                    "connections": [{
                        "id": "conn-1",
                        "expected_host_id": "old-host",
                    }]
                }
            if path.endswith("/test"):
                return {"ok": False, "observed_host_id": "new-host"}
            raise AssertionError("retrust mutation must not happen after decline")

    monkeypatch.setattr(cli, "OuroborosHTTPClient", FakeClient)
    assert cli.main(["connections", "retrust", "conn-1", "--json"]) == 2
    assert confirmations == [("old-host", "new-host")]
    assert all(not path.endswith("/retrust") for _method, path, _body in calls)
