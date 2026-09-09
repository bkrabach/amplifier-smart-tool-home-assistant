"""Synthetic direct-control conformance tests; no real household or credentials."""

from __future__ import annotations
import json
import os
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from ha_analysis.control import ControlRuntime, OperationJournal, TrustStore
from ha_analysis.live import TransportError
from ha_analysis.management import ManagementRuntime
from ha_analysis.control_cli import main as control_main


class Credentials:
    def __init__(self) -> None:
        self.origin, self.token = "http://ha.test:8123", "synthetic-token"

    def endpoint(self) -> tuple[str, str]:
        return self.origin, "trusted_local_or_vpn"

    def credential_for(self, _origin: object) -> str:
        return self.token


class Reader:
    def __init__(self) -> None:
        self.states = {
            "light.living_room_lamp_1": {
                "state": "on",
                "attributes": {
                    "xy_color": [0.64, 0.33],
                    "effect": "rainbow",
                    "unrelated": "NO_LEAK",
                },
            },
            "group.living_room_lamps": {
                "state": "on",
                "attributes": {"entity_id": ["light.living_room_lamp_1"]},
            },
            "script.party": {"state": "on", "attributes": {}},
        }

    def list_services(self, _origin: object, _token: str) -> object:
        return [
            {
                "domain": "light",
                "services": {
                    "turn_on": {
                        "description": "Turn on",
                        "fields": {"xy_color": {}, "effect": {}},
                    },
                    "turn_off": {"fields": {}},
                },
            },
            {
                "domain": "script",
                "services": {"party": {"fields": {}}, "turn_off": {"fields": {}}},
            },
            {
                "domain": "homeassistant",
                "services": {"turn_off": {"fields": {}}, "restart": {"fields": {}}},
            },
        ]

    def list_registry(self, _origin: object, _token: str) -> object:
        return [
            {
                "entity_id": "light.living_room_lamp_1",
                "name": "Living room lamp",
                "area_id": "living_room",
                "device_id": "living_room_lamp_1",
            },
            {
                "entity_id": "light.living_room_lamp_2",
                "name": "Living room lamp",
                "area_id": "living_room",
            },
            {"entity_id": "group.living_room_lamps", "name": "Living room lamps"},
        ]

    def read_entity(self, _origin: object, target: str, _token: str) -> object:
        return self.states[target]


class Transport:
    def __init__(self, failure: bool = False) -> None:
        self.calls: list[tuple[str, str, object]] = []
        self.failure = failure

    def post_service(
        self, _origin: object, domain: str, service: str, payload: object, _token: str
    ) -> None:
        self.calls.append((domain, service, payload))
        if self.failure:
            raise TransportError()


def runtime(
    tmp_path: Path, transport: Transport | None = None
) -> tuple[ControlRuntime, Credentials, Transport]:
    credentials, sent = Credentials(), transport or Transport()
    return (
        ControlRuntime(
            stored_credentials=credentials,
            entity_reader=Reader(),
            service_transport=sent,
            trust_store=TrustStore(tmp_path),
            journal=OperationJournal(tmp_path),
        ),
        credentials,
        sent,
    )


def test_default_disabled_then_enable_repeat_and_revoke(tmp_path: Path) -> None:
    control, _credentials, sent = runtime(tmp_path)
    assert control.control_status()["details"]["trust"] == "disabled"
    assert (
        control.invoke(
            "light.turn_on", ["light.living_room_lamp_1"], data={"xy_color": [0.64, 0.33]}
        )["failures"][0]["code"]
        == "control_not_trusted"
    )
    assert sent.calls == []
    assert control.enable_control()["status"] == "ok"
    first = control.invoke(
        "light.turn_on",
        ["light.living_room_lamp_1"],
        data={"xy_color": [0.64, 0.33], "effect": "rainbow"},
    )
    second = control.invoke("light.turn_on", ["light.living_room_lamp_1"], data={})
    assert (
        first["details"]["effect"] == "observed"
        and second["status"] == "ok"
        and len(sent.calls) == 2
    )
    control.disable_control()
    assert (
        control.invoke("light.turn_on", ["light.living_room_lamp_1"], data={})["failures"][
            0
        ]["code"]
        == "control_not_trusted"
    )
    assert len(sent.calls) == 2


def test_token_or_origin_change_invalidates_grant(tmp_path: Path) -> None:
    control, credentials, sent = runtime(tmp_path)
    control.enable_control()
    credentials.token = "replacement"
    assert (
        control.invoke("light.turn_on", ["light.living_room_lamp_1"], data={})["failures"][
            0
        ]["code"]
        == "control_not_trusted"
    )
    credentials.token = "synthetic-token"
    credentials.origin = "http://other.test:8123"
    assert (
        control.invoke("light.turn_on", ["light.living_room_lamp_1"], data={})["failures"][
            0
        ]["code"]
        == "control_not_trusted"
        and sent.calls == []
    )


def test_catalog_names_resolution_dynamic_script_and_group(tmp_path: Path) -> None:
    control, _credentials, sent = runtime(tmp_path)
    control.enable_control()
    actions = control.list_actions("light")["details"]["actions"]
    assert next(item for item in actions if item["service"] == "light.turn_on")[
        "fields"
    ] == ["effect", "xy_color"]
    ambiguous = control.resolve({"name": "Living room lamp"})
    assert (
        ambiguous["failures"][0]["code"] == "ambiguous_target_name"
        and len(ambiguous["details"]["candidates"]) == 2
    )
    assert control.resolve({"area_id": "living_room"})["details"]["targets"] == [
        "light.living_room_lamp_1",
        "light.living_room_lamp_2",
    ]
    script = control.invoke(
        "script.party", [], data={"playlist_id": "abc", "effect": "party"}
    )
    assert script["status"] == "ok" and sent.calls[-1] == (
        "script",
        "party",
        {"playlist_id": "abc", "effect": "party"},
    )
    group = control.invoke(
        "light.turn_on", ["group.living_room_lamps"], data={"effect": "rainbow"}
    )
    assert (
        group["status"] == "ok"
        and group["warnings"][0]["code"] == "opaque_ha_side_fanout"
    )


def test_invalid_or_admin_inputs_never_post_and_errors_do_not_leak(
    tmp_path: Path,
) -> None:
    control, _credentials, sent = runtime(tmp_path)
    control.enable_control()
    for service, data, targets in [
        ("homeassistant.restart", {}, ["light.living_room_lamp_1"]),
        ("light.turn_on", {"entity_id": ["light.living_room_lamp_2"]}, ["light.living_room_lamp_1"]),
        ("light.turn_on", {"pin": "SENTINEL"}, ["light.living_room_lamp_1"]),
        ("light.turn_on", {"xy_color": [float("nan"), 0]}, ["light.living_room_lamp_1"]),
        ("script.party", {}, ["light.living_room_lamp_1"]),
    ]:
        document = control.invoke(service, targets, data=data)
        assert document["status"] == "failed" and "SENTINEL" not in json.dumps(document)
    assert sent.calls == []


def test_timeout_unknown_no_retry_and_old_api_never_sends(tmp_path: Path) -> None:
    sent = Transport(failure=True)
    control, _credentials, _sent = runtime(tmp_path, sent)
    control.enable_control()
    assert (
        control.invoke("light.turn_on", ["light.living_room_lamp_1"], data={})["status"]
        == "outcome_unknown"
        and len(sent.calls) == 1
    )
    assert (
        control.plan_action("light.turn_on", ["light.living_room_lamp_1"], {})["failures"][
            0
        ]["code"]
        == "migrated_to_invoke"
    )
    assert (
        control.execute_action("old-plan")["failures"][0]["code"]
        == "migrated_to_invoke"
        and len(sent.calls) == 1
    )


def test_operation_audit_is_redacted_and_durable(tmp_path: Path) -> None:
    control, _credentials, _sent = runtime(tmp_path)
    control.enable_control()
    control.invoke("light.turn_on", ["light.living_room_lamp_1"], data={"effect": "rainbow"})
    record = (tmp_path / "ha-analysis" / "operations.jsonl").read_text()
    assert (
        "synthetic-token" not in record
        and "intent_recorded" in record
        and '"effect":"rainbow"' in record
    )


def test_setup_invalidates_existing_control_grant(tmp_path: Path) -> None:
    trust = TrustStore()
    trust.enable(
        {
            "origin": "http://ha.test:8123",
            "transport": "trusted_local_or_vpn",
            "credential_sha256": "x",
        }
    )
    assert (
        ManagementRuntime(config_home=tmp_path / "config").setup(
            "http://ha.test:8123", "trusted_local_or_vpn"
        )["status"]
        == "ok"
    )
    assert trust.status() == "disabled"


def test_entity_id_selector_and_attribute_observation_are_exact(tmp_path: Path) -> None:
    control, _credentials, sent = runtime(tmp_path)
    control.enable_control()
    assert control.resolve({"entity_id": "light.living_room_lamp_1"})["details"][
        "targets"
    ] == ["light.living_room_lamp_1"]
    result = control.invoke(
        "light.turn_on",
        selector={"entity_id": "light.living_room_lamp_1"},
        data={"xy_color": [0.1, 0.2]},
    )
    assert result["details"]["effect"] == "partial"
    assert result["details"]["observations"][0]["status"] == "mismatched"
    assert sent.calls[-1][2]["entity_id"] == ["light.living_room_lamp_1"]


def test_off_is_observed_for_turn_off_and_dynamic_unknown_is_unverified(
    tmp_path: Path,
) -> None:
    control, _credentials, _sent = runtime(tmp_path)
    reader = control._reader
    reader.states["light.living_room_lamp_1"]["state"] = "off"
    control.enable_control()
    off = control.invoke("light.turn_off", ["light.living_room_lamp_1"], data={})
    reader.states["light.living_room_lamp_1"]["state"] = "on"
    unknown = control.invoke(
        "light.turn_on", ["light.living_room_lamp_1"], data={"integration_value": 2}
    )
    assert off["details"]["observations"][0]["status"] == "observed"
    assert unknown["details"]["observations"][0]["status"] == "unverified"


def test_remote_activity_is_observed_and_credential_shaped_state_is_withheld(tmp_path: Path) -> None:
    control, _credentials, _sent = runtime(tmp_path)
    reader = control._reader
    reader.states["remote.living_room_media"] = {
        "state": "on",
        "attributes": {"current_activity": "Streaming", "api_token": "must-not-leak"},
    }
    reader.list_services = lambda *_args: [
        {"domain": "remote", "services": {"turn_on": {"fields": {"activity": {}}}}},
    ]
    control.enable_control()
    observed = control.invoke("remote.turn_on", ["remote.living_room_media"], data={"activity": "Streaming"})
    assert observed["details"]["effect"] == "observed"
    assert observed["details"]["observations"][0]["attributes"]["current_activity"] == "Streaming"
    reader.states["remote.living_room_media"]["state"] = "Bearer synthetic-state-secret"
    withheld = control.invoke("remote.turn_on", ["remote.living_room_media"], data={"activity": "Streaming"})
    assert withheld["details"]["observations"][0]["state"] == "[WITHHELD]"
    assert "synthetic-state-secret" not in json.dumps(withheld)


def test_invoke_deadline_refuses_before_any_post(tmp_path: Path) -> None:
    control, _credentials, sent = runtime(tmp_path)
    control.enable_control()
    result = control.invoke(
        "light.turn_on",
        ["light.living_room_lamp_1"],
        data={},
        deadline=time.monotonic() - 0.001,
    )
    assert result["failures"][0]["code"] == "operation_deadline_elapsed"
    assert sent.calls == []


def test_deadline_elapsed_during_catalog_refuses_before_post(
    tmp_path: Path, monkeypatch: object
) -> None:
    control, _credentials, sent = runtime(tmp_path)
    control.enable_control()
    now = [0.0]
    original_catalog = control._catalog

    def catalog(*args: object) -> object:
        now[0] = 2.0
        return original_catalog(*args)

    monkeypatch.setattr("ha_analysis.control.time.monotonic", lambda: now[0])  # type: ignore[attr-defined]
    control._catalog = catalog
    result = control.invoke("light.turn_on", ["light.living_room_lamp_1"], data={}, deadline=1.0)
    assert result["failures"][0]["code"] == "operation_deadline_elapsed"
    assert sent.calls == []


def test_exact_target_preflight_group_and_mutation_are_safe(tmp_path: Path) -> None:
    control, _credentials, sent = runtime(tmp_path)
    reader = control._reader
    reader.states["light.living_room_lamp_2"] = {"state": "on", "attributes": {}}
    control.enable_control()
    reader.states.pop("light.living_room_lamp_2")
    absent = control.invoke(
        "light.turn_on", ["light.living_room_lamp_1", "light.living_room_lamp_2"], data={}
    )
    assert absent["failures"][0]["code"] == "target_unavailable" and sent.calls == []
    reader.states["light.living_room_lamp_2"] = {"state": "on", "attributes": {}}
    reader.states["light.group"] = {
        "state": "on",
        "attributes": {"entity_id": ["light.living_room_lamp_1"]},
    }
    duplicate = control.invoke(
        "light.turn_on", ["light.group", "light.living_room_lamp_1"], data={}
    )
    assert (
        duplicate["failures"][0]["code"] == "duplicate_group_member_target"
        and sent.calls == []
    )
    mutable = {"effect": {"nested": ["before"]}}
    original_read = reader.read_entity

    def mutate(*args: object) -> object:
        mutable["effect"]["nested"][0] = "after"
        return original_read(*args)

    reader.read_entity = mutate
    result = control.invoke("light.turn_on", ["light.living_room_lamp_1"], data=mutable)
    assert result["status"] == "ok"
    assert sent.calls[-1][2]["effect"] == {"nested": ["before"]}


def test_corrupt_or_revoked_trust_and_audit_failure_never_post(tmp_path: Path) -> None:
    control, _credentials, sent = runtime(tmp_path)
    control.enable_control()
    control._trust.path.write_text("{broken")
    assert (
        control.invoke("light.turn_on", ["light.living_room_lamp_1"], data={})["failures"][
            0
        ]["code"]
        == "control_not_trusted"
    )
    assert sent.calls == []
    control.enable_control()

    class RevokingJournal(OperationJournal):
        def record(self, value: dict[str, object]) -> None:
            super().record(value)
            control.disable_control()

    control._journal = RevokingJournal(tmp_path)
    assert (
        control.invoke("light.turn_on", ["light.living_room_lamp_1"], data={})["failures"][
            0
        ]["code"]
        == "control_trust_changed"
    )
    assert sent.calls == []

    class BrokenJournal:
        def record(self, value: dict[str, object]) -> None:
            raise OSError()

    control._journal = BrokenJournal()
    assert (
        control.invoke("light.turn_on", ["light.living_room_lamp_1"], data={})["failures"][
            0
        ]["code"]
        == "audit_unavailable"
    )
    assert sent.calls == []


def test_script_builtin_targets_and_dynamic_named_script_are_distinct(
    tmp_path: Path,
) -> None:
    control, _credentials, sent = runtime(tmp_path)
    control.enable_control()
    builtin = control.invoke("script.turn_off", ["script.party"], data={})
    direct = control.invoke(
        "script.party", ["script.party"], data={"command": "allowed variable"}
    )
    assert builtin["status"] == "ok"
    assert sent.calls[-2] == ("script", "turn_off", {"entity_id": ["script.party"]})
    assert direct["status"] == "ok"
    assert sent.calls[-1] == ("script", "party", {"command": "allowed variable"})


def test_cli_duplicate_json_and_legacy_flags_are_safe(capsys: object) -> None:
    assert (
        control_main(
            [
                "invoke",
                "light.turn_on",
                "--targets",
                '["light.one"]',
                "--data",
                '{"effect":"a","effect":"SENTINEL"}',
            ]
        )
        == 2
    )
    assert "SENTINEL" not in capsys.readouterr().err
    assert (
        control_main(
            [
                "plan",
                "--targets",
                '["light.one"]',
                "--parameters",
                '{"token":"SENTINEL"}',
            ]
        )
        == 1
    )
    assert "migrated_to_invoke" in capsys.readouterr().out


def test_installed_cli_manifest_and_loopback_control(tmp_path: Path) -> None:
    """Exercise installed entry points against an isolated fake HA and test-only credential seam."""
    posts: list[tuple[str, object]] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            pass

        def do_GET(self) -> None:
            assert self.headers["Authorization"] == "Bearer synthetic-token"
            body = (
                [
                    {
                        "domain": "light",
                        "services": {
                            "turn_on": {"fields": {"xy_color": {}, "effect": {}}}
                        },
                    },
                    {"domain": "script", "services": {"party": {"fields": {}}}},
                ]
                if self.path == "/api/services"
                else {
                    "state": "on",
                    "attributes": {
                        "xy_color": [0.64, 0.33],
                        "effect": "rainbow",
                        "entity_id": ["light.one"],
                    },
                }
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(body).encode())

        def do_POST(self) -> None:
            assert self.headers["Authorization"] == "Bearer synthetic-token"
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            posts.append((self.path, body))
            self.send_response(500 if body.get("effect") == "after-effect-500" else 200)
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    root, injected = Path(__file__).resolve().parents[1], tmp_path / "injected"
    injected.mkdir()
    (injected / "sitecustomize.py").write_text(
        "import ha_analysis.management as m\nclass S:\n def describe(self): return 'test'\n def get_credential(self,key): return 'synthetic-token'\nm.KeyringSecretStore=S\n"
    )
    config = tmp_path / "config" / "ha-analysis"
    config.mkdir(parents=True)
    config.joinpath("settings.json").write_text(
        json.dumps(
            {
                "origin": {
                    "scheme": "http",
                    "host": "127.0.0.1",
                    "port": server.server_port,
                },
                "transport_mode": "trusted_local_or_vpn",
                "auth_mode": "long_lived_access_token",
            }
        )
    )
    for candidate in (root / "dist").glob("ha_analysis-*.whl"):
        candidate.unlink()
    build = subprocess.run(
        ["uv", "build", "--wheel"],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    assert build.returncode == 0, build.stderr
    wheel = next((root / "dist").glob("ha_analysis-0.8.0-*.whl"))
    venv = tmp_path / "venv"
    created = subprocess.run(
        ["uv", "venv", "--python", "3.13", str(venv)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert created.returncode == 0, created.stderr
    installed = subprocess.run(
        ["uv", "pip", "install", "--python", str(venv / "bin/python"), str(wheel)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert installed.returncode == 0, installed.stderr
    env = {
        **os.environ,
        "PYTHONPATH": str(injected),
        "XDG_CONFIG_HOME": str(tmp_path / "config"),
        "XDG_STATE_HOME": str(tmp_path / "state"),
    }

    def run(*args: str, expected: int = 0) -> dict[str, object]:
        done = subprocess.run(
            [str(venv / "bin" / args[0]), *args[1:]],
            cwd=tmp_path,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        assert done.returncode == expected, done.stderr
        return json.loads(done.stdout)

    imported = subprocess.run(
        [
            str(venv / "bin/python"),
            "-c",
            "import ha_analysis; print(ha_analysis.__file__)",
        ],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert (
        imported.returncode == 0
        and "site-packages" in imported.stdout
        and str(root / "src") not in imported.stdout
    )
    installed_sdk = subprocess.run(
        [
            str(venv / "bin/python"),
            "-c",
            (
                "import importlib.metadata as m,json,pathlib; "
                "print(json.dumps({name:json.loads(pathlib.Path(m.distribution(name).locate_file(next(str(f) for f in m.distribution(name).files if str(f).endswith('direct_url.json')))).read_text()) "
                "for name in ('amplifier-agent','amplifier-agent-engine')}))"
            ),
        ],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert installed_sdk.returncode == 0, installed_sdk.stderr
    direct_urls = json.loads(installed_sdk.stdout)
    for value in direct_urls.values():
        assert value["vcs_info"]["commit_id"] == "412cc176cfa5bd219254060ede7f03bbf6578005"
    help_result = subprocess.run(
        [str(venv / "bin/ha-control"), "run", "--help"],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert help_result.returncode == 0 and "--read-only" in help_result.stdout
    source_help = subprocess.run(
        ["uv", "run", "--no-project", "src/ha_analysis/cli.py", "control", "run", "--help"],
        cwd=root,
        env={**env, "PYTHONPATH": f"{injected}:{root / 'src'}"},
        text=True,
        capture_output=True,
        check=False,
    )
    assert source_help.returncode == 0 and "--dry-run" in source_help.stdout
    assert run("ha-analysis", "manifest")["version"] == "0.8.0"
    assert (
        run(
            "ha-analysis",
            "control",
            "invoke",
            "light.turn_on",
            "--targets",
            '["light.one"]',
            "--data",
            "{}",
            expected=1,
        )["failures"][0]["code"]
        == "control_not_trusted"
    )
    assert posts == []
    assert run("ha-control", "trust", "enable")["details"]["trust"] == "enabled"
    assert (
        run("ha-control", "actions", "--domain", "light")["details"]["actions"][0][
            "service"
        ]
        == "light.turn_on"
    )
    result = run(
        "ha-analysis",
        "control",
        "invoke",
        "light.turn_on",
        "--targets",
        '["light.one","light.two","light.three"]',
        "--data",
        '{"xy_color":[0.64,0.33]}',
    )
    group = run(
        "ha-control",
        "invoke",
        "light.turn_on",
        "--targets",
        '["light.group"]',
        "--data",
        '{"effect":"rainbow"}',
    )
    script = run(
        "ha-control",
        "invoke",
        "script.party",
        "--targets",
        "[]",
        "--data",
        '{"playlist_id":"night"}',
    )
    assert run("ha-control", "trust", "disable")["details"]["trust"] == "disabled"
    assert (
        run(
            "ha-control",
            "invoke",
            "light.turn_on",
            "--targets",
            '["light.one"]',
            "--data",
            "{}",
            expected=1,
        )["failures"][0]["code"]
        == "control_not_trusted"
    )
    before_retry = len(posts)
    run("ha-control", "trust", "enable")
    unknown = run(
        "ha-control",
        "invoke",
        "light.turn_on",
        "--targets",
        '["light.one"]',
        "--data",
        '{"effect":"after-effect-500"}',
        expected=1,
    )
    source = subprocess.run(
        [
            "uv",
            "run",
            "--no-project",
            "src/ha_analysis/cli.py",
            "control",
            "invoke",
            "light.turn_on",
            "--targets",
            '["light.living_room_lamp_1"]',
            "--data",
            "{}",
            "--dry-run",
        ],
        cwd=root,
        env={**env, "PYTHONPATH": f"{injected}:{root / 'src'}"},
        text=True,
        capture_output=True,
        check=False,
    )
    server.shutdown()
    server.server_close()
    assert source.returncode == 0, source.stderr
    assert json.loads(source.stdout)["details"]["outcome"] == "dry_run"
    assert result["details"]["effect"] == "observed"
    assert group["warnings"][0]["code"] == "opaque_ha_side_fanout"
    assert script["details"]["service"] == "script.party"
    assert unknown["status"] == "outcome_unknown" and len(posts) == before_retry + 1
    assert posts[0] == (
        "/api/services/light/turn_on",
        {
            "entity_id": ["light.one", "light.two", "light.three"],
            "xy_color": [0.64, 0.33],
        },
    )
