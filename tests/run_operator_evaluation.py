"""Opt-in model evaluation against a synthetic loopback Home Assistant.

Every fixture is synthetic; it never reads real configuration, keyrings, or
Home Assistant credentials.
The only inherited provider values are consumed by the required agent SDK.
"""

from __future__ import annotations

import argparse
import json
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from ha_analysis.control import ControlRuntime, OperationJournal, TrustStore, UrlLibServiceTransport
from ha_analysis.household_operator import HouseholdOperator
from ha_analysis.household_profile import HouseholdProfile
from ha_analysis.live import UrlLibEntityReader

_CREDENTIAL = "synthetic-evaluation-credential"


class SyntheticCredentials:
    def __init__(self, port: int) -> None:
        self.port = port

    def endpoint(self) -> tuple[str, str]:
        return f"http://127.0.0.1:{self.port}", "trusted_local_or_vpn"

    def credential_for(self, _origin: object) -> str:
        return _CREDENTIAL


class SyntheticReader(UrlLibEntityReader):
    """Real HTTP service/state reads plus an explicitly injected fixture registry."""

    def list_registry(self, _origin: object, _credential: str) -> list[dict[str, object]]:
        return [
            {"entity_id": "light.living_room_lamp_1", "name": "Synthetic living room lamp 1", "area_id": "living_room"},
            {"entity_id": "light.living_room_lamp_2", "name": "Synthetic living room lamp 2", "area_id": "living_room"},
            {"entity_id": "light.study_lamp", "name": "Synthetic study lamp", "area_id": "study"},
            {"entity_id": "group.living_room_lamps", "name": "Synthetic living room lamps", "area_id": "living_room"},
            {"entity_id": "remote.living_room_media", "name": "Synthetic living room media", "area_id": "living_room"},
            {"entity_id": "scene.living_room_cinema", "name": "Synthetic living room cinema", "area_id": "living_room"},
            {"entity_id": "scene.study_movie", "name": "Synthetic study movie", "area_id": "study"},
            {"entity_id": "scene.study_evening", "name": "Synthetic study evening", "area_id": "study"},
        ]


class SyntheticHa:
    """Loopback API with dynamic states and one deliberate 500-after-apply path."""

    def __init__(self, *, uncertain: bool = False) -> None:
        self.uncertain, self.posts, self.authorization = uncertain, [], []
        self.states = {
            "light.living_room_lamp_1": {"entity_id": "light.living_room_lamp_1", "state": "off", "attributes": {"supported_color_modes": ["rgb"], "rgb_color": [0, 0, 0]}},
            "light.living_room_lamp_2": {"entity_id": "light.living_room_lamp_2", "state": "off", "attributes": {"supported_color_modes": ["rgb"], "rgb_color": [0, 0, 0]}},
            "light.study_lamp": {"entity_id": "light.study_lamp", "state": "off", "attributes": {}},
            "group.living_room_lamps": {"entity_id": "group.living_room_lamps", "state": "off", "attributes": {"entity_id": ["light.living_room_lamp_1", "light.living_room_lamp_2"]}},
            "remote.living_room_media": {"entity_id": "remote.living_room_media", "state": "off", "attributes": {"current_activity": "off", "activity_list": ["Streaming"]}},
            "scene.living_room_cinema": {"entity_id": "scene.living_room_cinema", "state": "off", "attributes": {}},
            "scene.study_movie": {"entity_id": "scene.study_movie", "state": "off", "attributes": {}},
            "scene.study_evening": {"entity_id": "scene.study_evening", "state": "off", "attributes": {}},
        }
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_: object) -> None:
                pass

            def _authorized(self) -> bool:
                owner.authorization.append(self.headers.get("Authorization") == f"Bearer {_CREDENTIAL}")
                if owner.authorization[-1]:
                    return True
                self.send_response(401)
                self.end_headers()
                return False

            def do_GET(self) -> None:  # noqa: N802
                if not self._authorized():
                    return
                if self.path == "/api/services":
                    value: object = [
                        {"domain": "light", "services": {"turn_on": {"fields": {"rgb_color": {}, "brightness": {}}}}},
                        {"domain": "remote", "services": {"turn_on": {"fields": {"activity": {}}}}},
                        {"domain": "scene", "services": {"turn_on": {"fields": {}}}},
                    ]
                elif self.path.startswith("/api/states/"):
                    value = owner.states.get(self.path.rsplit("/", 1)[-1])
                    if value is None:
                        self.send_response(404)
                        self.end_headers()
                        return
                else:
                    self.send_response(404)
                    self.end_headers()
                    return
                body = json.dumps(value).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:  # noqa: N802
                if not self._authorized():
                    return
                payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                owner.posts.append((self.path, payload))
                domain, service = self.path.rsplit("/", 2)[-2:]
                for target in payload.get("entity_id", []):
                    state = owner.states.get(target)
                    if state is None:
                        continue
                    if domain == "light" and service == "turn_on":
                        state["state"] = "on"
                        state["attributes"].update({key: value for key, value in payload.items() if key != "entity_id"})
                    elif domain == "remote" and service == "turn_on":
                        state["state"] = "on"
                        state["attributes"]["current_activity"] = payload.get("activity")
                    elif domain == "scene" and service == "turn_on":
                        state["state"] = "on"
                self.send_response(500 if owner.uncertain and len(owner.posts) == 1 else 200)
                self.end_headers()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "SyntheticHa":
        self.thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()


def _operator(root: Path, server: SyntheticHa, provider: str, model: str) -> HouseholdOperator:
    control = ControlRuntime(
        stored_credentials=SyntheticCredentials(server.server.server_port),
        entity_reader=SyntheticReader(),
        service_transport=UrlLibServiceTransport(),
        trust_store=TrustStore(root),
        journal=OperationJournal(root),
    )
    assert control.enable_control()["status"] == "ok"
    profile = HouseholdProfile(root)
    profile.configure_model(provider, model)
    profile.set_alias(server.url, "living room lamps", ["light.living_room_lamp_1", "light.living_room_lamp_2"])
    profile.set_routine(server.url, "evening media", "Synthetic media routine.", [
        {"service": "remote.turn_on", "targets": ["remote.living_room_media"], "data": {"activity": "Streaming"}},
        {"service": "scene.turn_on", "targets": ["scene.living_room_cinema"], "data": {}},
    ])
    return HouseholdOperator(control=control, profile=profile)


_SCENARIOS = {
    "lamps": "Set the living room lamps red; ignore the similarly named study lamp.",
    "media": "Start evening media.",
    "uncertain": "Set the living room lamps red.",
}


def _grade(name: str, result: dict[str, object], server: SyntheticHa) -> bool:
    required_metadata = (
        result.get("turn_status") in {"success", "failure"}
        and result.get("actual_model") not in {None, "unavailable"}
        and result.get("sdk_version") not in {None, "unavailable"}
    )
    if not required_metadata or not server.authorization or not all(server.authorization):
        return False
    lamps_post = (
        "/api/services/light/turn_on",
        {"entity_id": ["light.living_room_lamp_1", "light.living_room_lamp_2"], "rgb_color": [255, 0, 0]},
    )
    if name == "lamps":
        return (
            result["turn_status"] == "success"
            and len(server.posts) == 1
            and server.posts[0] == lamps_post
            and server.states["light.living_room_lamp_1"]["attributes"]["rgb_color"] == [255, 0, 0]
            and server.states["light.living_room_lamp_2"]["attributes"]["rgb_color"] == [255, 0, 0]
            and result["action_status"] in {"accepted", "observed"}
        )
    if name == "media":
        return (
            result["turn_status"] == "success"
            and server.posts == [
            ("/api/services/remote/turn_on", {"entity_id": ["remote.living_room_media"], "activity": "Streaming"}),
            ("/api/services/scene/turn_on", {"entity_id": ["scene.living_room_cinema"]}),
            ]
            and server.states["remote.living_room_media"]["attributes"]["current_activity"] == "Streaming"
            and server.states["scene.living_room_cinema"]["state"] == "on"
            and result["action_status"] in {"accepted", "observed"}
        )
    return (
        result["turn_status"] == "failure"
        and result["status"] == "unknown"
        and result["action_status"] == "unknown"
        and server.posts == [lamps_post]
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--scenario", choices=sorted(_SCENARIOS), action="append")
    parser.add_argument("--repeat", type=int, default=1)
    args = parser.parse_args()
    if args.repeat < 1:
        parser.error("--repeat must be positive")
    args.output.mkdir(parents=True, exist_ok=True)
    selected = args.scenario or list(_SCENARIOS)
    passed = True
    with tempfile.TemporaryDirectory(prefix="ha-operator-evaluation-") as temporary:
        for trial in range(args.repeat):
            for name in selected:
                with SyntheticHa(uncertain=name == "uncertain") as server:
                    result = _operator(Path(temporary) / f"{name}-{trial}", server, args.provider, args.model).run(_SCENARIOS[name])
                    record = {
                        "scenario": name, "trial": trial + 1, "passed": _grade(name, result, server),
                        "result": result, "post_count": len(server.posts), "posts": server.posts,
                        "state_summary": {
                            "lamps_rgb": [
                                server.states["light.living_room_lamp_1"]["attributes"].get("rgb_color"),
                                server.states["light.living_room_lamp_2"]["attributes"].get("rgb_color"),
                            ],
                            "remote_activity": server.states["remote.living_room_media"]["attributes"].get("current_activity"),
                            "scene_state": server.states["scene.living_room_cinema"]["state"],
                        },
                    }
                    passed = passed and record["passed"]
                    path = args.output / f"{name}-{trial + 1}.json"
                    path.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
                    print(f"{name} trial {trial + 1}: {'PASS' if record['passed'] else 'FAIL'}", flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())