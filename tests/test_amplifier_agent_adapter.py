"""C6/T6 containment tests for the optional amplifier-agent interpreter."""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import subprocess
import sys
import threading
import tomllib
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from ha_analysis import AnalysisRuntime
from ha_analysis import cli as cli_module
from ha_analysis import amplifier_agent_adapter as adapter_module
from ha_analysis.amplifier_agent_adapter import (
    MODEL_RUNTIME,
    AmplifierAgentInterpreter,
    ModelRuntimeError,
)

ROOT = Path(__file__).parents[1]


class FakeChatCompletions:
    """A local OpenAI-compatible server; it never reaches a real provider."""

    def __init__(self, responses: list[dict[str, Any]]) -> None:
        self.responses = responses
        self.requests: list[dict[str, Any]] = []
        self.served: list[dict[str, Any]] = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_: object) -> None:
                pass

            def do_POST(self) -> None:  # noqa: N802 - HTTP handler API
                owner.requests.append(
                    json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                )
                response = owner.responses.pop(0)
                owner.served.append(response)
                model = "fixture-model"
                base = {
                    "id": "fixture",
                    "object": "chat.completion.chunk",
                    "created": 1,
                    "model": model,
                }
                if "tool" in response:
                    delta = {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "index": 0,
                                "id": "call-fixture",
                                "type": "function",
                                "function": {
                                    "name": response["tool"],
                                    "arguments": json.dumps(response["arguments"]),
                                },
                            }
                        ],
                    }
                    frames = [
                        {**base, "choices": [{"index": 0, "delta": delta, "finish_reason": None}]},
                        {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]},
                    ]
                else:
                    frames = [
                        {
                            **base,
                            "choices": [
                                {
                                    "index": 0,
                                    "delta": {"content": response["text"]},
                                    "finish_reason": None,
                                }
                            ],
                        },
                        {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
                    ]
                frames[-1]["usage"] = {
                    "prompt_tokens": 1,
                    "completion_tokens": 1,
                    "total_tokens": 2,
                }
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                for frame in frames:
                    self.wfile.write(f"data: {json.dumps(frame)}\n\n".encode())
                self.wfile.write(b"data: [DONE]\n\n")

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._server.server_port}/v1"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> "FakeChatCompletions":
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._server.shutdown()
        self._thread.join()
        self._server.server_close()


class ForbiddenEgress:
    """A local endpoint that must never receive a denied web-fetch request."""

    def __init__(self) -> None:
        self.requests = 0
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_: object) -> None:
                pass

            def do_GET(self) -> None:  # noqa: N802 - HTTP handler API
                owner.requests += 1
                self.send_response(200)
                self.end_headers()

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._server.server_port}/secret"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> "ForbiddenEgress":
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._server.shutdown()
        self._thread.join()
        self._server.server_close()


@pytest.fixture
def agent_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in tuple(os.environ):
        if name.startswith("AMPLIFIER_AGENT_"):
            monkeypatch.delenv(name)


def _interpreter(storage: Path) -> AmplifierAgentInterpreter:
    return AmplifierAgentInterpreter(
        provider="chat-completions", model="fixture-model", storage_root=storage
    )


def _files(root: Path) -> list[Path]:
    return list(root.rglob("*")) if root.exists() else []


def test_t6_installed_agent_uses_only_redacted_selected_payload_and_ephemeral_storage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, agent_environment: None
) -> None:
    secret = "selected-evidence-secret"
    storage = tmp_path / "ephemeral"
    with FakeChatCompletions([{"text": '{"advice":"review it"}'}]) as provider:
        monkeypatch.setenv("CHAT_COMPLETIONS_BASE_URL", provider.url)
        result = AnalysisRuntime(model_interpreter=_interpreter(storage)).interpret_evidence(
            [{"state": "on", "token": secret}],
            {"interpretation_kind": "advice"},
        )

    assert result["output"]["interpretation"] == {"advice": "review it"}
    assert result["failures"] == []
    sent = json.dumps(provider.requests[0])
    assert secret not in sent
    assert "[REDACTED]" in sent
    assert "interpretation_kind" in sent
    assert not _files(storage), "ephemeral sessions must not create a transcript"


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("bash", lambda root: {"command": f"touch {root / 'shell-effect'}"}),
        ("read_file", lambda root: {"file_path": str(root / "secret-sentinel.txt")}),
    ],
)
def test_t6_tool_requests_are_denied_before_shell_or_file_read_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    agent_environment: None,
    tool: str,
    arguments: Any,
) -> None:
    storage = tmp_path / "storage"
    secret = tmp_path / "secret-sentinel.txt"
    secret.write_text("must-never-reach-provider", encoding="utf-8")
    request = arguments(tmp_path)
    with FakeChatCompletions([{"tool": tool, "arguments": request}]) as provider:
        monkeypatch.setenv("CHAT_COMPLETIONS_BASE_URL", provider.url)
        result = AnalysisRuntime(model_interpreter=_interpreter(storage)).interpret_evidence(
            [{"state": "on"}], {"interpretation_kind": "advice"}
        )

    assert provider.served == [{"tool": tool, "arguments": request}]
    assert result["output"]["interpretation"] is None
    assert [failure["code"] for failure in result["failures"]] == [
        "model_tool_request_denied"
    ]
    assert not (tmp_path / "shell-effect").exists()
    assert "must-never-reach-provider" not in json.dumps(provider.requests)
    assert not _files(storage)


def test_t6_denied_web_fetch_makes_no_egress_or_storage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, agent_environment: None
) -> None:
    storage = tmp_path / "storage"
    with ForbiddenEgress() as egress:
        with FakeChatCompletions(
            [{"tool": "web_fetch", "arguments": {"url": egress.url}}]
        ) as provider:
            monkeypatch.setenv("CHAT_COMPLETIONS_BASE_URL", provider.url)
            result = AnalysisRuntime(model_interpreter=_interpreter(storage)).interpret_evidence(
                [{"state": "on"}], {"interpretation_kind": "advice"}
            )

    assert [failure["code"] for failure in result["failures"]] == [
        "model_tool_request_denied"
    ]
    assert egress.requests == 0
    assert len(provider.requests) == 1
    assert not _files(storage)


def test_t6_durable_control_writes_while_adapter_ephemeral_session_does_not(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, agent_environment: None
) -> None:
    agent_sdk = importlib.import_module("amplifier_agent")
    ephemeral = tmp_path / "ephemeral"
    durable = tmp_path / "durable"
    with FakeChatCompletions(
        [{"text": '{"advice":"ephemeral"}'}, {"text": '{"advice":"durable"}'}]
    ) as provider:
        monkeypatch.setenv("CHAT_COMPLETIONS_BASE_URL", provider.url)
        assert _interpreter(ephemeral).interpret([{"state": "on"}], "advice") == {
            "advice": "ephemeral"
        }

        async def durable_turn() -> object:
            async with await agent_sdk.create_agent(
                agent_sdk.AgentOptions(
                    provider="chat-completions",
                    model="fixture-model",
                    storage=durable,
                    approvals="deny",
                    tools=[],
                    skills=[],
                    mcp_servers=[],
                )
            ) as agent:
                async with await agent.create_session(
                    agent_sdk.SessionOptions(persistence="durable")
                ) as session:
                    return await session.run(
                        agent_sdk.TurnInput([agent_sdk.TextPart("return JSON")])
                    )

        result = asyncio.run(durable_turn())

    assert result.state == "success"
    assert not _files(ephemeral)
    assert (durable / "workspaces" / "default" / "sessions.sqlite3").is_file()


def test_t6_scope_replaces_ambient_environment_and_restores_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: dict[str, Any] = {}

    @dataclass
    class AgentError(Exception):
        code: str

    class Session:
        async def __aenter__(self) -> "Session":
            return self

        async def __aexit__(self, *_: object) -> None:
            pass

        async def run(self, _: object) -> object:
            observed["turn_environment"] = dict(os.environ)
            return SimpleNamespace(state="success", error=None, content=[SimpleNamespace(text="{}")])

    class Agent:
        async def __aenter__(self) -> "Agent":
            return self

        async def __aexit__(self, *_: object) -> None:
            pass

        async def create_session(self, options: object) -> Session:
            observed["session"] = options
            return Session()

    async def create_agent(options: object) -> Agent:
        observed["options"] = options
        observed["construction_environment"] = dict(os.environ)
        return Agent()

    fake_sdk = SimpleNamespace(
        AgentError=AgentError,
        AgentOptions=lambda **kwargs: SimpleNamespace(**kwargs),
        SessionOptions=lambda **kwargs: SimpleNamespace(**kwargs),
        TurnInput=lambda **kwargs: SimpleNamespace(**kwargs),
        TextPart=lambda text: SimpleNamespace(text=text),
        create_agent=create_agent,
    )
    monkeypatch.setattr(
        adapter_module,
        "_load_agent_sdk",
        lambda: fake_sdk,
    )
    monkeypatch.setenv("AMPLIFIER_AGENT_CONFIG", "/hostile/config.json")
    monkeypatch.setenv("AMPLIFIER_AGENT_PROVIDER", "hostile-provider")
    monkeypatch.setenv("HOME_ASSISTANT_TOKEN", "synthetic-ha-token")
    monkeypatch.setenv("XDG_CONFIG_HOME", "/hostile/persisted-settings")
    monkeypatch.setenv("OPENAI_API_KEY", "unrelated-provider-key")
    monkeypatch.setenv("CHAT_COMPLETIONS_API_KEY", "selected-provider-key")
    monkeypatch.setenv("CHAT_COMPLETIONS_BASE_URL", "http://127.0.0.1:9999/v1")

    assert AmplifierAgentInterpreter(
        provider="chat-completions", model="fixture", storage_root=tmp_path
    ).interpret([{"state": "on"}], "advice") == {}
    scoped = observed["construction_environment"]
    assert observed["turn_environment"] == scoped
    assert "AMPLIFIER_AGENT_CONFIG" not in scoped
    assert "AMPLIFIER_AGENT_PROVIDER" not in scoped
    assert "HOME_ASSISTANT_TOKEN" not in scoped
    assert "OPENAI_API_KEY" not in scoped
    assert scoped["CHAT_COMPLETIONS_API_KEY"] == "selected-provider-key"
    assert scoped["CHAT_COMPLETIONS_BASE_URL"] == "http://127.0.0.1:9999/v1"
    assert scoped["XDG_CONFIG_HOME"] != "/hostile/persisted-settings"
    assert scoped["HOME"] != os.environ["HOME"]
    assert observed["options"].provider == "chat-completions"
    assert observed["options"].model == "fixture"
    assert observed["options"].storage == tmp_path
    assert observed["options"].approvals == "deny"
    assert observed["options"].tools == observed["options"].skills == observed["options"].mcp_servers == []
    assert observed["session"].persistence == "ephemeral"
    assert os.environ["AMPLIFIER_AGENT_CONFIG"] == "/hostile/config.json"
    assert os.environ["AMPLIFIER_AGENT_PROVIDER"] == "hostile-provider"
    assert os.environ["HOME_ASSISTANT_TOKEN"] == "synthetic-ha-token"
    assert os.environ["XDG_CONFIG_HOME"] == "/hostile/persisted-settings"
    assert os.environ["OPENAI_API_KEY"] == "unrelated-provider-key"


def test_t6_actual_resolved_config_receives_only_scoped_provider_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_sdk = importlib.import_module("amplifier_agent")
    observed: dict[str, Any] = {}
    original_create_agent = real_sdk.create_agent

    async def capture_agent(options: object) -> object:
        agent = await original_create_agent(options)
        config = agent._port._target.config  # type: ignore[attr-defined]
        observed["environment"] = dict(config.environment)
        observed["connection"] = dict(config.connection)
        return agent

    scoped_sdk = SimpleNamespace(
        AgentError=real_sdk.AgentError,
        AgentOptions=real_sdk.AgentOptions,
        SessionOptions=real_sdk.SessionOptions,
        TextPart=real_sdk.TextPart,
        TurnInput=real_sdk.TurnInput,
        create_agent=capture_agent,
    )
    monkeypatch.setattr(adapter_module, "_load_agent_sdk", lambda: scoped_sdk)
    inherited = {
        "AMPLIFIER_AGENT_CONFIG": "/unsafe/agent-config.json",
        "AMPLIFIER_AGENT_STORAGE": "/unsafe/agent-storage",
        "ANTHROPIC_API_KEY": "unrelated-anthropic-key",
        "HOME": "/unsafe/home",
        "HOME_ASSISTANT_ORIGIN": "https://synthetic-ha.invalid",
        "HOME_ASSISTANT_TOKEN": "synthetic-ha-token",
        "HTTP_PROXY": "http://synthetic-proxy.invalid",
        "OPENAI_API_KEY": "unrelated-openai-key",
        "XDG_CACHE_HOME": "/unsafe/cache",
        "XDG_CONFIG_HOME": "/unsafe/persisted-settings",
        "XDG_STATE_HOME": "/unsafe/state",
        "XDG_DATA_HOME": "/unsafe/data",
        "CHAT_COMPLETIONS_API_KEY": "selected-provider-key",
    }
    for name, value in inherited.items():
        monkeypatch.setenv(name, value)
    storage = tmp_path / "ephemeral"
    with FakeChatCompletions([{"text": '{"advice":"safe"}'}]) as provider:
        monkeypatch.setenv("CHAT_COMPLETIONS_BASE_URL", provider.url)
        result = _interpreter(storage).interpret([{"state": "on"}], "advice")

    environment = observed["environment"]
    expected = {
        *adapter_module._SAFE_RUNTIME_ENVIRONMENT,
        "HOME",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "CHAT_COMPLETIONS_API_KEY",
        "CHAT_COMPLETIONS_BASE_URL",
    }
    assert set(environment) == expected
    assert environment["CHAT_COMPLETIONS_API_KEY"] == "selected-provider-key"
    assert environment["CHAT_COMPLETIONS_BASE_URL"] == provider.url
    for name in (
        "AMPLIFIER_AGENT_CONFIG",
        "AMPLIFIER_AGENT_STORAGE",
        "ANTHROPIC_API_KEY",
        "HOME_ASSISTANT_ORIGIN",
        "HOME_ASSISTANT_TOKEN",
        "HTTP_PROXY",
        "OPENAI_API_KEY",
    ):
        assert name not in environment
    temporary_root = Path(environment["HOME"]).parent
    assert all(
        Path(environment[name]).parent == temporary_root
        for name in ("HOME", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME")
    )
    assert observed["connection"] == {
        "api_key": "selected-provider-key",
        "base_url": provider.url,
    }
    assert result == {"advice": "safe"}
    assert len(provider.requests) == 1
    assert not _files(storage)
    assert not temporary_root.exists()
    for name, value in inherited.items():
        assert os.environ[name] == value
    assert os.environ["CHAT_COMPLETIONS_BASE_URL"] == provider.url


def test_t6_invalid_json_and_terminal_or_raised_agent_errors_are_explicit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class AgentError(Exception):
        def __init__(self, code: str) -> None:
            self.code = code

    def sdk_for(result: object | Exception) -> object:
        class Session:
            async def __aenter__(self) -> "Session":
                return self

            async def __aexit__(self, *_: object) -> None:
                pass

            async def run(self, _: object) -> object:
                if isinstance(result, Exception):
                    raise result
                return result

        class Agent:
            async def __aenter__(self) -> "Agent":
                return self

            async def __aexit__(self, *_: object) -> None:
                pass

            async def create_session(self, _: object) -> Session:
                return Session()

        async def create_agent(_: object) -> Agent:
            return Agent()

        return SimpleNamespace(
            AgentError=AgentError,
            AgentOptions=lambda **kwargs: SimpleNamespace(**kwargs),
            SessionOptions=lambda **kwargs: SimpleNamespace(**kwargs),
            TurnInput=lambda **kwargs: SimpleNamespace(**kwargs),
            TextPart=lambda text: SimpleNamespace(text=text),
            create_agent=create_agent,
        )

    def run(result: object | Exception) -> dict[str, object]:
        monkeypatch.setattr(
            adapter_module,
            "_load_agent_sdk",
            lambda: sdk_for(result),
        )
        return AnalysisRuntime(
            model_interpreter=AmplifierAgentInterpreter(
                provider="chat-completions", model="fixture", storage_root=tmp_path
            )
        ).interpret_evidence([{"state": "on"}], {"interpretation_kind": "advice"})

    invalid = run(SimpleNamespace(state="success", error=None, content=[SimpleNamespace(text="not JSON")]))
    terminal = run(SimpleNamespace(state="failure", error=AgentError("provider_failed"), content=None))
    denied = run(SimpleNamespace(state="rejected", error=AgentError("approval_denied"), content=None))
    raised = run(AgentError("approval_denied"))
    assert [item["code"] for item in invalid["failures"]] == ["model_response_invalid"]
    assert [item["code"] for item in terminal["failures"]] == ["model_agent_failed"]
    assert [item["code"] for item in denied["failures"]] == ["model_tool_request_denied"]
    assert [item["code"] for item in raised["failures"]] == ["model_tool_request_denied"]


def test_t6_runtime_dependency_and_python_floor_fail_explicitly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    interpreter = AmplifierAgentInterpreter(
        provider="chat-completions", model="fixture", storage_root=tmp_path
    )
    monkeypatch.setattr(
        adapter_module,
        "_load_agent_sdk",
        lambda: (_ for _ in ()).throw(ImportError()),
    )
    unavailable = AnalysisRuntime(model_interpreter=interpreter).interpret_evidence(
        [{"state": "on"}], {"interpretation_kind": "advice"}
    )
    monkeypatch.setattr(adapter_module.sys, "version_info", (3, 11))
    unsupported = AnalysisRuntime(model_interpreter=interpreter).interpret_evidence(
        [{"state": "on"}], {"interpretation_kind": "advice"}
    )
    assert [item["code"] for item in unavailable["failures"]] == ["model_runtime_unavailable"]
    assert [item["code"] for item in unsupported["failures"]] == [
        "model_runtime_python_unsupported"
    ]


def test_t6_unsupported_provider_fails_before_optional_runtime_import(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        adapter_module,
        "_load_agent_sdk",
        lambda: (_ for _ in ()).throw(AssertionError("must not import")),
    )
    with pytest.raises(ModelRuntimeError) as raised:
        AmplifierAgentInterpreter(
            provider="github-copilot", model="fixture", storage_root=tmp_path
        ).interpret([], "advice")
    assert raised.value.code == "model_runtime_provider_unsupported"


def test_t6_adapter_works_from_a_running_event_loop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class AgentError(Exception):
        code = "provider_failed"

    fake_sdk = SimpleNamespace(
        AgentError=AgentError,
        AgentOptions=lambda **kwargs: SimpleNamespace(**kwargs),
        SessionOptions=lambda **kwargs: SimpleNamespace(**kwargs),
        TurnInput=lambda **kwargs: SimpleNamespace(**kwargs),
        TextPart=lambda text: SimpleNamespace(text=text),
    )

    class Session:
        async def __aenter__(self) -> "Session":
            return self

        async def __aexit__(self, *_: object) -> None:
            pass

        async def run(self, _: object) -> object:
            return SimpleNamespace(state="success", error=None, content=[SimpleNamespace(text='{"ok":true}')])

    class Agent:
        async def __aenter__(self) -> "Agent":
            return self

        async def __aexit__(self, *_: object) -> None:
            pass

        async def create_session(self, _: object) -> Session:
            return Session()

    async def create_agent(_: object) -> Agent:
        return Agent()

    fake_sdk.create_agent = create_agent
    monkeypatch.setattr(
        adapter_module, "_load_agent_sdk", lambda: fake_sdk
    )

    async def call() -> object:
        return AmplifierAgentInterpreter(
            provider="chat-completions", model="fixture", storage_root=tmp_path
        ).interpret([], "advice")

    assert asyncio.run(call()) == {"ok": True}


def test_t6_manifest_help_and_offline_do_not_import_optional_dependency() -> None:
    code = """
import sys
from ha_analysis import AnalysisRuntime
from ha_analysis.cli import main
assert main(["manifest", "--format", "json"]) == 0
try:
    main(["--help"])
except SystemExit:
    pass
assert AnalysisRuntime().offline_analyze([{"state": "on"}], {"analysis_kind": "structural_summary"})["failures"] == []
assert "amplifier_agent" not in sys.modules
"""
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_c2_cli_constructs_the_same_explicit_adapter_configuration(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    constructed: list[tuple[str, str]] = []

    class Interpreter:
        def __init__(self, *, provider: str, model: str) -> None:
            constructed.append((provider, model))

        def interpret(self, _: object, __: str) -> object:
            return {"advice": "fixture"}

    monkeypatch.setattr(cli_module, "AmplifierAgentInterpreter", Interpreter)
    assert cli_module.main(
        [
            "interpret_evidence",
            "--selected-evidence",
            '[{"state":"on"}]',
            "--request",
            '{"interpretation_kind":"advice"}',
            "--model-runtime",
            MODEL_RUNTIME,
            "--model-provider",
            "chat-completions",
            "--model",
            "fixture-model",
        ]
    ) == 0
    assert constructed == [("chat-completions", "fixture-model")]
    assert json.loads(capsys.readouterr().out)["output"]["interpretation"] == {"advice": "fixture"}
    with pytest.raises(SystemExit):
        cli_module.main(
            [
                "interpret_evidence",
                "--selected-evidence",
                "[]",
                "--request",
                "{}",
                "--model-provider",
                "chat-completions",
            ]
        )


def test_c2_cli_and_library_are_equivalent_with_the_selected_agent_adapter(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    agent_environment: None,
) -> None:
    argv = [
        "interpret_evidence",
        "--selected-evidence",
        '[{"state":"on"}]',
        "--request",
        '{"interpretation_kind":"advice"}',
        "--model-runtime",
        MODEL_RUNTIME,
        "--model-provider",
        "chat-completions",
        "--model",
        "fixture-model",
    ]
    with FakeChatCompletions(
        [{"text": '{"advice":"equivalent"}'}, {"text": '{"advice":"equivalent"}'}]
    ) as provider:
        monkeypatch.setenv("CHAT_COMPLETIONS_BASE_URL", provider.url)
        library = AnalysisRuntime(
            model_interpreter=AmplifierAgentInterpreter(
                provider="chat-completions",
                model="fixture-model",
                storage_root=tmp_path / "library-storage",
            )
        ).interpret_evidence([{"state": "on"}], {"interpretation_kind": "advice"})
        assert cli_module.main(argv) == 0
        cli = json.loads(capsys.readouterr().out)

    assert _without_timestamp(cli) == _without_timestamp(library)


def test_t6_pin_python_marker_and_hatch_direct_reference_metadata() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    requirements = project["project"]["dependencies"]
    assert project["project"]["requires-python"] == ">=3.12"
    assert requirements[2:] == [
        "amplifier-agent @ git+https://github.com/microsoft/amplifier-agent@412cc176cfa5bd219254060ede7f03bbf6578005#subdirectory=packages/python",
        "amplifier-agent-engine @ git+https://github.com/microsoft/amplifier-agent@412cc176cfa5bd219254060ede7f03bbf6578005#subdirectory=packages/engine",
    ]
    assert project["tool"]["hatch"]["metadata"]["allow-direct-references"] is True


def _without_timestamp(result: dict[str, object]) -> dict[str, object]:
    copied = dict(result)
    copied.pop("processed_at")
    return copied