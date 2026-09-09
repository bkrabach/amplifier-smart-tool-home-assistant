"""Contained adapter for the pinned ``amplifier-agent`` runtime.

The package is intentionally imported only while an explicitly selected
interpretation runs. This keeps metadata and deterministic operations free of
its provider initialization costs.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import sys
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from queue import Queue
from tempfile import TemporaryDirectory, gettempdir
from typing import Any

from .types import JsonValue

MODEL_RUNTIME = "amplifier-agent"
DEFAULT_STORAGE_ROOT = Path(gettempdir()) / "ha-analysis-amplifier-agent"
_ENVIRONMENT_LOCK = threading.RLock()
_RETURN_JSON_INSTRUCTION = (
    "Return the requested advisory interpretation as one strict JSON object. "
    "Do not request or use a tool."
)
_SAFE_RUNTIME_ENVIRONMENT = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TZ": "UTC",
}
# These are the sole provider-controlled values that can cross into the agent
# process.  Every other inherited environment value is deliberately excluded,
# including Home Assistant, settings, proxy, and unrelated provider values.
_PROVIDER_ENVIRONMENT_VARIABLES = {
    "anthropic": ("ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL"),
    "azure-openai": (
        "AZURE_OPENAI_API_KEY",
        "AZURE_OPENAI_ENDPOINT",
        "AZURE_TENANT_ID",
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
    ),
    "chat-completions": (
        "CHAT_COMPLETIONS_API_KEY",
        "CHAT_COMPLETIONS_BASE_URL",
    ),
    "gemini": (
        "GOOGLE_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_GEMINI_BASE_URL",
    ),
    "ollama": ("OLLAMA_API_KEY", "OLLAMA_HOST"),
    "openai": ("OPENAI_API_KEY", "OPENAI_BASE_URL"),
    "vllm": ("VLLM_API_KEY", "VLLM_BASE_URL"),
}


class ModelRuntimeError(Exception):
    """A safe, explicit failure that the public runtime maps to C8."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class AmplifierAgentInterpreter:
    """Run one isolated, ephemeral agent turn for ``interpret_evidence`` only."""

    def __init__(
        self,
        *,
        provider: str,
        model: str,
        storage_root: str | Path = DEFAULT_STORAGE_ROOT,
    ) -> None:
        if not isinstance(provider, str) or not provider:
            raise ValueError("A non-empty model provider is required.")
        if not isinstance(model, str) or not model:
            raise ValueError("A non-empty model name is required.")
        self._provider = provider
        self._model = model
        self._storage_root = Path(storage_root)

    def interpret(
        self, selected_evidence: list[JsonValue], interpretation_kind: str
    ) -> JsonValue:
        """Return one provider JSON object, or raise an explicit safe failure."""

        if sys.version_info < (3, 12):
            raise ModelRuntimeError(
                "model_runtime_python_unsupported",
                "The amplifier-agent model runtime requires Python 3.12 or newer.",
            )
        if self._provider not in _PROVIDER_ENVIRONMENT_VARIABLES:
            raise ModelRuntimeError(
                "model_runtime_provider_unsupported",
                "The selected provider is not supported by the contained amplifier-agent runtime.",
            )
        payload = json.dumps(
            {
                "selected_evidence": selected_evidence,
                "interpretation_kind": interpretation_kind,
            },
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )
        with TemporaryDirectory(prefix="ha-analysis-agent-") as temporary_root:
            with _scoped_runtime_environment(self._provider, Path(temporary_root)):
                return _run_async(
                    lambda: self._interpret_async(payload),
                    force_thread=_has_running_event_loop(),
                )

    async def _interpret_async(self, payload: str) -> JsonValue:
        try:
            agent_sdk = _load_agent_sdk()
        except (ImportError, OSError) as error:
            raise ModelRuntimeError(
                "model_runtime_unavailable",
                "The amplifier-agent runtime is unavailable. Reinstall ha-analysis.",
            ) from error

        options = agent_sdk.AgentOptions(
            provider=self._provider,
            model=self._model,
            instructions=_RETURN_JSON_INSTRUCTION,
            tools=[],
            skills=[],
            mcp_servers=[],
            storage=self._storage_root,
            approvals="deny",
            tool_error_policy="stop",
        )
        try:
            async with await agent_sdk.create_agent(options) as agent:
                async with await agent.create_session(
                    agent_sdk.SessionOptions(persistence="ephemeral")
                ) as session:
                    result = await session.run(
                        agent_sdk.TurnInput(content=[agent_sdk.TextPart(payload)])
                    )
        except agent_sdk.AgentError as error:
            raise _agent_failure(error) from error

        if result.state != "success" or result.error is not None:
            raise _agent_failure(result.error)
        text = "".join(
            part.text
            for part in result.content or []
            if isinstance(getattr(part, "text", None), str)
        )
        try:
            value = json.loads(text, parse_constant=_reject_non_json_constant)
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise ModelRuntimeError(
                "model_response_invalid",
                "The model response was not one strict JSON object.",
            ) from error
        if not isinstance(value, dict):
            raise ModelRuntimeError(
                "model_response_invalid",
                "The model response was not one strict JSON object.",
            )
        return value


def _agent_failure(error: Any) -> ModelRuntimeError:
    if getattr(error, "code", None) == "approval_denied":
        return ModelRuntimeError(
            "model_tool_request_denied",
            "The model requested a tool and the request was denied before execution.",
        )
    return ModelRuntimeError(
        "model_agent_failed",
        "The amplifier-agent model runtime failed.",
    )


def _load_agent_sdk() -> Any:
    """Import the dependency at use time, never at module import time."""

    return importlib.import_module("amplifier_agent")


def _reject_non_json_constant(value: str) -> None:
    raise ValueError(f"Non-JSON constant {value!r}")


def _has_running_event_loop() -> bool:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return False
    return True


def _run_async(
    operation: Callable[[], Any], *, force_thread: bool
) -> JsonValue:
    if not force_thread:
        return asyncio.run(operation())

    result: Queue[tuple[bool, object]] = Queue(maxsize=1)

    def run() -> None:
        try:
            result.put((True, asyncio.run(operation())))
        except BaseException as error:
            result.put((False, error))

    thread = threading.Thread(target=run, name="ha-analysis-model-runtime")
    thread.start()
    thread.join()
    success, value = result.get()
    if success:
        return value  # type: ignore[return-value]
    raise value  # type: ignore[misc]


@contextmanager
def _scoped_runtime_environment(provider: str, root: Path) -> Iterator[None]:
    """Give the agent a minimal process environment for construction and turns.

    The process-wide mutation is serialized because the pinned agent snapshots
    ``os.environ`` into its resolved configuration.  ``HOME`` and all XDG
    roots are dedicated temporary locations, while only the selected
    provider's documented connection variables are copied from the parent.
    """

    with _ENVIRONMENT_LOCK:
        roots = {
            "HOME": root / "home",
            "XDG_CACHE_HOME": root / "cache",
            "XDG_CONFIG_HOME": root / "config",
            "XDG_DATA_HOME": root / "data",
            "XDG_STATE_HOME": root / "state",
        }
        for path in roots.values():
            path.mkdir(parents=True, exist_ok=True)
        scoped = {
            **_SAFE_RUNTIME_ENVIRONMENT,
            **{name: str(path) for name, path in roots.items()},
            **{
                name: os.environ[name]
                for name in _PROVIDER_ENVIRONMENT_VARIABLES[provider]
                if name in os.environ
            },
        }
        saved = dict(os.environ)
        os.environ.clear()
        os.environ.update(scoped)
        try:
            yield
        finally:
            os.environ.clear()
            os.environ.update(saved)