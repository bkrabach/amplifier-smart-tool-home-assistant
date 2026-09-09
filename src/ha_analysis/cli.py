#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "click>=8.1",
#   "keyring>=24.0",
#   "amplifier-agent @ git+https://github.com/microsoft/amplifier-agent@412cc176cfa5bd219254060ede7f03bbf6578005#subdirectory=packages/python",
#   "amplifier-agent-engine @ git+https://github.com/microsoft/amplifier-agent@412cc176cfa5bd219254060ede7f03bbf6578005#subdirectory=packages/engine",
# ]
# ///
"""Thin JSON/file adapter for the library-first Home Assistant analysis runtime.

This adapter selects an operation and renders its document. It decides nothing:
target resolution, request selection, redaction, analysis, model invocation,
result construction (C2) and origin normalization, transport selection,
credential input handling, secret-store access and settings persistence (C9)
all live in the library.

The inline script metadata above lets the packaging descriptor's source-tree
recipe (``uv run --no-project`` on this file) resolve the one runtime dependency
for itself, so a clean checkout with no synced environment can still reach an
operating-system secret store. It changes nothing about *when* that dependency
is imported: :mod:`ha_analysis.secret_store` still imports ``keyring`` lazily,
so metadata, help, offline, and model paths never touch it.
"""

from __future__ import annotations

import os
import sys

if __package__ in {None, ""}:  # Supports the descriptor's source-tree invocation.
    sys.path[0] = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

import argparse
import json
from pathlib import Path
from collections.abc import Callable, Sequence
from typing import NoReturn

from ha_analysis.api import AnalysisRuntime
from ha_analysis.amplifier_agent_adapter import AmplifierAgentInterpreter, MODEL_RUNTIME
from ha_analysis.management import ManagementRuntime, serialize_document
from ha_analysis.presentation import render_management_text
from ha_analysis.manifest import load_manifest
from ha_analysis.origins import TRANSPORT_MODES

METADATA_COMMANDS = ("manifest",)
ANALYSIS_COMMANDS = ("offline_analyze", "inspect_live_entities", "interpret_evidence", "check_connection", "find_entities")
MANAGEMENT_COMMANDS = ("setup", "login", "status", "logout")
KNOWN_COMMANDS = METADATA_COMMANDS + ANALYSIS_COMMANDS + ("inspect", "check", "find") + MANAGEMENT_COMMANDS

#: The complete set of tokens ``login`` will tolerate. C9 forbids the credential
#: from ever being a command-line argument, so anything else is refused by name
#: of the rule rather than by quoting what the caller typed.
LOGIN_FORMAT_CHOICES = frozenset({"auto", "text", "json"})
LOGIN_ARGUMENT_REFUSED = (
    "login accepts no credential argument. Supply the token on stdin with "
    "--token-stdin, or run login with no options to be prompted."
)
UNRECOGNIZED_ARGUMENTS = "unrecognized arguments were supplied"
UNRECOGNIZED_COMMAND = (
    "unrecognized command; choose from " + ", ".join(KNOWN_COMMANDS)
)


class _StrictArgumentParser(argparse.ArgumentParser):
    """A parser that never guesses, and optionally never quotes what it was given.

    Two hardenings, both in service of C9's "the credential MUST NOT be accepted
    as a command-line argument":

    * ``allow_abbrev`` is off, so ``--token=SECRET`` and ``--tok=SECRET`` cannot
      be silently matched to ``--token-stdin`` and reported back with the value
      attached ("ignored explicit argument ...");
    * a parser marked ``static_error`` reports only that fixed sentence, so no
      error path can echo a value a caller should never have placed in argv.

    Two further argparse messages quote raw argv and are replaced everywhere for
    the same reason: "unrecognized arguments: ...", the invalid-choice report
    for a *positional*, and invalid values for the management ``--format`` flag.
    """

    static_error: str | None = None
    _ECHOES_ARGV = "unrecognized arguments:"

    def __init__(self, *args: object, **kwargs: object) -> None:
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]

    def _check_value(self, action: argparse.Action, value: object) -> None:
        try:
            super()._check_value(action, value)
        except argparse.ArgumentError:
            if action.dest == "format" and action.choices == ("auto", "text", "json"):
                raise argparse.ArgumentError(
                    action, "format must be one of: auto, text, json"
                ) from None
            if action.option_strings:
                raise
            # A positional's rejected value is raw argv; report the closed
            # choice list instead of quoting what the caller typed.
            raise argparse.ArgumentError(action, UNRECOGNIZED_COMMAND) from None

    def parse_known_args(
        self, args: Sequence[str] | None = None, namespace: argparse.Namespace | None = None
    ) -> tuple[argparse.Namespace, list[str]]:
        """Keep direct parser callers from letting ``--help`` bypass login checks."""

        tokens = list(sys.argv[1:] if args is None else args)
        command = next((token for token in tokens if not token.startswith("-")), None)
        if command == "login" and not _login_argv_is_safe(tokens):
            self.error(LOGIN_ARGUMENT_REFUSED)
        return super().parse_known_args(args, namespace)

    def error(self, message: str) -> NoReturn:
        if self.static_error is not None:
            message = self.static_error
        elif message.startswith(self._ECHOES_ARGV):
            message = UNRECOGNIZED_ARGUMENTS
        super().error(message)


def main(
    argv: list[str] | None = None,
    *,
    runtime: AnalysisRuntime | None = None,
    management: ManagementRuntime | None = None,
    credential_provider: Callable[[], str] | None = None,
) -> int:
    """Adapt CLI input to a runtime; injection is for in-process adapter tests only."""

    tokens = list(sys.argv[1:] if argv is None else argv)
    if tokens and tokens[0] == "control":
        from ha_analysis.control_cli import main as control_main
        return control_main(tokens[1:], prog_name="ha-analysis control")
    parser = _parser()
    _refuse_unsafe_argv(parser, argv)
    args, extra = parser.parse_known_args(argv)
    if extra:
        # Deliberately does not echo the values back: a credential must never be
        # a command-line argument (C9), and a usage error must not reprint one
        # that a caller supplied anyway.
        parser.error(UNRECOGNIZED_ARGUMENTS)
    if args.command == "manifest":
        if args.format != "json":
            parser.error("manifest format must be json")
        print(json.dumps(load_manifest(), sort_keys=True, separators=(",", ":")))
        return 0
    if args.command in MANAGEMENT_COMMANDS:
        return _management(args, parser, management)
    if (
        args.command in {"inspect_live_entities", "inspect", "check", "find"}
        and args.transport_mode is not None
        and args.origin is None
    ):
        # A usage constraint, not a domain decision: the configured origin
        # carries its own transport mode, so overriding one without the other
        # would be ambiguous.
        parser.error("--transport-mode requires --origin")
    if args.command == "interpret_evidence":
        selected_runtime = args.model_runtime
        if selected_runtime == MODEL_RUNTIME and (
            not args.model_provider or not args.model
        ):
            parser.error(
                "--model-runtime amplifier-agent requires --model-provider and --model"
            )
        if selected_runtime is None and (args.model_provider or args.model):
            parser.error("--model-provider and --model require --model-runtime")

    runtime = runtime or _analysis_runtime(args)
    if args.command == "offline_analyze":
        result = runtime.offline_analyze(
            _json_input(args.evidence, args.evidence_file), _json_value(args.request)
        )
    elif args.command in {"inspect_live_entities", "inspect"}:
        result = runtime.inspect_live_entities(
            args.origin, _json_value(args.targets), credential_provider,
            attributes=_json_value(args.attributes) if args.attributes else (),
            include_timestamps=args.include_timestamps,
        )
    elif args.command == "check":
        result = runtime.check_connection(args.origin, credential_provider)
    elif args.command == "find":
        result = runtime.find_entities(args.origin, _json_value(args.request), credential_provider)
    elif args.command == "interpret_evidence":
        result = runtime.interpret_evidence(
            _json_input(args.selected_evidence, args.selected_evidence_file),
            _json_value(args.request),
        )
    else:
        parser.error("a named command is required")
        raise AssertionError("argparse.error must not return")
    print(runtime.serialize_result(result))
    return 1 if result["failures"] else 0


def _refuse_unsafe_argv(parser: argparse.ArgumentParser, argv: list[str] | None) -> None:
    """Refuse dangerous argv shapes before argparse can quote one back.

    argparse reports several errors by embedding the offending token
    ("invalid choice: 'X'", "ignored explicit argument 'X'"). For the one
    command that handles a credential - and for a bare token typed in place of
    a command, which is how a pasted token usually arrives - that is a
    disclosure. Both are decided here, statically, before parsing.
    """

    tokens: Sequence[str] = list(sys.argv[1:] if argv is None else argv)
    command = next((token for token in tokens if not token.startswith("-")), None)
    if command is not None and command not in KNOWN_COMMANDS:
        parser.error(UNRECOGNIZED_COMMAND)
    if command == "login" and not _login_argv_is_safe(tokens):
        parser.error(LOGIN_ARGUMENT_REFUSED)


def _login_argv_is_safe(tokens: Sequence[str]) -> bool:
    """Allow only the credential-free login grammar before argparse sees argv."""

    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in {"login", "-h", "--help", "--token-stdin"}:
            index += 1
            continue
        if token == "--format":
            if index + 1 >= len(tokens) or tokens[index + 1] not in LOGIN_FORMAT_CHOICES:
                return False
            index += 2
            continue
        if token.startswith("--format="):
            if token.removeprefix("--format=") not in LOGIN_FORMAT_CHOICES:
                return False
            index += 1
            continue
        return False
    return True


def _analysis_runtime(args: argparse.Namespace) -> AnalysisRuntime:
    transport_mode = getattr(args, "transport_mode", None)
    model_interpreter = None
    if getattr(args, "model_runtime", None) == MODEL_RUNTIME:
        model_interpreter = AmplifierAgentInterpreter(
            provider=args.model_provider,
            model=args.model,
        )
    return AnalysisRuntime(
        model_interpreter=model_interpreter,
        **({"transport_mode": transport_mode} if transport_mode is not None else {}),
    )


def _management(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    management: ManagementRuntime | None,
) -> int:
    management = management or ManagementRuntime()
    output_format = _management_output_format(args)
    if args.command == "setup":
        document = management.setup_from_input(
            args.origin,
            args.transport_mode,
            interactive=args.interactive,
            non_interactive=args.non_interactive,
            emit_next_step=output_format != "text",
        )
    elif args.command == "login":
        document = management.login(input_mode="stdin" if args.token_stdin else "prompt")
    elif args.command == "status":
        document = management.status()
    elif args.command == "logout":
        document = management.logout()
    else:  # pragma: no cover - argparse restricts the command set.
        parser.error("a named command is required")
        raise AssertionError("argparse.error must not return")
    print(serialize_document(document) if output_format == "json" else render_management_text(document))
    return 0 if document["status"] == "ok" else 1


def _management_output_format(args: argparse.Namespace) -> str:
    if args.format != "auto":
        return args.format
    if (args.command == "setup" and args.non_interactive) or (
        args.command == "login" and args.token_stdin
    ):
        return "json"
    try:
        return "text" if sys.stdin.isatty() and sys.stdout.isatty() else "json"
    except (OSError, UnicodeError):
        return "json"


def _parser() -> argparse.ArgumentParser:
    parser = _StrictArgumentParser(
        prog="ha-analysis",
        description=(
            "Bounded Home Assistant analysis, local connection setup, and status reporting. "
            "Analysis commands emit JSON."
        ),
        epilog=(
            "Quick zero-effect example: ha-analysis offline_analyze --evidence "
            "'{\"example\": true}' --request '{\"analysis_kind\":\"structural_summary\"}'.\n"
            "Direct trusted control: ha-analysis control --help.\n"
            "Documentation: https://github.com/bkrabach/amplifier-smart-tool-home-assistant/"
            "blob/main/docs/usage.md"
        ),
    )
    commands = parser.add_subparsers(dest="command", parser_class=_StrictArgumentParser)
    manifest = commands.add_parser(
        "manifest",
        help="Print packaged metadata only; no Home Assistant or model activity.",
        description="Print the packaged manifest as JSON only. This is local metadata; it does not contact Home Assistant or a model.",
    )
    manifest.add_argument(
        "--format", default="json", choices=("json",), help="Output format: json only (default: json)."
    )

    offline = commands.add_parser(
        "offline_analyze",
        help="[deterministic] Summarize caller-supplied JSON evidence.",
        description=(
            "Produce a deterministic structural summary from caller-supplied JSON. "
            "Use exactly one of --evidence or --evidence-file; stdin is not an input. "
            "It emits JSON and does not contact Home Assistant, a model, or a credential store."
        ),
    )
    _json_or_file(offline, "evidence", "Caller-supplied JSON evidence.")
    offline.add_argument(
        "--request",
        required=True,
        help='JSON request object, for example {"analysis_kind":"structural_summary"}.',
    )

    live = commands.add_parser(
        "inspect_live_entities",
        aliases=["inspect"],
        help="[deterministic] Read selected exact entity IDs.",
        description=(
            "Read only the exact entity IDs supplied in --targets. It uses the configured origin "
            "and its stored credential unless --origin is supplied; --transport-mode requires "
            "--origin. It emits JSON and does not discover an inventory or invoke a model."
        ),
    )
    live.add_argument(
        "--origin",
        help="Home Assistant origin URL. Defaults to the origin recorded by setup.",
    )
    live.add_argument(
        "--transport-mode",
        dest="transport_mode",
        choices=tuple(sorted(TRANSPORT_MODES)),
        help="Transport mode for --origin. Plaintext HTTP requires trusted_local_or_vpn.",
    )
    live.add_argument("--targets", required=True, help="JSON array of exact entity IDs.")
    live.add_argument("--attributes", help="JSON array of selected top-level attribute names.")
    live.add_argument("--include-timestamps", action="store_true", help="Include valid observed timestamps.")

    check = commands.add_parser(
        "check",
        help="[deterministic] Validate the configured Home Assistant API.",
        description=(
            "Make an authenticated, read-only connection check using the configured origin and "
            "stored credential, or an explicitly supplied --origin. --transport-mode requires "
            "--origin. It emits JSON and does not invoke a model."
        ),
    )
    check.add_argument("--origin", help="Home Assistant origin URL. Defaults to setup origin.")
    check.add_argument(
        "--transport-mode",
        dest="transport_mode",
        choices=tuple(sorted(TRANSPORT_MODES)),
        help="Transport mode for --origin; it cannot override the configured origin.",
    )

    find = commands.add_parser(
        "find",
        help="[deterministic] Search consented registry display metadata.",
        description=(
            "Read and locally filter enabled entity-registry display metadata only after the JSON "
            "request explicitly includes inventory_consent: true. It uses the configured origin "
            "and stored credential unless --origin is supplied; --transport-mode requires "
            "--origin. It emits JSON, selects nothing, and invokes no model."
        ),
    )
    find.add_argument("--origin", help="Home Assistant origin URL. Defaults to setup origin.")
    find.add_argument(
        "--transport-mode",
        dest="transport_mode",
        choices=tuple(sorted(TRANSPORT_MODES)),
        help="Transport mode for --origin; it cannot override the configured origin.",
    )
    find.add_argument("--request", required=True, help='JSON discovery request including inventory_consent: true.')

    interpretation = commands.add_parser(
        "interpret_evidence",
        help="[model-backed] Interpret caller-selected redacted evidence.",
        description=(
            "Send caller-selected, redacted evidence to the explicitly selected model provider "
            "for interpretation. Use exactly one of --selected-evidence or --selected-evidence-file; "
            "stdin is not an input. This path does not contact Home Assistant or use tools, and "
            "emits JSON."
        ),
    )
    _json_or_file(interpretation, "selected-evidence", "Caller-selected JSON evidence.")
    interpretation.add_argument(
        "--request",
        required=True,
        help='JSON request object, for example {"interpretation_kind":"advice"}.',
    )
    interpretation.add_argument(
        "--model-runtime",
        choices=(MODEL_RUNTIME,),
        help="Explicit model runtime; requires --model-provider and --model.",
    )
    interpretation.add_argument(
        "--model-provider",
        help="Provider identifier for --model-runtime amplifier-agent; required with that runtime.",
    )
    interpretation.add_argument(
        "--model",
        help="Model identifier for --model-runtime amplifier-agent; required with that runtime.",
    )

    setup = commands.add_parser(
        "setup",
        help="[management] Record the Home Assistant origin and transport mode.",
        description=(
            "Record local normalized origin, transport, and authentication-mode settings. Successful "
            "setup disables existing local control trust, does not accept a token, and does not "
            "contact Home Assistant or a model. Output defaults to auto: text only for terminal "
            "stdin and stdout, otherwise JSON."
        ),
    )
    setup.add_argument(
        "--origin",
        help=(
            "Home Assistant origin URL. Omit it in a terminal to be prompted; "
            "otherwise setup never prompts."
        ),
    )
    _management_format(setup)
    setup_mode = setup.add_mutually_exclusive_group()
    setup_mode.add_argument(
        "--interactive",
        action="store_true",
        help="Prompt on a terminal for a missing origin or an explicit HTTP trust choice.",
    )
    setup_mode.add_argument(
        "--non-interactive",
        action="store_true",
        help="Never prompt; --origin is required.",
    )
    setup.add_argument(
        "--transport-mode",
        dest="transport_mode",
        choices=tuple(sorted(TRANSPORT_MODES)),
        help=(
            "Defaults to https. HTTP requires trusted_local_or_vpn; interactive "
            "setup asks for that explicit choice when this option is omitted."
        ),
    )

    login = commands.add_parser(
        "login",
        help=(
            "[management] Store a long-lived access token in the operating-system "
            "secret store. The token is never a command-line argument."
        ),
        description=(
            "Store an interactively supplied Home Assistant long-lived access token in the approved "
            "operating-system secret store. A successful login disables existing local control trust. "
            "The token is never accepted in argv, and login does not validate it with a server. Create "
            "or revoke tokens separately in Home Assistant Profile Security. Output defaults to auto: "
            "text only for terminal stdin and stdout, otherwise JSON."
        ),
    )
    login.add_argument(
        "--token-stdin",
        dest="token_stdin",
        action="store_true",
        help="Read the token from the first line of stdin instead of prompting.",
    )
    _management_format(login)
    # The one command that handles a credential never quotes what it was given,
    # on any error path, for any reason.
    login.static_error = LOGIN_ARGUMENT_REFUSED  # type: ignore[attr-defined]

    status = commands.add_parser(
        "status",
        help="[management] Report local configuration and credential presence.",
        description=(
            "Read local configuration and the OS credential store to report readiness; it makes no "
            "Home Assistant request. Output defaults to auto: text only for terminal stdin and stdout, "
            "otherwise JSON."
        ),
    )
    _management_format(status)
    logout = commands.add_parser(
        "logout",
        help=(
            "[management] Delete the locally stored token. This performs no "
            "Home Assistant revocation."
        ),
        description=(
            "Delete only the locally stored token and disable local control trust for future calls. "
            "It does not contact Home Assistant, revoke a server-side token, or undo past actions; "
            "revoke a token separately in Home Assistant Profile Security. Output defaults to auto: "
            "text only for terminal stdin and stdout, otherwise JSON."
        ),
    )
    _management_format(logout)
    return parser


def _management_format(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--format",
        choices=("auto", "text", "json"),
        default="auto",
        help="Output format: auto, text, or json (default: auto; auto uses text only when stdin and stdout are terminals).",
    )


def _json_or_file(parser: argparse.ArgumentParser, name: str, help_text: str) -> None:
    destination = name.replace("-", "_")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(f"--{name}", dest=destination, help=help_text)
    group.add_argument(
        f"--{name}-file",
        dest=f"{destination}_file",
        help=f"{help_text.rstrip('.')} from a UTF-8 JSON file (not stdin).",
    )


def _json_input(inline: str | None, file_path: str | None) -> object:
    if file_path is not None:
        try:
            inline = Path(file_path).read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            return None
    return _json_value(inline)


def _json_value(value: str | None) -> object:
    try:
        return json.loads(value) if value is not None else None
    except json.JSONDecodeError:
        return None


if __name__ == "__main__":
    raise SystemExit(main())
