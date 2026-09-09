"""C9 and T10: the durable Linux long-lived-access-token lifecycle.

Every test here is deterministic and offline. No real Home Assistant server and
no real token is used anywhere; the one test that touches a real operating-system
secret store is opt-in, runs in a subprocess, and deletes what it wrote.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import textwrap
import uuid
from pathlib import Path

import pytest

from ha_analysis import cli as cli_module
from ha_analysis import management as management_module
from ha_analysis.api import AnalysisRuntime
from ha_analysis.cli import main as cli_main
from ha_analysis.management import (
    CredentialInputError,
    ManagementRuntime,
    StoredCredentials,
    credential_key,
    serialize_document,
    validate_credential,
    withhold_if_disclosed,
)
from ha_analysis.presentation import render_management_text
from ha_analysis.secret_store import (
    KeyringSecretStore,
    SecretStoreDependencyError,
    SecretStoreOperationError,
    SecretStoreUnavailableError,
    UnsupportedPlatformError,
    approve_backend,
)
from ha_analysis.origins import OriginError, normalize_origin, origin_url
from ha_analysis.settings import SettingsError, settings_path, validate_settings

ROOT = Path(__file__).parents[1]
SENTINEL = "llat_SENTINEL_kQ7x.notARealToken.9ZzP_do_not_store_me"
ROTATED = "llat_ROTATED_mB2v.notARealToken.4WwQ_do_not_store_me"
DOCUMENT_FIELDS = {
    "contract_version",
    "document_kind",
    "operation",
    "status",
    "produced_at",
    "configuration",
    "details",
    "notices",
    "failures",
}
ANALYSIS_ONLY_FIELDS = {
    "execution_class",
    "evidence_sources",
    "request_scope",
    "output",
    "redaction",
    "warnings",
    "requested_targets",
    "target_resolution",
}


class InMemorySecretStore:
    """A stand-in for an approved store; it never reaches the real keyring."""

    def __init__(self, *, backend: str = "test.ApprovedStore") -> None:
        self.entries: dict[str, str] = {}
        self.backend = backend
        self.writes: list[str] = []

    def describe(self) -> str:
        return self.backend

    def set_credential(self, key: str, credential: str) -> None:
        self.writes.append(key)
        self.entries[key] = credential

    def get_credential(self, key: str) -> str | None:
        return self.entries.get(key)

    def has_credential(self, key: str) -> bool:
        return key in self.entries

    def delete_credential(self, key: str) -> bool:
        return self.entries.pop(key, None) is not None


class UnavailableSecretStore(InMemorySecretStore):
    """No approved backend exists, so every operation fails closed."""

    def describe(self) -> str:
        raise SecretStoreUnavailableError(
            "The active keyring backend is not an approved operating-system secret store."
        )

    def get_credential(self, key: str) -> str | None:
        raise SecretStoreUnavailableError("No approved operating-system secret store is available.")

    def has_credential(self, key: str) -> bool:
        raise SecretStoreUnavailableError("No approved operating-system secret store is available.")

    def delete_credential(self, key: str) -> bool:
        raise SecretStoreUnavailableError("No approved operating-system secret store is available.")

    def set_credential(self, key: str, credential: str) -> None:  # pragma: no cover - guard
        raise AssertionError("An unavailable store must never be written to.")


class RefusingSecretStore(InMemorySecretStore):
    def set_credential(self, key: str, credential: str) -> None:
        raise SecretStoreOperationError("The secret store rejected the write.")


class DisclosingSecretStore(InMemorySecretStore):
    """A store whose own description would drag the credential into the document."""

    def __init__(self, credential: str) -> None:
        super().__init__(backend=f"test.Store<{credential}>")


class FakeReader:
    def __init__(self, responses: dict[str, object]) -> None:
        self.responses = responses
        self.calls: list[tuple[dict[str, object], str, str]] = []

    def read_entity(self, origin: dict[str, object], entity_id: str, credential: str) -> object:
        self.calls.append((origin, entity_id, credential))
        return self.responses[entity_id]


def _runtime(config_home: Path, store: InMemorySecretStore | None = None) -> ManagementRuntime:
    return ManagementRuntime(secret_store=store or InMemorySecretStore(), config_home=config_home)


def _configured(config_home: Path, store: InMemorySecretStore, origin: str = "https://ha.example:8123") -> ManagementRuntime:
    runtime = _runtime(config_home, store)
    assert runtime.setup(origin)["status"] == "ok"
    return runtime


def _without_time(document: dict[str, object]) -> dict[str, object]:
    trimmed = dict(document)
    trimmed.pop("produced_at")
    return trimmed


def _comparable(document: dict[str, object]) -> dict[str, object]:
    trimmed = _without_time(document)
    details = dict(trimmed.get("details") or {})
    details.pop("settings_path", None)
    trimmed["details"] = details
    return trimmed


def _integers(value: object) -> list[int]:
    if isinstance(value, bool):
        return []
    if isinstance(value, int):
        return [value]
    if isinstance(value, dict):
        return [item for nested in value.values() for item in _integers(nested)]
    if isinstance(value, list):
        return [item for nested in value for item in _integers(nested)]
    return []


def _files_containing(root: Path, needle: str) -> list[Path]:
    found: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            if needle in path.read_bytes().decode("utf-8", errors="ignore"):
                found.append(path)
        except OSError:  # pragma: no cover - unreadable file
            continue
    return found


# --------------------------------------------------------------------------
# C9: library-first management operations with equivalent CLI behavior
# --------------------------------------------------------------------------


def test_c9_every_management_operation_is_library_first_with_equivalent_cli(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    library_home = tmp_path / "library"
    cli_home = tmp_path / "cli"
    library_store = InMemorySecretStore()
    cli_store = InMemorySecretStore()
    library = _runtime(library_home, library_store)
    cli_runtime = _runtime(cli_home, cli_store)

    library_documents = [
        library.setup("https://ha.example:8123", "https"),
        library.login(lambda: SENTINEL),
        library.status(),
        library.logout(),
    ]
    invocations = [
        ["setup", "--origin", "https://ha.example:8123", "--transport-mode", "https"],
        ["login", "--token-stdin"],
        ["status"],
        ["logout"],
    ]
    cli_documents: list[dict[str, object]] = []
    for argv in invocations:
        if argv[0] == "login":
            sys.stdin = io.StringIO(f"{SENTINEL}\n")  # noqa: SIM115 - restored below
        try:
            exit_code = cli_main(argv, management=cli_runtime)
        finally:
            sys.stdin = sys.__stdin__
        assert exit_code == 0
        cli_documents.append(json.loads(capsys.readouterr().out))

    for library_document, cli_document in zip(library_documents, cli_documents, strict=True):
        # The settings path is the one honest difference: two separate homes.
        assert _comparable(cli_document) == _comparable(dict(library_document))
    # The settings each path wrote are byte-identical, so the CLI decided nothing.
    assert settings_path(library_home).read_bytes() == settings_path(cli_home).read_bytes()
    assert set(library_store.entries) == set(cli_store.entries)


def test_c9_a_management_document_is_never_an_analysis_result(tmp_path: Path) -> None:
    store = InMemorySecretStore()
    runtime = _configured(tmp_path, store)
    documents = [
        runtime.setup("https://ha.example:8123"),
        runtime.login(lambda: SENTINEL),
        runtime.status(),
        runtime.logout(),
    ]
    for document in documents:
        assert set(document) == DOCUMENT_FIELDS
        assert not ANALYSIS_ONLY_FIELDS & set(document)
        assert document["document_kind"] == "management"
        assert document["contract_version"] == "ha-analysis.v1"
        assert document["operation"] in {"setup", "login", "status", "logout"}
        assert document["operation"] not in {
            "offline_analyze",
            "inspect_live_entities",
            "interpret_evidence",
        }
        # No management document may claim to be observed Home Assistant evidence.
        assert "observed_home_assistant" not in json.dumps(document)
        json.loads(serialize_document(document))


def test_c9_a_document_outside_the_closed_schema_is_refused(tmp_path: Path) -> None:
    document = _runtime(tmp_path).status()
    smuggled = dict(document)
    smuggled["extra"] = SENTINEL
    with pytest.raises(ValueError):
        serialize_document(smuggled)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# C9: the credential is never a command-line argument
# --------------------------------------------------------------------------


def test_c9_login_accepts_no_credential_argument() -> None:
    parser = cli_module._parser()
    subcommands = next(
        action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
    )
    assert set(subcommands.choices) == {
        "manifest",
        "offline_analyze",
        "inspect_live_entities",
        "inspect",
        "interpret_evidence",
        "check",
        "find",
        "setup",
        "login",
        "status",
        "logout",
    }
    login = subcommands.choices["login"]
    value_taking = [
        action
        for action in login._actions
        if not isinstance(action, argparse._HelpAction)
        and action.nargs != 0
        and action.dest != "format"
    ]
    assert value_taking == [], "login must accept no value-bearing argument"

    for argv in (["login", SENTINEL], ["login", "--token", SENTINEL], ["login", "--token-stdin", SENTINEL]):
        completed = _cli(*argv)
        assert completed.returncode == 2
        assert completed.stdout == ""
        # The usage error must not reprint a value the caller should never have
        # placed in argv in the first place.
        assert SENTINEL not in completed.stderr


#: Every argv shape that carries a value into a credential-handling surface.
#: ``--token-stdin=X`` is the exact regression: argparse answered it with
#: "ignored explicit argument 'X'", printing the whole secret to stderr. The
#: abbreviated forms are the same defect reached through prefix matching, which
#: silently resolved ``--tok=X`` to ``--token-stdin``.
DANGEROUS_ARGV: tuple[tuple[str, ...], ...] = (
    ("login", "--format={secret}"),
    ("login", "--format", "{secret}"),
    ("login", "--form={secret}"),
    ("login", "--format=json={secret}"),
    ("login", "--token-stdin={secret}"),
    ("login", "--help", "--format={secret}"),
    ("login", "--format", "json", "{secret}"),
    ("login", "--token-stdin={secret}"),
    ("login", "--token={secret}"),
    ("login", "--token-std={secret}"),
    ("login", "--tok={secret}"),
    ("login", "--t={secret}"),
    ("login", "--token-stdin", "{secret}"),
    ("login", "--token-stdin", "--token={secret}"),
    ("login", "--token", "{secret}"),
    ("login", "{secret}"),
    ("login", "-t{secret}"),
    ("login", "--unknown-option={secret}"),
    ("login", "--token-stdin={secret}", "--token-stdin"),
    ("{secret}",),
    ("--token={secret}",),
    ("--token-stdin={secret}",),
    ("setup", "--origin", "https://ha.example:8123", "--token={secret}"),
    ("status", "--token={secret}"),
    ("logout", "--token-stdin={secret}"),
)


@pytest.mark.parametrize("template", DANGEROUS_ARGV, ids=lambda argv: " ".join(argv))
def test_no_argv_shape_can_make_the_cli_echo_a_credential(template: tuple[str, ...]) -> None:
    """REGRESSION: the parser must never quote a value back on any error path."""

    argv = [token.format(secret=SENTINEL) for token in template]
    completed = _cli(*argv)
    assert completed.returncode == 2, completed.stderr
    assert SENTINEL not in completed.stdout
    assert SENTINEL not in completed.stderr
    # Not even a fragment: argparse truncates nothing, but a future sanitizer
    # that only trimmed the value would still be a disclosure.
    for fragment in (SENTINEL[:16], SENTINEL[-16:], SENTINEL[8:24]):
        assert fragment not in completed.stdout + completed.stderr
    assert "error" in completed.stderr


@pytest.mark.parametrize("template", DANGEROUS_ARGV, ids=lambda argv: " ".join(argv))
def test_the_parser_alone_echoes_no_credential_without_the_pre_scan(
    template: tuple[str, ...], capsys: pytest.CaptureFixture[str]
) -> None:
    """The hardening holds even when the parser is driven directly.

    ``main`` refuses these shapes before argparse sees them, but that guard is
    one layer. This exercises the parser on its own, which is what any other
    caller of ``_parser()`` would get.
    """

    argv = [token.format(secret=SENTINEL) for token in template]
    with pytest.raises(SystemExit) as raised:
        cli_module._parser().parse_args(argv)
    assert raised.value.code == 2
    captured = capsys.readouterr()
    assert SENTINEL not in captured.out + captured.err


def test_login_is_immune_to_prefix_abbreviation() -> None:
    """``--tok=X`` must not resolve to ``--token-stdin`` and quote X back."""

    parser = cli_module._parser()
    assert parser.allow_abbrev is False
    subcommands = next(
        action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
    )
    for name, subparser in subcommands.choices.items():
        assert subparser.allow_abbrev is False, name
    assert subcommands.choices["login"].static_error == cli_module.LOGIN_ARGUMENT_REFUSED


@pytest.mark.parametrize(
    "argv",
    [
        ("login", "--format", "auto", "--help"),
        ("login", "--format=json", "--help"),
        ("login", "--format", "text", "--help"),
        ("login", "--format=json", "--token-stdin"),
    ],
)
def test_login_argv_scanner_allows_only_exact_format_values(argv: tuple[str, ...]) -> None:
    completed = _cli(*argv)
    assert completed.returncode in {0, 1}
    assert completed.returncode != 2, completed.stderr


@pytest.mark.parametrize("command", ("setup", "login", "status", "logout"))
@pytest.mark.parametrize(
    "format_argument",
    (("--format", SENTINEL), (f"--format={SENTINEL}",), (f"--format={SENTINEL}", "--help")),
)
def test_management_format_errors_never_echo_a_pasted_token(
    command: str, format_argument: tuple[str, ...], capsys: pytest.CaptureFixture[str]
) -> None:
    argv = [command, *format_argument]
    completed = _cli(*argv)
    assert completed.returncode == 2
    assert SENTINEL not in completed.stdout + completed.stderr
    expected = (
        cli_module.LOGIN_ARGUMENT_REFUSED
        if command == "login"
        else "format must be one of: auto, text, json"
    )
    assert expected in completed.stderr

    with pytest.raises(SystemExit) as raised:
        cli_module._parser().parse_args(argv)
    assert raised.value.code == 2
    captured = capsys.readouterr()
    assert SENTINEL not in captured.out + captured.err


def test_noncredential_parser_errors_stay_informative() -> None:
    """Hardening the credential surface must not blind every other message."""

    for argv, expected in (
        (["manifest", "--format", "text"], "invalid choice: 'text'"),
        (
            ["setup", "--origin", "https://ha.example:8123", "--transport-mode", "bogus"],
            "invalid choice: 'bogus'",
        ),
        (["offline_analyze", "--request", "{}"], "one of the arguments"),
        (["inspect_live_entities", "--targets"], "expected one argument"),
    ):
        completed = _cli(*argv)
        assert completed.returncode == 2
        assert expected in completed.stderr, completed.stderr

    # An unknown command names the closed choice list, all of it our own text.
    unknown = _cli("__not_a_command__")
    assert unknown.returncode == 2
    assert "unrecognized command" in unknown.stderr
    assert "__not_a_command__" not in unknown.stderr
    for command in cli_module.KNOWN_COMMANDS:
        assert command in unknown.stderr


def test_c9_login_reads_stdin_or_a_hidden_prompt_and_never_blocks_without_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = InMemorySecretStore()
    runtime = _configured(tmp_path, store)

    monkeypatch.setattr(sys, "stdin", io.StringIO(f"{SENTINEL}\n"))
    assert runtime.login(input_mode="stdin")["status"] == "ok"
    assert list(store.entries.values()) == [SENTINEL]

    # A non-interactive prompt must refuse rather than wait on input nobody can give.
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    refused = runtime.login(input_mode="prompt")
    assert refused["status"] == "failed"
    assert [item["code"] for item in refused["failures"]] == ["credential_input_unavailable"]

    class Terminal(io.StringIO):
        def isatty(self) -> bool:
            return True

    prompts: list[str] = []
    monkeypatch.setattr(sys, "stdin", Terminal(""))
    monkeypatch.setattr(
        management_module.getpass, "getpass", lambda prompt: prompts.append(prompt) or ROTATED
    )
    prompted = runtime.login(input_mode="prompt")
    assert prompted["status"] == "ok"
    assert prompts and "hidden" in prompts[0]
    assert list(store.entries.values()) == [ROTATED]


@pytest.mark.parametrize(
    ("supplied", "code"),
    [
        ("", "empty_credential"),
        ("x" * 4097, "credential_too_long"),
        ("abc\ndef", "invalid_credential"),
        ("abc def", "invalid_credential"),
        ("abc\tdef", "invalid_credential"),
        ("tokén", "invalid_credential"),
        ("abc\x00def", "invalid_credential"),
        (b"bytes", "invalid_credential"),
    ],
)
def test_c9_credential_validation_refuses_without_quoting_the_value(
    supplied: object, code: str
) -> None:
    with pytest.raises(CredentialInputError) as raised:
        validate_credential(supplied)
    assert raised.value.code == code
    if isinstance(supplied, str) and supplied:
        assert supplied not in raised.value.message
        assert str(len(supplied)) not in raised.value.message


# --------------------------------------------------------------------------
# C9: approved store only, no fallback, nothing written to any file
# --------------------------------------------------------------------------


def test_c9_login_fails_explicitly_and_writes_no_file_when_no_store_is_available(
    tmp_path: Path, isolated_environment: Path
) -> None:
    runtime = _configured(tmp_path, UnavailableSecretStore())
    document = runtime.login(lambda: SENTINEL)
    assert document["status"] == "failed"
    assert [item["code"] for item in document["failures"]] == ["secret_store_unavailable"]
    assert "credential_not_stored" in {item["code"] for item in document["notices"]}

    for root in (tmp_path, isolated_environment, settings_path(tmp_path).parent):
        assert _files_containing(root, SENTINEL) == []
    assert SENTINEL not in json.dumps(dict(os.environ))


def test_c9_login_fails_explicitly_when_an_approved_store_rejects_the_write(
    tmp_path: Path,
) -> None:
    runtime = _configured(tmp_path, RefusingSecretStore())
    document = runtime.login(lambda: SENTINEL)
    assert document["status"] == "failed"
    assert [item["code"] for item in document["failures"]] == ["secret_store_operation_failed"]
    assert _files_containing(tmp_path, SENTINEL) == []


def test_t10_only_operating_system_backends_are_approved() -> None:
    def backend(module: str, name: str, **attributes: object) -> object:
        kind = type(name, (), dict(attributes))
        kind.__module__ = module
        return kind()

    for module, name in (
        ("keyring.backends.SecretService", "Keyring"),
        ("keyring.backends.libsecret", "Keyring"),
        ("keyring.backends.kwallet", "DBusKeyring"),
        ("keyring.backends.kwallet", "DBusKeyringKWallet4"),
    ):
        assert approve_backend(backend(module, name)) == (module, name)

    for module, name in (
        ("keyring.backends.fail", "Keyring"),
        ("keyring.backends.null", "Keyring"),
        ("keyrings.alt.file", "PlaintextKeyring"),
        ("keyrings.alt.file_base", "Keyring"),
        ("keyring.backends.Windows", "WinVaultKeyring"),
        ("keyring.backends.macOS", "Keyring"),
        ("attacker.module", "Keyring"),
    ):
        with pytest.raises(SecretStoreUnavailableError):
            approve_backend(backend(module, name))

    approved = backend("keyring.backends.SecretService", "Keyring")
    plaintext = backend("keyrings.alt.file", "PlaintextKeyring")
    chainer = backend("keyring.backends.chainer", "ChainerBackend", backends=[approved])
    assert approve_backend(chainer) == ("keyring.backends.chainer", "ChainerBackend")
    # One unapproved member makes the whole chain unapproved: a chainer may
    # serve any single request from any member.
    mixed = backend("keyring.backends.chainer", "ChainerBackend", backends=[approved, plaintext])
    with pytest.raises(SecretStoreUnavailableError):
        approve_backend(mixed)
    empty = backend("keyring.backends.chainer", "ChainerBackend", backends=[])
    with pytest.raises(SecretStoreUnavailableError):
        approve_backend(empty)

    deep: object = approved
    for _ in range(12):
        deep = backend("keyring.backends.chainer", "ChainerBackend", backends=[deep])
    with pytest.raises(SecretStoreUnavailableError):
        approve_backend(deep)


def test_t10_secret_store_refuses_a_missing_keyring_and_a_non_linux_platform(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken() -> object:
        raise RuntimeError("the backend could not be resolved")

    with pytest.raises(SecretStoreUnavailableError) as unavailable:
        KeyringSecretStore(backend_factory=broken).describe()
    assert unavailable.value.code == "secret_store_unavailable"

    # An absent dependency is diagnosed as an absent dependency, not disguised
    # as "this computer has no secret store" - the two need different fixes.
    monkeypatch.setitem(sys.modules, "keyring", None)
    with pytest.raises(SecretStoreDependencyError) as missing:
        KeyringSecretStore().describe()
    assert missing.value.code == "secret_store_dependency_missing"
    assert isinstance(missing.value, SecretStoreUnavailableError), "still fail-closed"
    monkeypatch.undo()

    with pytest.raises(UnsupportedPlatformError) as unsupported:
        KeyringSecretStore(
            backend_factory=lambda: pytest.fail("no backend may be resolved off Linux"),
            platform="darwin",
        ).describe()
    assert unsupported.value.code == "unsupported_platform"
    for platform in ("win32", "darwin", "freebsd13"):
        with pytest.raises(UnsupportedPlatformError):
            KeyringSecretStore(backend_factory=lambda: None, platform=platform).set_credential(
                "key", SENTINEL
            )


def test_t10_a_backend_exception_never_carries_the_credential_out() -> None:
    class Leaky:
        def set_password(self, service: str, key: str, credential: str) -> None:
            raise RuntimeError(f"backend rejected {credential}")

        def get_password(self, service: str, key: str) -> str | None:
            return None

    leaky = Leaky()
    leaky.__class__.__module__ = "keyring.backends.SecretService"
    leaky.__class__.__name__ = "Keyring"
    store = KeyringSecretStore(backend_factory=lambda: leaky, platform="linux")
    with pytest.raises(SecretStoreOperationError) as raised:
        store.set_credential("key", SENTINEL)
    error = raised.value
    assert SENTINEL not in str(error)
    assert error.__cause__ is None and error.__context__ is None


# --------------------------------------------------------------------------
# C9: no credential in any document, log, or diagnostic
# --------------------------------------------------------------------------


def test_c9_no_management_document_carries_the_credential_or_a_derivative(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store = InMemorySecretStore()
    runtime = _configured(tmp_path, store)
    documents = [
        runtime.login(lambda: SENTINEL),
        runtime.status(),
        runtime.login(lambda: ROTATED),
        runtime.logout(),
        runtime.status(),
    ]
    fragments = [SENTINEL, ROTATED, SENTINEL[:12], SENTINEL[-12:], SENTINEL[10:22]]
    for document in documents:
        rendered = serialize_document(document)
        for fragment in fragments:
            assert fragment not in rendered
        # Not even the length is disclosed: no number in the document equals it.
        assert len(SENTINEL) not in _integers(document)
        assert len(ROTATED) not in _integers(document)
        for diagnostic in [*document["notices"], *document["failures"]]:
            for fragment in fragments:
                assert fragment not in diagnostic["message"] and fragment not in diagnostic["code"]
    captured = capsys.readouterr()
    assert SENTINEL not in captured.out + captured.err
    assert ROTATED not in captured.out + captured.err


def test_c9_a_document_that_would_disclose_the_credential_is_withheld(tmp_path: Path) -> None:
    store = DisclosingSecretStore(SENTINEL)
    runtime = _configured(tmp_path, store)
    document = runtime.login(lambda: SENTINEL)
    assert document["status"] == "withheld"
    assert [item["code"] for item in document["failures"]] == ["credential_disclosure_prevented"]
    assert SENTINEL not in serialize_document(document)
    assert document["configuration"] is None and document["details"] == {}
    assert "storage_outcome_unreported" in {item["code"] for item in document["notices"]}

    safe = _configured(tmp_path / "clean", InMemorySecretStore()).status()
    assert withhold_if_disclosed(safe, SENTINEL) is safe


# --------------------------------------------------------------------------
# C9: persisted settings hold only origin, transport mode, and auth mode
# --------------------------------------------------------------------------


def test_c9_settings_hold_only_the_three_permitted_fields_and_are_owner_only(
    tmp_path: Path,
) -> None:
    runtime = _configured(tmp_path, InMemorySecretStore())
    assert runtime.login(lambda: SENTINEL)["status"] == "ok"
    path = settings_path(tmp_path)
    document = json.loads(path.read_text())
    assert set(document) == {"origin", "transport_mode", "auth_mode"}
    assert set(document["origin"]) == {"scheme", "host", "port"}
    assert document["auth_mode"] == "long_lived_access_token"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert _files_containing(tmp_path, SENTINEL) == []
    assert list(path.parent.iterdir()) == [path], "no temporary file may survive a write"


def test_c9_setup_applies_the_same_transport_rule_as_a_live_read(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path)
    rejected = runtime.setup("http://ha.local:8123")
    assert rejected["status"] == "failed"
    assert [item["code"] for item in rejected["failures"]] == ["insecure_transport_rejected"]
    assert not settings_path(tmp_path).exists(), "a refused setup must persist nothing"

    live = AnalysisRuntime().inspect_live_entities(
        "http://ha.local:8123", ["light.kitchen"], lambda: "credential"
    )
    assert [item["code"] for item in live["failures"]] == ["insecure_transport_rejected"]

    accepted = runtime.setup("http://ha.local:8123", "trusted_local_or_vpn")
    assert accepted["status"] == "ok"
    assert accepted["configuration"]["transport_mode"] == "trusted_local_or_vpn"
    assert "plaintext_transport_selected" in {item["code"] for item in accepted["notices"]}
    assert json.loads(settings_path(tmp_path).read_text())["transport_mode"] == "trusted_local_or_vpn"


class InteractiveText(io.StringIO):
    """A deterministic terminal substitute for setup adapter tests."""

    def isatty(self) -> bool:
        return True


def test_management_text_presents_success_failure_and_unknown_states_safely(
    tmp_path: Path,
) -> None:
    store = InMemorySecretStore()
    runtime = _runtime(tmp_path, store)

    setup = runtime.setup("https://ha.example:8123")
    login = runtime.login(lambda: SENTINEL)
    status = runtime.status()
    logout = runtime.logout()
    for document, heading in (
        (setup, "Setup saved."),
        (login, "Token stored in OS secret store."),
        (status, "Status (local configuration)"),
        (logout, "Token deleted from OS secret store."),
    ):
        rendered = render_management_text(document)
        assert rendered.startswith(heading)
        assert "no connection test" in rendered.lower()
        assert SENTINEL not in rendered
        assert all(
            len(line) <= 78
            for line in rendered.splitlines()
            if not line.startswith(("Next:", "Then run:"))
        )

    missing = render_management_text(_configured(tmp_path / "missing", InMemorySecretStore()).status())
    assert "Token: not stored." in missing
    assert missing.endswith("Next: ha-analysis login")
    unknown = render_management_text(_configured(tmp_path / "unknown", UnavailableSecretStore()).status())
    assert "Token: unknown (OS secret store unavailable)." in unknown
    assert "Token: not stored." not in unknown
    assert "Notice [secret_store_unavailable]:" in unknown
    assert "active keyring backend is not an" in unknown
    assert "approved operating-system secret store." in unknown

    unconfigured = render_management_text(_runtime(tmp_path / "unconfigured").status())
    assert "Token: not checked (no configured server)." in unconfigured
    assert unconfigured.endswith(
        "Next: ha-analysis setup --origin https://your-home-assistant:8123"
    )

    for document, heading in (
        (_runtime(tmp_path / "setup-failure").setup("not a URL"), "Setup failed."),
        (_runtime(tmp_path / "login-failure").login(lambda: SENTINEL), "Login failed."),
        (_runtime(tmp_path / "logout-failure").logout(), "Logout failed."),
    ):
        assert render_management_text(document).startswith(heading)


def test_management_text_escapes_control_characters_and_preserves_diagnostic_messages(
    tmp_path: Path,
) -> None:
    document = _configured(tmp_path, InMemorySecretStore()).status()
    document["configuration"]["origin_url"] = "https://ha.example/\x1b[2J"
    document["notices"].append(
        {"code": "unknown\x1b[2J", "message": f"{SENTINEL}\x1b[2J"}
    )

    rendered = render_management_text(document)
    assert "\x1b" not in rendered
    assert "\\x1b[2J" in rendered
    assert SENTINEL in rendered
    assert "unknown\\x1b[2J" in rendered

    smuggled = dict(document)
    smuggled["extra"] = "ignored"
    with pytest.raises(ValueError):
        render_management_text(smuggled)  # type: ignore[arg-type]


def test_management_text_preserves_notices_and_cleanup_advice(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, InMemorySecretStore())
    assert runtime.setup("https://old.example:8123")["status"] == "ok"
    runtime.login(lambda: SENTINEL)
    changed = runtime.setup("https://new.example:8123")
    rendered = render_management_text(changed)
    assert "https://old.example:8123" in rendered
    assert "configure that origin again and" in rendered
    assert "run logout." in rendered

    withheld = runtime.login(lambda: SENTINEL)
    withheld["status"] = "withheld"
    withheld["notices"].append(
        {"code": "extra_notice", "message": "The original notice remains visible."}
    )
    rendered_withheld = render_management_text(withheld)
    assert "Notice [extra_notice]: The original notice remains visible." in rendered_withheld
    assert rendered_withheld.endswith("Next: ha-analysis status")

    failed = _runtime(tmp_path / "failed").login(lambda: SENTINEL)
    failed["notices"].append(
        {"code": "extra_notice", "message": "A failed operation keeps this notice."}
    )
    assert "Notice [extra_notice]: A failed operation keeps this notice." in render_management_text(
        failed
    )


def test_https_remains_encrypted_when_trusted_transport_mode_is_selected(tmp_path: Path) -> None:
    document = _runtime(tmp_path).setup("https://ha.example:8123", "trusted_local_or_vpn")
    rendered = render_management_text(document)
    assert "Transport: HTTPS (encrypted)." in rendered
    assert "HTTP (unencrypted" not in rendered


@pytest.mark.parametrize(
    ("argv", "stdin_tty", "stdout_tty", "expected"),
    [
        (["setup", "--origin", "https://ha.example:8123"], True, True, "text"),
        (["setup", "--origin", "https://ha.example:8123"], False, True, "json"),
        (["setup", "--origin", "https://ha.example:8123"], True, False, "json"),
        (
            ["setup", "--origin", "https://ha.example:8123", "--non-interactive"],
            True,
            True,
            "json",
        ),
        (["login"], True, True, "text"),
        (["login", "--token-stdin"], True, True, "json"),
        (["status"], True, True, "text"),
        (["logout"], True, True, "text"),
    ],
)
def test_management_auto_format_uses_both_standard_streams(
    monkeypatch: pytest.MonkeyPatch,
    argv: list[str],
    stdin_tty: bool,
    stdout_tty: bool,
    expected: str,
) -> None:
    class Stream(io.StringIO):
        def __init__(self, is_tty: bool) -> None:
            super().__init__()
            self._is_tty = is_tty

        def isatty(self) -> bool:
            return self._is_tty

    monkeypatch.setattr(sys, "stdin", Stream(stdin_tty))
    monkeypatch.setattr(sys, "stdout", Stream(stdout_tty))
    args = cli_module._parser().parse_args(argv)
    assert cli_module._management_output_format(args) == expected


def test_management_auto_format_falls_back_to_json_when_tty_query_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BrokenStream(io.StringIO):
        def isatty(self) -> bool:
            raise OSError("not available")

    monkeypatch.setattr(sys, "stdin", BrokenStream())
    monkeypatch.setattr(sys, "stdout", InteractiveText())
    args = cli_module._parser().parse_args(["status"])
    assert cli_module._management_output_format(args) == "json"


def test_explicit_management_format_overrides_redirects_without_changing_effects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    text_store = InMemorySecretStore()
    json_store = InMemorySecretStore()
    text_runtime = _runtime(tmp_path / "text", text_store)
    json_runtime = _runtime(tmp_path / "json", json_store)
    text_stdout = io.StringIO()
    json_stdout = InteractiveText()
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    monkeypatch.setattr(sys, "stdout", text_stdout)
    assert cli_main(
        [
            "setup",
            "--origin",
            "https://ha.example:8123",
            "--non-interactive",
            "--format",
            "text",
        ],
        management=text_runtime,
    ) == 0
    monkeypatch.setattr(sys, "stdout", json_stdout)
    assert cli_main(
        [
            "setup",
            "--origin",
            "https://ha.example:8123",
            "--non-interactive",
            "--format=json",
        ],
        management=json_runtime,
    ) == 0

    assert text_stdout.getvalue().startswith("Setup saved.")
    assert json.loads(json_stdout.getvalue())["status"] == "ok"
    assert settings_path(tmp_path / "text").read_bytes() == settings_path(tmp_path / "json").read_bytes()
    assert text_store.entries == json_store.entries == {}


def test_noninteractive_auto_format_is_one_json_document(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stdout = io.StringIO()
    monkeypatch.setattr(sys, "stdin", InteractiveText())
    monkeypatch.setattr(sys, "stdout", stdout)
    assert cli_main(
        [
            "setup",
            "--origin",
            "https://ha.example:8123",
            "--non-interactive",
        ],
        management=_runtime(tmp_path, InMemorySecretStore()),
    ) == 0
    assert stdout.getvalue().count("\n") == 1
    assert json.loads(stdout.getvalue())["status"] == "ok"


def test_text_setup_does_not_duplicate_the_library_next_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stdout = InteractiveText()
    stderr = InteractiveText()
    monkeypatch.setattr(sys, "stdin", InteractiveText("https://ha.example:8123\n"))
    monkeypatch.setattr(sys, "stdout", stdout)
    monkeypatch.setattr(sys, "stderr", stderr)

    assert cli_main(["setup", "--format", "text"], management=_runtime(tmp_path)) == 0
    assert stdout.getvalue().count("ha-analysis login") == 1
    assert stdout.getvalue().count("paste a token into chat or an argument.") == 1
    assert "Next step:" not in stderr.getvalue()


def test_setup_without_origin_uses_a_tty_prompt_and_keeps_json_on_stdout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runtime = _runtime(tmp_path, InMemorySecretStore())
    prompt_output = InteractiveText()
    monkeypatch.setattr(sys, "stdin", InteractiveText("https://ha.example:8123\n"))
    monkeypatch.setattr(sys, "stderr", prompt_output)

    assert cli_main(["setup"], management=runtime) == 0
    rendered = capsys.readouterr().out
    assert rendered.count("\n") == 1
    document = json.loads(rendered)
    assert document["status"] == "ok"
    assert document["configuration"]["origin_url"] == "https://ha.example:8123"
    assert "Setup is local only" in prompt_output.getvalue()
    assert "ha-analysis login" in prompt_output.getvalue()
    assert "{" not in prompt_output.getvalue()


def test_setup_interactive_can_write_json_to_redirected_stdout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = _runtime(tmp_path, InMemorySecretStore())
    stdout = io.StringIO()
    stderr = InteractiveText()
    monkeypatch.setattr(sys, "stdin", InteractiveText("https://ha.example:8123\n"))
    monkeypatch.setattr(sys, "stderr", stderr)
    monkeypatch.setattr(sys, "stdout", stdout)

    assert cli_main(["setup", "--interactive"], management=runtime) == 0
    assert json.loads(stdout.getvalue())["status"] == "ok"
    assert "Home Assistant URL:" in stderr.getvalue()


@pytest.mark.parametrize(
    ("argv", "stdin_tty", "stderr_tty"),
    [
        (["setup"], False, True),
        (["setup"], True, False),
        (["setup", "--interactive"], False, True),
        (["setup", "--interactive"], True, False),
    ],
)
def test_setup_requires_stdin_and_stderr_ttys_before_prompting_or_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    argv: list[str],
    stdin_tty: bool,
    stderr_tty: bool,
) -> None:
    class InputThatMustNotBeRead(io.StringIO):
        def isatty(self) -> bool:
            return stdin_tty

        def readline(self, *args: object, **kwargs: object) -> str:
            raise AssertionError("setup must not read unavailable interactive input")

    class PromptOutput(io.StringIO):
        def isatty(self) -> bool:
            return stderr_tty

    runtime = _runtime(tmp_path, InMemorySecretStore())
    monkeypatch.setattr(sys, "stdin", InputThatMustNotBeRead())
    monkeypatch.setattr(sys, "stderr", PromptOutput())
    assert cli_main(argv, management=runtime) == 1
    document = json.loads(capsys.readouterr().out)
    assert [item["code"] for item in document["failures"]] == ["interactive_setup_unavailable"]
    assert not settings_path(tmp_path).exists()


def test_setup_origin_is_parameterized_and_noninteractive_matches_library(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    library = _runtime(tmp_path / "library", InMemorySecretStore())
    cli_runtime = _runtime(tmp_path / "cli", InMemorySecretStore())
    expected = library.setup("https://ha.example:8123")
    prompt_output = InteractiveText()
    monkeypatch.setattr(sys, "stdin", InteractiveText("must not be read\n"))
    monkeypatch.setattr(sys, "stderr", prompt_output)

    assert cli_main(
        ["setup", "--origin", "https://ha.example:8123", "--non-interactive"],
        management=cli_runtime,
    ) == 0
    actual = json.loads(capsys.readouterr().out)
    assert _comparable(actual) == _comparable(dict(expected))
    assert prompt_output.getvalue() == ""

    # The legacy flag-only form remains equally prompt-free, even on a terminal.
    assert cli_main(
        ["setup", "--origin", "https://second.example:8123"], management=cli_runtime
    ) == 0
    assert prompt_output.getvalue() == ""


def test_setup_noninteractive_missing_origin_does_not_read_or_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class InputThatMustNotBeRead(InteractiveText):
        def readline(self, *args: object, **kwargs: object) -> str:
            raise AssertionError("non-interactive setup must not read stdin")

    runtime = _runtime(tmp_path, InMemorySecretStore())
    monkeypatch.setattr(sys, "stdin", InputThatMustNotBeRead())
    monkeypatch.setattr(sys, "stderr", InteractiveText())
    assert cli_main(["setup", "--non-interactive"], management=runtime) == 1
    document = json.loads(capsys.readouterr().out)
    assert [item["code"] for item in document["failures"]] == ["origin_required"]
    assert not settings_path(tmp_path).exists()


@pytest.mark.parametrize(
    ("answer", "expected_status", "expected_mode"),
    [
        ("yes\n", "ok", "trusted_local_or_vpn"),
        ("perhaps\ny\n", "ok", "trusted_local_or_vpn"),
        ("\n", "failed", None),
        ("no\n", "failed", None),
    ],
)
def test_interactive_http_requires_an_explicit_trust_answer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    answer: str,
    expected_status: str,
    expected_mode: str | None,
) -> None:
    runtime = _runtime(tmp_path, InMemorySecretStore())
    prompt_output = InteractiveText()
    monkeypatch.setattr(sys, "stdin", InteractiveText(f"http://ha.example:8123\n{answer}"))
    monkeypatch.setattr(sys, "stderr", prompt_output)

    assert cli_main(["setup"], management=runtime) == (0 if expected_status == "ok" else 1)
    document = json.loads(capsys.readouterr().out)
    assert document["status"] == expected_status
    assert "HTTP is unencrypted" in prompt_output.getvalue()
    if expected_mode is None:
        assert [item["code"] for item in document["failures"]] == ["setup_cancelled"]
        assert not settings_path(tmp_path).exists()
    else:
        assert document["configuration"]["transport_mode"] == expected_mode


@pytest.mark.parametrize("origin", ["http://ha.local:8123", "http://ha.tailnet.test:8123"])
def test_interactive_http_host_names_never_infer_trust(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    origin: str,
) -> None:
    runtime = _runtime(tmp_path, InMemorySecretStore())
    monkeypatch.setattr(sys, "stdin", InteractiveText(f"{origin}\nno\n"))
    monkeypatch.setattr(sys, "stderr", InteractiveText())
    assert cli_main(["setup"], management=runtime) == 1
    assert [item["code"] for item in json.loads(capsys.readouterr().out)["failures"]] == [
        "setup_cancelled"
    ]
    assert not settings_path(tmp_path).exists()


def test_explicit_https_mode_does_not_offer_an_http_downgrade(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runtime = _runtime(tmp_path, InMemorySecretStore())
    prompt_output = InteractiveText()
    monkeypatch.setattr(sys, "stdin", InteractiveText("http://ha.example:8123\nyes\n"))
    monkeypatch.setattr(sys, "stderr", prompt_output)
    assert cli_main(
        ["setup", "--interactive", "--transport-mode", "https"], management=runtime
    ) == 1
    document = json.loads(capsys.readouterr().out)
    assert [item["code"] for item in document["failures"]] == ["insecure_transport_rejected"]
    assert "HTTP is unencrypted" not in prompt_output.getvalue()
    assert not settings_path(tmp_path).exists()


def test_explicit_trusted_http_selection_needs_no_second_confirmation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class InputThatMustNotBeRead(InteractiveText):
        def readline(self, *args: object, **kwargs: object) -> str:
            raise AssertionError("explicit transport selection must not be re-prompted")

    store = InMemorySecretStore()
    runtime = _runtime(tmp_path, store)
    prompt_output = InteractiveText()
    monkeypatch.setattr(sys, "stdin", InputThatMustNotBeRead())
    monkeypatch.setattr(sys, "stderr", prompt_output)
    assert cli_main(
        [
            "setup",
            "--interactive",
            "--origin",
            "http://ha.example:8123",
            "--transport-mode",
            "trusted_local_or_vpn",
        ],
        management=runtime,
    ) == 0
    assert json.loads(capsys.readouterr().out)["configuration"]["transport_mode"] == (
        "trusted_local_or_vpn"
    )
    assert "HTTP is unencrypted" not in prompt_output.getvalue()
    assert store.entries == {} and store.writes == []


@pytest.mark.parametrize(
    "bad_origin",
    [
        "https://ha.example?query=1",
        "https://user:pass@ha.example",
        "https://ha.exam\tple",
        "https://ha.example\r\r",
    ],
)
def test_interactive_setup_retries_typed_invalid_origin_without_echoing_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    bad_origin: str,
) -> None:
    runtime = _runtime(tmp_path, InMemorySecretStore())
    prompt_output = InteractiveText()
    monkeypatch.setattr(
        sys, "stdin", InteractiveText(f"{bad_origin}\nhttps://ha.example:8123\n")
    )
    monkeypatch.setattr(sys, "stderr", prompt_output)
    assert cli_main(["setup"], management=runtime) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "ok"
    assert bad_origin not in prompt_output.getvalue()
    assert prompt_output.getvalue().count("Home Assistant URL:") == 2


@pytest.mark.parametrize("error", [KeyboardInterrupt(), EOFError(), OSError(), UnicodeError()])
def test_interactive_setup_input_termination_preserves_existing_settings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    error: BaseException,
) -> None:
    class FailingInput(InteractiveText):
        def readline(self, *args: object, **kwargs: object) -> str:
            raise error

    runtime = _runtime(tmp_path, InMemorySecretStore())
    assert runtime.setup("https://existing.example:8123")["status"] == "ok"
    before = settings_path(tmp_path).read_bytes()
    monkeypatch.setattr(sys, "stdin", FailingInput())
    monkeypatch.setattr(sys, "stderr", InteractiveText())
    assert cli_main(["setup", "--interactive"], management=runtime) == 1
    document = json.loads(capsys.readouterr().out)
    assert document["status"] == "failed"
    assert settings_path(tmp_path).read_bytes() == before


@pytest.mark.parametrize("input_text", ["", "\n"])
def test_interactive_setup_closed_or_blank_input_does_not_loop_or_overwrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    input_text: str,
) -> None:
    runtime = _runtime(tmp_path, InMemorySecretStore())
    assert runtime.setup("https://existing.example:8123")["status"] == "ok"
    before = settings_path(tmp_path).read_bytes()
    monkeypatch.setattr(sys, "stdin", InteractiveText(input_text))
    monkeypatch.setattr(sys, "stderr", InteractiveText())
    assert cli_main(["setup", "--interactive"], management=runtime) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "failed"
    assert settings_path(tmp_path).read_bytes() == before


def test_setup_flags_are_mutually_exclusive_and_help_describes_prompt_policy() -> None:
    failed = _cli("setup", "--interactive", "--non-interactive")
    assert failed.returncode == 2
    assert "not allowed with argument" in failed.stderr

    help_output = _cli("setup", "--help")
    assert help_output.returncode == 0
    for phrase in (
        "--interactive",
        "--non-interactive",
        "Defaults to https",
        "never prompts",
        "trusted_local_or_vpn",
    ):
        assert phrase in help_output.stdout

    tool_document = " ".join(
        (ROOT / "src" / "ha_analysis" / "SMART_TOOL.md").read_text().split()
    )
    for phrase in (
        "stderr",
        "--format auto|text|json",
        "both stdin and stdout are terminals",
        "no discovery, network",
        "token validation",
        "--interactive",
        "--non-interactive",
        "trusted_local_or_vpn",
    ):
        assert phrase in tool_document


@pytest.mark.parametrize(
    ("origin", "transport_mode", "code"),
    [
        ("ha.example", "https", "invalid_origin"),
        ("https://user:pw@ha.example", "https", "invalid_origin"),
        ("https://ha.example/api", "https", "invalid_origin"),
        ("https://ha.example?a=1", "https", "invalid_origin"),
        ("https://ha.example:0", "https", "invalid_origin"),
        ("ftp://ha.example", "https", "invalid_origin"),
        (None, "https", "invalid_origin"),
        ("https://ha.example", "insecure", "invalid_transport_mode"),
    ],
)
def test_c9_setup_refuses_a_malformed_origin_or_transport_mode(
    tmp_path: Path, origin: object, transport_mode: str, code: str
) -> None:
    document = _runtime(tmp_path).setup(origin, transport_mode)
    assert document["status"] == "failed"
    assert [item["code"] for item in document["failures"]] == [code]
    assert not settings_path(tmp_path).exists()


def test_c9_stored_settings_are_refused_when_they_are_unsafe_or_unrecognised(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    path = settings_path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    for document, code in (
        ({"origin": {"scheme": "https", "host": "ha.example", "port": 443}, "transport_mode": "https", "auth_mode": "long_lived_access_token", "token": SENTINEL}, "unknown_settings_field"),
        ({"origin": {"scheme": "https", "host": "ha.example", "port": 443}, "transport_mode": "https"}, "settings_incomplete"),
        ({"origin": {"scheme": "http", "host": "ha.local", "port": 8123}, "transport_mode": "https", "auth_mode": "long_lived_access_token"}, "insecure_transport_rejected"),
        ({"origin": {"scheme": "https", "host": "HA.EXAMPLE", "port": 443}, "transport_mode": "https", "auth_mode": "long_lived_access_token"}, "invalid_origin"),
        ({"origin": {"scheme": "https", "host": "ha.example", "port": 443}, "transport_mode": "https", "auth_mode": "oauth"}, "unsupported_auth_mode"),
    ):
        path.write_text(json.dumps(document))
        reported = runtime.status()
        assert reported["status"] == "failed"
        assert [item["code"] for item in reported["failures"]] == [code]

    path.write_text("{not json")
    assert [item["code"] for item in runtime.status()["failures"]] == ["settings_malformed"]

    path.unlink()
    path.symlink_to(tmp_path / "elsewhere.json")
    assert [item["code"] for item in runtime.status()["failures"]] == ["unsafe_settings_path"]


# --------------------------------------------------------------------------
# Malformed origins: refused, never crashed and never reinterpreted
# --------------------------------------------------------------------------

#: Authority strings that made ``urlparse`` itself raise, so the shared rule
#: leaked a ValueError traceback out of both ``setup`` and a live read.
MALFORMED_BRACKET_ORIGINS: tuple[str, ...] = (
    "https://[abc]",
    "https://[::1",
    "https://ha]",
    "https://[]",
    "https://a[b].c",
    "https://[[::1]]",
    "https://[::1]]",
    "https://[[::1]",
    "https://[:::1]",
    "https://[1.2.3.4]",
    "https://[v1.fe80::a]",
    "https://[fe80::1%]",
    "https://[",
    "https://]",
    "https://[]:8123",
)

#: Authority strings that parse cleanly but are not a host this tool will bind
#: a credential to. ``ha.example@attacker.example`` is the dangerous one: it
#: renders a URL whose real host is ``attacker.example``.
UNSAFE_HOST_ORIGINS: tuple[str, ...] = (
    "https://ha.example evil",
    "https://ha.example@attacker.example",
    "https://ha.exa\x00mple",
    "https://ha.\u0435xample",  # Cyrillic homograph of "ha.example"
    "https://ha.exam\tple",
    "https://ha.example\nx",
    "https://ha..example",
    "https://-ha.example",
    "https://ha.example-",
    "https://ha_example.com",
    "https://" + "a" * 300,
)


@pytest.mark.parametrize("origin", MALFORMED_BRACKET_ORIGINS + UNSAFE_HOST_ORIGINS)
def test_a_malformed_origin_is_a_diagnostic_not_a_traceback(
    tmp_path: Path, origin: str
) -> None:
    """REGRESSION: these raised an uncaught ValueError out of the shared rule."""

    with pytest.raises(OriginError) as raised:
        normalize_origin(origin, "https")
    assert raised.value.code == "invalid_origin"
    assert origin not in raised.value.message, "a refusal must not echo the input"

    # Both callers of the one rule must report it the same way.
    document = _runtime(tmp_path).setup(origin)
    assert document["status"] == "failed"
    assert [item["code"] for item in document["failures"]] == ["invalid_origin"]
    assert not settings_path(tmp_path).exists(), "a refused origin must persist nothing"

    reader = FakeReader({})
    live = AnalysisRuntime(entity_reader=reader).inspect_live_entities(
        origin, ["light.kitchen"], lambda: pytest.fail("no credential may be requested")
    )
    assert [item["code"] for item in live["failures"]] == ["invalid_origin"]
    assert live["target_resolution"] == [{"target": "light.kitchen", "status": "not_inspected"}]
    assert reader.calls == []


@pytest.mark.parametrize(
    "origin",
    # A NUL cannot be placed in argv at all - the OS refuses it before the tool
    # runs - so it is exercised through the settings file instead, where it can
    # genuinely arrive. Excluding it here keeps this test about the tool.
    [item for item in MALFORMED_BRACKET_ORIGINS + UNSAFE_HOST_ORIGINS if "\x00" not in item],
)
def test_a_malformed_origin_reaches_the_cli_as_json_not_a_stack_trace(origin: str) -> None:
    completed = _cli("setup", "--origin", origin)
    assert completed.returncode == 1, completed.stderr
    assert "Traceback" not in completed.stderr
    assert completed.stderr == ""
    assert [item["code"] for item in json.loads(completed.stdout)["failures"]] == ["invalid_origin"]


@pytest.mark.parametrize(
    ("origin", "expected"),
    [
        ("https://[::1]:8123", {"scheme": "https", "host": "::1", "port": 8123}),
        ("https://[::1]", {"scheme": "https", "host": "::1", "port": 443}),
        ("https://[FE80::1]:8123", {"scheme": "https", "host": "fe80::1", "port": 8123}),
        (
            "https://[fe80::1%25eth0]:8123",
            {"scheme": "https", "host": "fe80::1%25eth0", "port": 8123},
        ),
        (
            "https://[::ffff:1.2.3.4]:8123",
            {"scheme": "https", "host": "::ffff:1.2.3.4", "port": 8123},
        ),
        ("https://192.0.2.5:8123", {"scheme": "https", "host": "192.0.2.5", "port": 8123}),
        ("https://HA.Example:8123", {"scheme": "https", "host": "ha.example", "port": 8123}),
        ("https://ha.example.", {"scheme": "https", "host": "ha.example.", "port": 443}),
        (
            "https://xn--80ak6aa92e.example",
            {"scheme": "https", "host": "xn--80ak6aa92e.example", "port": 443},
        ),
    ],
)
def test_valid_origins_including_ipv6_still_normalize_and_render(
    tmp_path: Path, origin: str, expected: dict[str, object]
) -> None:
    """Hardening must not cost a legitimate IPv6 or IDN-punycode endpoint."""

    assert normalize_origin(origin, "https") == expected

    document = _runtime(tmp_path).setup(origin)
    assert document["status"] == "ok"
    assert document["configuration"]["origin"] == expected
    # origin_url still brackets IPv6 and only IPv6, and round-trips exactly.
    rendered = origin_url(expected)  # type: ignore[arg-type]
    assert ("[" in rendered) is (":" in expected["host"])  # type: ignore[operator]
    assert document["configuration"]["origin_url"] == rendered
    assert normalize_origin(rendered, "https") == expected


# --------------------------------------------------------------------------
# Persisted settings are an editable input, revalidated through the one rule
# --------------------------------------------------------------------------

#: Concrete hand-edited ``settings.json`` hosts. Each one previously passed the
#: field-by-field check and was used to re-key and look up a credential.
STORED_HOST_ATTACKS: tuple[tuple[str, str], ...] = (
    ("ha.example evil", "a space smuggled into the authority"),
    ("ha.example\nx: y", "an embedded line break"),
    ("ha.example@attacker.example", "userinfo that moves the real host"),
    ("[abc]", "a bracketed non-address"),
    ("[::1]", "a bracketed IPv6 (storage holds it unbracketed)"),
    ("[::1", "an unbalanced bracket"),
    ("ha.example/api", "an embedded path"),
    ("ha.example?q=1", "an embedded query"),
    ("ha.example#fragment", "an embedded fragment"),
    ("ha.exa\x00mple", "an embedded NUL"),
    ("ha.exam\tple", "an embedded tab urlparse would silently strip"),
    ("ha.\u0435xample", "a Cyrillic homograph"),
    ("ha.example:9999", "a port smuggled into the host"),
    ("HA.EXAMPLE", "a non-normalized host"),
    ("ha..example", "an empty label"),
    ("-ha.example", "a leading hyphen"),
    ("user:pw@ha.example", "full userinfo"),
    ("ha.example evil@attacker.example", "both at once"),
    ("", "an empty host"),
)


@pytest.mark.parametrize(
    ("host", "why"), STORED_HOST_ATTACKS, ids=[why for _, why in STORED_HOST_ATTACKS]
)
def test_a_hand_edited_settings_host_is_refused_before_any_secret_store_access(
    tmp_path: Path, host: str, why: str
) -> None:
    """REGRESSION: every one of these was accepted and used to key a credential."""

    document = {
        "origin": {"scheme": "https", "host": host, "port": 443},
        "transport_mode": "https",
        "auth_mode": "long_lived_access_token",
    }
    with pytest.raises(SettingsError) as raised:
        validate_settings(document)
    assert raised.value.code in {"invalid_origin", "unknown_settings_field"}

    path = settings_path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document))

    # A store that screams if it is touched at all: refusal must come first.
    class ForbiddenSecretStore(InMemorySecretStore):
        def describe(self) -> str:
            raise AssertionError(f"the secret store was reached for {why}")

        def get_credential(self, key: str) -> str | None:
            raise AssertionError(f"a credential was looked up for {why}")

        def has_credential(self, key: str) -> bool:
            raise AssertionError(f"a credential was probed for {why}")

        def set_credential(self, key: str, credential: str) -> None:
            raise AssertionError(f"a credential was stored for {why}")

        def delete_credential(self, key: str) -> bool:
            raise AssertionError(f"a credential was deleted for {why}")

    runtime = ManagementRuntime(secret_store=ForbiddenSecretStore(), config_home=tmp_path)
    for document_produced in (
        runtime.status(),
        runtime.login(lambda: SENTINEL),
        runtime.logout(),
    ):
        assert document_produced["status"] == "failed"
        assert [item["code"] for item in document_produced["failures"]] == ["invalid_origin"]
        assert document_produced["configuration"] is None
        # A refusal is still a credential-free management document.
        assert SENTINEL not in serialize_document(document_produced)
        if host:
            assert host not in serialize_document(document_produced)

    # The live path refuses on the same footing, and asks for no credential.
    live = AnalysisRuntime(
        entity_reader=FakeReader({}),
        stored_credentials=StoredCredentials(
            secret_store=ForbiddenSecretStore(), config_home=tmp_path
        ),
    ).inspect_live_entities(None, ["light.kitchen"])
    assert [item["code"] for item in live["failures"]] == ["invalid_origin"]


@pytest.mark.parametrize(
    ("host", "port", "scheme", "transport_mode"),
    [
        ("ha.example", 443, "https", "https"),
        ("::1", 8123, "https", "https"),
        ("fe80::1%25eth0", 8123, "https", "https"),
        ("::ffff:1.2.3.4", 8123, "https", "https"),
        ("192.0.2.5", 8123, "https", "https"),
        ("ha.local", 8123, "http", "trusted_local_or_vpn"),
    ],
)
def test_a_valid_stored_origin_including_ipv6_still_loads_and_keys_a_credential(
    tmp_path: Path, host: str, port: int, scheme: str, transport_mode: str
) -> None:
    stored = {
        "origin": {"scheme": scheme, "host": host, "port": port},
        "transport_mode": transport_mode,
        "auth_mode": "long_lived_access_token",
    }
    assert validate_settings(stored)["origin"] == stored["origin"]

    path = settings_path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(stored))
    store = InMemorySecretStore()
    runtime = ManagementRuntime(secret_store=store, config_home=tmp_path)

    login = runtime.login(lambda: SENTINEL)
    assert login["status"] == "ok"
    assert login["configuration"]["origin"] == stored["origin"]
    key = next(iter(store.entries))
    assert origin_url(stored["origin"]) in key  # type: ignore[arg-type]
    assert runtime.status()["details"]["credential_present"] is True

    # The stored credential reaches a live read for exactly this origin.
    reader = FakeReader({"light.kitchen": {"state": "on"}})
    live = AnalysisRuntime(
        entity_reader=reader,
        transport_mode=transport_mode,
        stored_credentials=StoredCredentials(secret_store=store, config_home=tmp_path),
    ).inspect_live_entities(None, ["light.kitchen"])
    assert live["failures"] == []
    assert reader.calls[0][0] == stored["origin"]
    assert reader.calls[0][2] == SENTINEL


def test_a_settings_round_trip_is_stable_for_every_origin_setup_accepts(
    tmp_path: Path,
) -> None:
    """Whatever setup writes must load back unchanged, or the guard is too strict."""

    for origin, transport_mode in (
        ("https://ha.example:8123", "https"),
        ("https://[::1]:8123", "https"),
        ("https://[fe80::1%25eth0]:8123", "https"),
        ("https://192.0.2.5", "https"),
        ("http://ha.local:8123", "trusted_local_or_vpn"),
        ("https://HA.Example", "https"),
    ):
        home = tmp_path / origin.replace("/", "_").replace(":", "-").replace("%", "p")
        runtime = _runtime(home)
        written = runtime.setup(origin, transport_mode)
        assert written["status"] == "ok", origin
        reloaded = runtime.status()
        assert reloaded["status"] == "ok", origin
        assert reloaded["configuration"] == written["configuration"], origin


# --------------------------------------------------------------------------
# C9: origin binding, in-place replacement, local-only idempotent logout
# --------------------------------------------------------------------------


def test_c9_a_repeated_login_replaces_the_credential_in_place(tmp_path: Path) -> None:
    store = InMemorySecretStore()
    runtime = _configured(tmp_path, store)
    first = runtime.login(lambda: SENTINEL)
    second = runtime.login(lambda: ROTATED)
    assert first["details"]["replaced_existing"] is False
    assert second["details"]["replaced_existing"] is True
    assert len(store.entries) == 1, "credentials must not accumulate"
    assert list(store.entries.values()) == [ROTATED]
    assert store.writes[0] == store.writes[1]


def test_c9_a_new_origin_never_adopts_the_previous_credential(tmp_path: Path) -> None:
    store = InMemorySecretStore()
    runtime = _configured(tmp_path, store, "https://first.example:8123")
    runtime.login(lambda: SENTINEL)
    first_key = next(iter(store.entries))

    changed = runtime.setup("https://second.example:8123")
    assert changed["details"]["origin_changed"] is True
    codes = {item["code"] for item in changed["notices"]}
    assert "origin_changed_credential_not_adopted" in codes
    assert SENTINEL not in serialize_document(changed)

    reported = runtime.status()
    assert reported["configuration"]["origin_url"] == "https://second.example:8123"
    assert reported["details"]["credential_present"] is False
    assert reported["details"]["ready"] is False

    runtime.login(lambda: ROTATED)
    assert len(store.entries) == 2 and store.entries[first_key] == SENTINEL
    assert credential_key({"scheme": "https", "host": "first.example", "port": 8123}) != credential_key(
        {"scheme": "https", "host": "second.example", "port": 8123}
    )
    # Deleting the second origin's credential must leave the first one alone.
    assert runtime.logout()["details"]["deleted"] is True
    assert store.entries == {first_key: SENTINEL}


def test_c9_logout_is_local_only_and_idempotent(tmp_path: Path) -> None:
    store = InMemorySecretStore()
    runtime = _configured(tmp_path, store)
    runtime.login(lambda: SENTINEL)

    first = runtime.logout()
    assert first["status"] == "ok"
    assert first["details"]["deleted"] is True
    assert first["details"]["server_side_revocation_performed"] is False
    assert first["details"]["home_assistant_request_made"] is False
    revocation = next(item for item in first["notices"] if item["code"] == "no_server_side_revocation")
    assert "No Home Assistant revocation was performed" in revocation["message"]
    assert "remains valid at Home Assistant" in revocation["message"]

    second = runtime.logout()
    assert second["status"] == "ok"
    assert second["details"]["deleted"] is False
    assert "nothing_to_delete" in {item["code"] for item in second["notices"]}
    assert store.entries == {}
    # Settings survive a logout: only the credential is destroyed.
    assert settings_path(tmp_path).exists()


def test_c9_status_reports_a_store_read_failure_without_inventing_an_answer(
    tmp_path: Path,
) -> None:
    class ReadableButFailing(InMemorySecretStore):
        def has_credential(self, key: str) -> bool:
            raise SecretStoreOperationError("The secret store rejected the read.")

    runtime = _configured(tmp_path, ReadableButFailing())
    document = runtime.status()
    assert document["status"] == "ok"
    assert document["details"]["secret_store_available"] is True
    # Unknown is reported as unknown, never as "no credential".
    assert document["details"]["credential_present"] is None
    assert document["details"]["ready"] is False
    assert "secret_store_operation_failed" in {item["code"] for item in document["notices"]}


def test_c9_management_operations_require_configuration_first(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path)
    for document in (runtime.login(lambda: SENTINEL), runtime.logout()):
        assert document["status"] == "failed"
        assert [item["code"] for item in document["failures"]] == ["not_configured"]
    reported = runtime.status()
    assert reported["status"] == "ok"
    assert reported["details"]["configured"] is False
    assert reported["details"]["ready"] is False
    assert reported["configuration"] is None
    assert "not_configured" in {item["code"] for item in reported["notices"]}


# --------------------------------------------------------------------------
# C9: management makes no Home Assistant request and no model invocation
# --------------------------------------------------------------------------


def test_c9_management_touches_no_network_and_no_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError("a management operation must make no network request")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr("urllib.request.build_opener", forbidden)
    monkeypatch.setattr("urllib.request.urlopen", forbidden)

    store = InMemorySecretStore()
    runtime = _runtime(tmp_path, store)
    assert runtime.setup("https://ha.example:8123")["status"] == "ok"
    login = runtime.login(lambda: SENTINEL)
    assert login["status"] == "ok"
    assert login["details"]["home_assistant_request_made"] is False
    assert "credential_not_validated" in {item["code"] for item in login["notices"]}
    validation = next(item for item in login["notices"] if item["code"] == "credential_not_validated")
    assert "made no Home Assistant request" in validation["message"]
    assert runtime.status()["status"] == "ok"
    assert runtime.logout()["status"] == "ok"

    # Structural proof to match the behavioral one: the management module holds
    # no transport import and no model boundary at all.
    source = (ROOT / "src" / "ha_analysis" / "management.py").read_text()
    for forbidden in ("urllib", "http.client", "socket", "from .live", "from .api"):
        assert forbidden not in source, forbidden
    for forbidden in ("ModelInterpreter", "interpret", "model_interpreter"):
        assert forbidden not in source, forbidden


def test_c9_metadata_and_offline_paths_never_import_keyring_or_read_settings(
    tmp_path: Path,
) -> None:
    program = textwrap.dedent(
        """
        import json, sys
        from ha_analysis.api import AnalysisRuntime
        from ha_analysis.cli import main
        from ha_analysis.settings import settings_path

        main(["manifest"])
        main(["offline_analyze", "--evidence", '[{"state":"on"}]',
              "--request", '{"analysis_kind":"structural_summary"}'])
        try:
            main(["--help"])
        except SystemExit:
            pass

        class Reader:
            def read_entity(self, origin, entity_id, credential):
                return {"state": "on"}

        # An injected provider must short-circuit the stored-credential path
        # entirely: no store, no settings, no keyring.
        result = AnalysisRuntime(entity_reader=Reader()).inspect_live_entities(
            "https://ha.example", ["light.kitchen"], lambda: "injected"
        )
        assert result["failures"] == [], result["failures"]
        assert "keyring" not in sys.modules, sorted(m for m in sys.modules if "key" in m)
        assert not settings_path().exists()
        print("CLEAN")
        """
    )
    completed = subprocess.run(
        [sys.executable, "-c", program],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src"), "XDG_CONFIG_HOME": str(tmp_path)},
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "CLEAN" in completed.stdout


# --------------------------------------------------------------------------
# C7 + C9: the stored credential reaches a live read only through the boundary
# --------------------------------------------------------------------------


def test_c9_a_live_read_uses_the_stored_credential_only_for_the_configured_origin(
    tmp_path: Path,
) -> None:
    store = InMemorySecretStore()
    management = _configured(tmp_path, store, "https://ha.example:8123")
    management.login(lambda: SENTINEL)
    reader = FakeReader({"light.kitchen": {"state": "on"}})
    runtime = AnalysisRuntime(
        entity_reader=reader,
        stored_credentials=StoredCredentials(secret_store=store, config_home=tmp_path),
    )

    configured = runtime.inspect_live_entities(None, ["light.kitchen"])
    assert configured["failures"] == []
    assert configured["evidence_sources"][0]["origin"] == {
        "scheme": "https",
        "host": "ha.example",
        "port": 8123,
    }
    assert reader.calls[0][2] == SENTINEL
    assert SENTINEL not in json.dumps(configured)
    assert SENTINEL not in runtime.serialize_result(configured)

    # Naming the configured origin explicitly is the same origin, so it works.
    explicit = runtime.inspect_live_entities("https://HA.example:8123", ["light.kitchen"])
    assert explicit["failures"] == [] and len(reader.calls) == 2

    # Any other origin must never receive it, and must not even reach the store.
    other = runtime.inspect_live_entities("https://other.example:8123", ["light.kitchen"])
    assert [item["code"] for item in other["failures"]] == ["credential_origin_mismatch"]
    assert len(reader.calls) == 2, "no read may happen without a credential"

    # An injected provider still wins, and the store is not consulted for it.
    injected = runtime.inspect_live_entities(
        "https://other.example:8123", ["light.kitchen"], lambda: "injected"
    )
    assert injected["failures"] == [] and reader.calls[2][2] == "injected"


def test_c9_a_live_read_reports_missing_configuration_and_missing_credential(
    tmp_path: Path,
) -> None:
    store = InMemorySecretStore()
    reader = FakeReader({"light.kitchen": {"state": "on"}})
    runtime = AnalysisRuntime(
        entity_reader=reader,
        stored_credentials=StoredCredentials(secret_store=store, config_home=tmp_path),
    )
    unconfigured = runtime.inspect_live_entities(None, ["light.kitchen"])
    assert [item["code"] for item in unconfigured["failures"]] == ["not_configured"]
    assert unconfigured["target_resolution"] == [
        {"target": "light.kitchen", "status": "not_inspected"}
    ]

    _configured(tmp_path, store, "https://ha.example:8123")
    missing = runtime.inspect_live_entities(None, ["light.kitchen"])
    assert [item["code"] for item in missing["failures"]] == ["credential_not_stored"]
    assert reader.calls == []

    unavailable = AnalysisRuntime(
        entity_reader=reader,
        stored_credentials=StoredCredentials(
            secret_store=UnavailableSecretStore(), config_home=tmp_path
        ),
    ).inspect_live_entities(None, ["light.kitchen"])
    assert [item["code"] for item in unavailable["failures"]] == ["secret_store_unavailable"]
    assert reader.calls == []


def test_c9_a_configured_plaintext_origin_is_used_only_with_its_trusted_mode(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store = InMemorySecretStore()
    management = _runtime(tmp_path, store)
    assert management.setup("http://ha.local:8123", "trusted_local_or_vpn")["status"] == "ok"
    management.login(lambda: SENTINEL)
    reader = FakeReader({"light.kitchen": {"state": "on"}})
    credentials = StoredCredentials(secret_store=store, config_home=tmp_path)

    # The persisted transport mode travels with the persisted origin.
    configured = AnalysisRuntime(
        entity_reader=reader, stored_credentials=credentials
    ).inspect_live_entities(None, ["light.kitchen"])
    assert configured["failures"] == []

    # Overriding the origin does not inherit that trust: it must be restated.
    assert cli_main(
        ["inspect_live_entities", "--origin", "http://ha.local:8123", "--targets", '["light.kitchen"]'],
        runtime=AnalysisRuntime(entity_reader=reader, stored_credentials=credentials),
    ) == 1
    rejected = json.loads(capsys.readouterr().out)
    assert [item["code"] for item in rejected["failures"]] == ["insecure_transport_rejected"]

    assert cli_main(
        [
            "inspect_live_entities",
            "--origin", "http://ha.local:8123",
            "--transport-mode", "trusted_local_or_vpn",
            "--targets", '["light.kitchen"]',
        ],
        runtime=AnalysisRuntime(
            entity_reader=reader,
            transport_mode="trusted_local_or_vpn",
            stored_credentials=credentials,
        ),
    ) == 0
    accepted = json.loads(capsys.readouterr().out)
    assert accepted["failures"] == []


def test_transport_mode_override_requires_an_origin() -> None:
    completed = _cli(
        "inspect_live_entities", "--transport-mode", "trusted_local_or_vpn", "--targets", "[]"
    )
    assert completed.returncode == 2 and completed.stdout == ""
    assert "--transport-mode requires --origin" in completed.stderr


# --------------------------------------------------------------------------
# Installed CLI behavior, and the reserved surface that must stay absent
# --------------------------------------------------------------------------


def test_installed_cli_configuration_flow_reports_honestly_without_an_approved_store(
    tmp_path: Path,
) -> None:
    environment = {
        **os.environ,
        "PYTHONPATH": str(ROOT / "src"),
        "XDG_CONFIG_HOME": str(tmp_path),
        "PYTHON_KEYRING_BACKEND": "keyring.backends.fail.Keyring",
    }

    def run(*arguments: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "ha_analysis.cli", *arguments],
            cwd=ROOT,
            env=environment,
            input=stdin if stdin is not None else "",
            text=True,
            capture_output=True,
            check=False,
        )

    setup = run("setup", "--origin", "https://ha.example:8123")
    assert setup.returncode == 0
    assert json.loads(setup.stdout)["document_kind"] == "management"

    status = run("status")
    assert status.returncode == 0
    reported = json.loads(status.stdout)
    assert reported["details"]["configured"] is True
    assert reported["details"]["secret_store_available"] is False
    assert reported["details"]["ready"] is False

    login = run("login", "--token-stdin", stdin=f"{SENTINEL}\n")
    assert login.returncode == 1
    document = json.loads(login.stdout)
    assert document["status"] == "failed"
    assert [item["code"] for item in document["failures"]] == ["secret_store_unavailable"]
    assert SENTINEL not in login.stdout + login.stderr
    assert _files_containing(tmp_path, SENTINEL) == []

    logout = run("logout")
    assert logout.returncode == 1
    assert [item["code"] for item in json.loads(logout.stdout)["failures"]] == [
        "secret_store_unavailable"
    ]

    # A closed stdin must never hang a login.
    closed = subprocess.run(
        [sys.executable, "-m", "ha_analysis.cli", "login"],
        cwd=ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert closed.returncode == 1
    assert [item["code"] for item in json.loads(closed.stdout)["failures"]] == [
        "credential_input_unavailable"
    ]


@pytest.mark.parametrize(
    ("supplied", "code"),
    [
        (b"", "empty_credential"),
        (b"\xff\xfe\xff\n", "credential_input_unavailable"),
        (b"x" * 5000 + b"\n", "credential_too_long"),
        (b"abc def\n", "invalid_credential"),
        (b"   \n", "invalid_credential"),
    ],
)
def test_login_from_stdin_refuses_bad_input_without_hanging_or_echoing(
    tmp_path: Path, supplied: bytes, code: str
) -> None:
    """Every malformed automation input must fail fast, quietly, and non-zero."""

    environment = {
        **os.environ,
        "PYTHONPATH": str(ROOT / "src"),
        "XDG_CONFIG_HOME": str(tmp_path),
        "PYTHON_KEYRING_BACKEND": "keyring.backends.fail.Keyring",
    }
    setup = subprocess.run(
        [sys.executable, "-m", "ha_analysis.cli", "setup", "--origin", "https://ha.example:8123"],
        cwd=ROOT, env=environment, input="", text=True, capture_output=True, check=False,
    )
    assert setup.returncode == 0
    completed = subprocess.run(
        [sys.executable, "-m", "ha_analysis.cli", "login", "--token-stdin"],
        cwd=ROOT, env=environment, input=supplied, capture_output=True, check=False, timeout=30,
    )
    assert completed.returncode == 1
    document = json.loads(completed.stdout.decode("utf-8"))
    assert document["status"] == "failed"
    assert [item["code"] for item in document["failures"]] == [code]
    if supplied.strip():
        assert supplied.strip() not in completed.stdout + completed.stderr
    assert _files_containing(tmp_path, "x" * 100) == []


def test_reserved_capabilities_remain_absent() -> None:
    parser = cli_module._parser()
    subcommands = next(
        action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
    )
    rendered = " ".join(subcommands.choices) + " " + parser.format_help()
    for reserved in ("oauth", "client-id", "client_id", "refresh", "revoke", "callback", "call_service"):
        assert reserved not in rendered.lower()

    import ha_analysis

    for reserved in ("oauth", "refresh_token", "revoke", "call_service", "discover"):
        assert not any(reserved in name.lower() for name in ha_analysis.__all__)


# --------------------------------------------------------------------------
# The packaging descriptor's own execution recipe must be self-sufficient
# --------------------------------------------------------------------------


def test_descriptor_declares_the_runtime_dependency_it_needs() -> None:
    """The inline script metadata and the package must not drift apart."""

    import tomllib

    descriptor = json.loads((ROOT / "smart-tool.json").read_text())
    script = ROOT / descriptor["cli_argv"][-1]
    assert script.is_file(), descriptor["cli_argv"]

    lines = script.read_text().splitlines()
    start = lines.index("# /// script")
    end = lines.index("# ///", start + 1)
    block = "\n".join(line.removeprefix("# ").removeprefix("#") for line in lines[start + 1 : end])
    metadata = tomllib.loads(block)

    packaged = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert metadata["dependencies"] == packaged["dependencies"]
    assert metadata["requires-python"] == packaged["requires-python"]
    assert any(item.startswith("keyring") for item in metadata["dependencies"])


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv is required to run the descriptor recipe")
def test_descriptor_recipe_resolves_keyring_from_a_scratch_directory(tmp_path: Path) -> None:
    """REGRESSION: a clean checkout could not resolve ``keyring`` for login.

    The descriptor's recipe is ``uv run --no-project <script>``, which resolves
    nothing from the project. Copies only the package and the descriptor into a
    scratch directory - no ``pyproject.toml``, no ``.venv``, no ``PYTHONPATH``,
    no active virtualenv - and drives the real recipe there.
    """

    descriptor = json.loads((ROOT / "smart-tool.json").read_text())
    scratch = tmp_path / "scratch"
    (scratch / "src").mkdir(parents=True)
    shutil.copytree(ROOT / "src" / "ha_analysis", scratch / "src" / "ha_analysis")
    shutil.copy(ROOT / "smart-tool.json", scratch / "smart-tool.json")
    shutil.rmtree(scratch / "src" / "ha_analysis" / "__pycache__", ignore_errors=True)
    assert not (scratch / "pyproject.toml").exists()
    assert not (scratch / ".venv").exists()

    config_home = tmp_path / "config"
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"VIRTUAL_ENV", "PYTHONPATH", "PYTHON_KEYRING_BACKEND", "XDG_CONFIG_HOME"}
    }
    environment["XDG_CONFIG_HOME"] = str(config_home)

    def recipe(*arguments: str, stdin: str = "", **overrides: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [*descriptor["cli_argv"], *arguments],
            cwd=scratch,
            env={**environment, **overrides},
            input=stdin,
            text=True,
            capture_output=True,
            check=False,
            timeout=600,
        )

    manifest = recipe("manifest", "--format", "json")
    assert manifest.returncode == 0, manifest.stderr
    assert json.loads(manifest.stdout)["name"] == "ha-analysis"
    # Metadata must still cost nothing: no configuration is read or written.
    assert not config_home.exists()

    assert recipe("setup", "--origin", "https://ha.example:8123").returncode == 0

    # The proof: with the store deliberately pinned to an unapproved backend,
    # the refusal must be "this backend is not approved" - which is only
    # reachable once `keyring` itself imported. A missing dependency would
    # report `secret_store_dependency_missing` instead.
    login = recipe(
        "login",
        "--token-stdin",
        stdin="not-a-real-token-probe\n",
        PYTHON_KEYRING_BACKEND="keyring.backends.fail.Keyring",
    )
    assert login.returncode == 1, login.stderr
    document = json.loads(login.stdout)
    assert document["status"] == "failed"
    codes = [item["code"] for item in document["failures"]]
    assert codes == ["secret_store_unavailable"], document["failures"]
    assert "secret_store_dependency_missing" not in codes
    # Fail-closed is intact: nothing was written anywhere under the scratch tree.
    assert "credential_not_stored" in {item["code"] for item in document["notices"]}
    assert _files_containing(scratch, "not-a-real-token-probe") == []
    assert _files_containing(config_home, "not-a-real-token-probe") == []


# --------------------------------------------------------------------------
# Opt-in: a real operating-system secret store
# --------------------------------------------------------------------------


@pytest.mark.skipif(
    os.environ.get("HA_ANALYSIS_REAL_SECRET_STORE") != "1",
    reason="set HA_ANALYSIS_REAL_SECRET_STORE=1 to exercise the real OS secret store",
)
@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux-only by contract")
def test_real_operating_system_secret_store_round_trip(tmp_path: Path) -> None:
    """Round-trip, rotate, and delete a throwaway value in the real OS store.

    Runs in a subprocess with the suite's fail-backend pin removed, because
    ``keyring`` resolves and caches its backend once per process. Every value is
    randomly generated per run and is never a real token.
    """

    program = textwrap.dedent(
        """
        import json, uuid
        from ha_analysis.management import ManagementRuntime, credential_key
        from ha_analysis.secret_store import KeyringSecretStore

        marker = "not-a-real-token-" + uuid.uuid4().hex
        rotated = "not-a-real-token-" + uuid.uuid4().hex
        origin = "https://probe-%s.invalid:8123" % uuid.uuid4().hex
        runtime = ManagementRuntime()
        report = {}
        try:
            report["setup"] = runtime.setup(origin)["status"]
            first = runtime.login(lambda: marker)
            report["login"] = first["status"]
            report["backend"] = first["details"].get("secret_store_backend")
            report["present"] = runtime.status()["details"]["credential_present"]
            second = runtime.login(lambda: rotated)
            report["replaced"] = second["details"]["replaced_existing"]
            report["deleted"] = runtime.logout()["details"]["deleted"]
            report["deleted_again"] = runtime.logout()["details"]["deleted"]
            report["absent_after"] = runtime.status()["details"]["credential_present"]
            report["leaked"] = any(
                marker in json.dumps(document) or rotated in json.dumps(document)
                for document in (first, second)
            )
        finally:
            try:
                KeyringSecretStore().delete_credential(
                    credential_key({"scheme": "https", "host": origin.split("//")[1].split(":")[0], "port": 8123})
                )
            except Exception:
                pass
        print(json.dumps(report))
        """
    )
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"PYTHON_KEYRING_BACKEND"}
    }
    environment["PYTHONPATH"] = str(ROOT / "src")
    environment["XDG_CONFIG_HOME"] = str(tmp_path)
    completed = subprocess.run(
        [sys.executable, "-c", program],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout.strip().splitlines()[-1])
    assert report["setup"] == "ok" and report["login"] == "ok"
    assert report["backend"].startswith("keyring.backends.")
    assert report["present"] is True
    assert report["replaced"] is True
    assert report["deleted"] is True
    assert report["deleted_again"] is False
    assert report["absent_after"] is False
    assert report["leaked"] is False


def _cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "ha_analysis.cli", *arguments],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
