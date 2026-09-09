"""The C9 long-lived-access-token lifecycle: ``setup``, ``login``, ``status``, ``logout``.

These are management operations, not analysis operations. They perform no
analysis, make no Home Assistant request and no model invocation, and they
return a :class:`~ha_analysis.types.ManagementDocument` rather than an analysis
``Result`` - so a management outcome can never be read as observed Home
Assistant evidence.

Everything a user interface might be tempted to do for itself lives here:
origin normalization (delegated to :mod:`ha_analysis.origins`), transport
selection, credential input handling, secret-store access, and settings
persistence. A CLI selects an operation and renders the document; it decides
nothing.
"""

from __future__ import annotations

import getpass
import json
import os
import sys
from pathlib import Path
from typing import TextIO

from .clock import utc_timestamp
from .origins import OriginError, normalize_origin, origin_url
from .secret_store import KeyringSecretStore, SecretStoreError
from .settings import (
    LONG_LIVED_ACCESS_TOKEN,
    Settings,
    SettingsError,
    load_settings,
    save_settings,
    settings_path,
)
from .types import (
    CredentialInput,
    Diagnostic,
    JsonValue,
    ManagementConfiguration,
    ManagementDocument,
    ManagementOperationKind,
    Origin,
    SecretStore,
)

CONTRACT_VERSION = "ha-analysis.v1"
DOCUMENT_KIND = "management"
MANAGEMENT_OPERATIONS: tuple[str, ...] = ("setup", "login", "status", "logout")
DOCUMENT_FIELDS: frozenset[str] = frozenset(
    {
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
)
CREDENTIAL_INPUT_MODES: tuple[str, ...] = ("prompt", "stdin")
MAXIMUM_CREDENTIAL_LENGTH = 4096
CREDENTIAL_PROMPT = "Home Assistant long-lived access token (input is hidden): "

NO_SERVER_SIDE_REVOCATION = (
    "The credential was deleted from this computer only. No Home Assistant "
    "revocation was performed, and the token remains valid at Home Assistant "
    "until you delete it there."
)


def _invalidate_control_trust() -> None:
    """A local lifecycle change invalidates control without changing management envelopes."""
    try:
        from .control import invalidate_control_trust
        invalidate_control_trust()
    except OSError:
        # If state is unreadable, control itself fails closed when it next checks trust.
        pass
NOT_VALIDATED = (
    "The credential was stored exactly as supplied. This tool made no Home "
    "Assistant request, so it has not been checked against Home Assistant."
)
SETUP_GUIDANCE = (
    "Setup is local only: it saves the URL, not a token, and does not contact Home "
    "Assistant. Enter an absolute HTTP or HTTPS URL with an optional port.\n"
)
SETUP_ORIGIN_PROMPT = "Home Assistant URL: "
SETUP_HTTP_PROMPT = (
    "HTTP is unencrypted; future requests send your token over it. Trusted LAN or "
    "VPN only. Select trusted_local_or_vpn? [y/N] "
)
SETUP_NEXT_STEP = (
    "Next step: create a long-lived access token in your Home Assistant profile > "
    "Security, then run ha-analysis login. Never paste a token into chat or an "
    "argument.\n"
)


class CredentialInputError(Exception):
    """A credential could not be read from the requested input channel."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class StoredCredentialError(Exception):
    """A stored credential could not be supplied for a requested live read."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def credential_key(origin: Origin) -> str:
    """Bind one stored entry to one normalized origin and the one v1 auth mode.

    A fixed key per origin is what makes a repeated ``login`` replace the stored
    credential in place instead of accumulating credentials. How entries are
    named is a mechanism owned by tests, not a public contract detail.
    """

    return f"{LONG_LIVED_ACCESS_TOKEN}:{origin_url(origin)}"


def read_credential(input_mode: str) -> str:
    """Read a credential through a channel that is never a process argument.

    C9: "The credential MUST NOT be accepted as a command-line argument."
    Both channels here keep it out of ``argv`` and out of shell history.
    """

    if input_mode == "stdin":
        supplied: str | None = None
        try:
            supplied = sys.stdin.readline()
        except (OSError, UnicodeError):
            # Not chained: a decoding error quotes the offending bytes, which are
            # the very material this channel exists to protect.
            supplied = None
        if supplied is None:
            raise CredentialInputError(
                "credential_input_unavailable", "The credential could not be read from stdin."
            )
        return supplied.rstrip("\r\n")
    if input_mode == "prompt":
        if not sys.stdin.isatty():
            # Refusing beats blocking on input a caller cannot supply.
            raise CredentialInputError(
                "credential_input_unavailable",
                "No interactive terminal is available; supply the credential on "
                "stdin with --token-stdin instead.",
            )
        try:
            return getpass.getpass(CREDENTIAL_PROMPT)
        except (OSError, EOFError) as error:
            raise CredentialInputError(
                "credential_input_unavailable", "The credential prompt could not be used."
            ) from error
    raise CredentialInputError(
        "invalid_credential_input_mode", "The requested credential input mode is not supported."
    )


def validate_credential(credential: object) -> str:
    """Accept only a plausible bearer credential, describing it without quoting it.

    Every message here is static. None of them reproduces the value, a substring
    of it, or its length.
    """

    if not isinstance(credential, str):
        raise CredentialInputError(
            "invalid_credential", "The supplied credential is not text."
        )
    if not credential:
        raise CredentialInputError(
            "empty_credential", "No credential was supplied, so nothing was stored."
        )
    if len(credential) > MAXIMUM_CREDENTIAL_LENGTH:
        raise CredentialInputError(
            "credential_too_long", "The supplied credential is longer than this tool accepts."
        )
    if any(not ("\x21" <= character <= "\x7e") for character in credential):
        raise CredentialInputError(
            "invalid_credential",
            "A long-lived access token contains only printable ASCII characters "
            "with no spaces or line breaks.",
        )
    return credential


class StoredCredentials:
    """Supply the stored credential to a live read through the C7 provider boundary.

    C9 permits an explicitly requested live read for the *configured* origin to
    obtain its material from the stored credential. Every other origin is
    refused here, before the secret store is touched at all.
    """

    def __init__(
        self,
        *,
        secret_store: SecretStore | None = None,
        config_home: str | os.PathLike[str] | None = None,
    ) -> None:
        self._secret_store = secret_store
        self._config_home = config_home

    def _store(self) -> SecretStore:
        if self._secret_store is None:
            self._secret_store = KeyringSecretStore()
        return self._secret_store

    def _settings(self) -> Settings:
        try:
            settings = load_settings(settings_path(self._config_home))
        except SettingsError as error:
            raise StoredCredentialError(error.code, error.message) from error
        if settings is None:
            raise StoredCredentialError(
                "not_configured",
                "No Home Assistant origin is configured; run setup and login first.",
            )
        return settings

    def endpoint(self) -> tuple[str, str]:
        """Return the configured ``(origin URL, transport mode)`` pair."""

        settings = self._settings()
        return origin_url(settings["origin"]), settings["transport_mode"]

    def credential_for(self, origin: Origin) -> str:
        """Return the credential stored for exactly this origin, or fail."""

        settings = self._settings()
        if settings["origin"] != origin:
            raise StoredCredentialError(
                "credential_origin_mismatch",
                "No credential is stored for the requested origin; the stored "
                "credential belongs to the configured origin and is not reused.",
            )
        try:
            credential = self._store().get_credential(credential_key(origin))
        except SecretStoreError as error:
            raise StoredCredentialError(error.code, str(error)) from error
        if credential is None:
            raise StoredCredentialError(
                "credential_not_stored",
                "No credential is stored for the configured origin; run login first.",
            )
        return credential


class ManagementRuntime:
    """The library-first home of every C9 management operation."""

    def __init__(
        self,
        *,
        secret_store: SecretStore | None = None,
        config_home: str | os.PathLike[str] | None = None,
    ) -> None:
        self._secret_store = secret_store
        self._config_home = config_home

    @property
    def settings_path(self) -> Path:
        """Resolve the settings path on demand; never at construction time."""

        return settings_path(self._config_home)

    def _store(self) -> SecretStore:
        # Constructed lazily so that no management path other than one that
        # genuinely needs a store ever imports keyring or wakes a backend.
        if self._secret_store is None:
            self._secret_store = KeyringSecretStore()
        return self._secret_store

    def setup(self, origin: object, transport_mode: object = "https") -> ManagementDocument:
        """Record the durable non-secret configuration for one origin.

        Never touches the secret store: configuration and credentials are
        separate acts, and a configuration change must not depend on, or fail
        because of, the availability of a store.
        """

        try:
            normalized = normalize_origin(origin, transport_mode)
        except OriginError as error:
            return _failed("setup", [_diagnostic(error.code, error.message)])

        notices: list[Diagnostic] = []
        previous: Settings | None = None
        path = None
        try:
            path = settings_path(self._config_home)
            previous = load_settings(path)
        except SettingsError as error:
            if path is None:
                return _failed("setup", [_diagnostic(error.code, error.message)])
            notices.append(
                _diagnostic(
                    "previous_settings_replaced",
                    f"The existing settings file was not usable and is being replaced ({error.code}).",
                )
            )
        settings: Settings = {
            "origin": normalized,
            "transport_mode": str(transport_mode),
            "auth_mode": LONG_LIVED_ACCESS_TOKEN,
        }
        try:
            save_settings(path, settings)
        except SettingsError as error:
            return _failed("setup", [_diagnostic(error.code, error.message)])
        _invalidate_control_trust()

        origin_changed = previous is not None and previous["origin"] != normalized
        if origin_changed:
            assert previous is not None
            notices.append(
                _diagnostic(
                    "origin_changed_credential_not_adopted",
                    "The configured origin changed. A credential stored for "
                    f"{origin_url(previous['origin'])} is not adopted for the new "
                    "origin and is never sent to it. To remove it, configure that "
                    "origin again and run logout.",
                )
            )
        if normalized["scheme"] != "https":
            notices.append(
                _diagnostic(
                    "plaintext_transport_selected",
                    "This origin is plaintext HTTP and was accepted only because "
                    "trusted_local_or_vpn was explicitly selected.",
                )
            )
        return _document(
            operation="setup",
            status="ok",
            configuration=_configuration(settings),
            details={
                "settings_path": str(path),
                "origin_changed": origin_changed,
                "credential_stored_by_setup": False,
            },
            notices=notices,
        )

    def setup_from_input(
        self,
        origin: object | None = None,
        transport_mode: object | None = None,
        *,
        interactive: bool = False,
        non_interactive: bool = False,
        emit_next_step: bool = True,
        input_stream: TextIO | None = None,
        prompt_output: TextIO | None = None,
    ) -> ManagementDocument:
        """Adapt terminal input to :meth:`setup` without adding a second setup path.

        With a supplied origin this stays parameterized unless ``interactive`` is
        explicitly requested.  With no origin, a usable terminal opts into the
        local-only prompt; non-terminal and explicitly non-interactive calls fail
        before reading input or touching settings.
        """

        input_stream = input_stream or sys.stdin
        prompt_output = prompt_output or sys.stderr
        wants_prompt = interactive or (origin is None and not non_interactive)

        if non_interactive:
            if origin is None:
                return _setup_input_failed(
                    "origin_required",
                    "A Home Assistant origin is required for non-interactive setup; "
                    "supply --origin.",
                )
            return self.setup(origin, "https" if transport_mode is None else transport_mode)

        if not wants_prompt:
            return self.setup(origin, "https" if transport_mode is None else transport_mode)

        if not _setup_terminal_is_usable(input_stream, prompt_output):
            return _setup_input_failed(
                "interactive_setup_unavailable",
                "Interactive setup requires both stdin and stderr to be terminals; "
                "supply --origin for non-interactive setup.",
            )
        if not _write_setup_message(prompt_output, SETUP_GUIDANCE):
            return _setup_input_failed(
                "setup_input_unavailable",
                "The interactive setup prompt could not be used.",
            )

        if origin is not None:
            document = self.setup(origin, "https" if transport_mode is None else transport_mode)
        else:
            document = self._setup_prompt_for_origin(
                input_stream, prompt_output, transport_mode
            )

        if (
            origin is not None
            and document["status"] == "failed"
            and transport_mode is None
            and _has_failure(document, "insecure_transport_rejected")
        ):
            document = self._setup_prompt_for_trusted_transport(
                origin, input_stream, prompt_output
            )
        if document["status"] == "ok" and emit_next_step:
            # Setup already succeeded; its durable outcome must not be rewritten as
            # a failure merely because advice could not be displayed.
            _write_setup_message(prompt_output, SETUP_NEXT_STEP)
        return document

    def _setup_prompt_for_origin(
        self, input_stream: TextIO, prompt_output: TextIO, transport_mode: object | None
    ) -> ManagementDocument:
        while True:
            supplied, failure = _read_setup_line(input_stream, prompt_output, SETUP_ORIGIN_PROMPT)
            if failure is not None:
                return failure
            assert supplied is not None
            if supplied == "":
                return _setup_input_failed(
                    "origin_required",
                    "A non-empty Home Assistant URL is required; no settings were saved.",
                )
            document = self.setup(supplied, "https" if transport_mode is None else transport_mode)
            if (
                document["status"] == "failed"
                and transport_mode is None
                and _has_failure(document, "insecure_transport_rejected")
            ):
                return self._setup_prompt_for_trusted_transport(
                    supplied, input_stream, prompt_output
                )
            if document["status"] != "failed" or not _has_failure(document, "invalid_origin"):
                return document
            message = document["failures"][0]["message"]
            if not _write_setup_message(prompt_output, f"{message} Try again.\n"):
                return _setup_input_failed(
                    "setup_input_unavailable",
                    "The interactive setup prompt could not be used.",
                )

    def _setup_prompt_for_trusted_transport(
        self, origin: object | None, input_stream: TextIO, prompt_output: TextIO
    ) -> ManagementDocument:
        while True:
            answer, failure = _read_setup_line(input_stream, prompt_output, SETUP_HTTP_PROMPT)
            if failure is not None:
                return failure
            assert answer is not None
            if answer.casefold() in {"y", "yes"}:
                return self.setup(origin, "trusted_local_or_vpn")
            if answer == "" or answer.casefold() in {"n", "no"}:
                _write_setup_message(prompt_output, "Setup cancelled; no settings were saved.\n")
                return _setup_input_failed(
                    "setup_cancelled", "Setup was cancelled; no settings were saved."
                )
            if not _write_setup_message(
                prompt_output, "Please answer y or yes to select unencrypted HTTP, or no to cancel.\n"
            ):
                return _setup_input_failed(
                    "setup_input_unavailable",
                    "The interactive setup prompt could not be used.",
                )

    def login(
        self,
        credential_input: CredentialInput | None = None,
        *,
        input_mode: str = "prompt",
    ) -> ManagementDocument:
        """Place a caller-supplied credential into the approved OS secret store.

        Makes no Home Assistant request, and never claims the credential was
        validated by one.
        """

        try:
            settings = self._require_settings()
        except _ManagementFailure as failure:
            return _failed("login", failure.failures)

        try:
            supplied = credential_input() if credential_input is not None else read_credential(input_mode)
            credential = validate_credential(supplied)
        except CredentialInputError as error:
            return _failed("login", [_diagnostic(error.code, error.message)])
        except Exception:
            # A caller-supplied input callable may carry the value in its own
            # exception; the original is deliberately not chained or quoted.
            return _failed(
                "login",
                [
                    _diagnostic(
                        "credential_input_unavailable",
                        "The credential input channel failed before anything was stored.",
                    )
                ],
            )

        origin = settings["origin"]
        key = credential_key(origin)
        try:
            store = self._store()
            backend = store.describe()
            replaced = store.has_credential(key)
            store.set_credential(key, credential)
        except SecretStoreError as error:
            # No fallback of any kind: an unusable store means nothing is stored.
            return _failed(
                "login",
                [_diagnostic(error.code, str(error))],
                notices=[
                    _diagnostic(
                        "credential_not_stored",
                        "No credential was written anywhere. This tool never falls "
                        "back to a file, an environment variable, or a plaintext store.",
                    )
                ],
            )
        _invalidate_control_trust()

        document = _document(
            operation="login",
            status="ok",
            configuration=_configuration(settings),
            details={
                "stored": True,
                "replaced_existing": replaced,
                "secret_store_backend": backend,
                "home_assistant_request_made": False,
            },
            notices=[
                _diagnostic("credential_not_validated", NOT_VALIDATED),
                _diagnostic(
                    "credential_bound_to_origin",
                    "The credential is bound to the configured origin and is never "
                    "sent to any other origin.",
                ),
            ],
        )
        return withhold_if_disclosed(document, credential)

    def status(self) -> ManagementDocument:
        """Report configuration and credential presence, and nothing secret."""

        notices: list[Diagnostic] = []
        settings: Settings | None = None
        try:
            path = settings_path(self._config_home)
            settings = load_settings(path)
        except SettingsError as error:
            return _failed("status", [_diagnostic(error.code, error.message)])
        if settings is None:
            notices.append(
                _diagnostic(
                    "not_configured",
                    "No Home Assistant origin is configured; run setup first.",
                )
            )

        backend: str | None = None
        store_available = False
        try:
            backend = self._store().describe()
            store_available = True
        except SecretStoreError as error:
            notices.append(_diagnostic(error.code, str(error)))

        credential_present: bool | None = None
        if settings is not None and store_available:
            try:
                credential_present = self._store().has_credential(credential_key(settings["origin"]))
            except SecretStoreError as error:
                notices.append(_diagnostic(error.code, str(error)))
        if credential_present is False:
            notices.append(
                _diagnostic(
                    "credential_not_stored",
                    "No credential is stored for the configured origin; run login.",
                )
            )
        return _document(
            operation="status",
            status="ok",
            configuration=_configuration(settings) if settings is not None else None,
            details={
                "settings_path": str(path),
                "configured": settings is not None,
                "secret_store_available": store_available,
                "secret_store_backend": backend,
                "credential_present": credential_present,
                "ready": settings is not None and credential_present is True,
            },
            notices=notices,
        )

    def logout(self) -> ManagementDocument:
        """Delete the locally stored credential, and say what that does not do."""

        try:
            settings = self._require_settings()
        except _ManagementFailure as failure:
            return _failed("logout", failure.failures)
        try:
            store = self._store()
            backend = store.describe()
            deleted = store.delete_credential(credential_key(settings["origin"]))
        except SecretStoreError as error:
            return _failed("logout", [_diagnostic(error.code, str(error))])
        _invalidate_control_trust()
        return _document(
            operation="logout",
            status="ok",
            configuration=_configuration(settings),
            details={
                "deleted": deleted,
                "secret_store_backend": backend,
                "server_side_revocation_performed": False,
                "home_assistant_request_made": False,
            },
            notices=[
                _diagnostic("no_server_side_revocation", NO_SERVER_SIDE_REVOCATION),
                _diagnostic(
                    "nothing_to_delete" if not deleted else "credential_deleted",
                    "No stored credential existed for the configured origin."
                    if not deleted
                    else "The stored credential for the configured origin was deleted.",
                ),
            ],
        )

    def _require_settings(self) -> Settings:
        try:
            settings = load_settings(settings_path(self._config_home))
        except SettingsError as error:
            raise _ManagementFailure([_diagnostic(error.code, error.message)]) from error
        if settings is None:
            raise _ManagementFailure(
                [
                    _diagnostic(
                        "not_configured",
                        "No Home Assistant origin is configured; run setup first.",
                    )
                ]
            )
        return settings


def _setup_terminal_is_usable(input_stream: TextIO, prompt_output: TextIO) -> bool:
    try:
        return input_stream.isatty() and prompt_output.isatty()
    except (OSError, UnicodeError):
        return False


def _write_setup_message(prompt_output: TextIO, message: str) -> bool:
    try:
        prompt_output.write(message)
        prompt_output.flush()
    except (OSError, UnicodeError):
        return False
    return True


def _read_setup_line(
    input_stream: TextIO, prompt_output: TextIO, prompt: str
) -> tuple[str | None, ManagementDocument | None]:
    if not _write_setup_message(prompt_output, prompt):
        return None, _setup_input_failed(
            "setup_input_unavailable", "The interactive setup prompt could not be used."
        )
    try:
        supplied = input_stream.readline()
    except KeyboardInterrupt:
        return None, _setup_input_failed(
            "setup_cancelled", "Setup was cancelled; no settings were saved."
        )
    except (EOFError, OSError, UnicodeError):
        return None, _setup_input_failed(
            "setup_input_unavailable",
            "Setup input could not be read; no settings were saved.",
        )
    if supplied == "":
        return None, _setup_input_failed(
            "setup_input_unavailable",
            "Setup input ended; no settings were saved.",
        )
    supplied = supplied.removesuffix("\n").removesuffix("\r")
    return supplied, None


def _has_failure(document: ManagementDocument, code: str) -> bool:
    return any(failure["code"] == code for failure in document["failures"])


def _setup_input_failed(code: str, message: str) -> ManagementDocument:
    return _failed("setup", [_diagnostic(code, message)])


def serialize_document(document: ManagementDocument) -> str:
    """Render a management document, or fail rather than emit an unknown shape."""

    if set(document) != DOCUMENT_FIELDS:
        raise ValueError("The management document does not match the closed schema.")
    return json.dumps(document, sort_keys=True, separators=(",", ":"))


def withhold_if_disclosed(document: ManagementDocument, credential: str) -> ManagementDocument:
    """Withhold a document that would disclose the credential, and say so.

    C9: "if a document cannot be produced without disclosing it, the operation
    MUST withhold that document and report the withholding."
    """

    try:
        rendered = serialize_document(document)
    except (TypeError, ValueError):
        return _withheld(
            document["operation"],
            "document_not_serializable",
            "The management document could not be rendered safely and was withheld.",
        )
    if credential and credential in rendered:
        return _withheld(
            document["operation"],
            "credential_disclosure_prevented",
            "The management document would have disclosed the credential and was withheld.",
        )
    return document


class _ManagementFailure(Exception):
    def __init__(self, failures: list[Diagnostic]) -> None:
        super().__init__("management operation failed")
        self.failures = failures


def _configuration(settings: Settings) -> ManagementConfiguration:
    return {
        "origin": dict(settings["origin"]),  # type: ignore[typeddict-item]
        "origin_url": origin_url(settings["origin"]),
        "transport_mode": settings["transport_mode"],
        "auth_mode": settings["auth_mode"],
    }


def _document(
    *,
    operation: ManagementOperationKind,
    status: str,
    configuration: ManagementConfiguration | None,
    details: dict[str, JsonValue],
    notices: list[Diagnostic] | None = None,
    failures: list[Diagnostic] | None = None,
) -> ManagementDocument:
    return {
        "contract_version": CONTRACT_VERSION,
        "document_kind": DOCUMENT_KIND,
        "operation": operation,
        "status": status,  # type: ignore[typeddict-item]
        "produced_at": utc_timestamp(),
        "configuration": configuration,
        "details": details,
        "notices": notices or [],
        "failures": failures or [],
    }


def _failed(
    operation: ManagementOperationKind,
    failures: list[Diagnostic],
    notices: list[Diagnostic] | None = None,
) -> ManagementDocument:
    return _document(
        operation=operation,
        status="failed",
        configuration=None,
        details={},
        notices=notices,
        failures=failures,
    )


def _withheld(
    operation: ManagementOperationKind, code: str, message: str
) -> ManagementDocument:
    return _document(
        operation=operation,
        status="withheld",
        configuration=None,
        details={},
        notices=[
            _diagnostic(
                "storage_outcome_unreported",
                "Because the document was withheld, this tool is not reporting the "
                "outcome of the store operation. Run status to see whether a "
                "credential is present.",
            )
        ],
        failures=[_diagnostic(code, message)],
    )


def _diagnostic(code: str, message: str) -> Diagnostic:
    return {"code": code, "message": message}
