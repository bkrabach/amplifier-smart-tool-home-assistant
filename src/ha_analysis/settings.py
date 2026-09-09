"""The durable non-secret configuration document required by C9.

C9: "Persisted settings MUST contain only the normalized origin, the explicitly
selected transport mode, and the auth mode." That is read literally here: the
document has exactly three fields and the allow-list is enforced on read *and*
on write, so a credential cannot reach this file even by mistake. There is no
schema-version field, because that would be a fourth field; an unrecognised
field is instead refused outright, which gives the same forward safety.

Writes are atomic and owner-only. Reads refuse a symlink, a non-regular file,
an unknown field, and a stored origin whose transport mode would violate C7.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import TypedDict

from .origins import TRANSPORT_MODES, OriginError, normalize_origin, origin_url
from .types import Origin

APPLICATION_DIRECTORY = "ha-analysis"
SETTINGS_FILENAME = "settings.json"
LONG_LIVED_ACCESS_TOKEN = "long_lived_access_token"
AUTH_MODES: frozenset[str] = frozenset({LONG_LIVED_ACCESS_TOKEN})
SETTINGS_FIELDS: tuple[str, ...] = ("origin", "transport_mode", "auth_mode")
ORIGIN_FIELDS: tuple[str, ...] = ("scheme", "host", "port")
DIRECTORY_MODE = 0o700
FILE_MODE = 0o600


class Settings(TypedDict):
    """The complete, closed set of durable non-secret settings."""

    origin: Origin
    transport_mode: str
    auth_mode: str


class SettingsError(Exception):
    """A settings read or write that refused to proceed, with a static code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def settings_path(config_home: str | os.PathLike[str] | None = None) -> Path:
    """Resolve the settings file under the XDG configuration home."""

    if config_home is not None:
        root = Path(config_home)
    else:
        configured = os.environ.get("XDG_CONFIG_HOME")
        # The XDG base-directory specification requires a relative value to be
        # ignored, so a stray relative setting cannot redirect the file.
        if configured and Path(configured).is_absolute():
            root = Path(configured)
        else:
            try:
                root = Path.home() / ".config"
            except RuntimeError as error:
                # An environment with no resolvable home is a settings failure,
                # never an exception that escapes an operation's own reporting.
                raise SettingsError(
                    "settings_home_unresolvable",
                    "No configuration home could be resolved for this user.",
                ) from error
    return root / APPLICATION_DIRECTORY / SETTINGS_FILENAME


def load_settings(path: Path) -> Settings | None:
    """Return validated settings, ``None`` when none are configured, or fail closed."""

    _refuse_unsafe_path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except (OSError, UnicodeError) as error:
        raise SettingsError("settings_unreadable", "The settings file could not be read.") from error
    try:
        document = json.loads(text)
    except json.JSONDecodeError as error:
        raise SettingsError("settings_malformed", "The settings file is not valid JSON.") from error
    return validate_settings(document)


def save_settings(path: Path, settings: Settings) -> None:
    """Write owner-only settings atomically, re-validating the allow-list first."""

    validated = validate_settings(dict(settings))
    _refuse_unsafe_path(path)
    directory = path.parent
    try:
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, DIRECTORY_MODE)
    except OSError as error:
        raise SettingsError(
            "settings_unwritable", "The settings directory could not be prepared."
        ) from error

    payload = json.dumps(validated, sort_keys=True, indent=2) + "\n"
    temporary = directory / f".{SETTINGS_FILENAME}.{os.getpid()}.tmp"
    try:
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, FILE_MODE
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            _remove_quietly(temporary)
            raise
        os.replace(temporary, path)
    except OSError as error:
        _remove_quietly(temporary)
        raise SettingsError(
            "settings_unwritable", "The settings file could not be written."
        ) from error


def validate_settings(document: object) -> Settings:
    """Validate the closed three-field schema, refusing anything else."""

    if not isinstance(document, dict):
        raise SettingsError("settings_malformed", "Settings must be a JSON object.")
    unknown = sorted(key for key in document if key not in SETTINGS_FIELDS)
    if unknown:
        raise SettingsError(
            "unknown_settings_field",
            f"Settings contain unsupported fields: {', '.join(unknown)}.",
        )
    missing = [key for key in SETTINGS_FIELDS if key not in document]
    if missing:
        raise SettingsError(
            "settings_incomplete", f"Settings are missing fields: {', '.join(missing)}."
        )

    transport_mode = document["transport_mode"]
    if transport_mode not in TRANSPORT_MODES:
        raise SettingsError(
            "invalid_transport_mode", "The stored transport mode is not supported."
        )
    auth_mode = document["auth_mode"]
    if auth_mode not in AUTH_MODES:
        raise SettingsError("unsupported_auth_mode", "The stored auth mode is not supported.")

    origin = _validate_origin(document["origin"], transport_mode)
    return {"origin": origin, "transport_mode": transport_mode, "auth_mode": auth_mode}


def _validate_origin(value: object, transport_mode: str) -> Origin:
    """Re-derive a stored origin through the ONE normalization implementation.

    A settings file is an editable input, not trusted state. Field-by-field
    inspection is not enough: a hand-edited host such as
    ``ha.example@attacker.example`` passes every shape check and yet renders a
    URL whose real host is ``attacker.example``, which would send a credential
    somewhere C7 never authorized. So the stored origin is rendered back to a
    URL, pushed through :func:`~ha_analysis.origins.normalize_origin`, and
    required to come back *identical*. Anything that normalization would change,
    reject, or interpret differently is refused instead.
    """

    if not isinstance(value, dict):
        raise SettingsError("invalid_origin", "The stored origin must be a JSON object.")
    unknown = sorted(key for key in value if key not in ORIGIN_FIELDS)
    if unknown:
        raise SettingsError(
            "unknown_settings_field",
            f"The stored origin contains unsupported fields: {', '.join(unknown)}.",
        )
    if any(key not in value for key in ORIGIN_FIELDS):
        raise SettingsError("invalid_origin", "The stored origin is incomplete.")
    scheme = value["scheme"]
    host = value["host"]
    port = value["port"]
    if scheme not in {"http", "https"}:
        raise SettingsError("invalid_origin", "The stored origin scheme is not supported.")
    if not isinstance(host, str) or not host:
        raise SettingsError("invalid_origin", "The stored origin host is not usable.")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise SettingsError("invalid_origin", "The stored origin port is not valid.")

    candidate: Origin = {"scheme": scheme, "host": host, "port": port}
    try:
        normalized = normalize_origin(origin_url(candidate), transport_mode)
    except OriginError as error:
        # The origin rule's own code is carried through, so a stored plaintext
        # origin without trusted_local_or_vpn still reports
        # insecure_transport_rejected rather than a generic refusal.
        raise SettingsError(error.code, f"The stored origin was refused: {error.message}") from error
    if normalized != candidate:
        raise SettingsError(
            "invalid_origin",
            "The stored origin is not in normalized form and was refused rather "
            "than reinterpreted.",
        )
    return normalized


def _refuse_unsafe_path(path: Path) -> None:
    if path.is_symlink():
        raise SettingsError(
            "unsafe_settings_path", "The settings path is a symbolic link and was refused."
        )
    if path.parent.is_symlink():
        raise SettingsError(
            "unsafe_settings_path", "The settings directory is a symbolic link and was refused."
        )
    if path.exists() and not path.is_file():
        raise SettingsError("unsafe_settings_path", "The settings path is not a regular file.")


def _remove_quietly(path: Path) -> None:
    try:
        os.unlink(path)
    except OSError:
        return
