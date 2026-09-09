"""Fail-closed recursive redaction for protected output and model sinks."""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence

from .types import JsonValue

MINIMUM_REDACTED_KEY_PARTS = (
    "authorization",
    "cookie",
    "password",
    "secret",
    "token",
    "api_key",
    "access_key",
    "private_key",
    "bearer",
    "latitude",
    "longitude",
    "location",
    "address",
    "code",
    "pin",
)
REDACTED_VALUE = "[REDACTED]"
_CREDENTIAL_VALUE = re.compile(
    r"(?i)(?:\bbearer\s+\S+|\b(?:api[-_ ]?key|access[-_ ]?key|token|password|passcode)\s*[:=]|\beyJ[a-z0-9_-]{10,}\.)"
)


class RedactionError(ValueError):
    """Raised when a value cannot be safely converted to JSON-equivalent data."""


def key_has_sensitive_component(key: object) -> bool:
    """Recognize full sensitive components, including camel-case and hyphen forms."""

    if not isinstance(key, str):
        return False
    split = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", key)
    words = re.sub(r"[^A-Za-z0-9]+", " ", split).casefold().split()
    parts = set(words) | {"".join(words)}
    sensitive = {
        "authorization", "cookie", "password", "secret", "token", "apikey",
        "accesskey", "privatekey", "bearer", "code", "pin", "credential", "key",
    }
    return bool(parts & sensitive) or ({"api", "key"} <= parts) or ({"access", "key"} <= parts)


def has_credential_material(value: object) -> bool:
    """Return whether JSON-like content contains credential-shaped material."""

    if isinstance(value, str):
        return bool(_CREDENTIAL_VALUE.search(value))
    if isinstance(value, Mapping):
        return any(key_has_sensitive_component(key) or has_credential_material(item) for key, item in value.items())
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)) and any(
        has_credential_material(item) for item in value
    )


def safe_text(value: object, limit: int) -> bool:
    """Bound free text and reject credential-shaped values before persistence/output."""

    return isinstance(value, str) and 0 < len(value) <= limit and "\x00" not in value and not has_credential_material(value)


def require_json(value: object) -> JsonValue:
    """Return a JSON-equivalent deep copy or fail before an unsafe sink is used."""

    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise RedactionError("Non-finite numbers are not JSON-equivalent.")
        return value
    if isinstance(value, Mapping):
        copied: dict[str, JsonValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise RedactionError("JSON object keys must be strings.")
            copied[key] = require_json(item)
        return copied
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [require_json(item) for item in value]
    raise RedactionError("Value is not JSON-equivalent.")


def redact(value: object, extra_key_parts: tuple[str, ...] = ()) -> tuple[JsonValue, int]:
    """Deep-copy and redact values selected by a minimum or caller-extended key set."""

    key_parts = MINIMUM_REDACTED_KEY_PARTS + tuple(part.lower() for part in extra_key_parts)
    return _redact(require_json(value), key_parts)


def _redact(value: JsonValue, key_parts: tuple[str, ...]) -> tuple[JsonValue, int]:
    if isinstance(value, list):
        redacted_items = [_redact(item, key_parts) for item in value]
        return [item for item, _ in redacted_items], sum(count for _, count in redacted_items)
    if isinstance(value, dict):
        copied: dict[str, JsonValue] = {}
        count = 0
        for key, item in value.items():
            if key_has_sensitive_component(key) or any(part in key.lower() for part in key_parts):
                copied[key] = REDACTED_VALUE
                count += 1
            else:
                copied[key], nested_count = _redact(item, key_parts)
                count += nested_count
        return copied, count
    return value, 0