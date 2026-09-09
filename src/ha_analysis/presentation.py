"""Safe, bounded plain-text presentation for management documents.

This module is deliberately a pure presentation boundary.  It neither reads
settings nor accesses a secret store; callers provide the document already
produced by :mod:`ha_analysis.management`.
"""

from __future__ import annotations

import textwrap
import unicodedata
from collections.abc import Mapping

from .management import DOCUMENT_FIELDS, MANAGEMENT_OPERATIONS, serialize_document
from .types import ManagementDocument

_WIDTH = 78
_CONFIGURATION_FIELDS = frozenset({"origin", "origin_url", "transport_mode", "auth_mode"})
_ORIGIN_FIELDS = frozenset({"scheme", "host", "port"})
_DIAGNOSTIC_FIELDS = frozenset({"code", "message"})

_SUMMARIZED_NOTICES = {
    "setup": {
        "plaintext_transport_selected",
    },
    "login": {
        "credential_not_validated",
        "credential_bound_to_origin",
    },
    "status": set(),
    "logout": {
        "credential_deleted",
        "no_server_side_revocation",
        "nothing_to_delete",
    },
}


def render_management_text(document: ManagementDocument) -> str:
    """Render a closed management document as concise, terminal-safe text.

    ``serialize_document`` remains the authority for the wire document's
    closed top-level schema.  The additional checks below prevent a caller
    from presenting an arbitrary mapping or diagnostic through this human
    interface.
    """

    _validate_document(document)
    if document["status"] != "ok":
        return _render_failure(document)

    operation = document["operation"]
    if operation == "setup":
        lines = _render_setup(document)
    elif operation == "login":
        lines = _render_login(document)
    elif operation == "status":
        lines = _render_status(document)
    else:
        lines = _render_logout(document)
    lines.extend(_remaining_notices(document))
    next_step = _next_step(document)
    if next_step is not None:
        lines.append(next_step)
    return "\n".join(_wrap_lines(lines))


def _validate_document(document: ManagementDocument) -> None:
    """Reject values outside the presentation boundary's closed shape."""

    serialize_document(document)
    if not isinstance(document, Mapping):
        raise ValueError("The management document does not match the closed schema.")
    if set(document) != DOCUMENT_FIELDS:
        raise ValueError("The management document does not match the closed schema.")
    if document["operation"] not in MANAGEMENT_OPERATIONS:
        raise ValueError("The management document does not match the closed schema.")
    if document["status"] not in {"ok", "failed", "withheld"}:
        raise ValueError("The management document does not match the closed schema.")
    if not isinstance(document["details"], Mapping):
        raise ValueError("The management document does not match the closed schema.")
    _validate_configuration(document["configuration"])
    for diagnostic in [*document["notices"], *document["failures"]]:
        if (
            not isinstance(diagnostic, Mapping)
            or set(diagnostic) != _DIAGNOSTIC_FIELDS
            or not isinstance(diagnostic["code"], str)
            or not isinstance(diagnostic["message"], str)
        ):
            raise ValueError("The management document does not match the closed schema.")


def _validate_configuration(configuration: object) -> None:
    if configuration is None:
        return
    if not isinstance(configuration, Mapping) or set(configuration) != _CONFIGURATION_FIELDS:
        raise ValueError("The management document does not match the closed schema.")
    origin = configuration["origin"]
    if (
        not isinstance(origin, Mapping)
        or set(origin) != _ORIGIN_FIELDS
        or not isinstance(origin["scheme"], str)
        or not isinstance(origin["host"], str)
        or isinstance(origin["port"], bool)
        or not isinstance(origin["port"], int)
    ):
        raise ValueError("The management document does not match the closed schema.")
    for field in ("origin_url", "transport_mode", "auth_mode"):
        if not isinstance(configuration[field], str):
            raise ValueError("The management document does not match the closed schema.")


def _render_setup(document: ManagementDocument) -> list[str]:
    configuration = _configuration(document)
    return [
        "Setup saved.",
        f"Server: {_safe_text(configuration['origin_url'])}",
        f"Transport: {_transport_label(configuration)}",
        "Local only: no connection test performed; no token saved.",
        "Create a long-lived access token in Home Assistant profile > Security. Never "
        "paste a token into chat or an argument.",
    ]


def _render_login(document: ManagementDocument) -> list[str]:
    configuration = _configuration(document)
    replaced = document["details"].get("replaced_existing") is True
    return [
        "Token replaced in OS secret store." if replaced else "Token stored in OS secret store.",
        f"Server: {_safe_text(configuration['origin_url'])}",
        "Not contacted or validated: no connection test performed.",
        "Bound to this server; it will not be sent elsewhere.",
    ]


def _render_status(document: ManagementDocument) -> list[str]:
    configuration = document["configuration"]
    if configuration is None:
        return [
            "Status (local configuration)",
            "Server: not configured.",
            "Token: not checked (no configured server).",
            "No connection test performed.",
        ]
    credential = document["details"].get("credential_present")
    if credential is True:
        token = "stored."
    elif credential is False:
        token = "not stored."
    elif document["details"].get("secret_store_available") is False:
        token = "unknown (OS secret store unavailable)."
    else:
        token = "unknown."
    return [
        "Status (local configuration)",
        f"Server: {_safe_text(configuration['origin_url'])}",
        f"Transport: {_transport_label(configuration)}",
        f"Token: {token}",
        "No connection test performed.",
    ]


def _render_logout(document: ManagementDocument) -> list[str]:
    configuration = _configuration(document)
    deleted = document["details"].get("deleted") is True
    return [
        "Token deleted from OS secret store." if deleted else "No local token was stored.",
        f"Server: {_safe_text(configuration['origin_url'])}",
        (
            "Local copy only: no HA revocation; the token remains valid at Home "
            "Assistant until deleted there."
        ),
        "No connection test performed.",
    ]


def _render_failure(document: ManagementDocument) -> str:
    operation = document["operation"]
    heading = (
        "Login outcome withheld."
        if document["status"] == "withheld"
        else f"{operation.capitalize()} failed."
    )
    lines = [heading]
    lines.extend(
        f"[{_safe_text(diagnostic['code'])}] {_diagnostic_text(diagnostic)}"
        for diagnostic in document["failures"]
    )
    lines.extend(_remaining_notices(document))
    next_step = _next_step(document)
    if next_step is not None:
        lines.append(next_step)
    return "\n".join(_wrap_lines(lines))


def _remaining_notices(document: ManagementDocument) -> list[str]:
    summarized = _SUMMARIZED_NOTICES[document["operation"]] if document["status"] == "ok" else set()
    return [
        f"Notice [{_safe_text(diagnostic['code'])}]: {_diagnostic_text(diagnostic)}"
        for diagnostic in document["notices"]
        if diagnostic["code"] not in summarized
    ]


def _next_step(document: ManagementDocument) -> str | None:
    diagnostics = [*document["notices"], *document["failures"]]
    codes = {diagnostic["code"] for diagnostic in diagnostics}
    if document["status"] == "ok" and document["operation"] == "setup":
        return "Next: ha-analysis login"
    if document["status"] == "ok" and document["operation"] == "login":
        return "Next: ha-analysis status"
    if document["status"] == "withheld":
        return "Next: ha-analysis status"
    if "not_configured" in codes:
        return "Next: ha-analysis setup --origin https://your-home-assistant:8123"
    if "origin_required" in codes:
        return "Next: ha-analysis setup --origin https://your-home-assistant:8123"
    if document["operation"] == "login" and "credential_input_unavailable" in codes:
        return "Next: provide the token on stdin with ha-analysis login --token-stdin"
    if document["operation"] == "status" and document["status"] == "ok":
        if document["configuration"] is None:
            return "Next: ha-analysis setup --origin https://your-home-assistant:8123"
        if document["details"].get("credential_present") is False:
            return "Next: ha-analysis login"
    if document["operation"] == "status" and "credential_not_stored" in codes:
        return "Next: ha-analysis login"
    return None


def _configuration(document: ManagementDocument) -> Mapping[str, object]:
    configuration = document["configuration"]
    if configuration is None:
        raise ValueError("The management document does not match the closed schema.")
    return configuration


def _transport_label(configuration: Mapping[str, object]) -> str:
    origin = configuration["origin"]
    assert isinstance(origin, Mapping)
    if origin["scheme"] == "https":
        return "HTTPS (encrypted)."
    if origin["scheme"] == "http" and configuration["transport_mode"] == "trusted_local_or_vpn":
        return "HTTP (unencrypted; explicitly trusted LAN/VPN)."
    return f"Unknown transport ({_safe_text(str(configuration['transport_mode']))})."


def _diagnostic_text(diagnostic: Mapping[str, object]) -> str:
    message = diagnostic["message"]
    assert isinstance(message, str)
    return _safe_text(message)


def _safe_text(value: str) -> str:
    """Make all control characters visible rather than executable by a terminal."""

    escaped: list[str] = []
    for character in value:
        if unicodedata.category(character).startswith("C"):
            escaped.append(f"\\x{ord(character):02x}")
        else:
            escaped.append(character)
    return "".join(escaped)


def _wrap_lines(lines: list[str]) -> list[str]:
    rendered: list[str] = []
    for line in lines:
        if line.startswith("Next:") or line.startswith("Then run:"):
            rendered.append(line)
            continue
        rendered.extend(
            textwrap.wrap(
                line,
                width=_WIDTH,
                break_long_words=True,
                break_on_hyphens=False,
                replace_whitespace=False,
            )
            or [""]
        )
    return rendered