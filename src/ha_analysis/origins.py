"""The single origin-normalization and transport-gate implementation.

C7 states the transport rule for a live read and C9 requires ``setup`` to apply
"the same transport rule C7 states". A second copy of that rule is a second
place for it to drift, so the rule exists here exactly once and both the
live-read path (:mod:`ha_analysis.api`) and the management path
(:mod:`ha_analysis.management`) call into it.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from .types import Origin

TRANSPORT_MODES: frozenset[str] = frozenset({"https", "trusted_local_or_vpn"})
DEFAULT_PORTS: dict[str, int] = {"https": 443, "http": 80}
MINIMUM_PORT = 1
MAXIMUM_PORT = 65535
MAXIMUM_HOST_LENGTH = 253
MAXIMUM_LABEL_LENGTH = 63

#: One DNS label: ASCII letters, digits, and inner hyphens only. Deliberately
#: strict - ``urlparse`` accepts a host containing a space, a NUL, or a
#: homograph character without complaint, and silently *strips* a tab, so the
#: parser alone cannot be trusted to say what a host is.
_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


class OriginError(ValueError):
    """A rejected origin or transport mode carrying a static, credential-free code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def transport_permits(origin: Origin, transport_mode: str) -> bool:
    """Apply C7's transport rule: plaintext requires an explicit trusted mode."""

    return origin["scheme"] == "https" or transport_mode == "trusted_local_or_vpn"


def normalize_origin(origin: object, transport_mode: object) -> Origin:
    """Return the normalized origin tuple, or raise :class:`OriginError`.

    The checks run in a fixed order so that a caller who supplies both an
    unsupported transport mode and a malformed origin is told about the
    transport mode first, exactly as the live path has always behaved.
    """

    if transport_mode not in TRANSPORT_MODES:
        raise OriginError("invalid_transport_mode", "Transport mode is not supported.")
    if not isinstance(origin, str):
        raise OriginError("invalid_origin", "Origin must be an absolute HTTP or HTTPS URL.")
    if any(character in origin for character in "\t\r\n"):
        # urlparse silently DELETES these before parsing, so "ha.exam<TAB>ple"
        # would otherwise be accepted as "ha.example". Refuse the input rather
        # than quietly binding a credential to a host nobody typed.
        raise OriginError("invalid_origin", "Origin contains a tab or line break.")
    try:
        # A malformed authority - an unbalanced or non-address bracket such as
        # "https://[abc]", "https://[::1", or "https://ha]" - makes urlparse
        # itself raise. That is a rejected origin, not a crash.
        parsed = urlparse(origin)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise OriginError("invalid_origin", "Origin is not a well-formed URL.") from error
    if (
        parsed.scheme not in DEFAULT_PORTS
        or not hostname
        or parsed.username
        or parsed.password
        or parsed.params
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise OriginError("invalid_origin", "Origin must be a scheme, host, and optional port only.")
    if port is not None and not MINIMUM_PORT <= port <= MAXIMUM_PORT:
        raise OriginError("invalid_origin", "Origin port is invalid.")
    normalized: Origin = {
        "scheme": parsed.scheme,
        "host": normalize_host(hostname),
        "port": port if port is not None else DEFAULT_PORTS[parsed.scheme],
    }
    if not transport_permits(normalized, str(transport_mode)):
        raise OriginError(
            "insecure_transport_rejected", "HTTP requires trusted_local_or_vpn transport mode."
        )
    return normalized


def normalize_host(hostname: str) -> str:
    """Return a lowercase host that is definitely a DNS name, IPv4, or IPv6 literal.

    ``urlparse`` is not a validator: it accepts a host containing a space, a
    NUL, or a Cyrillic homograph, and silently strips a tab. Since the host is
    what binds a stored credential and what a request is actually sent to, it is
    checked positively here rather than assumed.
    """

    host = hostname.lower()
    if not host or len(host) > MAXIMUM_HOST_LENGTH:
        raise OriginError("invalid_origin", "Origin host is missing or too long.")
    if not host.isascii():
        # Refused rather than guessed at: an internationalized name must be
        # supplied already punycode-encoded, so a homograph cannot masquerade
        # as the origin a credential is bound to.
        raise OriginError(
            "invalid_origin",
            "Origin host must be ASCII; supply an internationalized name in its "
            "punycode form.",
        )
    if any(character <= " " or character == "\x7f" for character in host):
        raise OriginError("invalid_origin", "Origin host contains a space or control character.")
    if ":" in host:
        # Only an IPv6 literal may contain a colon at this point; urlparse has
        # already removed the brackets and any port.
        address, separator, zone = host.partition("%")
        try:
            parsed_address = ipaddress.ip_address(address)
        except ValueError as error:
            raise OriginError("invalid_origin", "Origin host is not a valid IP address.") from error
        if parsed_address.version != 6:
            raise OriginError("invalid_origin", "Origin host is not a valid IP address.")
        if separator and not zone:
            raise OriginError("invalid_origin", "Origin host has an empty IPv6 zone identifier.")
        return host
    if any(character in host for character in "[]@/?#\\"):
        raise OriginError("invalid_origin", "Origin host contains a character that is not allowed.")
    if all(part.isdigit() for part in host.split(".")) and host.count(".") == 3:
        try:
            ipaddress.IPv4Address(host)
        except ValueError as error:
            raise OriginError("invalid_origin", "Origin host is not a valid IP address.") from error
        return host
    labels = host.split(".")
    if host.endswith("."):  # One trailing root dot is legal; an empty label is not.
        labels = labels[:-1]
    if not labels or any(
        not label or len(label) > MAXIMUM_LABEL_LENGTH or not _LABEL.fullmatch(label)
        for label in labels
    ):
        raise OriginError("invalid_origin", "Origin host is not a valid host name.")
    return host


def origin_url(origin: Origin) -> str:
    """Render the canonical origin string used for URLs and credential binding."""

    return f"{origin['scheme']}://{origin_authority(origin)}"


def origin_authority(origin: Origin) -> str:
    """Render a normalized origin as an HTTP ``Host`` authority."""

    host = origin["host"]
    rendered_host = f"[{host}]" if ":" in host else host
    return f"{rendered_host}:{origin['port']}"
