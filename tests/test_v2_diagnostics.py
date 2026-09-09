from __future__ import annotations

import json
import socket
import struct
import threading
import time

import pytest
from ha_analysis import AnalysisRuntime
from ha_analysis.cli import main as cli_main
from ha_analysis import live
from ha_analysis.live import AuthorizationError, ResponseTooLargeError, TransportError, UrlLibEntityReader


_TEST_WEBSOCKET_KEY = b"0123456789abcdef"


@pytest.fixture(autouse=True)
def deterministic_websocket_random(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make synthetic upgrade responses able to calculate the client-key accept."""

    monkeypatch.setattr(
        live,
        "urandom",
        lambda length: _TEST_WEBSOCKET_KEY if length == 16 else b"\0" * length,
    )


class DiagnosticReader:
    def __init__(self, entries: object = None, check_error: Exception | None = None) -> None:
        self.entries = entries if entries is not None else []
        self.check_error = check_error
        self.calls: list[str] = []

    def read_entity(self, origin: object, entity_id: str, credential: str) -> object:
        self.calls.append(f"state:{entity_id}")
        return {
            "state": "on",
            "attributes": {
                "friendly_name": "Kitchen Light",
                "unit_of_measurement": "W",
                "password": "never-output",
            },
            "last_changed": "2024-01-15T10:00:00Z",
            "last_updated": "bad",
        }

    def check_connection(self, origin: object, credential: str) -> None:
        self.calls.append("check")
        if self.check_error:
            raise self.check_error

    def list_display_entities(self, origin: object, credential: str) -> list[object]:
        self.calls.append("registry")
        if isinstance(self.entries, Exception):
            raise self.entries
        return list(self.entries)


def test_check_success_and_authentication_refusal_are_explicit() -> None:
    reader = DiagnosticReader()
    accepted = AnalysisRuntime(entity_reader=reader).check_connection(
        "https://ha.example", lambda: "test-token"
    )
    assert accepted["output"] == {
        "kind": "connection_check", "api_reachable": True, "authentication": "accepted"
    }
    assert accepted["request_scope"]["request_count"] == 1
    rejected = AnalysisRuntime(entity_reader=DiagnosticReader(check_error=AuthorizationError())).check_connection(
        "https://ha.example", lambda: "test-token"
    )
    assert rejected["output"]["authentication"] == "rejected"
    assert rejected["failures"][0]["code"] == "authorization_failed"
    assert "test-token" not in json.dumps(rejected)


def test_find_requires_each_call_consent_and_never_falls_back_to_states() -> None:
    reader = DiagnosticReader([
        {"entity_id": "light.kitchen", "name": "Kitchen"},
        {"entity_id": "light.secret", "name": "Secret", "token": "leak"},
        {"entity_id": "sensor.kitchen_power", "name": "Power"},
    ])
    runtime = AnalysisRuntime(entity_reader=reader)
    refused = runtime.find_entities("https://ha.example", {"query": "kitchen"}, lambda: "token")
    assert refused["failures"][0]["code"] == "invalid_discovery_request"
    assert reader.calls == []
    result = runtime.find_entities(
        "https://ha.example",
        {"query": "kitchen", "domain": "light", "limit": 1, "inventory_consent": True},
        lambda: "token",
    )
    assert reader.calls == ["registry"]
    assert result["output"]["entities"] == [{"entity_id": "light.kitchen", "name": "Kitchen"}]
    assert result["output"]["matched_count"] == 1
    assert result["request_scope"]["inventory_received"] is True
    assert "leak" not in json.dumps(result)
    unsupported = AnalysisRuntime(entity_reader=DiagnosticReader(entries=TransportError())).find_entities(
        "https://ha.example", {"domain": "light", "inventory_consent": True}, lambda: "token"
    )
    assert unsupported["failures"][0]["code"] == "discovery_failed"
    assert unsupported["output"]["registered_count"] is None


def test_find_refuses_wildcards_bad_limits_and_empty_selection_before_transport() -> None:
    reader = DiagnosticReader()
    runtime = AnalysisRuntime(entity_reader=reader)
    for request in (
        {"query": "*", "inventory_consent": True},
        {"query": "", "inventory_consent": True},
        {"domain": "light", "limit": 101, "inventory_consent": True},
    ):
        result = runtime.find_entities("https://ha.example", request, lambda: "token")
        assert result["failures"][0]["code"] == "invalid_discovery_request"
    assert reader.calls == []


def test_find_timeout_is_explicit_and_has_no_state_list_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, float]] = []

    class TimeoutSocket:
        def settimeout(self, timeout: float) -> None:
            calls.append((None, timeout))

        def connect(self, address: object) -> None:
            calls[-1] = (address, calls[-1][1])
            raise socket.timeout()

        def close(self) -> None:
            return None

    monkeypatch.setattr(live.socket, "getaddrinfo", _single_address)
    monkeypatch.setattr(live.socket, "socket", lambda *args: TimeoutSocket())
    result = AnalysisRuntime(entity_reader=UrlLibEntityReader()).find_entities(
        "https://ha.example",
        {"query": "kitchen", "inventory_consent": True},
        lambda: "token",
    )
    assert calls[0][0] == ("127.0.0.1", 443)
    assert 0 < calls[0][1] <= 20
    assert result["failures"][0]["code"] == "discovery_failed"
    assert result["output"]["registered_count"] is None
    assert result["request_scope"]["inventory_received"] is False


def _server_frame(value: object, first: int = 0x81, masked: bool = False) -> bytes:
    payload = json.dumps(value, separators=(",", ":")).encode("utf-8")
    mask_bit = 0x80 if masked else 0
    if len(payload) < 126:
        header = bytes([first, len(payload) | mask_bit])
    else:
        assert len(payload) <= 0xFFFF
        header = bytes([first, 126 | mask_bit]) + struct.pack("!H", len(payload))
    return header + (b"\0\0\0\0" if masked else b"") + payload


def _upgrade_headers(
    *,
    status: bytes = b"HTTP/1.1 101 Switching Protocols",
    upgrade: bytes = b"websocket",
    connection: bytes = b"Upgrade",
    accept: bytes | None = None,
) -> bytes:
    """Build a synthetic RFC 6455 response tied to the deterministic client key."""

    if accept is None:
        accept = live._websocket_accept("MDEyMzQ1Njc4OWFiY2RlZg==")
    return (
        status
        + b"\r\nUpgrade: "
        + upgrade
        + b"\r\nConnection: "
        + connection
        + b"\r\nSec-WebSocket-Accept: "
        + accept
        + b"\r\n\r\n"
    )


def _registry_exchange_chunks(
    registry_result: object | None = None, upgrade_response: bytes | None = None
) -> list[bytes]:
    if registry_result is None:
        registry_result = {
            "id": 1,
            "success": True,
            "result": {
                "entities": [
                    {
                        "ei": "light.kitchen",
                        "en": "Kitchen",
                    }
                ]
            },
        }
    result = _server_frame(registry_result)
    result_chunks = [result[:2]]
    if result[1] & 0x7F == 126:
        result_chunks.append(result[2:4])
        result_chunks.append(result[4:])
    else:
        result_chunks.append(result[2:])
    return [
        upgrade_response or _upgrade_headers(),
        _server_frame({"type": "auth_required"})[:2],
        _server_frame({"type": "auth_required"})[2:],
        _server_frame({"type": "auth_ok"})[:2],
        _server_frame({"type": "auth_ok"})[2:],
        *result_chunks,
    ]


def _coalesced_registry_exchange_chunks() -> list[bytes]:
    chunks = _registry_exchange_chunks()
    return [chunks[0] + chunks[1] + chunks[2], *chunks[3:]]


def _fully_coalesced_upgrade_chunks() -> list[bytes]:
    header = _upgrade_headers()
    result = _server_frame(
        {
            "id": 1,
            "success": True,
            "result": {"entities": [{"ei": "light.kitchen", "en": "Kitchen"}]},
        }
    )
    return [
        header + _server_frame({"type": "auth_required"}) + _server_frame({"type": "auth_ok"}) + result[:5],
        result[5:],
    ]


def _single_address(*args: object, **kwargs: object) -> list[tuple[object, ...]]:
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]


class SyntheticConnection:
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks
        self.sent: list[bytes] = []
        self.timeouts: list[float] = []
        self.connected_to: list[object] = []
        self.closed = False

    def __enter__(self) -> SyntheticConnection:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def settimeout(self, timeout: float) -> None:
        self.timeouts.append(timeout)

    def connect(self, address: object) -> None:
        self.connected_to.append(address)

    def close(self) -> None:
        self.closed = True

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, size: int) -> bytes:
        return self.chunks.pop(0)


def test_find_transport_uses_plain_ws_only_for_validated_trusted_http_and_tls_for_https(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connections: list[SyntheticConnection] = []
    http = SyntheticConnection(_registry_exchange_chunks())
    connections.append(http)
    monkeypatch.setattr(live.socket, "getaddrinfo", _single_address)
    monkeypatch.setattr(live.socket, "socket", lambda *args: http)
    monkeypatch.setattr(
        live.ssl,
        "create_default_context",
        lambda: pytest.fail("trusted HTTP must not start TLS"),
    )
    http_result = AnalysisRuntime(
        entity_reader=UrlLibEntityReader(), transport_mode="trusted_local_or_vpn"
    ).find_entities(
        "http://ha.example", {"query": "kitchen", "inventory_consent": True}, lambda: "synthetic-token"
    )
    assert http_result["output"]["entities"] == [{"entity_id": "light.kitchen", "name": "Kitchen"}]
    assert len(http.sent) == 3
    assert b"Host: ha.example:80\r\n" in http.sent[0]
    assert b"Sec-WebSocket-Version: 13\r\n" in http.sent[0]

    raw = SyntheticConnection([])
    https = SyntheticConnection(_registry_exchange_chunks())
    wrapped: list[tuple[object, str]] = []

    class SyntheticTlsContext:
        def wrap_socket(self, sock: object, *, server_hostname: str) -> SyntheticConnection:
            wrapped.append((sock, server_hostname))
            return https

    monkeypatch.setattr(live.socket, "socket", lambda *args: raw)
    monkeypatch.setattr(live.ssl, "create_default_context", SyntheticTlsContext)
    https_result = AnalysisRuntime(entity_reader=UrlLibEntityReader()).find_entities(
        "https://ha.example", {"query": "kitchen", "inventory_consent": True}, lambda: "synthetic-token"
    )
    assert https_result["output"]["entities"] == [{"entity_id": "light.kitchen", "name": "Kitchen"}]
    assert wrapped == [(raw, "ha.example")]
    assert len(https.sent) == 3


def test_find_preserves_a_coalesced_upgrade_auth_frame(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = SyntheticConnection(_coalesced_registry_exchange_chunks())
    monkeypatch.setattr(live.socket, "getaddrinfo", _single_address)
    monkeypatch.setattr(live.socket, "socket", lambda *args: connection)

    result = AnalysisRuntime(
        entity_reader=UrlLibEntityReader(), transport_mode="trusted_local_or_vpn"
    ).find_entities(
        "http://ha.example", {"query": "kitchen", "inventory_consent": True}, lambda: "synthetic-token"
    )

    assert result["output"]["entities"] == [{"entity_id": "light.kitchen", "name": "Kitchen"}]
    assert len(connection.sent) == 3
    assert connection.connected_to == [("127.0.0.1", 443)]


def test_find_preserves_every_frame_after_a_fully_coalesced_upgrade(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = SyntheticConnection(_fully_coalesced_upgrade_chunks())
    monkeypatch.setattr(live.socket, "getaddrinfo", _single_address)
    monkeypatch.setattr(live.socket, "socket", lambda *args: connection)

    result = AnalysisRuntime(
        entity_reader=UrlLibEntityReader(), transport_mode="trusted_local_or_vpn"
    ).find_entities(
        "http://ha.example", {"query": "kitchen", "inventory_consent": True}, lambda: "synthetic-token"
    )

    assert result["output"]["entities"] == [{"entity_id": "light.kitchen", "name": "Kitchen"}]
    assert len(connection.sent) == 3
    assert connection.chunks == []


def test_find_projects_compact_registry_entries_and_discards_malformed_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = SyntheticConnection(
        _registry_exchange_chunks(
            {
                "id": 1,
                "success": True,
                "result": {
                    "entities": [
                        {"ei": "light.kitchen", "en": "Kitchen", "pl": "Light", "ai": "area-id"},
                        {"ei": "sensor.unnamed", "en": "", "di": "device-id"},
                        {"ei": "switch.no_display_name", "hn": "house"},
                        {"ei": "", "en": "Ignored"},
                        {"ei": 1, "en": "Ignored"},
                        {"en": "Ignored"},
                        {"ei": "light.bad_name", "en": 1},
                        {"ei": "light.null_name", "en": None},
                    ]
                },
            }
        )
    )
    monkeypatch.setattr(live.socket, "getaddrinfo", _single_address)
    monkeypatch.setattr(live.socket, "socket", lambda *args: connection)

    result = AnalysisRuntime(
        entity_reader=UrlLibEntityReader(), transport_mode="trusted_local_or_vpn"
    ).find_entities(
        "http://ha.example", {"domain": "light", "inventory_consent": True}, lambda: "synthetic-token"
    )

    assert result["output"]["entities"] == [
        {"entity_id": "light.bad_name"},
        {"entity_id": "light.kitchen", "name": "Kitchen"},
        {"entity_id": "light.null_name"},
    ]
    assert result["output"]["registered_count"] == 5
    assert "area-id" not in json.dumps(result)
    assert "device-id" not in json.dumps(result)
    assert "house" not in json.dumps(result)


@pytest.mark.parametrize("wrapper", [[], {}, {"entities": {}}])
def test_find_rejects_a_malformed_registry_result_wrapper_without_a_state_fallback(
    monkeypatch: pytest.MonkeyPatch, wrapper: object
) -> None:
    connection = SyntheticConnection(
        _registry_exchange_chunks({"id": 1, "success": True, "result": wrapper})
    )
    monkeypatch.setattr(live.socket, "getaddrinfo", _single_address)
    monkeypatch.setattr(live.socket, "socket", lambda *args: connection)

    result = AnalysisRuntime(
        entity_reader=UrlLibEntityReader(), transport_mode="trusted_local_or_vpn"
    ).find_entities(
        "http://ha.example", {"query": "kitchen", "inventory_consent": True}, lambda: "synthetic-token"
    )

    assert result["failures"][0]["code"] == "discovery_failed"
    assert result["output"]["registered_count"] is None
    assert result["request_scope"]["inventory_received"] is False
    assert len(connection.sent) == 3


@pytest.mark.parametrize(
    ("first", "masked"),
    [
        (0x01, False),
        (0xC1, False),
        (0x81, True),
    ],
    ids=["fragmented_text", "reserved_bit", "masked_server_frame"],
)
def test_find_rejects_invalid_server_frames_before_registry_command(
    monkeypatch: pytest.MonkeyPatch, first: int, masked: bool
) -> None:
    connection = SyntheticConnection(
        [
            _upgrade_headers(),
            _server_frame({"type": "auth_required"}, first=first, masked=masked),
        ]
    )
    monkeypatch.setattr(live.socket, "getaddrinfo", _single_address)
    monkeypatch.setattr(live.socket, "socket", lambda *args: connection)

    result = AnalysisRuntime(
        entity_reader=UrlLibEntityReader(), transport_mode="trusted_local_or_vpn"
    ).find_entities(
        "http://ha.example", {"query": "kitchen", "inventory_consent": True}, lambda: "synthetic-token"
    )

    assert result["failures"][0]["code"] == "discovery_failed"
    assert result["output"]["entities"] == []
    assert result["output"]["registered_count"] is None
    assert result["request_scope"]["inventory_received"] is False
    assert len(connection.sent) == 1
    assert all(b"config/entity_registry/list_for_display" not in sent for sent in connection.sent)
    assert "synthetic-token" not in json.dumps(result)


@pytest.mark.parametrize(
    "response",
    [
        _upgrade_headers().replace(b"Sec-WebSocket-Accept: ", b"X-WebSocket-Accept: "),
        _upgrade_headers(accept=b"wrong"),
        _upgrade_headers(upgrade=b"h2c"),
        _upgrade_headers(connection=b"keep-alive"),
        _upgrade_headers(status=b"HTTP/1.1 101x Switching Protocols"),
        _upgrade_headers(status=b"HTTP/1.1 101"),
        _upgrade_headers(status=b"HTTP/1.1 101\tSwitching Protocols"),
        _upgrade_headers(status=b"HTTP/1.1 101 \0"),
        _upgrade_headers(status=b"HTTP/1.0 101 Switching Protocols"),
        _upgrade_headers(status=b"HTTP/1.1 200 OK"),
    ],
    ids=[
        "missing_accept",
        "wrong_accept",
        "missing_upgrade_token",
        "missing_connection_upgrade_token",
        "malformed_status",
        "missing_status_reason_delimiter",
        "tab_instead_of_status_reason_delimiter",
        "invalid_reason_phrase_character",
        "wrong_http_version",
        "non_101_status",
    ],
)
def test_find_rejects_unverified_upgrade_before_auth_or_registry_command(
    monkeypatch: pytest.MonkeyPatch, response: bytes
) -> None:
    connection = SyntheticConnection([response])
    monkeypatch.setattr(live.socket, "getaddrinfo", _single_address)
    monkeypatch.setattr(live.socket, "socket", lambda *args: connection)

    result = AnalysisRuntime(
        entity_reader=UrlLibEntityReader(), transport_mode="trusted_local_or_vpn"
    ).find_entities(
        "http://ha.example", {"query": "kitchen", "inventory_consent": True}, lambda: "synthetic-token"
    )

    assert result["failures"][0]["code"] == "discovery_failed"
    assert result["output"]["entities"] == []
    assert result["output"]["registered_count"] is None
    assert result["request_scope"]["inventory_received"] is False
    assert len(connection.sent) == 1
    assert connection.closed is True
    assert connection.sent[0].startswith(b"GET /api/websocket HTTP/1.1\r\n")
    assert b'"type":"auth"' not in connection.sent[0]
    assert b"config/entity_registry/list_for_display" not in connection.sent[0]
    assert b"synthetic-token" not in b"".join(connection.sent)


@pytest.mark.parametrize(
    "status",
    [b"HTTP/1.1 101 Switching Protocols", b"HTTP/1.1 101 "],
    ids=["reason_phrase", "empty_reason_phrase"],
)
def test_find_accepts_http11_101_status_line_with_delimited_reason_phrase(
    monkeypatch: pytest.MonkeyPatch, status: bytes
) -> None:
    connection = SyntheticConnection(_registry_exchange_chunks(upgrade_response=_upgrade_headers(status=status)))
    monkeypatch.setattr(live.socket, "getaddrinfo", _single_address)
    monkeypatch.setattr(live.socket, "socket", lambda *args: connection)

    result = AnalysisRuntime(
        entity_reader=UrlLibEntityReader(), transport_mode="trusted_local_or_vpn"
    ).find_entities(
        "http://ha.example", {"query": "kitchen", "inventory_consent": True}, lambda: "synthetic-token"
    )

    assert result["failures"] == []
    assert result["output"]["entities"] == [{"entity_id": "light.kitchen", "name": "Kitchen"}]
    assert len(connection.sent) == 3


def test_find_renders_normalized_ipv6_host_as_http_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = SyntheticConnection(_registry_exchange_chunks())
    monkeypatch.setattr(live.socket, "getaddrinfo", _single_address)
    monkeypatch.setattr(live.socket, "socket", lambda *args: connection)

    result = AnalysisRuntime(
        entity_reader=UrlLibEntityReader(), transport_mode="trusted_local_or_vpn"
    ).find_entities(
        "http://[::1]", {"query": "kitchen", "inventory_consent": True}, lambda: "synthetic-token"
    )

    assert result["failures"] == []
    assert b"Host: [::1]:80\r\n" in connection.sent[0]


def test_find_accepts_case_insensitive_comma_separated_upgrade_tokens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _upgrade_headers(upgrade=b"h2c, WebSocket", connection=b"keep-alive, uPgRaDe")
    response = response.replace(b"Upgrade:", b"uPgRaDe:").replace(b"Connection:", b"cOnNeCtIoN:")
    connection = SyntheticConnection(_registry_exchange_chunks(upgrade_response=response))
    monkeypatch.setattr(live.socket, "getaddrinfo", _single_address)
    monkeypatch.setattr(live.socket, "socket", lambda *args: connection)

    result = AnalysisRuntime(
        entity_reader=UrlLibEntityReader(), transport_mode="trusted_local_or_vpn"
    ).find_entities(
        "http://ha.example", {"query": "kitchen", "inventory_consent": True}, lambda: "synthetic-token"
    )

    assert result["failures"] == []
    assert len(connection.sent) == 3


def test_upgrade_headers_remain_bounded_when_no_terminator_arrives() -> None:
    class OversizedHeaders:
        def settimeout(self, timeout: float) -> None:
            return None

        def recv(self, size: int) -> bytes:
            return b"x" * size

    with pytest.raises(TransportError):
        live._read_headers(OversizedHeaders(), time.monotonic() + 1)  # type: ignore[arg-type]


def test_untrusted_or_invalid_plaintext_discovery_never_requests_a_credential_or_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential_requests = 0
    socket_requests: list[object] = []

    def credential() -> str:
        nonlocal credential_requests
        credential_requests += 1
        return "synthetic-token"

    def create_socket(*args: object) -> object:
        socket_requests.append(args)
        raise AssertionError("invalid origin must fail before socket use")

    monkeypatch.setattr(live.socket, "socket", create_socket)
    runtime = AnalysisRuntime(entity_reader=UrlLibEntityReader())
    for origin in ("http://ha.example", "http://ha.example/not-an-origin"):
        result = runtime.find_entities(
            origin, {"query": "kitchen", "inventory_consent": True}, credential
        )
        assert result["failures"][0]["code"] in {"insecure_transport_rejected", "invalid_origin"}
    assert credential_requests == 0
    assert socket_requests == []
    assert "synthetic-token" not in json.dumps(result)


def test_find_enforces_one_total_deadline_across_successful_individual_operations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = 0.0

    class SlowConnection(SyntheticConnection):
        def sendall(self, data: bytes) -> None:
            nonlocal now
            super().sendall(data)
            now += 5

        def recv(self, size: int) -> bytes:
            nonlocal now
            chunk = super().recv(size)
            now += 5
            return chunk

    connection = SlowConnection(_registry_exchange_chunks())
    monkeypatch.setattr(live.time, "monotonic", lambda: now)
    monkeypatch.setattr(live.socket, "getaddrinfo", _single_address)
    monkeypatch.setattr(live.socket, "socket", lambda *args: connection)
    result = AnalysisRuntime(
        entity_reader=UrlLibEntityReader(), transport_mode="trusted_local_or_vpn"
    ).find_entities(
        "http://ha.example", {"query": "kitchen", "inventory_consent": True}, lambda: "synthetic-token"
    )
    assert result["failures"][0]["code"] == "discovery_failed"
    assert result["output"]["registered_count"] is None
    assert result["request_scope"]["inventory_received"] is False
    assert len(connection.sent) == 1
    assert all(timeout > 0 for timeout in connection.timeouts)


def test_find_deadline_bounds_delayed_resolution_without_socket_or_credential_leak(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release_resolver = threading.Event()
    resolver_finished = threading.Event()
    socket_requests: list[tuple[object, ...]] = []
    credential_requests = 0

    def delayed_resolution(*args: object, **kwargs: object) -> list[tuple[object, ...]]:
        release_resolver.wait()
        resolver_finished.set()
        return _single_address()

    def credential() -> str:
        nonlocal credential_requests
        credential_requests += 1
        return "synthetic-token"

    monkeypatch.setattr(live, "_DISCOVERY_TIMEOUT_SECONDS", 0.02)
    monkeypatch.setattr(live.socket, "getaddrinfo", delayed_resolution)
    monkeypatch.setattr(live.socket, "socket", lambda *args: socket_requests.append(args))
    started = time.monotonic()
    try:
        result = AnalysisRuntime(entity_reader=UrlLibEntityReader()).find_entities(
            "https://ha.example", {"query": "kitchen", "inventory_consent": True}, credential
        )
    finally:
        release_resolver.set()
    elapsed = time.monotonic() - started

    assert result["failures"][0]["code"] == "discovery_failed"
    assert 0.01 <= elapsed < 0.5
    assert credential_requests == 1
    assert "synthetic-token" not in json.dumps(result)
    assert socket_requests == []
    assert resolver_finished.wait(1)


def test_find_deadline_is_shared_by_each_resolved_address_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = 0.0
    timeouts: list[float] = []
    attempts: list[object] = []
    credential_requests = 0
    candidates = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 443)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 443, 0, 0)),
    ]

    class SlowFailingSocket:
        def settimeout(self, timeout: float) -> None:
            timeouts.append(timeout)

        def connect(self, address: object) -> None:
            nonlocal now
            attempts.append(address)
            now += 11
            raise socket.timeout()

        def close(self) -> None:
            return None

    def credential() -> str:
        nonlocal credential_requests
        credential_requests += 1
        return "synthetic-token"

    monkeypatch.setattr(live.time, "monotonic", lambda: now)
    monkeypatch.setattr(live.socket, "getaddrinfo", lambda *args, **kwargs: candidates)
    monkeypatch.setattr(live.socket, "socket", lambda *args: SlowFailingSocket())
    result = AnalysisRuntime(entity_reader=UrlLibEntityReader()).find_entities(
        "https://ha.example", {"query": "kitchen", "inventory_consent": True}, credential
    )

    assert result["failures"][0]["code"] == "discovery_failed"
    assert attempts == [candidate[4] for candidate in candidates]
    assert timeouts == [20, 9]
    assert now > 20
    assert credential_requests == 1
    assert "synthetic-token" not in json.dumps(result)


def test_find_deadline_is_checked_after_delayed_tls_before_any_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = 0.0
    raw = SyntheticConnection([])
    credential_requests = 0

    class DelayedTlsContext:
        def wrap_socket(self, sock: object, *, server_hostname: str) -> SyntheticConnection:
            nonlocal now
            now += 21
            return raw

    def credential() -> str:
        nonlocal credential_requests
        credential_requests += 1
        return "synthetic-token"

    monkeypatch.setattr(live.time, "monotonic", lambda: now)
    monkeypatch.setattr(live.socket, "getaddrinfo", _single_address)
    monkeypatch.setattr(live.socket, "socket", lambda *args: raw)
    monkeypatch.setattr(live.ssl, "create_default_context", DelayedTlsContext)
    result = AnalysisRuntime(entity_reader=UrlLibEntityReader()).find_entities(
        "https://ha.example", {"query": "kitchen", "inventory_consent": True}, credential
    )

    assert result["failures"][0]["code"] == "discovery_failed"
    assert now == 21
    assert credential_requests == 1
    assert raw.sent == []
    assert raw.closed is True
    assert "synthetic-token" not in json.dumps(result)


def test_find_closes_a_successfully_connected_socket_when_the_deadline_has_expired(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = 0.0
    credential_requests = 0

    class DelayedConnectSocket:
        def __init__(self) -> None:
            self.connect_attempts: list[object] = []
            self.close_calls = 0
            self.sent: list[bytes] = []

        def settimeout(self, timeout: float) -> None:
            return None

        def connect(self, address: object) -> None:
            nonlocal now
            self.connect_attempts.append(address)
            now += 21

        def close(self) -> None:
            self.close_calls += 1

        def sendall(self, data: bytes) -> None:
            self.sent.append(data)

    connection = DelayedConnectSocket()

    def credential() -> str:
        nonlocal credential_requests
        credential_requests += 1
        return "synthetic-token"

    monkeypatch.setattr(live.time, "monotonic", lambda: now)
    monkeypatch.setattr(live.socket, "getaddrinfo", _single_address)
    monkeypatch.setattr(live.socket, "socket", lambda *args: connection)
    result = AnalysisRuntime(entity_reader=UrlLibEntityReader()).find_entities(
        "https://ha.example", {"query": "kitchen", "inventory_consent": True}, credential
    )

    assert result["failures"][0]["code"] == "discovery_failed"
    assert result["output"]["registered_count"] is None
    assert result["request_scope"]["inventory_received"] is False
    assert connection.connect_attempts == [("127.0.0.1", 443)]
    assert connection.close_calls == 1
    assert connection.sent == []
    assert credential_requests == 1
    assert "synthetic-token" not in json.dumps(result)


def test_oversized_websocket_frame_is_rejected_before_body_or_json_decode() -> None:
    class HeaderOnlyConnection:
        def __init__(self) -> None:
            self.chunks = [b"\x81\x7f", struct.pack("!Q", 4 * 1024 * 1024 + 1)]

        def settimeout(self, timeout: float) -> None:
            return None

        def recv(self, size: int) -> bytes:
            return self.chunks.pop(0)

    with pytest.raises(ResponseTooLargeError):
        live._read_frame(HeaderOnlyConnection(), 4 * 1024 * 1024, time.monotonic() + 1)  # type: ignore[arg-type]


def test_outbound_websocket_frame_uses_64_bit_length_at_65536_bytes() -> None:
    class FrameSink:
        def __init__(self) -> None:
            self.timeout: float | None = None
            self.data = b""

        def settimeout(self, timeout: float) -> None:
            self.timeout = timeout

        def sendall(self, data: bytes) -> None:
            self.data = data

    empty_payload_length = len(json.dumps({"value": ""}, separators=(",", ":")).encode("utf-8"))
    sink = FrameSink()
    live._send_frame(
        sink,  # type: ignore[arg-type]
        {"value": "x" * (65536 - empty_payload_length)},
        time.monotonic() + 1,
    )
    assert sink.data[:2] == b"\x81\xff"
    assert struct.unpack("!Q", sink.data[2:10])[0] == 65536
    assert len(sink.data) == 2 + 8 + 4 + 65536

    result = AnalysisRuntime(entity_reader=DiagnosticReader(entries=ResponseTooLargeError())).find_entities(
        "https://ha.example", {"domain": "light", "inventory_consent": True}, lambda: "token"
    )
    assert result["failures"][0]["code"] == "discovery_failed"
    assert result["output"]["entities"] == []
    assert result["output"]["matched_count"] is None


def test_inspection_selected_fields_are_minimized_redacted_and_scoped() -> None:
    reader = DiagnosticReader()
    result = AnalysisRuntime(entity_reader=reader).inspect_live_entities(
        "https://ha.example", ["light.kitchen"], lambda: "token",
        attributes=["friendly_name", "password"], include_timestamps=True,
    )
    entity = result["output"]["entities"][0]
    assert entity["attributes"] == {"friendly_name": "Kitchen Light", "password": "[REDACTED]"}
    assert entity["last_changed"] == "2024-01-15T10:00:00Z"
    assert "last_updated" not in entity
    assert result["request_scope"]["attributes"] == ["friendly_name", "password"]
    assert "never-output" not in json.dumps(result)
    invalid = AnalysisRuntime(entity_reader=reader).inspect_live_entities(
        "https://ha.example", ["light.kitchen"], lambda: "token", attributes=["a.b"]
    )
    assert invalid["failures"][0]["code"] == "invalid_attributes"
    assert reader.calls == ["state:light.kitchen"]


def test_cli_aliases_delegate_to_same_runtime(capsys: object) -> None:
    runtime = AnalysisRuntime(entity_reader=DiagnosticReader())
    assert cli_main(
        ["check", "--origin", "https://ha.example"], runtime=runtime, credential_provider=lambda: "token"
    ) == 0
    assert json.loads(capsys.readouterr().out)["operation"] == "check_connection"  # type: ignore[attr-defined]
    assert cli_main(
        ["inspect", "--origin", "https://ha.example", "--targets", '["light.kitchen"]'],
        runtime=runtime, credential_provider=lambda: "token",
    ) == 0
    assert json.loads(capsys.readouterr().out)["operation"] == "inspect_live_entities"  # type: ignore[attr-defined]