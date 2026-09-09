"""Bounded read-only Home Assistant transport operations."""

from __future__ import annotations

import json
import queue
import socket
import ssl
import struct
import threading
import time
from base64 import b64encode
from hashlib import sha1
from hmac import compare_digest
from os import urandom
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .origins import origin_authority, origin_url
from .types import JsonValue, Origin


class EntityAbsentError(Exception):
    """The requested exact entity did not exist."""


class AuthorizationError(Exception):
    """Authentication or authorization failed."""


class OriginChangeError(Exception):
    """A redirect tried to move the request to another origin."""


class TransportError(Exception):
    """The exact state request did not complete safely."""


class ResponseTooLargeError(TransportError):
    """A bounded response exceeded its public operation limit."""


_DISCOVERY_TIMEOUT_SECONDS = 20.0
_WEBSOCKET_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class _PlainSocketContext:
    """Match the TLS context-manager interface without upgrading trusted HTTP."""

    def wrap_socket(
        self, sock: socket.socket, *, server_hostname: str
    ) -> socket.socket:
        return sock


class _RejectRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        raise OriginChangeError()


class UrlLibEntityReader:
    """Read one entity through ``GET /api/states/<encoded entity id>`` only."""

    def read_entity(self, origin: Origin, entity_id: str, credential: str) -> JsonValue:
        url = f"{origin_url(origin)}/api/states/{quote(entity_id, safe='')}"
        request = Request(
            url,
            method="GET",
            headers={
                "Authorization": f"Bearer {credential}",
                "Accept": "application/json",
            },
        )
        try:
            with build_opener(ProxyHandler({}), _RejectRedirect()).open(
                request, timeout=10
            ) as response:
                return json.loads(_read_limited(response, 1024 * 1024).decode("utf-8"))
        except HTTPError as error:
            if error.code == 404:
                raise EntityAbsentError() from error
            if error.code in {401, 403}:
                raise AuthorizationError() from error
            raise TransportError() from error
        except OriginChangeError:
            raise
        except (URLError, OSError, UnicodeError, json.JSONDecodeError) as error:
            raise TransportError() from error

    def check_connection(self, origin: Origin, credential: str) -> None:
        """Perform precisely one non-following authenticated ``GET /api/``."""
        request = Request(
            f"{origin_url(origin)}/api/",
            method="GET",
            headers={
                "Authorization": f"Bearer {credential}",
                "Accept": "application/json",
            },
        )
        try:
            with build_opener(ProxyHandler({}), _RejectRedirect()).open(
                request, timeout=10
            ) as response:
                payload = json.loads(
                    _read_limited(response, 1024 * 1024).decode("utf-8")
                )
            if (
                not isinstance(payload, dict)
                or payload.get("message") != "API running."
            ):
                raise TransportError()
        except HTTPError as error:
            if error.code in {401, 403}:
                raise AuthorizationError() from error
            raise TransportError() from error
        except OriginChangeError:
            raise
        except (URLError, OSError, UnicodeError, json.JSONDecodeError) as error:
            raise TransportError() from error

    def list_services(
        self, origin: Origin, credential: str, deadline: float | None = None
    ) -> JsonValue:
        """Read the runtime service catalog without proxy or redirect handling."""
        request = Request(
            f"{origin_url(origin)}/api/services",
            method="GET",
            headers={
                "Authorization": f"Bearer {credential}",
                "Accept": "application/json",
            },
        )
        timeout = (
            min(10.0, max(0.0, deadline - time.monotonic()))
            if deadline is not None
            else 10.0
        )
        if timeout <= 0:
            raise TransportError()
        try:
            with build_opener(ProxyHandler({}), _RejectRedirect()).open(
                request, timeout=timeout
            ) as response:
                result = json.loads(
                    _read_limited(response, 1024 * 1024).decode("utf-8")
                )
            if not isinstance(result, list):
                raise TransportError()
            return result
        except HTTPError as error:
            if error.code in {401, 403}:
                raise AuthorizationError() from error
            raise TransportError() from error
        except OriginChangeError:
            raise
        except (URLError, OSError, UnicodeError, json.JSONDecodeError) as error:
            raise TransportError() from error

    def list_registry(
        self, origin: Origin, credential: str
    ) -> list[dict[str, JsonValue]]:
        """Read entity/device registries and project only selector-resolution fields."""
        results = _websocket_commands(
            origin,
            credential,
            (
                "config/entity_registry/list",
                "config/device_registry/list",
                "config/area_registry/list",
                "config/label_registry/list",
            ),
        )
        entities, devices, areas, labels = results
        if (
            not all(
                isinstance(items, list) and len(items) <= 10_000 for items in results
            )
            or not isinstance(entities, list)
            or not isinstance(devices, list)
            or not isinstance(areas, list)
            or not isinstance(labels, list)
        ):
            raise TransportError()
        area_names = {
            item.get("area_id") or item.get("id"): item.get("name")
            for item in areas
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        }
        label_names = {
            item.get("label_id") or item.get("id"): item.get("name")
            for item in labels
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        }
        device_details = {
            item.get("id"): (
                item.get("area_id"),
                item.get("name_by_user") or item.get("name"),
            )
            for item in devices
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        }
        projected: list[dict[str, JsonValue]] = []
        for item in entities:
            if not isinstance(item, dict) or not isinstance(item.get("entity_id"), str):
                continue
            entity: dict[str, JsonValue] = {"entity_id": item["entity_id"]}
            name = item.get("name") or item.get("original_name")
            if isinstance(name, str):
                entity["name"] = name
            for key in ("device_id", "area_id", "labels"):
                if key in item:
                    entity[key] = item[key]
            if not isinstance(entity.get("area_id"), str) and isinstance(
                entity.get("device_id"), str
            ):
                device = device_details.get(entity["device_id"])
                if device and isinstance(device[0], str):
                    entity["area_id"] = device[0]
            if isinstance(entity.get("area_id"), str) and isinstance(
                area_names.get(entity["area_id"]), str
            ):
                entity["area_name"] = area_names[entity["area_id"]]
            if isinstance(entity.get("device_id"), str):
                device = device_details.get(entity["device_id"])
                if device and isinstance(device[1], str):
                    entity["device_name"] = device[1]
            if isinstance(entity.get("labels"), list):
                entity["label_names"] = [
                    label_names[label]
                    for label in entity["labels"]
                    if isinstance(label, str)
                    and isinstance(label_names.get(label), str)
                ]
            projected.append(entity)
        return projected

    def list_display_entities(self, origin: Origin, credential: str) -> list[JsonValue]:
        """Read one authenticated registry-display WebSocket response and close."""
        host, port = origin["host"], origin["port"]
        key = b64encode(urandom(16)).decode("ascii")
        deadline = time.monotonic() + _DISCOVERY_TIMEOUT_SECONDS
        try:
            with _connect(host, port, deadline) as raw:
                socket_context = (
                    ssl.create_default_context()
                    if origin["scheme"] == "https"
                    else _PlainSocketContext()
                )
                raw.settimeout(_remaining(deadline))
                with socket_context.wrap_socket(
                    raw, server_hostname=host
                ) as connection:
                    _remaining(deadline)
                    connection.settimeout(_remaining(deadline))
                    request = (
                        f"GET /api/websocket HTTP/1.1\r\nHost: {origin_authority(origin)}\r\n"
                        f"Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"
                        f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
                    ).encode()
                    _send(connection, request, deadline)
                    response, buffered_data = _read_headers(connection, deadline)
                    _validate_upgrade_response(response, key)
                    welcome = _read_frame(
                        connection, 4 * 1024 * 1024, deadline, buffered_data
                    )
                    if (
                        not isinstance(welcome, dict)
                        or welcome.get("type") != "auth_required"
                    ):
                        raise TransportError()
                    _send_frame(
                        connection,
                        {"type": "auth", "access_token": credential},
                        deadline,
                    )
                    auth = _read_frame(
                        connection, 4 * 1024 * 1024, deadline, buffered_data
                    )
                    if not isinstance(auth, dict) or auth.get("type") != "auth_ok":
                        raise AuthorizationError()
                    _send_frame(
                        connection,
                        {"id": 1, "type": "config/entity_registry/list_for_display"},
                        deadline,
                    )
                    result = _read_frame(
                        connection, 4 * 1024 * 1024, deadline, buffered_data
                    )
                    if (
                        not isinstance(result, dict)
                        or result.get("id") != 1
                        or not result.get("success")
                    ):
                        raise TransportError()
                    wrapper = result.get("result")
                    entries = (
                        wrapper.get("entities") if isinstance(wrapper, dict) else None
                    )
                    if not isinstance(entries, list) or len(entries) > 10000:
                        raise TransportError()
                    return [
                        display
                        for entry in entries
                        if (display := _display_entity(entry)) is not None
                    ]
        except (OSError, UnicodeError, json.JSONDecodeError, struct.error) as error:
            raise TransportError() from error


def _websocket_commands(
    origin: Origin, credential: str, commands: tuple[str, ...]
) -> list[JsonValue]:
    """Run bounded registry commands over one authenticated Home Assistant websocket."""
    key, deadline = (
        b64encode(urandom(16)).decode("ascii"),
        time.monotonic() + _DISCOVERY_TIMEOUT_SECONDS,
    )
    try:
        with _connect(origin["host"], origin["port"], deadline) as raw:
            context = (
                ssl.create_default_context()
                if origin["scheme"] == "https"
                else _PlainSocketContext()
            )
            with context.wrap_socket(raw, server_hostname=origin["host"]) as connection:
                request = (
                    f"GET /api/websocket HTTP/1.1\r\nHost: {origin_authority(origin)}\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n\r\n"
                ).encode()
                _send(connection, request, deadline)
                headers, buffered = _read_headers(connection, deadline)
                _validate_upgrade_response(headers, key)
                welcome = _read_frame(connection, 4 * 1024 * 1024, deadline, buffered)
                if not isinstance(welcome, dict) or welcome.get("type") != "auth_required":
                    raise TransportError()
                _send_frame(
                    connection, {"type": "auth", "access_token": credential}, deadline
                )
                auth = _read_frame(connection, 4 * 1024 * 1024, deadline, buffered)
                if not isinstance(auth, dict) or auth.get("type") != "auth_ok":
                    raise AuthorizationError()
                results: list[JsonValue] = []
                for index in range(1, len(commands) + 1):
                    _send_frame(
                        connection, {"id": index, "type": commands[index - 1]}, deadline
                    )
                    response = _read_frame(
                        connection, 4 * 1024 * 1024, deadline, buffered
                    )
                    if (
                        not isinstance(response, dict)
                        or response.get("id") != index
                        or response.get("success") is not True
                    ):
                        raise TransportError()
                    results.append(response.get("result"))
                return results
    except (OSError, UnicodeError, json.JSONDecodeError, struct.error) as error:
        raise TransportError() from error


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TransportError()
    return remaining


def _resolve_addresses(
    host: str, port: int, deadline: float
) -> list[tuple[object, ...]]:
    """Resolve within the discovery deadline without letting DNS extend it."""
    result: queue.Queue[tuple[list[tuple[object, ...]] | None, Exception | None]] = (
        queue.Queue(1)
    )

    def resolve() -> None:
        try:
            addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except Exception as error:
            result.put((None, error))
        else:
            result.put((addresses, None))

    worker = threading.Thread(target=resolve, daemon=True)
    worker.start()
    try:
        addresses, error = result.get(timeout=_remaining(deadline))
    except queue.Empty as error:
        raise TransportError() from error
    _remaining(deadline)
    if error is not None or not addresses:
        raise TransportError() from error
    return addresses


def _connect(host: str, port: int, deadline: float) -> socket.socket:
    """Try resolver-provided stream addresses in order under one deadline."""
    last_error: OSError | None = None
    for family, socktype, protocol, _canonname, address in _resolve_addresses(
        host, port, deadline
    ):
        connection = socket.socket(family, socktype, protocol)
        try:
            connection.settimeout(_remaining(deadline))
            connection.connect(address)
            _remaining(deadline)
            return connection
        except OSError as error:
            last_error = error
            connection.close()
            _remaining(deadline)
        except Exception:
            connection.close()
            raise
    raise TransportError() from last_error


def _send(
    connection: socket.socket | ssl.SSLSocket, data: bytes, deadline: float
) -> None:
    connection.settimeout(_remaining(deadline))
    connection.sendall(data)


def _read_limited(response: object, limit: int) -> bytes:
    data = response.read(limit + 1)  # type: ignore[attr-defined]
    if len(data) > limit:
        raise ResponseTooLargeError()
    return data


def _read_headers(
    connection: socket.socket | ssl.SSLSocket, deadline: float
) -> tuple[bytes, bytearray]:
    data = b""
    while True:
        header_end = data.find(b"\r\n\r\n")
        if header_end >= 0:
            header_end += 4
            if header_end > 16384:
                raise TransportError()
            return data[:header_end], bytearray(data[header_end:])
        chunk = _receive(connection, 1024, deadline)
        if not chunk:
            raise TransportError()
        data += chunk
        if len(data) > 16384:
            raise TransportError()


def _websocket_accept(key: str) -> bytes:
    """Calculate the RFC 6455 server accept value for a client key."""

    return b64encode(sha1(key.encode("ascii") + _WEBSOCKET_GUID).digest())


def _validate_upgrade_response(response: bytes, key: str) -> None:
    """Require a complete RFC 6455 HTTP upgrade before WebSocket authentication."""

    try:
        lines = response[:-4].decode("ascii").split("\r\n")
    except UnicodeDecodeError as error:
        raise TransportError() from error
    status_parts = lines[0].split(" ", 2) if lines else []
    if (
        len(status_parts) != 3
        or status_parts[0] != "HTTP/1.1"
        or status_parts[1] != "101"
        or any(
            character != "\t" and not " " <= character <= "~"
            for character in status_parts[2]
        )
    ):
        raise TransportError()
    headers: dict[str, list[str]] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(":")
        if not separator or not name or name != name.strip():
            raise TransportError()
        headers.setdefault(name.strip().lower(), []).append(value.strip())
    accepts = headers.get("sec-websocket-accept", [])
    expected_accept = _websocket_accept(key).decode("ascii")
    if (
        len(accepts) != 1
        or not compare_digest(accepts[0], expected_accept)
        or not _header_has_token(headers.get("upgrade", []), "websocket")
        or not _header_has_token(headers.get("connection", []), "upgrade")
    ):
        raise TransportError()


def _header_has_token(values: list[str], expected: str) -> bool:
    """Match an RFC token in one or more comma-separated header field values."""

    return any(
        token.strip().lower() == expected
        for value in values
        for token in value.split(",")
    )


def _receive(
    connection: socket.socket | ssl.SSLSocket, length: int, deadline: float
) -> bytes:
    connection.settimeout(_remaining(deadline))
    return connection.recv(length)


def _read_exact(
    connection: socket.socket | ssl.SSLSocket,
    length: int,
    deadline: float,
    buffered: bytearray | None = None,
) -> bytes:
    data = bytearray()
    if buffered:
        buffered_length = min(length, len(buffered))
        data += buffered[:buffered_length]
        del buffered[:buffered_length]
    while len(data) < length:
        chunk = _receive(connection, length - len(data), deadline)
        if not chunk:
            raise TransportError()
        data += chunk
    return bytes(data)


def _read_frame(
    connection: socket.socket | ssl.SSLSocket,
    limit: int,
    deadline: float,
    buffered: bytearray | None = None,
) -> JsonValue:
    first, second = _read_exact(connection, 2, deadline, buffered)
    if first & 0xF0 != 0x80 or second & 0x80:
        raise TransportError()
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", _read_exact(connection, 2, deadline, buffered))[0]
    elif length == 127:
        length = struct.unpack("!Q", _read_exact(connection, 8, deadline, buffered))[0]
    if (first & 0x0F) != 1:
        raise TransportError()
    if length > limit:
        raise ResponseTooLargeError()
    return json.loads(
        _read_exact(connection, length, deadline, buffered).decode("utf-8")
    )


def _display_entity(entry: JsonValue) -> dict[str, JsonValue] | None:
    """Project documented compact registry metadata into the display boundary."""
    if not isinstance(entry, dict):
        return None
    entity_id = entry.get("ei")
    if not isinstance(entity_id, str) or not entity_id:
        return None
    display: dict[str, JsonValue] = {"entity_id": entity_id}
    name = entry.get("en")
    if isinstance(name, str) and name:
        display["name"] = name
    return display


def _send_frame(
    connection: socket.socket | ssl.SSLSocket, value: object, deadline: float
) -> None:
    payload = json.dumps(value, separators=(",", ":")).encode("utf-8")
    mask = urandom(4)
    length = len(payload)
    if length < 126:
        header = bytes([0x81, 0x80 | length])
    elif length <= 0xFFFF:
        header = bytes([0x81, 0x80 | 126]) + struct.pack("!H", length)
    else:
        header = bytes([0x81, 0x80 | 127]) + struct.pack("!Q", length)
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    _send(connection, header + mask + masked, deadline)
