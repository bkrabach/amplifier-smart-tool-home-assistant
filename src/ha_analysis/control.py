"""Direct, revocable Home Assistant household control."""

from __future__ import annotations

import copy
import hashlib
import inspect
import json
import math
import os
import queue
import re
import socket
import ssl
import stat
import time
import threading
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol

from .clock import utc_timestamp
from .live import (
    EntityAbsentError,
    TransportError,
    UrlLibEntityReader,
    _resolve_addresses,
)
from .management import StoredCredentialError, StoredCredentials
from .origins import OriginError, normalize_origin, origin_authority
from .redaction import has_credential_material, key_has_sensitive_component

CONTRACT_VERSION = "home-assistant.v1"
DOCUMENT_FIELDS = frozenset(
    {
        "contract_version",
        "document_kind",
        "operation",
        "status",
        "produced_at",
        "details",
        "warnings",
        "failures",
    }
)
_ENTITY_ID = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")
_SERVICE = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")
_MAX_TARGETS = 128
_MAX_DATA_BYTES = 16 * 1024
_MAX_STATE_BYTES = 64 * 1024
_MAX_OBSERVATION_SECONDS = 10.0
_SAFE_DOMAINS = frozenset(
    {
        "light",
        "switch",
        "fan",
        "climate",
        "cover",
        "lock",
        "alarm_control_panel",
        "media_player",
        "vacuum",
        "scene",
        "script",
        "automation",
        "group",
        "input_boolean",
        "input_number",
        "input_select",
        "input_text",
        "input_datetime",
        "input_button",
        "number",
        "select",
        "button",
        "counter",
        "humidifier",
        "water_heater",
        "valve",
        "siren",
        "remote",
        "timer",
    }
)
_ADMIN_ACTIONS = frozenset(
    {
        "reload",
        "restart",
        "check_config",
        "save",
        "configure",
        "create",
        "delete",
        "install",
        "update",
        "token",
        "auth",
        "shell",
        "command",
    }
)
_SECRET_KEYS = frozenset(
    {
        "pin",
        "code",
        "password",
        "passcode",
        "token",
        "access_token",
        "api_key",
        "access_key",
        "private_key",
        "authorization",
        "cookie",
        "secret",
        "credential",
    }
)
_TARGET_KEYS = frozenset(
    {"entity_id", "area_id", "device_id", "label_id", "floor_id", "target"}
)
_OBSERVED_ATTRIBUTES = frozenset(
    {
        "rgb_color",
        "xy_color",
        "hs_color",
        "brightness",
        "effect",
        "color_temp",
        "color_temp_kelvin",
        "percentage",
        "temperature",
        "hvac_mode",
        "current_temperature",
        "volume_level",
        "current_activity",
    }
)


class ServiceTransport(Protocol):
    def post_service(
        self,
        origin: dict[str, Any],
        domain: str,
        service: str,
        payload: dict[str, Any],
        credential: str,
        deadline: float | None = None,
    ) -> None: ...


class ServiceRejectedError(TransportError):
    """A non-2xx service response; a possible partial effect remains unknown."""


class UrlLibServiceTransport:
    """One direct, proxy-free and retry-free POST under a shared ten-second deadline."""

    def post_service(
        self,
        origin: dict[str, Any],
        domain: str,
        service: str,
        payload: dict[str, Any],
        credential: str,
        deadline: float | None = None,
    ) -> None:
        body = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
        if len(body) > _MAX_DATA_BYTES + 2048:
            raise TransportError()
        deadline = min(
            deadline if deadline is not None else float("inf"),
            time.monotonic() + _MAX_OBSERVATION_SECONDS,
        )
        connection: socket.socket | ssl.SSLSocket | None = None
        try:
            for family, socktype, protocol, _canon, address in _resolve_addresses(
                origin["host"], origin["port"], deadline
            ):
                raw = socket.socket(family, socktype, protocol)
                try:
                    raw.settimeout(_remaining(deadline))
                    raw.connect(address)
                    connection = (
                        ssl.create_default_context().wrap_socket(
                            raw, server_hostname=origin["host"]
                        )
                        if origin["scheme"] == "https"
                        else raw
                    )
                    break
                except OSError:
                    raw.close()
            if connection is None:
                raise TransportError()
            request = (
                f"POST /api/services/{domain}/{service} HTTP/1.1\r\n"
                f"Host: {origin_authority(origin)}\r\n"
                f"Authorization: Bearer {credential}\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            ).encode("ascii") + body
            connection.settimeout(_remaining(deadline))
            connection.sendall(request)
            header = _read_header(connection, deadline)
            match = re.match(rb"HTTP/1\.[01] ([0-9]{3}) ", header)
            if not match:
                raise TransportError()
            if not 200 <= int(match.group(1)) < 300:
                raise ServiceRejectedError()
        except (TransportError, ServiceRejectedError):
            raise
        except (OSError, UnicodeError, ValueError) as error:
            raise TransportError() from error
        finally:
            if connection is not None:
                connection.close()


def _post_service(
    transport: ServiceTransport,
    endpoint: dict[str, Any],
    domain: str,
    service: str,
    payload: dict[str, Any],
    credential: str,
    deadline: float | None,
) -> None:
    """Pass an absolute deadline to the built-in transport without breaking seams."""

    if deadline is not None and time.monotonic() >= deadline:
        raise TransportError()
    if "deadline" in _parameters(transport.post_service):
        transport.post_service(endpoint, domain, service, payload, credential, deadline)
    else:
        transport.post_service(endpoint, domain, service, payload, credential)


def _parameters(callable_value: Any) -> Mapping[str, inspect.Parameter]:
    """Read a callable signature without invoking an injected seam."""

    try:
        return inspect.signature(callable_value).parameters
    except (TypeError, ValueError):
        return {}


class TrustStore:
    """Owner-only local grant state, storing a SHA-256 credential identity only."""

    def __init__(self, state_home: str | os.PathLike[str] | None = None) -> None:
        self.path = _state_path(state_home, "control-trust.json")

    def enable(self, binding: dict[str, str]) -> None:
        self._write({"enabled": True, "binding": binding})

    def disable(self) -> None:
        self._write({"enabled": False})

    def status(self, binding: dict[str, str] | None = None) -> str:
        try:
            value = self._read()
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
            return "unavailable"
        if not isinstance(value, Mapping) or set(value) - {"enabled", "binding"}:
            return "unavailable"
        if value.get("enabled") is not True:
            return "disabled"
        if not isinstance(value.get("binding"), Mapping):
            return "unavailable"
        return (
            "enabled"
            if binding is not None and value["binding"] == binding
            else "binding_mismatch"
        )

    def _read(self) -> object:
        _check_private_path(self.path, allow_absent=True, size_limit=4096)
        try:
            with open(self.path, "rb") as handle:
                return json.loads(handle.read(_MAX_STATE_BYTES).decode("utf-8"))
        except FileNotFoundError:
            return {"enabled": False}

    def _write(self, value: dict[str, Any]) -> None:
        _prepare_private_directory(self.path.parent)
        _check_private_path(self.path, allow_absent=True, size_limit=4096)
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        temporary = self.path.with_name(
            f".{self.path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
        )
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            os.chmod(self.path, 0o600)
        except BaseException:
            try:
                temporary.unlink()
            except OSError:
                pass
            raise


def invalidate_control_trust(state_home: str | os.PathLike[str] | None = None) -> None:
    """Invalidate local trust after deliberate setup/login/logout changes."""
    TrustStore(state_home).disable()


class OperationJournal:
    """Durable append-only, owner-only redacted operation records."""

    def __init__(self, state_home: str | os.PathLike[str] | None = None) -> None:
        self.path = _state_path(state_home, "operations.jsonl")

    def record(self, value: dict[str, Any]) -> None:
        _prepare_private_directory(self.path.parent)
        _check_private_path(self.path, allow_absent=True, size_limit=1024 * 1024)
        encoded = (
            json.dumps(
                value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("utf-8")
            + b"\n"
        )
        descriptor = os.open(
            self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600
        )
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                raise OSError("unsafe operation journal")
            os.write(descriptor, encoded)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


class ControlRuntime:
    """Shared library for trust, runtime discovery, resolution, and direct invocation."""

    def __init__(
        self,
        *,
        stored_credentials: Any | None = None,
        entity_reader: Any | None = None,
        service_transport: ServiceTransport | None = None,
        trust_store: TrustStore | None = None,
        journal: OperationJournal | None = None,
        state_home: str | os.PathLike[str] | None = None,
        **_old: Any,
    ) -> None:
        self._credentials = stored_credentials or StoredCredentials()
        self._reader = entity_reader or UrlLibEntityReader()
        self._transport = service_transport or UrlLibServiceTransport()
        self._trust = trust_store or TrustStore(state_home)
        self._journal = journal or OperationJournal(state_home)

    def enable_control(self) -> dict[str, Any]:
        binding, failure = self._binding()
        if failure:
            return _document(
                "enable_control",
                "failed",
                {"trust": "disabled"},
                failures=[_failure(failure)],
            )
        try:
            self._trust.enable(binding)
        except OSError:
            return _document(
                "enable_control",
                "failed",
                {"trust": "disabled"},
                failures=[_failure("trust_unavailable")],
            )
        return _document("enable_control", "ok", {"trust": "enabled"})

    def disable_control(self) -> dict[str, Any]:
        try:
            self._trust.disable()
        except OSError:
            return _document(
                "disable_control",
                "failed",
                {"trust": "unknown"},
                failures=[_failure("trust_unavailable")],
            )
        return _document("disable_control", "ok", {"trust": "disabled"})

    def control_status(self) -> dict[str, Any]:
        binding, failure = self._binding()
        state = "disabled" if failure else self._trust.status(binding)
        return _document(
            "control_status",
            "ok",
            {
                "trust": "enabled" if state == "enabled" else "disabled",
                "reason": failure or state,
            },
        )

    def list_actions(self, domain: str | None = None) -> dict[str, Any]:
        endpoint, credential, failure = self._endpoint()
        if failure:
            return _document(
                "list_actions", "failed", {"actions": []}, failures=[_failure(failure)]
            )
        catalog = self._catalog(endpoint, credential)
        if catalog is None:
            return _document(
                "list_actions",
                "failed",
                {"actions": []},
                failures=[_failure("service_catalog_unavailable")],
            )
        return _document(
            "list_actions",
            "ok",
            {
                "actions": [
                    _project_action(name, spec)
                    for name, spec in sorted(catalog.items())
                    if domain is None or name.startswith(domain + ".")
                ]
            },
        )

    def find(self, query: object) -> dict[str, Any]:
        if not isinstance(query, str) or not query.strip() or len(query) > 160:
            return _document(
                "find", "failed", {"matches": []}, failures=[_failure("invalid_query")]
            )
        endpoint, credential, failure = self._endpoint()
        entries = None if failure else self._registry(endpoint, credential)
        if entries is None:
            return _document(
                "find",
                "failed",
                {"matches": []},
                failures=[_failure(failure or "registry_unavailable")],
            )
        needle = query.casefold()
        matches = [
            _public_entity(item)
            for item in entries
            if needle in item["entity_id"].casefold()
            or needle in str(item.get("name", "")).casefold()
        ]
        return _document("find", "ok", {"matches": matches[:_MAX_TARGETS]})

    def resolve(self, selector: object) -> dict[str, Any]:
        endpoint, credential, failure = self._endpoint()
        targets, failure = (
            (None, failure)
            if failure
            else self._resolve(selector, endpoint, credential)
        )
        details: dict[str, Any] = {"targets": targets or []}
        if failure == "ambiguous_target_name":
            details["candidates"] = self._name_candidates(
                selector, endpoint, credential
            )
        return _document(
            "resolve",
            "ok" if failure is None else "failed",
            details,
            failures=[] if failure is None else [_failure(failure)],
        )

    def invoke(
        self,
        service: object,
        targets: object = None,
        selector: object = None,
        data: object = None,
        dry_run: bool = False,
        *,
        deadline: float | None = None,
    ) -> dict[str, Any]:
        operation_id = str(uuid.uuid4())
        if deadline is not None and time.monotonic() >= deadline:
            return self._refuse(operation_id, "operation_deadline_elapsed")
        parsed, service_failure = _validate_service(service)
        safe_data, data_failure = _validate_data(data)
        if (targets is None) == (selector is None):
            return self._refuse(operation_id, "exactly_one_target_source_required")
        if service_failure or data_failure or not isinstance(dry_run, bool):
            return self._refuse(
                operation_id, service_failure or data_failure or "invalid_dry_run"
            )
        assert parsed is not None and safe_data is not None
        endpoint, credential, endpoint_failure = self._endpoint()
        if endpoint_failure:
            return self._refuse(operation_id, endpoint_failure)
        binding = _binding(endpoint, credential)
        if self._trust.status(binding) != "enabled":
            return self._refuse(operation_id, "control_not_trusted")
        catalog = self._catalog(endpoint, credential, deadline)
        if catalog is None or parsed not in catalog:
            return self._refuse(operation_id, "service_not_registered")
        if deadline is not None and time.monotonic() >= deadline:
            return self._refuse(operation_id, "operation_deadline_elapsed")
        if _requires_response(catalog[parsed]):
            return self._refuse(operation_id, "service_response_unsupported")
        domain, action = parsed.split(".", 1)
        direct_script = domain == "script" and action not in {
            "turn_on",
            "turn_off",
            "toggle",
        }
        resolved, resolution_failure = self._resolve_for_service(
            targets if targets is not None else selector,
            endpoint,
            credential,
            domain,
            direct_script,
            action,
        )
        if resolution_failure:
            return self._refuse(operation_id, resolution_failure)
        assert resolved is not None
        if not direct_script and not resolved:
            return self._refuse(operation_id, "empty_targets")
        preflight_failure, group_warning = self._preflight(
            endpoint, credential, resolved, domain, safe_data, direct_script, deadline
        )
        if preflight_failure:
            return self._refuse(operation_id, preflight_failure)
        actual_service = parsed
        if direct_script:
            actual_service = f"script.{action}"
            payload = safe_data
            public_targets = [actual_service]
        else:
            payload = {"entity_id": resolved, **safe_data}
            public_targets = resolved
        warnings = []
        if domain in {"script", "scene", "automation"} or group_warning:
            warnings.append(_failure("opaque_ha_side_fanout"))
        details = {
            "operation_id": operation_id,
            "service": actual_service,
            "targets": public_targets,
            "dry_run": dry_run,
        }
        if dry_run:
            return _document(
                "invoke", "ok", {**details, "outcome": "dry_run"}, warnings=warnings
            )
        if not self._still_trusted(endpoint, credential, binding):
            return self._refuse(operation_id, "control_trust_changed", warnings)
        if deadline is not None and time.monotonic() >= deadline:
            return self._refuse(operation_id, "operation_deadline_elapsed", warnings)
        try:
            self._journal.record(
                {
                    **details,
                    "parameters": safe_data,
                    "result": "intent_recorded",
                    "at": utc_timestamp(),
                }
            )
        except OSError:
            return _document(
                "invoke",
                "failed",
                {**details, "outcome": "not_dispatched"},
                warnings=warnings,
                failures=[_failure("audit_unavailable")],
            )
        # Journal writes can block: a second current binding read closes that gap before POST.
        if not self._still_trusted(endpoint, credential, binding):
            return _document(
                "invoke",
                "failed",
                {**details, "outcome": "not_dispatched"},
                warnings=warnings,
                failures=[_failure("control_trust_changed")],
            )
        if deadline is not None and time.monotonic() >= deadline:
            return _document(
                "invoke",
                "failed",
                {**details, "outcome": "not_dispatched"},
                warnings=warnings,
                failures=[_failure("operation_deadline_elapsed")],
            )
        try:
            _post_service(
                self._transport, endpoint, domain, action, payload, credential, deadline
            )
        except Exception:
            completion_warning = self._record_completion(
                operation_id, "outcome_unknown"
            )
            return _document(
                "invoke",
                "outcome_unknown",
                {**details, "outcome": "outcome_unknown"},
                warnings=warnings + [_failure("delivery_unknown")] + completion_warning,
            )
        observations = self._observe(
            endpoint, credential, resolved, parsed, safe_data, direct_script, deadline
        )
        effect = _effect(observations, direct_script)
        completion_warning = self._record_completion(operation_id, effect)
        return _document(
            "invoke",
            "ok",
            {
                **details,
                "outcome": "accepted",
                "effect": effect,
                "observations": observations,
            },
            warnings=warnings + completion_warning,
        )

    def plan_action(self, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return _document(
            "plan_action",
            "failed",
            {"outcome": "not_dispatched"},
            failures=[_failure("migrated_to_invoke")],
        )

    def execute_action(self, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return _document(
            "execute_action",
            "failed",
            {"outcome": "not_dispatched"},
            failures=[_failure("migrated_to_invoke")],
        )

    def action_status(self, plan_id: object) -> dict[str, Any]:
        from .control_journal import read_legacy_plan_status

        status = read_legacy_plan_status(plan_id)
        return _document(
            "action_status",
            "ok" if status is not None else "failed",
            {"status": status},
            failures=[] if status is not None else [_failure("legacy_plan_absent")],
        )

    def _refuse(
        self,
        operation_id: str,
        reason: str,
        warnings: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        try:
            self._journal.record(
                {
                    "operation_id": operation_id,
                    "result": "refused",
                    "reason": reason,
                    "at": utc_timestamp(),
                }
            )
        except OSError:
            return _document(
                "invoke",
                "failed",
                {"operation_id": operation_id, "outcome": "not_dispatched"},
                warnings=warnings,
                failures=[_failure("audit_unavailable")],
            )
        return _document(
            "invoke",
            "failed",
            {"operation_id": operation_id, "outcome": "not_dispatched"},
            warnings=warnings,
            failures=[_failure(reason)],
        )

    def _endpoint(self) -> tuple[dict[str, Any] | None, str | None, str | None]:
        try:
            url, transport = self._credentials.endpoint()
            endpoint = {**normalize_origin(url, transport), "transport_mode": transport}
            credential = self._credentials.credential_for(
                {key: endpoint[key] for key in ("scheme", "host", "port")}
            )
            return endpoint, credential, None
        except (StoredCredentialError, OriginError):
            return None, None, "configuration_unavailable"
        except Exception:
            return None, None, "credential_unavailable"

    def _binding(self) -> tuple[dict[str, str] | None, str | None]:
        endpoint, credential, failure = self._endpoint()
        return (None, failure) if failure else (_binding(endpoint, credential), None)

    def _still_trusted(
        self, endpoint: dict[str, Any], credential: str, binding: dict[str, str]
    ) -> bool:
        current_endpoint, current_credential, failure = self._endpoint()
        return (
            not failure
            and current_endpoint == endpoint
            and current_credential == credential
            and self._trust.status(binding) == "enabled"
        )

    def _catalog(
        self, endpoint: dict[str, Any], credential: str, deadline: float | None = None
    ) -> dict[str, Mapping[str, Any]] | None:
        try:
            kwargs: dict[str, object] = {}
            if deadline is not None and "deadline" in _parameters(self._reader.list_services):
                kwargs["deadline"] = deadline
            raw = self._reader.list_services(_origin(endpoint), credential, **kwargs)
        except Exception:
            return None
        return _catalog(raw)

    def _registry(
        self, endpoint: dict[str, Any], credential: str
    ) -> list[dict[str, Any]] | None:
        try:
            raw = self._reader.list_registry(_origin(endpoint), credential)
        except Exception:
            return None
        if not isinstance(raw, list) or len(raw) > 10_000:
            return None
        return [
            dict(item)
            for item in raw
            if isinstance(item, Mapping)
            and _ENTITY_ID.fullmatch(str(item.get("entity_id", "")))
            and item.get("disabled_by") is None
        ]

    def _resolve(
        self, value: object, endpoint: dict[str, Any], credential: str
    ) -> tuple[list[str] | None, str | None]:
        if isinstance(value, Sequence) and not isinstance(
            value, (str, bytes, bytearray)
        ):
            items = list(value)
            if (
                not 1 <= len(items) <= _MAX_TARGETS
                or any(
                    not isinstance(item, str) or not _ENTITY_ID.fullmatch(item)
                    for item in items
                )
                or len(set(items)) != len(items)
            ):
                return None, "invalid_targets"
            return items, None
        if not isinstance(value, Mapping) or len(value) != 1:
            return None, "invalid_selector"
        key, wanted = next(iter(value.items()))
        if key == "entity_id" and isinstance(wanted, str):
            return self._resolve([wanted], endpoint, credential)
        if key == "entity_id":
            return self._resolve(wanted, endpoint, credential)
        if (
            key not in {"name", "area_id", "device_id", "label_id"}
            or not isinstance(wanted, str)
            or not wanted
        ):
            return None, "invalid_selector"
        entries = self._registry(endpoint, credential)
        if entries is None:
            return None, "registry_unavailable"
        wanted_folded = wanted.casefold()

        def matches(entry: Mapping[str, Any]) -> bool:
            if key == "name":
                return (
                    isinstance(entry.get("name"), str)
                    and entry["name"].casefold() == wanted_folded
                )
            if key == "label_id":
                return (
                    wanted == entry.get("label_id")
                    or wanted in entry.get("labels", [])
                    or wanted_folded
                    in [
                        name.casefold()
                        for name in entry.get("label_names", [])
                        if isinstance(name, str)
                    ]
                )
            return (
                wanted == entry.get(key)
                or wanted_folded
                == str(entry.get(key.replace("_id", "_name"), "")).casefold()
            )

        found = sorted(entry["entity_id"] for entry in entries if matches(entry))
        if key == "name" and len(found) > 1:
            return None, "ambiguous_target_name"
        if not found:
            return None, "empty_targets"
        return (
            (found, None) if len(found) <= _MAX_TARGETS else (None, "too_many_targets")
        )

    def _resolve_for_service(
        self,
        value: object,
        endpoint: dict[str, Any],
        credential: str,
        domain: str,
        direct_script: bool,
        action: str,
    ) -> tuple[list[str] | None, str | None]:
        if direct_script:
            expected = f"script.{action}"
            if value == []:
                return [expected], None
            targets, failure = self._resolve(value, endpoint, credential)
            if failure:
                return None, failure
            return (
                ([expected], None)
                if targets == [expected]
                else (None, "script_targets_conflict")
            )
        targets, failure = self._resolve(value, endpoint, credential)
        if failure:
            return None, failure
        assert targets is not None
        if domain == "homeassistant":
            return targets, None
        if isinstance(value, Mapping) and next(iter(value)) in {
            "area_id",
            "device_id",
            "label_id",
        }:
            targets = [
                target
                for target in targets
                if target.startswith((domain + ".", "group."))
            ]
            return (targets, None) if targets else (None, "empty_compatible_targets")
        if any(not target.startswith((domain + ".", "group.")) for target in targets):
            return None, "incompatible_targets"
        return targets, None

    def _name_candidates(
        self, selector: object, endpoint: dict[str, Any] | None, credential: str | None
    ) -> list[dict[str, Any]]:
        if (
            not isinstance(selector, Mapping)
            or not isinstance(selector.get("name"), str)
            or endpoint is None
            or credential is None
        ):
            return []
        return [
            _public_entity(item)
            for item in self._registry(endpoint, credential) or []
            if isinstance(item.get("name"), str)
            and item["name"].casefold() == selector["name"].casefold()
        ][:_MAX_TARGETS]

    def _preflight(
        self,
        endpoint: dict[str, Any],
        credential: str,
        targets: list[str],
        domain: str,
        data: dict[str, Any],
        direct_script: bool,
        deadline: float | None = None,
    ) -> tuple[str | None, bool]:
        deadline = min(deadline or float("inf"), time.monotonic() + _MAX_OBSERVATION_SECONDS)
        groups: dict[str, list[str]] = {}
        for target in targets:
            if direct_script:
                continue
            try:
                entity = _bounded_read(
                    self._reader, _origin(endpoint), target, credential, deadline
                )
            except EntityAbsentError:
                return "target_absent", False
            except Exception:
                return "target_unavailable", False
            if not _valid_entity(entity, target):
                return "target_malformed", False
            attrs = entity.get("attributes", {})
            members = attrs.get("entity_id") if isinstance(attrs, Mapping) else None
            if isinstance(members, list) and target.split(".", 1)[0] in {
                "group",
                "light",
                "fan",
            }:
                groups[target] = [
                    member for member in members if isinstance(member, str)
                ]
        members = {
            member for group_members in groups.values() for member in group_members
        }
        if any(target in members for target in targets if target not in groups):
            return "duplicate_group_member_target", False
        return None, bool(groups)

    def _observe(
        self,
        endpoint: dict[str, Any],
        credential: str,
        targets: list[str],
        service: str,
        data: dict[str, Any],
        direct_script: bool,
        deadline: float | None = None,
    ) -> list[dict[str, Any]]:
        if direct_script:
            return []
        deadline = min(deadline or float("inf"), time.monotonic() + _MAX_OBSERVATION_SECONDS)
        expected_state = _expected_state(service)
        requested = {
            key: value for key, value in data.items() if key in _OBSERVED_ATTRIBUTES
        }
        if service == "remote.turn_on" and isinstance(data.get("activity"), str):
            requested["current_activity"] = data["activity"]
        has_unverifiable_data = bool(
            set(data)
            - set(requested)
            - ({"activity"} if service == "remote.turn_on" else set())
        )
        result: list[dict[str, Any]] = []
        for target in targets:
            try:
                entity = _bounded_read(
                    self._reader, _origin(endpoint), target, credential, deadline
                )
                if not _valid_entity(entity, target):
                    raise TransportError()
                state, attrs = entity["state"], entity["attributes"]
                projected = {
                    key: attrs[key]
                    for key in _OBSERVED_ATTRIBUTES
                    if key in attrs and _safe_json(attrs[key]) and not has_credential_material(attrs[key])
                }
                state_ok = expected_state is None or state == expected_state
                if has_credential_material(state):
                    status = "withheld"
                elif state in {"unavailable", "unknown"} and service.startswith("scene."):
                    status = "unverified"
                elif state in {"unavailable", "unknown"}:
                    status = state
                elif not state_ok:
                    status = "partial"
                elif has_unverifiable_data:
                    status = "unverified"
                elif any(key not in projected for key in requested):
                    status = "unverified"
                elif any(projected[key] != value for key, value in requested.items()):
                    status = "mismatched"
                else:
                    status = "observed"
                item: dict[str, Any] = {
                    "target": target,
                    "status": status,
                    "observed_at": utc_timestamp(),
                }
                item["state"] = "[WITHHELD]" if status == "withheld" else state
                if projected:
                    item["attributes"] = projected
                result.append(item)
            except Exception:
                result.append(
                    {
                        "target": target,
                        "status": "unavailable",
                        "observed_at": utc_timestamp(),
                    }
                )
        return result

    def _record_completion(
        self, operation_id: str, result: str
    ) -> list[dict[str, str]]:
        try:
            self._journal.record(
                {"operation_id": operation_id, "result": result, "at": utc_timestamp()}
            )
        except OSError:
            return [_failure("audit_completion_unknown")]
        return []


def _state_path(state_home: str | os.PathLike[str] | None, filename: str) -> Path:
    root = Path(
        state_home or os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")
    )
    return root / "ha-analysis" / filename


def _prepare_private_directory(path: Path) -> None:
    if path.is_symlink():
        raise OSError("unsafe path")
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077:
        raise OSError("unsafe directory")


def _check_private_path(path: Path, *, allow_absent: bool, size_limit: int) -> None:
    if path.parent.is_symlink():
        raise OSError("unsafe parent")
    try:
        info = path.lstat()
    except FileNotFoundError:
        if allow_absent:
            return
        raise
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_mode & 0o077
        or info.st_size > size_limit
    ):
        raise OSError("unsafe file")


def _origin(endpoint: Mapping[str, Any]) -> dict[str, Any]:
    return {key: endpoint[key] for key in ("scheme", "host", "port")}


def _binding(endpoint: dict[str, Any] | None, credential: str | None) -> dict[str, str]:
    assert endpoint is not None and credential is not None
    return {
        "origin": f"{endpoint['scheme']}://{endpoint['host']}:{endpoint['port']}",
        "transport": str(endpoint["transport_mode"]),
        "credential_sha256": hashlib.sha256(credential.encode()).hexdigest(),
    }


def _validate_service(value: object) -> tuple[str | None, str | None]:
    if not isinstance(value, str) or not _SERVICE.fullmatch(value):
        return None, "invalid_service"
    domain, action = value.split(".", 1)
    if domain == "homeassistant":
        return (
            (value, None)
            if action in {"turn_on", "turn_off", "toggle"}
            else (None, "administrative_service")
        )
    if domain not in _SAFE_DOMAINS:
        return None, "domain_not_household"
    if action in _ADMIN_ACTIONS:
        return None, "administrative_service"
    return value, None


def _validate_data(value: object) -> tuple[dict[str, Any] | None, str | None]:
    if value is None:
        return {}, None
    if (
        not isinstance(value, Mapping)
        or set(value) & _TARGET_KEYS
        or _has_secret_key(value)
    ):
        return None, "target_injection_refused" if isinstance(value, Mapping) and set(
            value
        ) & _TARGET_KEYS else "secret_data_refused" if isinstance(
            value, Mapping
        ) else "invalid_data"
    if not _safe_json(value):
        return None, "invalid_data"
    try:
        copied = copy.deepcopy(dict(value))
        encoded = json.dumps(
            copied, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
    except (TypeError, ValueError, OverflowError):
        return None, "invalid_data"
    return (
        (None, "data_too_large") if len(encoded) > _MAX_DATA_BYTES else (copied, None)
    )


def _safe_json(value: object, depth: int = 0) -> bool:
    if depth > 8:
        return False
    if value is None or isinstance(value, bool):
        return True
    if isinstance(value, str):
        return len(value) <= 4096 and "\x00" not in value
    if isinstance(value, int) and not isinstance(value, bool):
        return value.bit_length() <= 1024
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, Mapping):
        return len(value) <= 128 and all(
            isinstance(key, str) and 0 < len(key) <= 160 and _safe_json(item, depth + 1)
            for key, item in value.items()
        )
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return len(value) <= 128 and all(_safe_json(item, depth + 1) for item in value)
    return False


def _has_secret_key(value: object) -> bool:
    if isinstance(value, Mapping):
        return any(
            isinstance(key, str)
            and (
                key.casefold() in _SECRET_KEYS
                or key_has_sensitive_component(key)
                or has_credential_material(item)
                or _has_secret_key(item)
            )
            for key, item in value.items()
        )
    return (
        isinstance(value, Sequence)
        and not isinstance(value, (str, bytes, bytearray))
        and any(_has_secret_key(item) or has_credential_material(item) for item in value)
    )


def _catalog(raw: object) -> dict[str, Mapping[str, Any]] | None:
    if not isinstance(raw, list) or len(raw) > 1000:
        return None
    result: dict[str, Mapping[str, Any]] = {}
    for entry in raw:
        if (
            not isinstance(entry, Mapping)
            or not isinstance(entry.get("domain"), str)
            or not isinstance(entry.get("services"), Mapping)
        ):
            continue
        for name, spec in entry["services"].items():
            valid, _ = _validate_service(f"{entry['domain']}.{name}")
            if valid and isinstance(spec, Mapping):
                result[valid] = spec
    return result


def _project_action(name: str, spec: Mapping[str, Any]) -> dict[str, Any]:
    fields, description = spec.get("fields"), spec.get("description")
    result: dict[str, Any] = {
        "service": name,
        "fields": sorted(key for key in fields if isinstance(key, str))[:128]
        if isinstance(fields, Mapping)
        else [],
    }
    if isinstance(description, str) and 0 < len(description) <= 500:
        result["description"] = description
    return result


def _requires_response(spec: Mapping[str, Any]) -> bool:
    return (
        isinstance(spec.get("response"), Mapping)
        and spec["response"].get("optional") is False
    )


def _public_entity(item: Mapping[str, Any]) -> dict[str, Any]:
    result = {"entity_id": item["entity_id"]}
    if isinstance(item.get("name"), str) and len(item["name"]) <= 160:
        result["name"] = item["name"]
    return result


def _valid_entity(value: object, target: str) -> bool:
    return (
        isinstance(value, Mapping)
        and value.get("entity_id", target) == target
        and isinstance(value.get("state"), str)
        and len(value["state"]) <= 80
        and isinstance(value.get("attributes"), Mapping)
    )


def _expected_state(service: str) -> str | None:
    _domain, action = service.split(".", 1)
    if action in {"turn_on", "open_cover", "unlock", "start"}:
        return {"open_cover": "open", "unlock": "unlocked", "start": "cleaning"}.get(
            action, "on"
        )
    if action in {"turn_off", "close_cover", "lock"}:
        return {"close_cover": "closed", "lock": "locked"}.get(action, "off")
    return None


def _effect(observations: list[dict[str, Any]], direct_script: bool) -> str:
    if direct_script or not observations:
        return "unverified"
    if all(item["status"] in {"observed", "unverified"} for item in observations):
        return "observed" if all(item["status"] == "observed" for item in observations) else "unverified"
    return (
        "observed"
        if all(item["status"] == "observed" for item in observations)
        else "partial"
    )


def _bounded_read(
    reader: Any, origin: dict[str, Any], target: str, credential: str, deadline: float
) -> Any:
    """Bound one read by the remaining aggregate preflight/observation deadline."""
    result: queue.Queue[tuple[Any, Exception | None]] = queue.Queue(1)

    def read() -> None:
        try:
            result.put((reader.read_entity(origin, target, credential), None))
        except Exception as error:
            result.put((None, error))

    threading.Thread(target=read, daemon=True).start()
    try:
        value, error = result.get(timeout=_remaining(deadline))
    except queue.Empty as error:
        raise TransportError() from error
    if error is not None:
        raise error
    return value


def _document(
    operation: str,
    status: str,
    details: dict[str, Any],
    warnings: list[dict[str, str]] | None = None,
    failures: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    return {
        "contract_version": CONTRACT_VERSION,
        "document_kind": "control",
        "operation": operation,
        "status": status,
        "produced_at": utc_timestamp(),
        "details": details,
        "warnings": warnings or [],
        "failures": failures or [],
    }


def serialize_document(document: Mapping[str, Any]) -> str:
    if (
        set(document) != DOCUMENT_FIELDS
        or document.get("contract_version") != CONTRACT_VERSION
        or document.get("document_kind") != "control"
    ):
        raise ValueError("control document does not match closed schema")
    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def _failure(code: str) -> dict[str, str]:
    return {"code": code, "message": code.replace("_", " ") + "."}


def _remaining(deadline: float) -> float:
    value = deadline - time.monotonic()
    if value <= 0:
        raise TransportError()
    return value


def _read_header(connection: socket.socket | ssl.SSLSocket, deadline: float) -> bytes:
    data = bytearray()
    while b"\r\n\r\n" not in data and len(data) <= 16384:
        connection.settimeout(_remaining(deadline))
        chunk = connection.recv(1024)
        if not chunk:
            raise TransportError()
        data.extend(chunk)
    if len(data) > 16384:
        raise TransportError()
    return bytes(data)
