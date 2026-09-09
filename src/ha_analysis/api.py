"""Library-first implementation of the three finite ``ha-analysis.v1`` operations."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime

from .clock import utc_timestamp
from .amplifier_agent_adapter import ModelRuntimeError
from .live import (
    AuthorizationError,
    EntityAbsentError,
    OriginChangeError,
    TransportError,
    UrlLibEntityReader,
)
from .management import StoredCredentialError, StoredCredentials
from .origins import OriginError, normalize_origin
from .redaction import RedactionError, redact, require_json
from .types import (
    Diagnostic,
    EntityReader,
    EvidenceSource,
    JsonValue,
    LiveEntityScope,
    ModelInterpretationScope,
    ModelInterpreter,
    OfflineAnalysisScope,
    Origin,
    Result,
    TargetResolution,
)

CONTRACT_VERSION = "ha-analysis.v2"
REDACTION_PROFILE = "ha-analysis.v1"
_ENTITY_ID = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")


class AnalysisRuntime:
    """Own the injectable boundaries while keeping public operations library-first."""

    def __init__(
        self,
        *,
        entity_reader: EntityReader | None = None,
        model_interpreter: ModelInterpreter | None = None,
        transport_mode: str = "https",
        stored_credentials: StoredCredentials | None = None,
    ) -> None:
        self._entity_reader = entity_reader or UrlLibEntityReader()
        self._model_interpreter = model_interpreter
        self._transport_mode = transport_mode
        # Constructed eagerly but inertly: it reads no settings and touches no
        # secret store until a live read actually needs one.
        self._stored_credentials = stored_credentials or StoredCredentials()

    def offline_analyze(self, evidence: object, request: object) -> Result:
        """Deterministically produce a structural summary of offline evidence."""

        sources, values, source_count, failures = _offline_sources(evidence)
        analysis_kind, extra_keys, request_failures = _analysis_request(request)
        scope: OfflineAnalysisScope = {
            "kind": "offline_evidence",
            "evidence_source_count": source_count,
            "analysis_kind": analysis_kind,
        }
        failures.extend(request_failures)
        if source_count == 0:
            failures.append(_diagnostic("empty_evidence", "At least one evidence source is required."))

        findings: JsonValue = None
        redaction_count = 0
        redaction_status = "not_applicable"
        if not failures:
            findings = _structural_summary(values)
            try:
                findings, redaction_count = redact(findings, extra_keys)
                redaction_status = "complete"
            except Exception:
                failures.append(_diagnostic("redaction_failed", "Redaction could not complete."))
                findings = None
                redaction_status = "withheld"
        return _result(
            operation="offline_analyze",
            execution_class="deterministic",
            evidence_sources=sources,
            request_scope=scope,
            output={"kind": "offline_analysis", "findings": findings},
            failures=failures,
            redaction_status=redaction_status,
            removed_value_count=redaction_count,
        )

    def inspect_live_entities(
        self,
        origin: object,
        targets: object,
        credential_provider: Callable[[], str] | None = None,
        *,
        attributes: object = (),
        include_timestamps: object = False,
    ) -> Result:
        """Inspect requested exact entity IDs through the one bounded GET family.

        ``origin`` may be ``None``, meaning "the origin this installation was
        configured for"; the configured endpoint is then resolved through the
        C9 settings rather than by any caller-side parsing. When no credential
        provider is injected, the C9 stored credential is supplied through the
        same C7 provider boundary - and only ever for the configured origin.
        """

        requested_targets, resolutions, target_count, target_failures = _targets(targets)
        scope: LiveEntityScope = {
            "kind": "entity_targets",
            "target_count": target_count,
            "attributes": [],
            "include_timestamps": False,
        }
        selected_attributes, selected_timestamps, field_failures = _inspection_fields(
            attributes, include_timestamps
        )
        scope["attributes"] = list(selected_attributes)
        scope["include_timestamps"] = selected_timestamps
        origin_url_value, transport_mode, endpoint_failures = self._endpoint(origin)
        if endpoint_failures:
            normalized_origin, origin_failures = None, endpoint_failures
        else:
            normalized_origin, origin_failures = _normalize_origin(origin_url_value, transport_mode)
        failures = target_failures + field_failures + origin_failures
        source: EvidenceSource = {"kind": "live"}
        if normalized_origin is not None:
            source["origin"] = normalized_origin
        if target_count == 0:
            failures.append(_diagnostic("empty_targets", "At least one entity target is required."))

        valid_indices = [
            index for index, resolution in enumerate(resolutions)
            if resolution["status"] == "not_inspected"
        ]
        if origin_failures or field_failures or not valid_indices:
            return _result(
                operation="inspect_live_entities",
                execution_class="deterministic",
                evidence_sources=[source],
                request_scope=scope,
                output={"kind": "live_entity_inspection", "entities": []},
                failures=failures,
                requested_targets=requested_targets,
                target_resolution=resolutions,
            )

        assert normalized_origin is not None
        provider = credential_provider or self._stored_credential_provider(normalized_origin)
        try:
            credential = provider()
        except StoredCredentialError as error:
            failures.append(_diagnostic(error.code, error.message))
            return _result(
                operation="inspect_live_entities",
                execution_class="deterministic",
                evidence_sources=[source],
                request_scope=scope,
                output={"kind": "live_entity_inspection", "entities": []},
                failures=failures,
                requested_targets=requested_targets,
                target_resolution=resolutions,
            )
        except Exception:  # Provider details can contain credential material.
            failures.append(_diagnostic("credential_unavailable", "Credential provider did not supply a credential."))
            return _result(
                operation="inspect_live_entities",
                execution_class="deterministic",
                evidence_sources=[source],
                request_scope=scope,
                output={"kind": "live_entity_inspection", "entities": []},
                failures=failures,
                requested_targets=requested_targets,
                target_resolution=resolutions,
            )
        if not isinstance(credential, str) or not credential:
            failures.append(_diagnostic("credential_unavailable", "Credential provider did not supply a credential."))
            return _result(
                operation="inspect_live_entities",
                execution_class="deterministic",
                evidence_sources=[source],
                request_scope=scope,
                output={"kind": "live_entity_inspection", "entities": []},
                failures=failures,
                requested_targets=requested_targets,
                target_resolution=resolutions,
            )

        entities: list[JsonValue] = []
        for index in valid_indices:
            target = requested_targets[index]
            try:
                raw_entity = self._entity_reader.read_entity(normalized_origin, target, credential)
                entity = _minimum_entity(
                    target, raw_entity, selected_attributes, selected_timestamps
                )
                entities.append(entity)
                resolutions[index]["status"] = "resolved"
            except EntityAbsentError:
                resolutions[index]["status"] = "absent"
                failures.append(_diagnostic("entity_absent", "Requested entity was not found.", target))
            except AuthorizationError:
                resolutions[index]["status"] = "unavailable"
                failures.append(_diagnostic("authorization_failed", "Live inspection was not authorized.", target))
            except OriginChangeError:
                resolutions[index]["status"] = "unavailable"
                failures.append(_diagnostic("origin_change_rejected", "Origin change was rejected before forwarding credentials.", target))
                _mark_not_inspected(resolutions, valid_indices, index + 1)
                break
            except Exception:
                resolutions[index]["status"] = "unavailable"
                failures.append(_diagnostic("live_read_failed", "Exact entity read was unavailable.", target))

        try:
            redacted_entities, removed_count = redact(entities)
            assert isinstance(redacted_entities, list)
            redaction_status = "complete"
        except Exception:
            redacted_entities = []
            removed_count = 0
            redaction_status = "withheld"
            failures.append(_diagnostic("redaction_failed", "Redaction could not complete."))
        return _result(
            operation="inspect_live_entities",
            execution_class="deterministic",
            evidence_sources=[source],
            request_scope=scope,
            output={"kind": "live_entity_inspection", "entities": redacted_entities},
            failures=failures,
            redaction_status=redaction_status,
            removed_value_count=removed_count,
            requested_targets=requested_targets,
            target_resolution=resolutions,
        )

    def check_connection(
        self, origin: object, credential_provider: Callable[[], str] | None = None
    ) -> Result:
        """Make precisely one authenticated ``GET /api/`` check."""
        source, normalized, credential, failures = self._live_inputs(origin, credential_provider)
        scope: dict[str, object] = {"kind": "connection_check", "request_count": 0}
        output: JsonValue = {
            "kind": "connection_check",
            "api_reachable": False,
            "authentication": "not_verified",
        }
        if failures or normalized is None or credential is None:
            return _result(operation="check_connection", execution_class="deterministic",
                           evidence_sources=[source], request_scope=scope, output=output, failures=failures)
        scope["request_count"] = 1
        try:
            self._entity_reader.check_connection(normalized, credential)
            output = {"kind": "connection_check", "api_reachable": True, "authentication": "accepted"}
        except AuthorizationError:
            output = {"kind": "connection_check", "api_reachable": True, "authentication": "rejected"}
            failures.append(_diagnostic("authorization_failed", "Connection check was not authorized."))
        except OriginChangeError:
            failures.append(_diagnostic("origin_change_rejected", "Origin change was rejected before forwarding credentials."))
        except Exception:
            failures.append(_diagnostic("connection_check_failed", "Connection check did not complete."))
        return _result(operation="check_connection", execution_class="deterministic",
                       evidence_sources=[source], request_scope=scope, output=output, failures=failures)

    def find_entities(
        self, origin: object, request: object, credential_provider: Callable[[], str] | None = None
    ) -> Result:
        """Search only explicitly consented registry display metadata."""
        scope, request_failures = _discovery_request(request)
        source, normalized, credential, failures = self._live_inputs(origin, credential_provider)
        failures = request_failures + failures
        empty: JsonValue = {
            "kind": "entity_discovery", "entities": [], "registered_count": None,
            "matched_count": None, "returned_count": 0, "truncated": False,
            "coverage": "enabled_registry_entries_only",
        }
        if failures or normalized is None or credential is None:
            return _result(operation="find_entities", execution_class="deterministic",
                           evidence_sources=[source], request_scope=scope, output=empty, failures=failures)
        try:
            records = self._entity_reader.list_display_entities(normalized, credential)
            scope["inventory_received"] = True
            matches = _display_matches(records, str(scope["query"]), scope["domain"])
            returned = matches[:int(scope["limit"])]
            output: JsonValue = {
                "kind": "entity_discovery", "entities": returned,
                "registered_count": len(records), "matched_count": len(matches),
                "returned_count": len(returned), "truncated": len(matches) > len(returned),
                "coverage": "enabled_registry_entries_only",
            }
            output, removed = redact(output)
            return _result(operation="find_entities", execution_class="deterministic",
                           evidence_sources=[source], request_scope=scope, output=output,
                           failures=failures, redaction_status="complete", removed_value_count=removed)
        except Exception:
            failures.append(_diagnostic("discovery_failed", "Entity-registry display discovery did not complete."))
            return _result(operation="find_entities", execution_class="deterministic",
                           evidence_sources=[source], request_scope=scope, output=empty, failures=failures)

    def _live_inputs(
        self, origin: object, credential_provider: Callable[[], str] | None
    ) -> tuple[EvidenceSource, Origin | None, str | None, list[Diagnostic]]:
        origin_value, transport_mode, endpoint_failures = self._endpoint(origin)
        if endpoint_failures:
            normalized, failures = None, list(endpoint_failures)
        else:
            normalized, failures = _normalize_origin(origin_value, transport_mode)
        source: EvidenceSource = {"kind": "live"}
        if normalized is not None:
            source["origin"] = normalized
        if failures or normalized is None:
            return source, normalized, None, failures
        try:
            credential = (credential_provider or self._stored_credential_provider(normalized))()
        except Exception:
            failures.append(_diagnostic("credential_unavailable", "Credential provider did not supply a credential."))
            return source, normalized, None, failures
        if not isinstance(credential, str) or not credential:
            failures.append(_diagnostic("credential_unavailable", "Credential provider did not supply a credential."))
            return source, normalized, None, failures
        return source, normalized, credential, failures

    def interpret_evidence(self, selected_evidence: object, request: object) -> Result:
        """Invoke only an injected model interpreter with redacted selected evidence."""

        sources, values, source_count, failures = _offline_sources(selected_evidence)
        interpretation_kind, extra_keys, request_failures = _interpretation_request(request)
        scope: ModelInterpretationScope = {
            "kind": "selected_evidence",
            "evidence_source_count": source_count,
            "interpretation_kind": interpretation_kind,
        }
        failures.extend(request_failures)
        if source_count == 0:
            failures.append(_diagnostic("empty_selected_evidence", "At least one selected evidence source is required."))

        interpretation: JsonValue = None
        redaction_status = "not_applicable"
        removed_count = 0
        if not failures:
            try:
                redacted_evidence, removed_count = redact(values, extra_keys)
                assert isinstance(redacted_evidence, list)
            except Exception:
                failures.append(_diagnostic("redaction_failed", "Redaction could not complete."))
                redaction_status = "withheld"
            else:
                redaction_status = "complete"
                if self._model_interpreter is None:
                    failures.append(
                        _diagnostic(
                            "model_provider_unconfigured",
                            "No model interpreter is configured for interpretation.",
                        )
                    )
                else:
                    try:
                        interpretation = self._model_interpreter.interpret(
                            redacted_evidence, interpretation_kind
                        )
                    except ModelRuntimeError as error:
                        interpretation = None
                        failures.append(_diagnostic(error.code, error.message))
                    except Exception:
                        interpretation = None
                        failures.append(_diagnostic("model_interpreter_failed", "Model interpretation failed."))
                    else:
                        try:
                            interpretation, output_removed = redact(
                                interpretation, extra_keys
                            )
                            removed_count += output_removed
                        except Exception:
                            interpretation = None
                            redaction_status = "withheld"
                            failures.append(_diagnostic("redaction_failed", "Redaction could not complete."))
        return _result(
            operation="interpret_evidence",
            execution_class="model_backed",
            evidence_sources=sources,
            request_scope=scope,
            output={"kind": "model_interpretation", "interpretation": interpretation},
            failures=failures,
            redaction_status=redaction_status,
            removed_value_count=removed_count,
        )

    def _endpoint(self, origin: object) -> tuple[object, str, list[Diagnostic]]:
        """Resolve the endpoint to read, from the caller or from C9 settings."""

        if origin is not None:
            return origin, self._transport_mode, []
        try:
            configured_origin, configured_transport = self._stored_credentials.endpoint()
        except StoredCredentialError as error:
            return None, self._transport_mode, [_diagnostic(error.code, error.message)]
        return configured_origin, configured_transport, []

    def _stored_credential_provider(self, origin: Origin) -> Callable[[], str]:
        """Bind the C9 stored credential to exactly one normalized origin."""

        def provider() -> str:
            return self._stored_credentials.credential_for(origin)

        return provider

    def serialize_result(self, result: Result) -> str:
        """Create a redacted JSON document for the protected CLI output sink."""

        import json

        try:
            safe_output, _ = redact(result["output"])
            safe = dict(result)
            safe["output"] = safe_output  # type: ignore[typeddict-item]
            return json.dumps(safe, sort_keys=True, separators=(",", ":"))
        except Exception:
            withheld = dict(result)
            withheld["output"] = _empty_output(result["operation"])
            withheld["redaction"] = {
                "status": "withheld",
                "profile": REDACTION_PROFILE,
                "removed_value_count": 0,
            }
            withheld["failures"] = [
                *result["failures"],
                _diagnostic("redaction_failed", "Redaction could not complete."),
            ]
            return json.dumps(withheld, sort_keys=True, separators=(",", ":"))


def _offline_sources(
    evidence: object,
) -> tuple[list[EvidenceSource], list[JsonValue], int, list[Diagnostic]]:
    if isinstance(evidence, Mapping):
        items: list[object] = [evidence]
    elif isinstance(evidence, Sequence) and not isinstance(evidence, (str, bytes, bytearray)):
        items = list(evidence)
    else:
        return [], [], 0, [_diagnostic("invalid_evidence", "Evidence must be a JSON object or array.")]
    sources: list[EvidenceSource] = []
    values: list[JsonValue] = []
    failures: list[Diagnostic] = []
    for index, item in enumerate(items):
        source: EvidenceSource = {"kind": "offline"}
        sources.append(source)
        try:
            copied = require_json(item)
        except RedactionError:
            failures.append(_diagnostic("invalid_evidence", "Evidence must be JSON-equivalent.", str(index)))
            continue
        if isinstance(copied, dict) and "observed_at" in copied:
            observed_at = copied["observed_at"]
            if isinstance(observed_at, str) and _is_rfc3339(observed_at):
                source["observed_at"] = observed_at
            else:
                failures.append(_diagnostic("invalid_observed_at", "Evidence observed_at must be an RFC3339 timestamp.", str(index)))
        values.append(copied)
    return sources, values, len(items), failures


def _analysis_request(request: object) -> tuple[str, tuple[str, ...], list[Diagnostic]]:
    kind, extras, failures = _request(request, "analysis_kind")
    if kind and kind != "structural_summary":
        failures.append(_diagnostic("unsupported_analysis_kind", "Only structural_summary is supported."))
    return kind, extras, failures


def _interpretation_request(request: object) -> tuple[str, tuple[str, ...], list[Diagnostic]]:
    return _request(request, "interpretation_kind")


def _request(request: object, kind_field: str) -> tuple[str, tuple[str, ...], list[Diagnostic]]:
    if not isinstance(request, Mapping):
        return "", (), [_diagnostic("invalid_request", "Request must be a JSON object.")]
    kind = request.get(kind_field)
    if not isinstance(kind, str) or not kind:
        return "", (), [_diagnostic("invalid_request", f"Request {kind_field} must be a non-empty string.")]
    extras = request.get("redaction_keys", [])
    if not isinstance(extras, list) or not all(isinstance(item, str) and item for item in extras):
        return kind, (), [_diagnostic("invalid_request", "Request redaction_keys must be a list of non-empty strings.")]
    return kind, tuple(extras), []


def _targets(targets: object) -> tuple[list[str], list[TargetResolution], int, list[Diagnostic]]:
    if not isinstance(targets, Sequence) or isinstance(targets, (str, bytes, bytearray)):
        return [], [], 0, [_diagnostic("invalid_targets", "Targets must be an array of entity IDs.")]
    requested: list[str] = []
    resolutions: list[TargetResolution] = []
    failures: list[Diagnostic] = []
    target_items = list(targets)
    for item in target_items:
        if not isinstance(item, str):
            failures.append(_diagnostic("invalid_target", "Each target must be a string entity ID."))
            continue
        requested.append(item)
        if _ENTITY_ID.fullmatch(item):
            resolutions.append({"target": item, "status": "not_inspected"})
        else:
            resolutions.append({"target": item, "status": "invalid"})
            failures.append(_diagnostic("invalid_target", "Target must be one exact Home Assistant entity ID.", item))
    return requested, resolutions, len(target_items), failures


def _normalize_origin(origin: object, transport_mode: str) -> tuple[Origin | None, list[Diagnostic]]:
    """Adapt the one shared origin rule to this operation's diagnostic shape."""

    try:
        return normalize_origin(origin, transport_mode), []
    except OriginError as error:
        return None, [_diagnostic(error.code, error.message)]


def _minimum_entity(
    target: str,
    raw_entity: JsonValue,
    attributes: tuple[str, ...] = (),
    include_timestamps: bool = False,
) -> JsonValue:
    if not isinstance(raw_entity, dict) or "state" not in raw_entity:
        raise TransportError()
    entity: dict[str, JsonValue] = {
        "entity_id": target,
        "state": require_json(raw_entity["state"]),
        "evidence_kind": "observed_home_assistant",
    }
    raw_attributes = raw_entity.get("attributes")
    if attributes and isinstance(raw_attributes, dict):
        entity["attributes"] = {
            name: require_json(raw_attributes[name]) for name in attributes if name in raw_attributes
        }
    if include_timestamps:
        for field in ("last_changed", "last_updated"):
            value = raw_entity.get(field)
            if isinstance(value, str) and _is_rfc3339(value):
                entity[field] = value
    return entity


def _inspection_fields(
    attributes: object, timestamps: object
) -> tuple[tuple[str, ...], bool, list[Diagnostic]]:
    if not isinstance(timestamps, bool):
        return (), False, [_diagnostic("invalid_timestamps", "include_timestamps must be boolean.")]
    if not isinstance(attributes, Sequence) or isinstance(attributes, (str, bytes, bytearray)):
        return (), timestamps, [_diagnostic("invalid_attributes", "Attributes must be an array of exact names.")]
    fields = list(attributes)
    if (
        len(fields) > 16
        or len(set(fields)) != len(fields)
        or not all(isinstance(item, str) and item and "." not in item and "*" not in item for item in fields)
    ):
        return (), timestamps, [_diagnostic("invalid_attributes", "Select at most 16 distinct exact top-level attribute names.")]
    return tuple(fields), timestamps, []


def _discovery_request(request: object) -> tuple[dict[str, object], list[Diagnostic]]:
    scope: dict[str, object] = {
        "kind": "display_inventory", "query": "", "domain": None, "limit": 20,
        "inventory_consent": False, "inventory_received": False, "filtering": "client_side",
    }
    if not isinstance(request, Mapping):
        return scope, [_diagnostic("invalid_discovery_request", "Discovery request must be a JSON object.")]
    query, domain, limit, consent = (
        request.get("query", ""), request.get("domain"), request.get("limit", 20),
        request.get("inventory_consent"),
    )
    if isinstance(query, str):
        scope["query"] = query
    if isinstance(domain, str):
        scope["domain"] = domain
    if isinstance(limit, int) and not isinstance(limit, bool):
        scope["limit"] = limit
    scope["inventory_consent"] = consent is True
    invalid = (
        consent is not True or not isinstance(query, str) or not isinstance(domain, (str, type(None)))
        or not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100
        or (not query.strip() and not domain) or "*" in query or "*" in (domain or "")
        or any(character in query for character in ("[", "]", "(", ")", "|", "\\"))
    )
    if invalid:
        return scope, [_diagnostic("invalid_discovery_request", "Discovery requires explicit consent, a literal query or domain, and a limit from 1 to 100.")]
    return scope, []


def _display_matches(records: Sequence[JsonValue], query: str, domain: object) -> list[JsonValue]:
    needle = query.casefold()
    prefix = f"{domain}." if isinstance(domain, str) and domain else None
    matches: list[JsonValue] = []
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("entity_id"), str):
            continue
        entity_id, name = record["entity_id"], record.get("name")
        if prefix and not entity_id.startswith(prefix):
            continue
        if needle and needle not in entity_id.casefold() and (
            not isinstance(name, str) or needle not in name.casefold()
        ):
            continue
        display: dict[str, JsonValue] = {"entity_id": entity_id}
        if isinstance(name, str):
            display["name"] = name
        matches.append(display)
    return sorted(matches, key=lambda item: str(item["entity_id"]))


def _structural_summary(values: list[JsonValue]) -> JsonValue:
    return {
        "analysis_kind": "structural_summary",
        "evidence_source_count": len(values),
        "source_shapes": [_shape(value) for value in values],
    }


def _shape(value: JsonValue) -> JsonValue:
    if isinstance(value, dict):
        return {"type": "object", "key_count": len(value)}
    if isinstance(value, list):
        return {"type": "array", "item_count": len(value)}
    if value is None:
        return {"type": "null"}
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, str):
        return {"type": "string"}
    return {"type": "number"}


def _mark_not_inspected(
    resolutions: list[TargetResolution], valid_indices: list[int], after_index: int
) -> None:
    for index in valid_indices:
        if index >= after_index:
            resolutions[index]["status"] = "not_inspected"


def _result(
    *,
    operation: str,
    execution_class: str,
    evidence_sources: list[EvidenceSource],
    request_scope: object,
    output: object,
    failures: list[Diagnostic],
    redaction_status: str = "not_applicable",
    removed_value_count: int = 0,
    requested_targets: list[str] | None = None,
    target_resolution: list[TargetResolution] | None = None,
) -> Result:
    result: Result = {
        "contract_version": CONTRACT_VERSION,
        "operation": operation,  # type: ignore[typeddict-item]
        "execution_class": execution_class,  # type: ignore[typeddict-item]
        "evidence_sources": evidence_sources,
        "processed_at": _timestamp(),
        "request_scope": request_scope,  # type: ignore[typeddict-item]
        "output": output,  # type: ignore[typeddict-item]
        "redaction": {
            "status": redaction_status,  # type: ignore[typeddict-item]
            "profile": REDACTION_PROFILE,
            "removed_value_count": removed_value_count,
        },
        "warnings": [],
        "failures": failures,
    }
    if requested_targets is not None and target_resolution is not None:
        result["requested_targets"] = requested_targets
        result["target_resolution"] = target_resolution
    return result


def _empty_output(operation: str) -> JsonValue:
    if operation == "offline_analyze":
        return {"kind": "offline_analysis", "findings": None}
    if operation == "inspect_live_entities":
        return {"kind": "live_entity_inspection", "entities": []}
    if operation == "check_connection":
        return {"kind": "connection_check", "api_reachable": False, "authentication": "not_verified"}
    if operation == "find_entities":
        return {
            "kind": "entity_discovery", "entities": [], "registered_count": None,
            "matched_count": None, "returned_count": 0, "truncated": False,
            "coverage": "enabled_registry_entries_only",
        }
    return {"kind": "model_interpretation", "interpretation": None}


def _timestamp() -> str:
    return utc_timestamp()


def _is_rfc3339(value: str) -> bool:
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return "T" in value and (value.endswith("Z") or "+" in value[10:] or "-" in value[10:])


def _diagnostic(code: str, message: str, target: str | None = None) -> Diagnostic:
    diagnostic: Diagnostic = {"code": code, "message": message}
    if target is not None:
        diagnostic["target"] = target
    return diagnostic