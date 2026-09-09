"""JSON-equivalent public result types for the ``ha-analysis.v1`` boundary."""

from __future__ import annotations

from typing import Literal, NotRequired, Protocol, TypeAlias, TypedDict

JsonPrimitive: TypeAlias = None | bool | int | float | str
JsonValue: TypeAlias = JsonPrimitive | list["JsonValue"] | dict[str, "JsonValue"]
OperationKind: TypeAlias = Literal[
    "offline_analyze", "inspect_live_entities", "interpret_evidence", "check_connection", "find_entities"
]
ExecutionClass: TypeAlias = Literal["deterministic", "model_backed"]
ManagementOperationKind: TypeAlias = Literal["setup", "login", "status", "logout"]
ManagementStatus: TypeAlias = Literal["ok", "failed", "withheld"]


class Origin(TypedDict):
    """The JSON representation of a normalized configured origin."""

    scheme: str
    host: str
    port: int


class EvidenceSource(TypedDict):
    kind: Literal["offline", "live"]
    observed_at: NotRequired[str]
    origin: NotRequired[Origin]


class Diagnostic(TypedDict):
    code: str
    message: str
    target: NotRequired[str]


class RedactionSummary(TypedDict):
    status: Literal["not_applicable", "complete", "withheld"]
    profile: Literal["ha-analysis.v1"]
    removed_value_count: int


class OfflineAnalysisScope(TypedDict):
    kind: Literal["offline_evidence"]
    evidence_source_count: int
    analysis_kind: str


class LiveEntityScope(TypedDict):
    kind: Literal["entity_targets"]
    target_count: int
    attributes: list[str]
    include_timestamps: bool


class ConnectionCheckScope(TypedDict):
    kind: Literal["connection_check"]
    request_count: Literal[0, 1]


class EntityDiscoveryScope(TypedDict):
    kind: Literal["display_inventory"]
    query: str
    domain: str | None
    limit: int
    inventory_consent: bool
    inventory_received: bool
    filtering: Literal["client_side"]


class ModelInterpretationScope(TypedDict):
    kind: Literal["selected_evidence"]
    evidence_source_count: int
    interpretation_kind: str


RequestScope: TypeAlias = (
    OfflineAnalysisScope | LiveEntityScope | ModelInterpretationScope | ConnectionCheckScope | EntityDiscoveryScope
)


class OfflineAnalysisOutput(TypedDict):
    kind: Literal["offline_analysis"]
    findings: JsonValue


class LiveEntityInspectionOutput(TypedDict):
    kind: Literal["live_entity_inspection"]
    entities: list[JsonValue]


class ModelInterpretationOutput(TypedDict):
    kind: Literal["model_interpretation"]
    interpretation: JsonValue


class ConnectionCheckOutput(TypedDict):
    kind: Literal["connection_check"]
    api_reachable: bool
    authentication: Literal["accepted", "rejected", "not_verified"]


class EntityDiscoveryOutput(TypedDict):
    kind: Literal["entity_discovery"]
    entities: list[JsonValue]
    registered_count: int | None
    matched_count: int | None
    returned_count: int
    truncated: bool
    coverage: Literal["enabled_registry_entries_only"]


OperationOutput: TypeAlias = (
    OfflineAnalysisOutput | LiveEntityInspectionOutput | ModelInterpretationOutput | ConnectionCheckOutput | EntityDiscoveryOutput
)


class TargetResolution(TypedDict):
    target: str
    status: Literal["resolved", "absent", "unavailable", "invalid", "not_inspected"]


class EntityReader(Protocol):
    """Narrow injected dependency for one exact Home Assistant entity read."""

    def read_entity(
        self, origin: Origin, entity_id: str, credential: str
    ) -> JsonValue: ...

    def check_connection(self, origin: Origin, credential: str) -> None: ...

    def list_display_entities(self, origin: Origin, credential: str) -> list[JsonValue]: ...


class ModelInterpreter(Protocol):
    """Narrow injected dependency for an explicitly selected evidence payload."""

    def interpret(
        self, selected_evidence: list[JsonValue], interpretation_kind: str
    ) -> JsonValue: ...


class SecretStore(Protocol):
    """Narrow injected boundary for the approved operating-system secret store."""

    def describe(self) -> str: ...

    def set_credential(self, key: str, credential: str) -> None: ...

    def get_credential(self, key: str) -> str | None: ...

    def has_credential(self, key: str) -> bool: ...

    def delete_credential(self, key: str) -> bool: ...


class CredentialInput(Protocol):
    """Narrow injected boundary that yields a caller-supplied credential once."""

    def __call__(self) -> str: ...


class Result(TypedDict):
    """The exact C1 envelope; live results add the two C1 live fields."""

    contract_version: str
    operation: OperationKind
    execution_class: ExecutionClass
    evidence_sources: list[EvidenceSource]
    processed_at: str
    request_scope: RequestScope
    output: OperationOutput
    redaction: RedactionSummary
    warnings: list[Diagnostic]
    failures: list[Diagnostic]
    requested_targets: NotRequired[list[str]]
    target_resolution: NotRequired[list[TargetResolution]]


class ManagementConfiguration(TypedDict):
    """The non-secret configuration a management document may disclose."""

    origin: Origin
    origin_url: str
    transport_mode: str
    auth_mode: str


class ManagementDocument(TypedDict):
    """The C9 management document.

    Deliberately not a :class:`Result`: it carries no ``execution_class``, no
    ``evidence_sources``, no ``request_scope``, and no ``output``, so it can
    never be mistaken for, or processed as, observed Home Assistant evidence.
    """

    contract_version: str
    document_kind: Literal["management"]
    operation: ManagementOperationKind
    status: ManagementStatus
    produced_at: str
    configuration: ManagementConfiguration | None
    details: dict[str, JsonValue]
    notices: list[Diagnostic]
    failures: list[Diagnostic]