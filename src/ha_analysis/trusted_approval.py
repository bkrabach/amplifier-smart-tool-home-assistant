"""Retired approval API compatibility types; no signer or verifier remains."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Protocol

ATTESTATION_VERSION = "retired"
@dataclass(frozen=True)
class TrustedApprovalConfig:
    issuer: str = ""
    audience: str = ""
    public_key: bytes = b""
@dataclass(frozen=True)
class TrustedApprovalRequest:
    plan_id: str = ""
    digest: str = ""
    expires_at: str = ""
    audience: str = ""
@dataclass(frozen=True)
class TrustedApprovalFact:
    issuer: str = ""
    audience: str = ""
    nonce_digest: str = ""
    attestation_digest: str = ""
    expires_at: str = ""
class TrustedApprovalSource(Protocol):
    def fetch_approval(self, request: TrustedApprovalRequest) -> bytes: ...
def approval_request(*_args: object, **_kwargs: object) -> TrustedApprovalRequest:
    raise RuntimeError("trusted approval was retired; enable control trust then invoke directly")
def verify_attestation(*_args: object, **_kwargs: object) -> TrustedApprovalFact:
    raise RuntimeError("trusted approval was retired; enable control trust then invoke directly")