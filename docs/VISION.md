# Home Assistant Smart Tool — Vision

**Status:** Ratified for implementation; not frozen.
**Scope:** Product direction; `contracts/home-assistant.v1.md` is the sole active behavioral authority.

## Desired state

Home Assistant Smart Tool is a household assistant and operator for its owner and the agents the owner chooses. It understands, resolves, diagnoses, inspects, and operates the home when invoked. The owner deliberately delegates control to the local tool and may revoke that trust.

Offline analysis and authenticated live reads do not require household-control trust. A separately enabled, connection-bound grant lets the host or a chosen agent make direct noninteractive device calls for the owner's requests. Granting trust does not choose targets, perform an action, authorize unrelated work, or start a persistent service.

The embedded operator understands higher-level requests using bounded Home Assistant discovery and owner-authored aliases, facts, and routines. Its selected provider may receive a bounded, redacted baseline of the configured home's saved profile, including records not explicitly named in the request. This is deliberate model context, not permission to disclose credentials, another home's records, or unrelated live state.

## Principles

1. **One behavior, thin adapters.** The shared library owns configuration, trust, discovery, resolution, invocation, redaction, and results. CLI and agent adapters use that behavior rather than implementing it again.
2. **Deliberate, revocable delegation.** Installation, token storage, upgrades, reads, and discovery do not enable control. Trust is bound to the normalized HA origin and credential identity; replacing either requires renewed trust. Setup, login, and logout invalidate the local grant. A host may apply contextual safeguards for genuinely destructive, irreversible, or high-impact requests, without requiring plans, signatures, or terminal ceremonies for ordinary device operations.
3. **Useful household breadth.** Runtime catalogs and state capabilities guide supported device, scene, script, automation, and helper operations. There is no baked per-field capability map, promise of every integration, or claim that metadata is a complete schema.
4. **Bounded, candid operation.** Explicit selectors resolve to deterministic bounded targets. Empty or ambiguous requests clarify or fail before dispatch. Results distinguish requests, acceptance, observations, partial effects, and unknown outcomes. Neither acceptance nor observed HA state alone proves physical success.
5. **Protect credentials and privacy.** HA credentials remain connection-bound in the approved OS keyring, with TLS or an explicit trusted-local-network transport choice and no cross-origin forwarding. Model inputs and other outputs are bounded and redacted for their purpose. Owner-profile baseline context is explicit; secret action values are not accepted through chat or argv.

## Deliberate limits

The grant delegates to a local agent/tool; it is not a sandbox against a malicious same-user process or cryptographic proof of human approval. Revocation blocks future dispatch but cannot retract an in-flight action. The product is not an arbitrary HTTP, shell, configuration, authentication, or HA-administration client. Advisory interpretation has no effect; the embedded household operator uses the same granted typed-control path for explicit model-backed actions. Saved routines provide neither background scheduling nor universal rollback.

## What this repo deliberately resists

Duplicated adapter behavior, mandatory approval bureaucracy for ordinary delegated actions, baked per-field capability catalogs, implicit all-home selection, unbounded autonomous work, credential disclosure, and claims of physical success without independent evidence.

## Changelog

- 2026-09-15 — Accepted the public canonical vision and explicit owner-profile baseline-context boundary.
