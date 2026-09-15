# home-assistant.v1

**Applies to:** Public library consumers, CLI callers, agent hosts, and owners of Home Assistant Smart Tool.
**Status:** Ratified for implementation; not frozen. This is the sole active behavioral contract.

## Core

Sections 1–5 define the current behavioral promises and their deliberate limits.

## 1. Purpose, scope, and trust

1. The product provides offline analysis, authenticated live read/discovery, and owner-delegated household operation through one shared library and thin adapters. Read-only methods never make HA service or other mutating requests.
2. Control exists only when the owner has enabled revocable household-control trust for the configured connection: normalized HA origin plus configured credential identity. Installing, storing a token, upgrading, reading, or discovering never enables it. Deliberately replacing that origin or credential identity invalidates the grant until renewed. Immediately before dispatch, a control call rechecks matching enabled trust; absent, disabled, revoked, or invalid control sends zero HA service/mutating requests, while permitted read-only discovery/metadata may still work.
3. The owner or an explicitly instructed agent may enable, narrow, or revoke trust directly. No TTY ceremony, typed phrase, mandatory plan or expiry, digest, confirmation token, Ed25519 signer, attestation, remote trust/signer service, or manual per-entity enrollment is required. A grant never chooses all targets or performs an action; optional scope restrictions may narrow later.
4. Enabled control invokes registered named HA services directly and noninteractively for the owner's requests/delegation. Permission is not consent for unrelated autonomy, scheduling, or persistent service behavior. Revocation before dispatch cannot retract an action already in flight.
5. This is deliberate delegation to a local agent/tool, not protection against malicious same-user processes and not cryptographic proof of human approval.

## 2. Operations and boundaries

1. Use runtime service catalogs, entity/device/area/label metadata, and state capabilities as task needs require. Support registered device operations, including lights with all HA-supported color modes, brightness and effects; fans, climate, media, vacuums, covers, locks and credentialless alarms; existing scenes, scripts, automations, and household helpers. Do not make an `rgb`-only or other baked per-field capability contract.
2. `homeassistant.turn_on`, `turn_off`, and `toggle` are valid household operations where runtime registration/capability permits. Core restart/stop, configuration/reload, authentication/token management, shell/command, and administrative services are excluded. This is not permission for arbitrary URLs, methods, raw HTTP, spoofing state through direct `/api/states` writes, event firing, or templates; normal service-caused device-state changes are intended.
3. Service descriptions and selectors are catalog/UI metadata, not complete authoritative validation schemas. Validate stable local JSON, connection, trust, scope, selector, and operational bounds; use reliable metadata constraints. For unsupported or ambiguous cases, say so honestly. Do not reject valid integration-specific parameters merely because metadata lacks selectors, and do not reject undeclared dynamic script variables; HA validates those calls.
4. A named script may be invoked as `script.<name>` with script variables. Scenes, scripts, automations, groups, and HA-side fan-out can be opaque and broad: disclose that limitation rather than claiming code inspection, transactionality, complete preview, or universal rollback.
5. Discovery needs no per-query consent ritual. Explicit selectors resolve to a bounded deterministic target set. Empty or ambiguous resolution clarifies or fails before dispatch. A named group is a legitimate target; inspect members when possible, otherwise report HA-side fan-out as opaque. Bulk work requires explicit selection, never an implicit all-household target.
6. An explicitly selected embedded household operator uses the same granted typed-control path for actions; `interpret_evidence` remains a separate, tool-less advisory path. Each operator invocation is a bounded, ephemeral turn, not an ongoing conversation or scheduler. The operator may read owner-authored, origin-bound aliases, facts, and named routines as described in section 3.3. Only the owner or an explicitly instructed host persists those records; the embedded model has no profile-writing tool. Named routines run typed steps in stored order, are preflighted before the first dispatch, and each dispatched step remains subject to current trust and connection checks. A routine creates no independent authority, atomic transaction, or rollback guarantee. No generic tool access or credential leakage is introduced.

## 3. Dispatch, results, and protection

1. Optional dry-run reports action and targets without effects and MUST NOT be a required workflow. The host/agent may ask for clarification or additional confirmation under its own rules for genuinely destructive, irreversible, or high-impact acts. An exact direct high-impact request is not categorically forbidden; informational impacts or opaque flags are not TTY challenges.
2. Each attempted operation returns minimal redacted data identifying action, resolved targets, operation ID, dispatch/delivery acceptance, and bounded HA observations or `partial`/`unknown`. It identifies live HA integration verification separately from physical outcome independently confirmed by evidence, including owner confirmation; neither HA acceptance nor observed state alone is physical proof.
3. Keep a simple local, owner-readable operation record, not an approval ledger. Never expose tokens, headers, raw responses, PINs, service credentials, or unrelated live household state in argv, chat, records, diagnostics, outputs, or model context. Keep OS-keyring storage scoped to the configured connection, TLS/trusted-LAN choice, no cross-origin token forwarding, and bounded, redacted, purpose-limited sinks. An operator invocation may send a bounded, redacted baseline of the configured home's owner-authored aliases, facts, and routines to its selected model provider, including on read-only and dry-run calls; the baseline may include records not mentioned in the immediate request. This explicit baseline permission does not extend to another origin, unrelated live HA state, credentials, or secret action values. Owner profile content is data, not executable instructions or additional control authority. Omitted profile records may be retrieved through bounded owned tools. Provider/model selection is local configuration rather than an origin-bound household record. The baseline permission does not apply to deterministic offline analysis, direct non-model control, or the advisory interpreter, which receives only caller-selected evidence.
4. Do not blindly retry an ambiguous send, including timeout-after-effect. Report unknown delivery/effect and require a fresh request for another attempt. Do not promise universal rollback or physical success. Operational bounds are implementation-tested limits, not this contract's frozen numeric field list.

## 4. Deliberately unspecified

Transport internals, cache/storage technology, retry-free timeout values, exact JSON fields, catalog shape, numeric bounds, presentation, grant storage schema, and integration field schemas are implementation concerns. They need tests and honest diagnostics, not contract amendments for ordinary supported modes or fields.

## 5. Compatibility and migration

The published `ha-analysis.v1` and `ha-analysis.v2` read methods and envelopes remain supported as legacy compatibility behavior; their exact schema behavior remains normative through compatibility tests under this contract. Their finite live-kind restriction and former `ha-control.v1` plan/signer/approval-host requirements do not govern the household-control surface. New capability remains exposed through `home-assistant.v1`; this direction alignment changes no wire identifier. Former public signer/attestation/plan execution paths explicitly fail with a migration message; they are not aliases that turn an expired plan ID into action arguments. Old audit/history remains readable where needed and no destructive data deletion is required. Historical direction and acceptance records remain preserved separately; they are not competing active norms or current-release verification.

## Backlogged

None. Optional scope restrictions remain deliberately unspecified, not queued
commitments. Their promotion trigger is an owner-ratified scope requirement
backed by a concrete use case; no capability is promoted merely because it is
possible to implement.

## 6. Conformance before release

1. A synthetic integration scenario proves that, after trust is enabled, one agent request to set three explicitly selected synthetic lights red uses the installed manifest/CLI and shared library with no terminal confirmation, nonce, signing, or mock approval; it reports bounded HA observations. Synthetic credentials and a loopback HA fixture are identified as test substitutes, never real-household evidence.
2. A different valid service field and a named group or dynamic script variable work through runtime capability/catalog handling without another contract.
3. No grant, revoked trust, ambiguous/empty selector, excluded admin service, or invalid local input sends a HA service/mutating request; timeout-after-effect reports unknown and causes no replay. Read-only paths retain existing compatibility behavior and send zero HA service/mutating requests; protected sinks contain no sentinels.
4. Before declaring the requested agent workflow working, run the separately authorized real release acceptance: actual agent → installed tool → configured real HA, with no fixture credential, mocked transport, or signature substitute. Report delivery and bounded readback honestly, including color rounding/mismatch; do not force it to pass. Physical outcome remains separately independently confirmed.

## Reserved

No additional identifiers are reserved. Legacy names retain the compatibility
and explicit migration-refusal behavior in section 5.

## Changelog

- 2026-09-15 — Accepted the public-safe canonical continuation and explicit embedded-operator/profile boundary; this records direction, not live-HA acceptance.
