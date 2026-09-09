# Architecture

The package is library-first. The two command-line programs adapt inputs and
render documents; safety and transport decisions live in the runtime classes.
The public exports are in `src/ha_analysis/__init__.py`.

## Public library surface

```python
from ha_analysis import AnalysisRuntime, ControlRuntime, HouseholdOperator

analysis = AnalysisRuntime()
result = analysis.offline_analyze(
    {"living_room": {"lamp": "light.living_room_lamp_1"}},
    {"analysis_kind": "structural_summary"},
)
```

`AnalysisRuntime` owns deterministic offline analysis, exact-ID inspection,
connection validation, consented discovery, and optional interpretation.
`ControlRuntime` owns trust state, registered-service discovery, target
resolution, validation, and one direct invocation. `HouseholdOperator` runs an
ephemeral embedded model turn whose effects go through `ControlRuntime`.

Other exported contracts support embedding and testing: `ManagementRuntime`,
`StoredCredentials`, `HouseholdProfile`, `CredentialInput`, `EntityReader`,
`ModelInterpreter`, `Result`, `ManagementDocument`, and `SecretStore`.

## CLI adapters

`ha-analysis` uses `argparse` (`src/ha_analysis/cli.py`), not Click. Its
`control` subcommand delegates to the Click-based `ha-control` adapter
(`src/ha_analysis/control_cli.py`). Both control entry points create the same
`ControlRuntime`; this is why `ha-analysis control invoke ...` and
`ha-control invoke ...` have the same control boundary.

Management (`setup`, `login`, `status`, `logout`) is separate from analysis.
It produces a management document rather than observed Home Assistant evidence.

## Six flows

```text
management lifecycle
  -> setup, login, status, or logout
  -> local settings / approved OS secret store
  -> management document (no Home Assistant request)

offline evidence
  -> AnalysisRuntime.offline_analyze
  -> structural summary + redaction
  -> local JSON result

exact selected entity IDs
  -> stored credential for configured origin
  -> bounded authenticated Home Assistant read
  -> projected/redacted JSON result

typed direct control
  -> trust + registered service + exact target + preflight
  -> durable local intent -> one Home Assistant service POST
  -> bounded readback receipt

caller-selected advisory evidence
  -> redaction -> explicitly selected tool-less model interpreter
  -> provider interpretation (no Home Assistant read)

embedded operator
  -> explicit provider/model + ephemeral SDK turn
  -> owned household tools only
  -> ControlRuntime for every potential effect
```

The Home Assistant calls happen in the package's transport layer, outside the
agent SDK. The embedded operator allows its seven owned tools only; built-in
SDK tools are denied. That restriction applies to SDK tools, not a claim that
every imaginable external tool is prevented by a prompt.

## Credentials, metadata, and transport

`ManagementRuntime` records a normalized origin and transport mode locally.
Every successful `setup`, `login`, or `logout` invalidates existing local
control trust. `login` accepts a Home Assistant long-lived access token only
via prompt or stdin and stores it in an allow-listed Linux OS secret store. The
token is bound to that configured origin and is not forwarded to another
origin. `logout` deletes only that local secret; it does not revoke the token
at Home Assistant or delete origin settings or owner profile records.

The secret-store allow-list accepts Secret Service/libsecret and KWallet
backends. There is no plaintext, file, or environment fallback for the Home
Assistant token. `status` reads configuration and credential presence; `check`
is the separate authenticated read-only request.

Household aliases, facts, routines, model selection, trust binding, and
operation metadata are local state. A provider/model choice is origin
independent; aliases, facts, and routines are origin-bound. When an operator
runs, a bounded projected view of origin-bound household metadata can go to the
chosen provider. The Home Assistant secret does not. Local JSON output may
still be sensitive even after redaction: do not post it publicly.

## Control boundary

Control starts disabled. The owner explicitly enables a grant bound to origin,
transport, and a credential identity. A changed configuration or credential
invalidates future control until the owner deliberately re-enables trust.

The runtime permits a fixed set of household domains and runtime-registered
services while refusing administrative/configuration action names, data-based
target injection, and PIN/code/password/token-style fields. It records intent
before a non-dry-run POST and does not automatically retry delivery.

Service acceptance and bounded observation are distinct from physical-world
proof. A service requiring a response payload is refused with
`service_response_unsupported`.

## Model paths

The legacy advisory path is `ha-analysis interpret_evidence`. It invokes a
model only when `--model-runtime amplifier-agent`, `--model-provider`, and
`--model` are selected. It supplies caller-selected redacted evidence to the
provider and configures the SDK with no tools, skills, or MCP servers; it makes
no Home Assistant read. Its all-tools denial is scoped to this advisory
interpreter. `ha-control agent configure` is separate: it stores the
provider/model selection only for the embedded operator.

The newer embedded path is `ha-control run`. It can use its owned household
tools, but `--read-only` blocks invokes and `--dry-run` suppresses their POSTs:

```python
# Requires an already configured origin, stored credential, and provider env.
operator = HouseholdOperator()
document = operator.run(
    "List the living room lamps",
    provider="PROVIDER",
    model="MODEL",
    read_only=True,
)
```

This snippet illustrates construction only; it is not safe to auto-execute in
an application because it can perform Home Assistant reads and provider calls.

Both direct pins are required at install time: `amplifier-agent` and
`amplifier-agent-engine` are pinned to
`412cc176cfa5bd219254060ede7f03bbf6578005`. The `agent` extra remains only as
an install-compatibility extra; it does not make the runtime optional.

## Safety limits, not guarantees

Bounds, redaction, explicit selection, trusted service validation, and
credential isolation reduce risk. They do not guarantee safety against prompt
injection, stale state, provider behavior, integration behavior, or real-world
effects. Treat model narration as unverified and action/readback records as
limited technical evidence.

## Continue reading

- README: https://github.com/bkrabach/amplifier-smart-tool-home-assistant
- Getting started: https://github.com/bkrabach/amplifier-smart-tool-home-assistant/blob/main/docs/getting-started.md
- Usage: https://github.com/bkrabach/amplifier-smart-tool-home-assistant/blob/main/docs/usage.md
- Troubleshooting: https://github.com/bkrabach/amplifier-smart-tool-home-assistant/blob/main/docs/troubleshooting.md