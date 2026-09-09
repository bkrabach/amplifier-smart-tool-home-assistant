---
smart_tool_format: 1
name: ha-analysis
version: 0.8.0
description: Safely analyze Home Assistant data and directly operate registered household services under revocable owner-granted trust.
use_cases:
  - Summarize the structure of caller-supplied Home Assistant evidence without network access
  - Inspect explicitly named Home Assistant entities through a bounded read-only interface
  - Check a configured Home Assistant API or consent to a bounded entity-registry display search
  - Configure one Home Assistant origin and store its long-lived access token in the Linux operating-system secret store
  - Enable revocable connection-bound trust, discover registered services, resolve explicit targets, and invoke household actions
  - Run an embedded model-backed household operator through the same trusted control boundary
platforms:
  - linux
---

# Home Assistant Smart Tool

Install the public package from its canonical source:

```console
uv tool install git+https://github.com/bkrabach/amplifier-smart-tool-home-assistant
```

Use this tool to examine caller-selected Home Assistant data without granting it
general control over a home. `offline_analyze` is deterministic and needs no
Home Assistant or model credentials. `check` makes one authenticated API request;
`find` makes one explicitly consented entity-registry display request (all enabled
registry metadata crosses that connection before local filtering, but only matches
with IDs and optional names are output); and `inspect` accepts only exact entity
IDs. `interpret_evidence` is explicitly model-backed and needs an
injected interpreter. The required `amplifier-agent` runtime is selected only
with `--model-runtime amplifier-agent --model-provider PROVIDER --model MODEL`;
the default has no model provider. The package requires Python 3.12 or newer.
The legacy advisory interpreter runs one ephemeral session with no tools,
skills, or MCP servers and denies tool requests before execution. This
tool-less restriction applies only to that advisory interpreter; the separately
documented embedded `ha-control run` operator has bounded household tools.

`setup`, `login`, `status`, and `logout` are management operations. They
configure the tool and report its configuration; they perform no analysis, make
no Home Assistant request, and return a management document rather than an
analysis result. Every successful `setup`, `login`, or `logout` disables
existing local control trust. `setup` writes the normalized origin, explicitly
chosen transport mode, and auth mode. `login` never accepts the token as a
command-line argument: it prompts, or reads stdin with `--token-stdin`, and
writes only into an approved Linux operating-system secret store. If no
approved store is available the login fails outright; the token is never
written to a file, an environment variable, or a plaintext store. `logout`
deletes only the configured origin's local Home Assistant secret, preserving
origin settings and owner profile records; it performs no Home Assistant
revocation. Delete the long-lived access token separately in Home Assistant
**Profile → Security** before logging in with a replacement when it is lost.

## Local setup

Run `ha-analysis setup` from a terminal to enter an absolute Home Assistant URL
including its scheme and, optionally, port:

```console
$ ha-analysis setup
Home Assistant URL: https://ha.example:8123
```

Management commands (`setup`, `login`, `status`, and `logout`) use
`--format auto|text|json` (default: `auto`). Auto uses concise text only when
both stdin and stdout are terminals. It otherwise writes one JSON document,
including when output is redirected, setup uses `--non-interactive`, or login
uses `--token-stdin`. Prompting still uses stderr and is not changed by the
output format. Use `--format text` for readable output even when redirecting,
or `--format json` for automation from a PTY:

```console
ha-analysis status --format text
ha-analysis status --format json
```

Successful setup saves normalized origin, transport mode, and auth mode locally,
then disables any existing control trust—even when the origin is unchanged. It
performs no discovery, network request, token entry, token validation, or model
work. A stored token is not a connection, authentication, or validation.

HTTPS is the default. For an HTTP URL, setup explains that future authenticated
requests would be unencrypted and requires an explicit `y` or `yes` confirmation
before it selects `trusted_local_or_vpn`. A local-looking host name does not
imply that trust. Create a long-lived access token in the Home Assistant profile
**Security** page before running `ha-analysis login`; never put a token in chat
or an argument.

Agents and other non-interactive callers must provide the URL directly, which
never prompts:

```console
ha-analysis setup --origin https://ha.example:8123
ha-analysis setup --origin http://ha.example:8123 --transport-mode trusted_local_or_vpn
```

Use `--interactive` to require the terminal flow (flags can seed its values), or
`--non-interactive` to guarantee that no prompt occurs; the latter requires
`--origin`. Interactive setup requires both stdin and stderr to be terminals,
while stdout may be redirected.

`find --request '{"query":"living room","inventory_consent":true}'` searches a literal
name/ID substring; it defaults to 20 results and permits 1 through 100. It never
falls back to all states, subscribes, invokes a model, or automatically inspects a
returned ID. `inspect --targets '["light.living_room_lamp_1"]' --attributes
'["friendly_name","unit_of_measurement"]' --include-timestamps` returns only the
selected present fields and valid timestamps.

The read-only analysis commands do not automatically discover entities, invoke
services, mutate state, read history/cameras/logbooks, or claim physical-world
outcomes. The package does not implement OAuth, client IDs, callback listeners,
token refresh, server-side revocation, account provisioning, or credential
storage on any platform other than Linux.

## Direct household control

Read-only analysis commands remain compatible and never invoke HA services.
Control is exposed by both `ha-control` and `ha-analysis control`; both call the
same `ControlRuntime` library. It is disabled by default. After normal `setup`
and `login`, explicitly grant it for the current normalized origin, transport,
and credential identity. All examples in this document are synthetic and do not
represent a real household:

```console
ha-control trust enable --format json
ha-control trust status --format json
ha-control actions --domain light --format json
ha-control find --query living-room --format json
ha-control resolve --selector '{"name":"Living room lamp 1"}' --format json
ha-control invoke light.turn_on --targets '["light.living_room_lamp_1"]' --data '{"xy_color":[0.64,0.33]}' --format json
ha-analysis control invoke light.turn_off --selector '{"area_id":"living_room"}' --data '{}' --dry-run --format json
ha-control trust disable --format json
```

`invoke` requires exactly one of `--targets` (an explicit JSON array of exact
entity IDs) or `--selector` (one `entity_id`, exact `name`, `area_id`,
`device_id`, or `label_id`). Names fail rather than choose an ambiguous match;
selectors cannot mean all devices. Runtime `/api/services` metadata determines
which named services are available. The tool permits household domains and
`homeassistant.turn_on|turn_off|toggle`, but rejects administrative/configuration
services, target injection in data, and PIN/code/password/token values. Dynamic
script variables and integration fields such as effects and all supported color
forms are passed to HA after bounded JSON validation.

Each non-dry request records durable local intent before its single service POST.
There is no plan, expiry, signature, terminal confirmation, or automatic retry.
Revocation, origin/token replacement, or an unreadable trust record stops future
POSTs. Results distinguish API delivery acceptance from bounded HA readback
(`observed`, `mismatched`, `partial`, `unavailable`, or `unverified`); neither proves a
physical outcome. Scenes, scripts, and groups may fan out opaquely. `plan` and
`execute` only return a migration error and never send a service request.

Services that require a returned response payload are currently refused as
`service_response_unsupported`; registration alone does not promise every
integration is supported. Immediate readback can lag a successful service call.
A later read-only inspection can establish a newer state without replaying the
action. Verification is limited to the configured integration's delivery and
bounded readback; it does not establish a physical-world outcome.

## Embedded household operator

`ha-control run` is the explicit model-backed household path. It uses the same
connection-bound control grant and `ControlRuntime` service validation as
`invoke`; it does not enable trust, write a profile, schedule work, or expose
shell/filesystem/browser/MCP tools. Configure a provider and model separately
(credentials remain provider environment configuration, never profile data):

```console
ha-control agent configure --provider PROVIDER --model MODEL
ha-control memory set-alias "living room lamps" '["light.living_room_lamp_1","light.living_room_lamp_2"]'
ha-control memory set-routine "study media" "Synthetic media setup" '[{"service":"remote.turn_on","targets":["remote.study_media"],"data":{"activity":"Streaming"}},{"service":"scene.turn_on","targets":["scene.study_media"],"data":{}}]'
ha-control run "What lights are in the living room?" --read-only --format json
ha-control run "Set the living room lamps red" --dry-run --format json
ha-control run "Start study media" --format json
```

Aliases, facts, and routines are owner-only local records bound to the
normalized Home Assistant origin. Routines are optional reusable workflows:
the model may select one by name, but cannot alter its stored steps. The host
preflights all routine steps before its first POST, dispatches stored steps in
order, and never retries uncertain delivery. Generic trusted typed invocation
is still available for requests that do not match a routine.

At the start of a turn, a bounded safe snapshot of current-origin owner
aliases, facts, routines, and their stored steps is supplied as clearly labeled
application data. Matching owner routines take priority over similarly named
discovered entities; the agent invokes them only through `ha_run_routine` by
exact name. This does not make routines a mandatory authorization artifact:
a later explicit request can use ordinary trusted typed actions instead.

Operator output is a `home-assistant.v1` `household_operator` document. Its
model narration is explicitly unverified. `turn_status` reports the SDK turn;
`action_status` reports actual dispatch/readback records. `accepted` means HA
accepted a request, not that a physical effect or a movie is proven. A failed,
rejected, denied, or timed-out turn remains failed/partial/unknown even in
read-only or dry-run modes. Results and model tool data are bounded/redacted;
no transcript is retained. Required-response services remain unsupported.
Dry runs report `action_status: not_attempted` and suppress model narration;
only the host-generated preview receipts describe those unexecuted operations.
New effects are admitted only within the operator's 120-second wall-clock
budget. A service already in flight may still have an unknown/partial outcome;
the host performs only bounded cancellation/terminal cleanup and never begins a
new step after its deadline.

Python 3.12 is the packaging floor. The required `amplifier-agent` binding and
`amplifier-agent-engine` are both direct Git pins at
`412cc176cfa5bd219254060ede7f03bbf6578005`; `uv.lock` records those exact
development/install resolutions. The retained empty `agent` extra is only
compatibility for older install commands, not an optional runtime.

## Public documentation

This packaged manifest is installed without the repository documentation tree.
Use these public absolute links for fuller guidance:

- https://github.com/bkrabach/amplifier-smart-tool-home-assistant/blob/main/docs/getting-started.md
- https://github.com/bkrabach/amplifier-smart-tool-home-assistant/blob/main/docs/usage.md
- https://github.com/bkrabach/amplifier-smart-tool-home-assistant/blob/main/docs/architecture.md
- https://github.com/bkrabach/amplifier-smart-tool-home-assistant/blob/main/docs/troubleshooting.md

For an authorized provider-only evaluation, run the synthetic loopback harness;
it never loads real HA configuration, keyring records, or credentials. The
provider/model pair is supplied explicitly and the output is limited to the
synthetic evaluation:

```console
python tests/run_operator_evaluation.py --provider PROVIDER --model MODEL --output ./evaluation-output
```
