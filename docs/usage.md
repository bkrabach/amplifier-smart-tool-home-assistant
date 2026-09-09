# Usage

Use `ha-analysis` for bounded analysis and `ha-control` for the separately
enabled control surface. Examples use only synthetic living-room lamps and
study/media entities.

## Command index

Use `-h` or `--help` for exact option grammar. `ha-analysis control` and
`ha-control` expose the same control commands.

| Entry point | Commands | Purpose |
| --- | --- | --- |
| `ha-analysis` | `manifest` | Print packaged smart-tool metadata locally. |
| `ha-analysis` | `offline_analyze`; `inspect_live_entities` (`inspect`); `check`; `find` | Offline analysis or bounded Home Assistant reads. |
| `ha-analysis` | `interpret_evidence` | Advisory interpretation of caller-selected evidence. |
| `ha-analysis` | `setup`; `login`; `status`; `logout` | Local origin and credential lifecycle management. |
| `ha-control` | `trust enable\|disable\|status`; `actions`; `find`; `resolve`; `invoke` | Enable, discover, select, and directly invoke bounded control. |
| `ha-control` | `agent configure\|status`; `run`; `memory set-alias\|set-fact\|set-routine\|list\|forget` | Configure or run the embedded operator and manage its local records. |

`ha-analysis manifest` emits the packaged `SMART_TOOL.md` front matter with
the closed fields `smart_tool_format`, `name`, `version`, `description`,
`use_cases`, and `platforms`; it has no Home Assistant or model activity. In a
source checkout, `smart-tool.json` points to that manifest and the
`src/ha_analysis/cli.py` source-tree command.

## Analysis commands

`offline_analyze` is deterministic and does not touch Home Assistant or a
model:

```console
ha-analysis offline_analyze \
  --evidence '{"living_room":{"lamps":["light.living_room_lamp_1","light.living_room_lamp_2"]},"study":{"media":"remote.study_media"}}' \
  --request '{"analysis_kind":"structural_summary"}'
```
`check` makes exactly one authenticated API request. `status` is different: it
only reports local setup and credential presence.

```console
ha-analysis status --format json
ha-analysis check
```
To inspect live state, supply a JSON array of exact entity IDs. Attributes are
an explicit JSON array, not a wildcard:

```console
ha-analysis inspect \
  --targets '["light.living_room_lamp_1","light.living_room_lamp_2"]' \
  --attributes '["friendly_name","brightness","rgb_color"]'
```
Use `find` only after consent; it searches enabled registry display metadata
and does not select or inspect any returned ID automatically:

```console
ha-analysis find \
  --request '{"query":"study","inventory_consent":true,"limit":20}'
```

## Interpret selected evidence (advisory)

`interpret_evidence` accepts only caller-selected JSON. It redacts that
evidence before sending it to the explicitly selected provider in a tool-less
advisory session; it does not make a Home Assistant request, but it is not
offline because it calls the provider.

```console
ha-analysis interpret_evidence \
  --selected-evidence '[{"entity_id":"light.living_room_lamp_1","state":"on","attributes":{"brightness":128}}]' \
  --request '{"interpretation_kind":"advice"}' \
  --model-runtime amplifier-agent \
  --model-provider PROVIDER \
  --model MODEL
```

`interpretation_kind` is any non-empty caller label, not a fixed enum.
Provider credentials come from the environment variables listed in
https://github.com/bkrabach/amplifier-smart-tool-home-assistant/blob/main/docs/getting-started.md,
not from Home Assistant or the local household profile.

## Discover, resolve, then invoke

The control CLI is implemented with Click. It emits JSON by default; pass
`--format text` for a concise terminal rendering.

```console
ha-control actions --domain light --format json
ha-control find --query "living room lamp" --format json
ha-control resolve --selector '{"name":"Living room lamp 1"}' --format json
```
`resolve` selectors contain exactly one of:

- `entity_id` — an exact ID, or an array of exact IDs
- `name` — an exact name; an ambiguous match fails and lists candidates
- `area_id`, `device_id`, or `label_id` — an explicit registry selector

Do not treat a substring search result as an authorization or target choice.
Choose an exact entity ID, or resolve an explicit selector, before invoking.

## Preview a direct action

Control begins disabled. The owner must deliberately enable it for the current
origin, transport, and credential identity:

```console
ha-control trust enable --format json
ha-control trust status --format json
```
Preview is the recommended first control step. It validates the service,
target, registry metadata, and data but sends no service POST:

```console
ha-control invoke light.turn_on \
  --targets '["light.living_room_lamp_1"]' \
  --data '{"rgb_color":[255,0,0],"brightness":128}' \
  --dry-run --format json
```
The same typed request without `--dry-run` is a write:

```console
ha-control invoke light.turn_on \
  --targets '["light.living_room_lamp_1"]' \
  --data '{"rgb_color":[255,0,0],"brightness":128}' \
  --format json
```
The data in the example is a common light payload, but availability is decided
by the configured integration's runtime service metadata and target
capabilities. `invoke` needs exactly one of `--targets` or `--selector`; it is
not an AI command and no model configuration is involved.

### Registered scripts without a target entity

A registered direct script service such as the synthetic
`script.study_media` may use an empty target array. This exception applies to
`script.<name>`, not `script.turn_on`, `script.turn_off`, or `script.toggle`;
the service must still be registered and local control trust must be enabled.

```console
ha-control invoke script.study_media --targets '[]' --data '{}' --dry-run
```

This preview sends no service POST, but it still performs Home Assistant reads
to validate the registered service. It is not an offline command, and the
example does not assert that a script with this name exists.

## Local aliases, facts, and routines

The model does not automatically write household terminology. Only an owner
can create these local, current-origin records:

```console
ha-control memory set-alias \
  "living room lamps" \
  '["light.living_room_lamp_1","light.living_room_lamp_2"]'

ha-control memory set-fact \
  "reading preference" \
  "Use warm lamp colors for reading"

ha-control memory set-routine \
  "study media" \
  "Start synthetic study media" \
  '[{"service":"remote.turn_on","targets":["remote.study_media"],"data":{"activity":"Streaming"}}]'
```

| Operation | Exact grammar |
| --- | --- |
| Store an alias | `set-alias PHRASE ENTITY_IDS_JSON` |
| Store a fact | `set-fact LABEL TEXT` |
| Store a routine | `set-routine NAME DESCRIPTION STEPS_JSON` |
| List records | `list [--kind aliases\|facts\|routines]` |
| Delete a record | `forget {aliases\|facts\|routines} NAME` |

`list` reads local records without writing them. `forget` deletes only one
local record; it is neither device undo nor Home Assistant token revocation.
Routine structure is validated when stored; runtime service and target
preflight happens only when that routine is run. Routines are reusable steps,
not a scheduler or ongoing conversation.

## Embedded operator

Configure a provider and model explicitly, then begin read-only:

```console
ha-control agent configure --provider PROVIDER --model MODEL
ha-control run "What lamps are in the living room?" --read-only --format json
```
`agent configure` stores only the embedded operator's provider/model selection;
it does not configure `interpret_evidence`.
`--read-only` permits bounded reads but blocks mutation. `--dry-run` can
inspect and preview would-be operations without POSTing; both modes may still
use the selected model provider and are not offline.

The operator is ephemeral: each `run` is one turn, with no continuing chat or
scheduler. Its text is unverified narration. Check `action_status` and the
individual action/readback records rather than treating prose as dispatch
evidence.

## Interpret outcomes conservatively

Before any non-dry-run request, the runtime checks trust, registered service,
target resolution, and target preflight. It writes durable local intent, then
sends a single POST. Multi-step routines are preflighted before the first POST
and dispatched in stored order; they are not atomic and have no rollback.

`accepted` means Home Assistant accepted a request, not that an external effect
is proven. Immediate state readback may report `observed`, `mismatched`,
`partial`, `unavailable`, or `unverified`. Scenes, scripts, groups, and the
synthetic `remote.study_media` example can fan out opaquely.

If delivery is unknown, state is delayed, or a service requires a response
payload, stop and inspect later. Do not retry or replay a request just because
the narration, response, or physical outcome is uncertain. An undo operation
depends on known prior state and is not implied by the tool.

## Continue reading

- README: https://github.com/bkrabach/amplifier-smart-tool-home-assistant
- Getting started: https://github.com/bkrabach/amplifier-smart-tool-home-assistant/blob/main/docs/getting-started.md
- Architecture: https://github.com/bkrabach/amplifier-smart-tool-home-assistant/blob/main/docs/architecture.md
- Troubleshooting: https://github.com/bkrabach/amplifier-smart-tool-home-assistant/blob/main/docs/troubleshooting.md