# Usage

Use `ha-analysis` for bounded analysis and `ha-control` for the separately
enabled control surface. Examples use only synthetic living-room lamps and
study/media entities.

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

## Routines and aliases are explicit records

The model cannot remember household terminology by itself. An owner may store
an alias or routine explicitly, and these records are bound to the current
origin:

```console
ha-control memory set-alias \
  "living room lamps" \
  '["light.living_room_lamp_1","light.living_room_lamp_2"]'

ha-control memory set-routine \
  "study media" \
  "Start synthetic study media" \
  '[{"service":"remote.turn_on","targets":["remote.study_media"],"data":{"activity":"Streaming"}}]'
```
Use `ha-control memory list` to see records and `memory forget KIND NAME` to
remove one. A routine holds validated stored steps; it is not a scheduler or an
ongoing conversation.

## Embedded operator

Configure a provider and model explicitly, then begin read-only:

```console
ha-control agent configure --provider PROVIDER --model MODEL
ha-control run "What lamps are in the living room?" --read-only --format json
```
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