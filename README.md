# Home Assistant Smart Tool

`ha-analysis` is a Linux command-line package for bounded Home Assistant
analysis and deliberately enabled household control. It separates deterministic
inspection from model-backed interpretation and from direct service requests, so
an operator can choose the capability that a task actually needs.

This is an independent project. It is not affiliated with, endorsed by, or
sponsored by Home Assistant or Microsoft.

## Install

Requirements:

- Python 3.12 or newer
- https://docs.astral.sh/uv/ and Git
- An approved Linux OS credential backend (Secret Service/libsecret or KWallet)
  only when configuring live Home Assistant access

Install the package from its canonical repository:

```console
uv tool install git+https://github.com/bkrabach/amplifier-smart-tool-home-assistant
```

The Python package and primary analysis command are named `ha-analysis`; the
repository is named `amplifier-smart-tool-home-assistant`. The separate
`ha-control` command is the intentional direct-control surface.

## Start with an offline, zero-effect command

This example uses caller-supplied synthetic evidence. It does not contact Home
Assistant, start a model, access credentials, or change anything.

```console
ha-analysis offline_analyze \
  --evidence '{"living_room":{"lamps":["light.living_room_lamp_1","light.living_room_lamp_2"]},"study":{"media":"remote.study_media"}}' \
  --request '{"analysis_kind":"structural_summary"}'
```

The result is a deterministic JSON document describing the structure of that
input. Use this path first when you only need to examine selected evidence.

## Choose a surface

| Surface | Entry point | What it does |
| --- | --- | --- |
| Offline or read-only analysis | `ha-analysis` | Deterministic offline summaries, exact-ID inspection, connection checks, and consented display discovery. |
| Deterministic direct trusted control | `ha-control invoke` | Validates a registered service and explicit target, then sends one request only when the owner has enabled trust. |
| Embedded operator | `ha-control run` | Runs one ephemeral model-backed turn through the same bounded control runtime. |

`ha-analysis invoke` does not exist: `invoke` is a typed direct-control command,
not a model feature, and needs no AI configuration. In contrast,
`interpret_evidence` and `ha-control run` are explicit model-backed paths.

## Minimal setup

1. Record the Home Assistant origin. Setup stores normalized origin, transport,
   and auth-mode settings locally; it neither stores a token nor contacts Home
   Assistant or a model. A successful rerun also disables any existing control
   trust, including when the origin is unchanged:

   ```console
   ha-analysis setup
   ```

2. Create a Home Assistant long-lived access token in **Profile → Security**,
   then store it interactively:

   ```console
   ha-analysis login
   ha-analysis check
   ```

3. Inspect only entity IDs you have chosen:

   ```console
   ha-analysis inspect \
     --targets '["light.living_room_lamp_1"]' \
     --attributes '["friendly_name","brightness"]'
   ```

Read https://github.com/bkrabach/amplifier-smart-tool-home-assistant/blob/main/docs/getting-started.md
before setup for transport, credential-store, and provider details. Read
https://github.com/bkrabach/amplifier-smart-tool-home-assistant/blob/main/docs/usage.md
for target selection and control commands.

### Enabling control is an owner decision

Control is disabled by default. `ha-control trust enable` is an owner decision
that permits real service control for the current origin, transport selection,
and stored credential identity:

```console
ha-control trust enable --format json
ha-control trust status --format json
```

Start an embedded-operator session with `--read-only`, or preview actions with
`--dry-run`. Those modes suppress service POSTs, but they can still read Home
Assistant and send selected household context to the chosen model provider.
They are not equivalent to the offline command above.

## Operational notes

- `ha-analysis status` reports local configuration and credential presence; it
  does not validate a Home Assistant connection.
- `ha-analysis check` performs the separate authenticated, read-only API
  validation.
- `ha-analysis find` requires explicit inventory consent and reads registry
  display metadata before filtering it locally.
- `ha-control actions`, `find`, and `resolve` are discovery/selection steps;
  they do not invoke a service.
- A successful service response is delivery acceptance, not proof of a physical
  outcome. Readback can be delayed or unavailable.

## Documentation

- https://github.com/bkrabach/amplifier-smart-tool-home-assistant/blob/main/docs/getting-started.md
  — prerequisites, credential setup, connection validation, and providers
- https://github.com/bkrabach/amplifier-smart-tool-home-assistant/blob/main/docs/usage.md
  — analysis, target resolution, previews, routines, and outcomes
- https://github.com/bkrabach/amplifier-smart-tool-home-assistant/blob/main/docs/architecture.md
  — library APIs, boundaries, and flows
- https://github.com/bkrabach/amplifier-smart-tool-home-assistant/blob/main/docs/troubleshooting.md
  — diagnostics and safe recovery
- Packaged smart-tool manifest:
  https://github.com/bkrabach/amplifier-smart-tool-home-assistant/blob/main/src/ha_analysis/SMART_TOOL.md

## Contributing

See https://github.com/bkrabach/amplifier-smart-tool-home-assistant/blob/main/CONTRIBUTING.md.
All public examples must be synthetic. Living-room lamps and study/media are
examples, not a closed entity vocabulary; never include real household,
provider, credential-store, or personal data.

For support policy, see
https://github.com/bkrabach/amplifier-smart-tool-home-assistant/blob/main/SUPPORT.md;
use https://github.com/bkrabach/amplifier-smart-tool-home-assistant/issues for
support requests.
For private vulnerability reporting, see https://github.com/bkrabach/amplifier-smart-tool-home-assistant/blob/main/SECURITY.md.

Community expectations:
https://github.com/bkrabach/amplifier-smart-tool-home-assistant/blob/main/CODE_OF_CONDUCT.md.

## Trademarks

Home Assistant and other names may be trademarks of their respective owners.
Use of a name here does not imply affiliation or endorsement.

## License

This project is licensed under the MIT License:
https://github.com/bkrabach/amplifier-smart-tool-home-assistant/blob/main/LICENSE.