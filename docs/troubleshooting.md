# Troubleshooting

Start with the narrowest diagnostic. The commands below do not perform a
service POST.

```console
ha-analysis status --format text
ha-analysis check
ha-control trust status --format json
```

`status` examines local configuration, secret-store availability, and
credential presence. `check` then makes the separate authenticated read-only
Home Assistant API request. `trust status` describes whether direct control is
currently enabled for the active binding.

## Setup and token storage

| Diagnostic code | Meaning | Safe next action |
| --- | --- | --- |
| `not_configured` | No configured Home Assistant origin exists. | Run `ha-analysis setup`. |
| `credential_not_stored` | No token is stored for the configured origin. | Create a token in Profile → Security, then run `ha-analysis login`. |
| `secret_store_dependency_missing` | The running installation cannot import its required `keyring` dependency. | Reinstall the package in the intended Python environment. |
| `secret_store_unavailable` | No approved OS secret-store backend is usable. | Start/configure Secret Service/libsecret or KWallet for the active session. |
| `secret_store_operation_failed` | An approved backend could not complete the requested operation. | Resolve the OS-store failure, then repeat the explicit operation. |
| `unsupported_platform` | The credential-store implementation is Linux-only. | Use a supported Linux environment; Windows and macOS are not claimed as supported. |
| `credential_input_unavailable` | Interactive input was unavailable or stdin could not be read. | Use an interactive terminal, or deliberately use `--token-stdin` without putting a token in arguments. |

No diagnostic permits a plaintext fallback. Do not move a Home Assistant token
to an environment variable, `.env` file, command argument, or chat message to
work around a secret-store error.

On a headless Linux system, a package may be installed but an active user
D-Bus session and approved secret-store service may still be absent. Establish
the intended session/backend instead of assuming Python `keyring` alone is a
credential store.

## Connection checks and reads

| Diagnostic code | Meaning | Safe next action |
| --- | --- | --- |
| `authorization_failed` | The server was reachable but rejected the token. | Create/store a valid token, then run `check` again. |
| `connection_check_failed` | The authenticated check did not complete. | Verify the configured origin and transport, then investigate the server/network separately. |
| `origin_change_rejected` | A redirect/origin change was rejected before credential forwarding. | Configure the intended absolute origin explicitly. |
| `credential_origin_mismatch` | A stored token belongs to a different configured origin. | Reconfigure the intended origin and login for that origin. |
| `entity_absent` | An exact requested entity ID was not found. | Use consented `find`, choose an exact current ID, then inspect it. |
| `live_read_failed` | The bounded exact-ID read was unavailable. | Stop and inspect local/server state before retrying. |
| `discovery_failed` | Consented entity-registry display discovery did not complete. | Check connection/authentication, then request discovery again only when appropriate. |

HTTP needs the explicit `trusted_local_or_vpn` transport selection. HTTPS is
the default. Do not treat a local-looking host name as evidence that HTTP is
safe.

Every successful `ha-analysis setup`, `login`, or `logout` disables existing
local control trust. Setup writes the three local settings fields even when the
origin is unchanged. Review the connection and make a new owner trust decision
only if direct control is again appropriate.

## Trust and direct control

| Diagnostic code | Meaning | Safe next action |
| --- | --- | --- |
| `configuration_unavailable` | Control cannot obtain current origin and credential. | Resolve `status` diagnostics first. |
| `control_not_trusted` | The owner has not enabled control for the current binding, or a successful setup/login/logout disabled it. | Review the target/service, then make the owner decision with `trust enable`. |
| `control_trust_changed` | Binding changed while preparing the request. | Stop; review the changed connection and explicitly request trust again if appropriate. |
| `trust_unavailable` | Local trust state could not be written/read safely. | Resolve the local state/storage problem; do not bypass it. |
| `service_not_registered` | The requested service is not in current runtime metadata. | Run `ha-control actions` and choose a registered service. |
| `service_response_unsupported` | The service requires a response payload this runtime does not support. | Do not invoke it through this tool. |
| `ambiguous_target_name` | An exact name matches more than one entity. | Use candidates to select an exact ID or a more specific selector. |
| `audit_unavailable` | Durable intent could not be recorded. | Do not bypass the audit; fix the local storage condition. |

If origin, transport, or credential identity changes, control fails closed.
`status`, checks, discovery, and other reads do not renew trust. Trust is not
something to silently re-enable; after reviewing the current connection, make
one deliberate owner decision before direct control is again appropriate.

## Delayed and unknown outcomes

A service request can be accepted while readback is delayed, unavailable,
mismatched, or partial. Scenes, scripts, groups, and media remotes can fan out
without an observable one-to-one result. `outcome_unknown` or
`delivery_unknown` means do not retry automatically: the original request may
have reached Home Assistant.

Use a later read-only `ha-analysis inspect` with known exact IDs to establish
newer state. Do not replay an action based only on an uncertain response, and
do not assume undo is possible without known prior state.

## Model-backed paths

| Diagnostic code or message | Meaning | Safe next action |
| --- | --- | --- |
| `model_provider_unconfigured` | Advisory interpretation has no selected interpreter. | Select the explicit model runtime/provider/model, or remain offline. |
| `model_runtime_provider_unsupported` | The requested provider identifier is not allowed. | Choose one of the documented provider identifiers. |
| `model_runtime_unavailable` | The installed agent runtime cannot be loaded. | Reinstall `ha-analysis`; do not substitute an unpinned runtime. |
| `model_runtime_python_unsupported` | The runtime needs Python 3.12 or newer. | Use a compliant Python installation. |
| “no supported model is configured” | `ha-control run` lacks a configured/overridden supported pair. | Run `ha-control agent configure --provider PROVIDER --model MODEL`. |
| “selected provider credentials are unavailable” | The chosen provider has no supported credential/configuration variable in the environment. | Follow that provider’s legitimate documentation; never reuse the Home Assistant token. |

`--read-only` and `--dry-run` prevent service POSTs but can still call the
chosen provider and read Home Assistant. They are not dry network tests.

For command grammar, run `ha-analysis --help` or `ha-control --help`. If a
package/runtime component is missing, reinstall rather than attempting an
unverified action against a live household.

## Continue reading

- README: https://github.com/bkrabach/amplifier-smart-tool-home-assistant
- Getting started: https://github.com/bkrabach/amplifier-smart-tool-home-assistant/blob/main/docs/getting-started.md
- Usage: https://github.com/bkrabach/amplifier-smart-tool-home-assistant/blob/main/docs/usage.md
- Architecture: https://github.com/bkrabach/amplifier-smart-tool-home-assistant/blob/main/docs/architecture.md