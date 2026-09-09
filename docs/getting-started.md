# Getting started

This guide configures the read-only analysis path first. All names and entity
IDs below are synthetic examples: living-room lamps and study/media only.

## 1. Meet the prerequisites

The supported credential-storage platform is Linux. Install Python 3.12 or
newer, `uv`, and Git, then install from the canonical repository:

```console
uv tool install git+https://github.com/bkrabach/amplifier-smart-tool-home-assistant
```
Credential storage needs more than the Python `keyring` package. A running,
approved Linux OS secret-store backend must be available through your active
desktop/session D-Bus connection:

| Accepted backend family | Typical Linux integration |
| --- | --- |
| Secret Service | Secret Service/libsecret |
| KWallet | KWallet |

Plaintext, file, null, failing, and unapproved keyring backends are refused.
`ha-analysis status` diagnoses availability without exposing a token.

## 2. Run the offline check first

This command is safe to run before any Home Assistant setup. It makes no
network request and needs neither Home Assistant nor model credentials.

```console
ha-analysis offline_analyze \
  --evidence '{"living_room":{"lamp":"light.living_room_lamp_1"},"study":{"media":"remote.study_media"}}' \
  --request '{"analysis_kind":"structural_summary"}'
```
`offline_analyze` accepts caller-supplied JSON and produces a deterministic
structural summary. Offline analysis needs no configuration and contacts neither
Home Assistant nor a provider. `setup` and `status` are also local-only, but
they read or write local configuration and, for status, may query the OS store.

## 3. Record an origin

Run interactive setup and enter an absolute origin, including the scheme:

```console
ha-analysis setup
```
HTTPS is the default. HTTP is intentionally not inferred from a local-looking
name: authenticated HTTP sends the token unencrypted. Interactive setup asks
for explicit confirmation; non-interactive HTTP requires this exact opt-in:

```console
ha-analysis setup \
  --origin http://example.invalid:8123 \
  --transport-mode trusted_local_or_vpn \
  --non-interactive
```
Successful setup writes normalized origin, transport mode, and auth-mode
settings, then disables any existing control trust—even if the origin is
unchanged. It does not test the server, accept a token, or contact a model.

## 4. Create and store the Home Assistant token

In Home Assistant, create a long-lived access token in **Profile → Security**.
Then run:

```console
ha-analysis login
```
The command prompts without echoing the token and writes it only to an approved
Linux OS secret store. Never put a Home Assistant token in chat, shell
arguments, or a `.env` file. `--token-stdin` exists for a deliberate
non-interactive handoff, but it still must not be a command argument.
Home Assistant authentication and model authentication are distinct:

- The Home Assistant token is stored by `login` in the approved OS secret
  store, bound to the configured origin.
- Model-provider credentials, if you choose to use a model path, stay in the
  provider's environment configuration. They are not placed in the household
  profile or Home Assistant credential store.

## 5. Diagnose, then validate

First inspect local readiness:

```console
ha-analysis status --format text
```
`status` reports configuration and whether a credential is present. It makes no
Home Assistant request. Validate the configured server and token separately:

```console
ha-analysis check
```
`check` makes one authenticated, read-only API request. A stored token is not
proof that it is accepted until this succeeds.

## 6. Discover with consent, then inspect exact IDs

Display discovery requires an explicit consent field:

```console
ha-analysis find \
  --request '{"query":"living room","inventory_consent":true}'
```
The tool receives enabled registry display metadata and filters it locally; it
does not automatically inspect a result. Copy or choose the exact entity ID,
then request only the fields you need:

```console
ha-analysis inspect \
  --targets '["light.living_room_lamp_1"]' \
  --attributes '["friendly_name","brightness"]' \
  --include-timestamps
```

## 7. Optionally configure a model provider

Only model-backed commands need a provider/model choice. Consult your
provider's legitimate setup documentation and export only the values it
requires. Configure a placeholder pair by replacing both upper-case values:

```console
ha-control agent configure --provider PROVIDER --model MODEL
```
Supported provider identifiers and environment values forwarded into the
contained runtime are:

| Provider | Forwarded environment variables |
| --- | --- |
| `anthropic` | `ANTHROPIC_API_KEY`, `ANTHROPIC_BASE_URL` |
| `azure-openai` | `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT`, `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` |
| `chat-completions` | `CHAT_COMPLETIONS_API_KEY`, `CHAT_COMPLETIONS_BASE_URL` |
| `gemini` | `GOOGLE_API_KEY`, `GEMINI_API_KEY`, `GOOGLE_GEMINI_BASE_URL` |
| `ollama` | `OLLAMA_API_KEY`, `OLLAMA_HOST` |
| `openai` | `OPENAI_API_KEY`, `OPENAI_BASE_URL` |
| `vllm` | `VLLM_API_KEY`, `VLLM_BASE_URL` |

This table documents permitted forwarding, not a promise that every provider
authentication flow or model is tested. `OPENAI_BASE_URL` is optional and is
for a custom endpoint when needed; do not set it merely because a provider is
selected.

For the first operator call, opt into reads only:

```console
ha-control run "What lamps are in the living room?" --read-only --format json
```
It may read Home Assistant and send bounded household context to the chosen
provider. Do not run it automatically.

## Continue reading

- README: https://github.com/bkrabach/amplifier-smart-tool-home-assistant
- Usage: https://github.com/bkrabach/amplifier-smart-tool-home-assistant/blob/main/docs/usage.md
- Architecture: https://github.com/bkrabach/amplifier-smart-tool-home-assistant/blob/main/docs/architecture.md
- Troubleshooting: https://github.com/bkrabach/amplifier-smart-tool-home-assistant/blob/main/docs/troubleshooting.md