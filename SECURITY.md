# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately at:

https://github.com/bkrabach/amplifier-smart-tool-home-assistant/security/advisories/new

Do not report vulnerabilities in a public issue. Do not include access tokens,
device inventory, household data, raw logs, or other secrets in a report.
Please provide the affected version, impact, and the smallest sanitized
reproduction steps needed to understand the issue. Do not include actual
secrets, including in a private report.

## Supported scope

The latest public `0.8.x` release is the supported scope. Fixes on `main` are
considered on a best-effort basis while they are in development. This personal
project does not offer an SLA or an end-of-life promise.

## Security and privacy notes

- The tool stores a Home Assistant access token only in an approved Linux
  operating-system keyring. Provider credentials are configured separately
  through that provider's environment configuration.
- Prefer HTTPS. Local HTTP is available only after an explicit opt-in to the
  documented trusted-local-or-VPN transport mode.
- Connection-bound trust permits only allowed household actions; it does not
  grant general administrative access.
- Model-backed dry runs and read-only operations can transmit household context
  to the selected provider. Inspect local records and provider privacy terms
  before using a provider, even when returned output is redacted.

If a token is exposed, revoke it in Home Assistant or the relevant service.
`logout` deletes only this tool's local copy; it does not revoke the token at
the service.