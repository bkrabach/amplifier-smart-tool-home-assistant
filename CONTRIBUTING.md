# Contributing

Thank you for improving `ha-analysis`. Keep changes small, reviewable, and
safe for a public repository.

## Before you start

- Read `README.md`, `AGENTS.md`, and the relevant guide in `docs/`.
- Use Python 3.12+ with uv. Install the locked development environment:

  ```console
  uv sync --locked --extra test
  ```

- Do not use real Home Assistant instances, provider accounts, secret stores,
  or household data in ordinary development or tests.

## Development and verification

Run the required local checks after a relevant change:

```console
uv run --extra test pytest
uv lock --check
uv build
```

The suite is deterministic by default. It must not require actual keys, make
Home Assistant requests, call model providers, or read a real OS credential
store. A real-keyring test is explicit opt-in and may skip in ordinary runs;
that skip is not proof that physical credential storage worked.

The optional live model evaluation harness can cost money and must never run
automatically in a pull request. If you choose to run it with an authorized
provider, keep its output local and do not paste raw provider output into an
issue or pull request.

## Public-data rules

All public examples and fixtures must be synthetic. Living-room lamps and
study/media are examples, not a closed vocabulary. Never commit:

- Home Assistant origins, tokens, names, entity inventories, screenshots, or
  live fixture data
- Provider credentials, environment dumps, raw model output, or secret-store
  contents
- Personal, machine, network, or filesystem identity information
- Private deny-list values or any data copied from another repository/history

Do a fresh semantic privacy review before proposing public content: read the
diff as a stranger and list anything that could identify a person, machine,
organization, or household. This review is separate from
automated secret scanning.

## Documentation and packaging

Keep documentation precise about network, credential, and effect boundaries.
Do not add fictional CLI output, claim unsupported platforms, or infer physical
results from accepted service requests. If you change a public claim, pin it to
the current implementation and test it where practical.

`SMART_TOOL.md` is the package readme and is included in built distributions.
Check its public absolute documentation links, root README links, and both wheel
and source-distribution contents after documentation/packaging changes.

The CI suite includes repository-file and documentation smoke checks. New
documentation fixtures must remain synthetic; they must not cause real
Home Assistant, provider, or secret-store calls.

## Pull requests

Open a focused pull request that explains:

1. What changed and why.
2. How a reviewer can reproduce or verify it.
3. Which commands/tests you ran and their result.
4. Any live check intentionally not run, including why.

Maintainers review contributions before merge. There is no contributor license
agreement and no promised response-time SLA. Use concise, clear commit messages
and describe verification in the pull request.

Use the issue tracker for support and feature discussion:
https://github.com/bkrabach/amplifier-smart-tool-home-assistant/issues

For a privately reported security concern, follow
https://github.com/bkrabach/amplifier-smart-tool-home-assistant/blob/main/SECURITY.md
instead of filing public details.