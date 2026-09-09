# Agent guide

## Scope and architecture

- Keep the library authoritative; CLI modules are thin adapters.
- `ha-analysis` uses argparse; `ha-control` uses Click.
- Preserve strict boundaries between offline analysis, live reads, and control.
- Do not weaken explicit trust, exact targets, redaction, or secret-store rules.
- Treat accepted delivery and readback as distinct from physical outcomes.

## Local workflow

```console
uv sync --locked --extra test
uv run --extra test pytest
uv lock --check
uv build
```

CI installs with `--locked`. Do not edit `uv.lock` casually or replace
the pinned agent SDK/engine revision without an intentional reviewed change.

## Test invariants

- Default pytest must use no actual Home Assistant, provider, or secret-store
  calls and requires no actual keys.
- A live model harness is explicit opt-in, may cost money, and never runs in PR
  automation.
- A real keyring test is opt-in; a normal-run skip is not proof of physical
  backend behavior.
- Tests feeding non-UTF-8 stdin must explicitly set `PYTHONIOENCODING` and
  assert the distinct `strict` and `surrogateescape` outcomes.
- Repository/doc smoke tests check links and standard repository files.

## Public-content rules

- Public examples and fixtures must be synthetic. Living-room lamps and
  study/media are examples, not a closed entity vocabulary.
- Never echo environment values, credentials, raw live outputs, or store data.
- Never commit household, machine, network, personal, or private deny-list data.
- Perform a fresh semantic privacy review for new public content before push.
- Keep `SMART_TOOL.md` front matter/version intact; use public absolute docs
  URLs there because the packaged manifest has no repository-relative docs.

## Change quality

- Update docs with behavior changes and verify README/docs links.
- Build wheel and sdist when docs or packaging change.
- Keep commits concise and conventional-style when commits are requested.
- Follow `CONTRIBUTING.md`; use `SECURITY.md` for private vulnerability policy.