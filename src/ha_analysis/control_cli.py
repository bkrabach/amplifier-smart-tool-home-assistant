"""Click adapter for the direct-control library."""

from __future__ import annotations

import json
from typing import Any

import click

from .control import ControlRuntime, serialize_document
from .household_operator import HouseholdOperator, HouseholdOperatorError
from .household_profile import HouseholdProfile, HouseholdProfileError
from .origins import origin_url


def _json(value: str, name: str) -> object:
    try:
        return json.loads(value, object_pairs_hook=_no_duplicate_keys)
    except (json.JSONDecodeError, ValueError) as error:
        raise click.UsageError("invalid control command arguments") from error


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def _emit(document: dict[str, Any], output: str) -> None:
    if output == "json":
        click.echo(serialize_document(document))
    else:
        click.echo(f"{document['operation']}: {document['status']}")
        click.echo(json.dumps(document["details"], sort_keys=True, ensure_ascii=True))
        for item in document["warnings"] + document["failures"]:
            click.echo(f"{item['code']}: {item['message']}")
    if document["status"] not in {"ok"}:
        raise SystemExit(1)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
def cli() -> None:
    """Direct Home Assistant household control under revocable local trust."""


@cli.group()
def trust() -> None:
    """Manage the connection-bound household-control grant."""


@trust.command("enable")
@click.option(
    "--format",
    "output",
    type=click.Choice(["json", "text"]),
    default="json",
    show_default=True,
    help="Render the result as json or concise text.",
)
def trust_enable(output: str) -> None:
    """Record an explicit owner control grant for the current local binding.

    The grant is local, bound to the configured origin and stored credential,
    and does not discover devices or send a service request. Example:
    ha-control trust enable --format json.
    """
    _emit(ControlRuntime().enable_control(), output)


@trust.command("disable")
@click.option(
    "--format",
    "output",
    type=click.Choice(["json", "text"]),
    default="json",
    show_default=True,
    help="Render the result as json or concise text.",
)
def trust_disable(output: str) -> None:
    """Disable local trust for all future control calls.

    This changes the local grant only. Example:
    ha-control trust disable --format json.
    """
    _emit(ControlRuntime().disable_control(), output)


@trust.command("status")
@click.option(
    "--format",
    "output",
    type=click.Choice(["json", "text"]),
    default="json",
    show_default=True,
    help="Render the result as json or concise text.",
)
def trust_status(output: str) -> None:
    """Report the local trust state for the current stored configuration.

    This reads local configuration and credential binding information. Example:
    ha-control trust status --format json.
    """
    _emit(ControlRuntime().control_status(), output)


@cli.command("actions")
@click.option("--domain", help="Optional Home Assistant service domain to list, for example light.")
@click.option(
    "--format",
    "output",
    type=click.Choice(["json", "text"]),
    default="json",
    show_default=True,
    help="Render the result as json or concise text.",
)
def actions(domain: str | None, output: str) -> None:
    """List registered Home Assistant service metadata without invoking a service.

    --domain filters returned actions locally after the service catalog read. This
    uses no model and sends no service POST. Example: ha-control actions --domain light.
    """
    _emit(ControlRuntime().list_actions(domain), output)


@cli.command("find")
@click.option("--query", required=True, help="Text to match against registry display metadata.")
@click.option(
    "--format",
    "output",
    type=click.Choice(["json", "text"]),
    default="json",
    show_default=True,
    help="Render the result as json or concise text.",
)
def find(query: str, output: str) -> None:
    """Find Home Assistant registry metadata without selecting or invoking anything.

    --query is a display-metadata search string, not an authorization or
    target choice. This uses no model and sends no service POST. Example:
    ha-control find --query "living room lamp".
    """
    _emit(ControlRuntime().find(query), output)


@cli.command("resolve")
@click.option(
    "--selector",
    required=True,
    help="JSON object with exactly one key: entity_id, name, area_id, device_id, or label_id.",
)
@click.option(
    "--format",
    "output",
    type=click.Choice(["json", "text"]),
    default="json",
    show_default=True,
    help="Render the result as json or concise text.",
)
def resolve(selector: str, output: str) -> None:
    """Resolve one explicit JSON selector through Home Assistant registry metadata.

    --selector has exactly one of entity_id, name, area_id, device_id, or
    label_id; it does not invoke a service. This uses no model and sends no
    service POST. Example: ha-control resolve --selector '{"entity_id":"light.lamp"}'.
    """
    _emit(ControlRuntime().resolve(_json(selector, "selector")), output)


@cli.command("invoke")
@click.argument("service")
@click.option("--targets", help="JSON array of exact entity IDs; provide exactly one target source.")
@click.option(
    "--selector",
    help="JSON selector with exactly one key: entity_id, name, area_id, device_id, or label_id.",
)
@click.option("--data", default="{}", show_default=True, help="JSON object of service data.")
@click.option("--dry-run", is_flag=True, help="Preview after Home Assistant reads but send no service POST.")
@click.option(
    "--format",
    "output",
    type=click.Choice(["json", "text"]),
    default="json",
    show_default=True,
    help="Render the result as json or concise text.",
)
def invoke(
    service: str,
    targets: str | None,
    selector: str | None,
    data: str,
    dry_run: bool,
    output: str,
) -> None:
    """Invoke one registered SERVICE in domain.action form.

    Provide exactly one of --targets (a JSON array) or --selector (one exact
    selector); --data is a JSON object. Current local trust is required even for
    --dry-run previews. A preview does Home Assistant
    reads but no service POST; it uses no AI and is not offline. A non-preview
    request may act once, has no retry, and has unverified or unavailable
    readback rather than a guaranteed physical outcome. A direct script.<name>
    accepts --targets '[]' only to name that script, never as generic “all
    targets.” Example: ha-control invoke light.turn_on --targets
    '["light.lamp"]' --data '{"brightness":128}' --dry-run.
    """
    if (targets is None) == (selector is None):
        raise click.UsageError("provide exactly one of --targets or --selector")
    _emit(
        ControlRuntime().invoke(
            service,
            _json(targets, "targets") if targets else None,
            _json(selector, "selector") if selector else None,
            _json(data, "data"),
            dry_run,
        ),
        output,
    )


@cli.group()
def agent() -> None:
    """Configure the embedded household operator; run is a root command."""


@agent.command("configure")
@click.option("--provider", required=True, help="Provider identifier to store locally.")
@click.option("--model", required=True, help="Model identifier to store locally.")
def agent_configure(provider: str, model: str) -> None:
    """Store a provider and model selection locally.

    --provider and --model select a future operator model; they are not
    credentials and this command does not contact Home Assistant. Output is
    JSON-only; there is no --format option. Example: ha-control agent configure
    --provider openai --model MODEL.
    """
    try:
        HouseholdProfile().configure_model(provider, model)
    except HouseholdProfileError as error:
        raise click.ClickException(str(error)) from error
    _operator_emit(_operator_document("agent_configure", "answered", {"provider": provider, "model": model}), "json")


@agent.command("status")
def agent_status() -> None:
    """Report locally stored operator configuration without testing connectivity.

    The result counts local configuration, not provider or Home Assistant
    availability. Output is JSON-only; there is no --format option. Example:
    ha-control agent status.
    """
    try:
        _operator_emit(_operator_document("agent_status", "answered", HouseholdProfile().status()), "json")
    except HouseholdProfileError as error:
        raise click.ClickException(str(error)) from error


@cli.command("run")
@click.argument("request")
@click.option("--read-only", is_flag=True, help="Allow reads but block service invocations.")
@click.option("--dry-run", is_flag=True, help="Preview possible actions but send no service POST.")
@click.option("--provider", help="Per-turn provider override; otherwise use the current profile.")
@click.option("--model", help="Per-turn model override; otherwise use the current profile.")
@click.option(
    "--format",
    "output",
    type=click.Choice(["json", "text"]),
    default="json",
    show_default=True,
    help="Render the result as json or concise text.",
)
def run(
    request: str, read_only: bool, dry_run: bool, provider: str | None, model: str | None, output: str
) -> None:
    """Run one quoted natural-language REQUEST through the configured operator.

    The current profile supplies its model unless --provider and --model override
    it for this turn. --read-only blocks invocations but may still read Home
    Assistant and use the model; --dry-run may preview after those
    reads without a service POST. Current trust is required for invocation and
    previews; when both flags are supplied, read-only wins. Authorized default
    execution is real control. Model narration is unverified and never proof of
    a physical outcome. Provider credentials are environment variables whose
    names, not values, are documented at
    https://github.com/bkrabach/amplifier-smart-tool-home-assistant/blob/main/docs/getting-started.md.
    Example: ha-control run "What lamps are in the living room?" --read-only.
    """
    try:
        result = HouseholdOperator().run(
            request, provider=provider, model=model, read_only=read_only, dry_run=dry_run
        )
    except HouseholdOperatorError as error:
        raise click.ClickException(str(error)) from error
    if output == "json":
        _operator_emit(result, output)
    else:
        _operator_emit(result, output)
    if result["status"] in {"failed", "partial", "unknown"}:
        raise SystemExit(1)


@cli.group(name="memory")
def memory() -> None:
    """Manage local, origin-bound aliases, facts, and reusable routines."""


def _profile_origin(control: ControlRuntime | None = None) -> str:
    endpoint, _credential, failure = (control or ControlRuntime())._endpoint()
    if failure or endpoint is None:
        raise click.ClickException("Home Assistant configuration is unavailable")
    return origin_url(endpoint)


@memory.command("set-alias")
@click.argument("phrase")
@click.argument("entity_ids")
def memory_set_alias(phrase: str, entity_ids: str) -> None:
    """Store PHRASE as a local alias for ENTITY_IDS.

    ENTITY_IDS is a JSON array of exact IDs. Memory is origin-bound local
    data: it may read a stored credential to identify that origin, makes no Home
    Assistant request, and has no immediate effect. Output is JSON-only; there
    is no --format option. Example: ha-control memory set-alias "lamp"
    '["light.lamp"]'.
    """
    try:
        HouseholdProfile().set_alias(_profile_origin(), phrase, _json(entity_ids, "entity_ids"))  # type: ignore[arg-type]
    except HouseholdProfileError as error:
        raise click.ClickException(str(error)) from error
    _operator_emit(_operator_document("memory_set_alias", "answered", {"kind": "alias"}), "json")


@memory.command("set-fact")
@click.argument("label")
@click.argument("text")
def memory_set_fact(label: str, text: str) -> None:
    """Store local fact TEXT under LABEL.

    Memory is origin-bound local data: it may read a stored credential to
    identify that origin, makes no Home Assistant request, and has no immediate
    effect. Output is JSON-only; there is no --format option. Example:
    ha-control memory set-fact preferred_brightness "128".
    """
    try:
        HouseholdProfile().set_fact(_profile_origin(), label, text)
    except HouseholdProfileError as error:
        raise click.ClickException(str(error)) from error
    _operator_emit(_operator_document("memory_set_fact", "answered", {"kind": "fact"}), "json")


@memory.command("set-routine")
@click.argument("name")
@click.argument("description")
@click.argument("steps")
def memory_set_routine(name: str, description: str, steps: str) -> None:
    """Store local routine STEPS under NAME with DESCRIPTION.

    STEPS is a JSON array of objects containing service, targets, and data;
    its structure is validated locally only, with no Home Assistant preflight or
    execution. Memory may read a stored credential to identify its origin but
    makes no Home Assistant request. Output is JSON-only; there is no --format
    option. Example: ha-control memory set-routine bedtime "Turn off"
    '[{"service":"light.turn_off","targets":["light.lamp"],"data":{}}]'.
    """
    try:
        HouseholdProfile().set_routine(_profile_origin(), name, description, _json(steps, "steps"))  # type: ignore[arg-type]
    except HouseholdProfileError as error:
        raise click.ClickException(str(error)) from error
    _operator_emit(_operator_document("memory_set_routine", "answered", {"kind": "routine"}), "json")


@memory.command("list")
@click.option(
    "--kind",
    type=click.Choice(["aliases", "facts", "routines"]),
    help="Optional plural record kind: aliases, facts, or routines; omit for all.",
)
def memory_list(kind: str | None) -> None:
    """List local origin-bound memory records.

    --kind optionally selects plural aliases, facts, or routines; omit it
    for all records. This makes no Home Assistant request. Output is JSON-only;
    there is no --format option. Example: ha-control memory list --kind aliases.
    """
    try:
        _operator_emit(_operator_document("memory_list", "answered", HouseholdProfile().records(_profile_origin(), kind)), "json")
    except HouseholdProfileError as error:
        raise click.ClickException(str(error)) from error


@memory.command("forget")
@click.argument("kind", type=click.Choice(["aliases", "facts", "routines"]))
@click.argument("name")
def memory_forget(kind: str, name: str) -> None:
    """Remove one local NAME record of plural KIND.

    KIND must be aliases, facts, or routines. Removal makes no Home
    Assistant request, does not revoke credentials, and cannot be undone.
    Output is JSON-only; there is no --format option. Example: ha-control memory
    forget aliases lamp.
    """
    try:
        removed = HouseholdProfile().forget(_profile_origin(), kind, name)
    except HouseholdProfileError as error:
        raise click.ClickException(str(error)) from error
    _operator_emit(_operator_document("memory_forget", "answered", {"removed": removed}), "json")


def _operator_document(operation: str, status: str, details: object) -> dict[str, object]:
    return {
        "contract_version": "home-assistant.v1",
        "document_kind": "household_operator",
        "operation": operation,
        "status": status,
        "details": details,
    }


def _operator_emit(document: dict[str, object], output: str) -> None:
    if output == "json":
        click.echo(json.dumps(document, sort_keys=True, ensure_ascii=True))
        return
    click.echo(f"{document['operation']}: {document['status']}")
    if document.get("execution_mode") == "dry_run":
        click.echo("Dry-run preview only; no device changes were sent.")
    elif document.get("model_narration_unverified"):
        click.echo("model narration (unverified): " + str(document["model_narration_unverified"]))
    if document.get("clarification"):
        click.echo("clarification: " + str(document["clarification"]))
    click.echo("action status: " + str(document.get("action_status", "not_attempted")))
    for action in document.get("actions", []):
        click.echo(json.dumps(action, sort_keys=True, ensure_ascii=True))
    if document.get("failure"):
        click.echo("failure: " + str(document["failure"]))


# Compatibility commands intentionally cannot dispatch an old plan.
@cli.command(
    "plan",
    hidden=True,
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
)
@click.pass_context
def plan(ctx: click.Context) -> None:
    """Report that retired planning cannot dispatch an action; use invoke instead."""
    _emit(ControlRuntime().plan_action(), "json")


@cli.command(
    "execute",
    hidden=True,
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
)
@click.pass_context
def execute(ctx: click.Context) -> None:
    """Report that retired execution cannot dispatch an action; use invoke instead."""
    _emit(ControlRuntime().execute_action(), "json")


def main(argv: list[str] | None = None, *, prog_name: str = "ha-control") -> int:
    """Run the Click adapter with an optional embedding program name."""

    try:
        cli.main(args=argv, prog_name=prog_name, standalone_mode=False)
    except click.ClickException as error:
        error.show()
        return error.exit_code
    except click.exceptions.Exit as error:
        return error.exit_code
    except SystemExit as error:
        return int(error.code) if isinstance(error.code, int) else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
