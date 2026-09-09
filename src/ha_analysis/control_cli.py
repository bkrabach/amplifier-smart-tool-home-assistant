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
)
def trust_enable(output: str) -> None:
    _emit(ControlRuntime().enable_control(), output)


@trust.command("disable")
@click.option(
    "--format",
    "output",
    type=click.Choice(["json", "text"]),
    default="json",
    show_default=True,
)
def trust_disable(output: str) -> None:
    _emit(ControlRuntime().disable_control(), output)


@trust.command("status")
@click.option(
    "--format",
    "output",
    type=click.Choice(["json", "text"]),
    default="json",
    show_default=True,
)
def trust_status(output: str) -> None:
    _emit(ControlRuntime().control_status(), output)


@cli.command("actions")
@click.option("--domain")
@click.option(
    "--format",
    "output",
    type=click.Choice(["json", "text"]),
    default="json",
    show_default=True,
)
def actions(domain: str | None, output: str) -> None:
    _emit(ControlRuntime().list_actions(domain), output)


@cli.command("find")
@click.option("--query", required=True)
@click.option(
    "--format",
    "output",
    type=click.Choice(["json", "text"]),
    default="json",
    show_default=True,
)
def find(query: str, output: str) -> None:
    _emit(ControlRuntime().find(query), output)


@cli.command("resolve")
@click.option("--selector", required=True)
@click.option(
    "--format",
    "output",
    type=click.Choice(["json", "text"]),
    default="json",
    show_default=True,
)
def resolve(selector: str, output: str) -> None:
    _emit(ControlRuntime().resolve(_json(selector, "selector")), output)


@cli.command("invoke")
@click.argument("service")
@click.option("--targets")
@click.option("--selector")
@click.option("--data", default="{}", show_default=True)
@click.option("--dry-run", is_flag=True)
@click.option(
    "--format",
    "output",
    type=click.Choice(["json", "text"]),
    default="json",
    show_default=True,
)
def invoke(
    service: str,
    targets: str | None,
    selector: str | None,
    data: str,
    dry_run: bool,
    output: str,
) -> None:
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
    """Configure and run the embedded household operator."""


@agent.command("configure")
@click.option("--provider", required=True)
@click.option("--model", required=True)
def agent_configure(provider: str, model: str) -> None:
    try:
        HouseholdProfile().configure_model(provider, model)
    except HouseholdProfileError as error:
        raise click.ClickException(str(error)) from error
    _operator_emit(_operator_document("agent_configure", "answered", {"provider": provider, "model": model}), "json")


@agent.command("status")
def agent_status() -> None:
    try:
        _operator_emit(_operator_document("agent_status", "answered", HouseholdProfile().status()), "json")
    except HouseholdProfileError as error:
        raise click.ClickException(str(error)) from error


@cli.command("run")
@click.argument("request")
@click.option("--read-only", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--provider")
@click.option("--model")
@click.option("--format", "output", type=click.Choice(["json", "text"]), default="json", show_default=True)
def run(
    request: str, read_only: bool, dry_run: bool, provider: str | None, model: str | None, output: str
) -> None:
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
    """Owner-only household aliases, facts, and reusable routines."""


def _profile_origin(control: ControlRuntime | None = None) -> str:
    endpoint, _credential, failure = (control or ControlRuntime())._endpoint()
    if failure or endpoint is None:
        raise click.ClickException("Home Assistant configuration is unavailable")
    return origin_url(endpoint)


@memory.command("set-alias")
@click.argument("phrase")
@click.argument("entity_ids")
def memory_set_alias(phrase: str, entity_ids: str) -> None:
    try:
        HouseholdProfile().set_alias(_profile_origin(), phrase, _json(entity_ids, "entity_ids"))  # type: ignore[arg-type]
    except HouseholdProfileError as error:
        raise click.ClickException(str(error)) from error
    _operator_emit(_operator_document("memory_set_alias", "answered", {"kind": "alias"}), "json")


@memory.command("set-fact")
@click.argument("label")
@click.argument("text")
def memory_set_fact(label: str, text: str) -> None:
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
    try:
        HouseholdProfile().set_routine(_profile_origin(), name, description, _json(steps, "steps"))  # type: ignore[arg-type]
    except HouseholdProfileError as error:
        raise click.ClickException(str(error)) from error
    _operator_emit(_operator_document("memory_set_routine", "answered", {"kind": "routine"}), "json")


@memory.command("list")
@click.option("--kind", type=click.Choice(["aliases", "facts", "routines"]))
def memory_list(kind: str | None) -> None:
    try:
        _operator_emit(_operator_document("memory_list", "answered", HouseholdProfile().records(_profile_origin(), kind)), "json")
    except HouseholdProfileError as error:
        raise click.ClickException(str(error)) from error


@memory.command("forget")
@click.argument("kind", type=click.Choice(["aliases", "facts", "routines"]))
@click.argument("name")
def memory_forget(kind: str, name: str) -> None:
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
    _emit(ControlRuntime().plan_action(), "json")


@cli.command(
    "execute",
    hidden=True,
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
)
@click.pass_context
def execute(ctx: click.Context) -> None:
    _emit(ControlRuntime().execute_action(), "json")


def main(argv: list[str] | None = None) -> int:
    try:
        cli.main(args=argv, prog_name="ha-control", standalone_mode=False)
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
