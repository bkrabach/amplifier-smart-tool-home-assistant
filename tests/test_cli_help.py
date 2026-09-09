"""Regression coverage for the public CLI help contract."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import click
import pytest

from ha_analysis import cli as analysis_cli
from ha_analysis import control_cli


ROOT = Path(__file__).resolve().parents[1]


def _analysis_routes() -> list[tuple[str, ...]]:
    """Discover every public argparse route, including aliases."""

    parser = analysis_cli._parser()
    subcommands = next(
        action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
    )
    return [(), *((name,) for name in subcommands.choices)]


def _visible_click_routes(
    command: click.Command, prefix: tuple[str, ...] = ()
) -> Iterator[tuple[str, ...]]:
    """Yield root, visible groups, and visible leaves from Click's live tree."""

    yield prefix
    if not isinstance(command, click.Group):
        return
    for name, child in command.commands.items():
        if child.hidden:
            continue
        yield from _visible_click_routes(child, (*prefix, name))


def _help(
    tmp_path: Path, invocation: int, module: str, route: tuple[str, ...], flag: str
) -> subprocess.CompletedProcess[str]:
    """Run source-tree help with a brand-new empty home and credential-free env."""

    home = tmp_path / f"home-{invocation}"
    environment = {
        "HOME": str(home),
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
        "PATH": os.environ["PATH"],
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": str(ROOT / "src"),
        "PYTHON_KEYRING_BACKEND": "keyring.backends.fail.Keyring",
        "XDG_CACHE_HOME": str(home / "cache"),
        "XDG_CONFIG_HOME": str(home / "config"),
        "XDG_DATA_HOME": str(home / "data"),
        "XDG_STATE_HOME": str(home / "state"),
    }
    return subprocess.run(
        [sys.executable, "-m", module, *route, flag],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
    )


def _compact(value: str) -> str:
    return " ".join(value.split())


def test_all_public_routes_accept_identical_short_and_long_help(tmp_path: Path) -> None:
    """Every discovered public route accepts equivalent short and long help."""

    analysis_routes = _analysis_routes()
    control_routes = list(_visible_click_routes(control_cli.cli))
    routes = (
        [("analysis", "ha_analysis.cli", route) for route in analysis_routes]
        + [("control", "ha_analysis.control_cli", route) for route in control_routes]
        + [("bridge", "ha_analysis.cli", ("control", *route)) for route in control_routes]
    )
    completed = 0
    for label, module, route in routes:
        short = _help(tmp_path, completed, module, route, "-h")
        completed += 1
        long = _help(tmp_path, completed, module, route, "--help")
        completed += 1
        assert short.returncode == long.returncode == 0, (label, route, short.stderr, long.stderr)
        assert short.stdout == long.stdout, (label, route)
        assert short.stderr == long.stderr == "", (label, route)
        if label == "bridge":
            assert "Usage: ha-analysis control" in short.stdout
        elif label == "control":
            assert "Usage: ha-control" in short.stdout
    assert completed == 2 * len(routes)
    assert all(not (tmp_path / f"home-{invocation}").exists() for invocation in range(completed))


def test_public_help_has_descriptions_and_option_help() -> None:
    """Live parser metadata remains useful when public commands are added."""

    parser = analysis_cli._parser()
    assert parser.description
    subcommands = next(
        action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
    )
    seen_parsers: set[int] = set()
    for name, command in subcommands.choices.items():
        if id(command) in seen_parsers:
            continue
        seen_parsers.add(id(command))
        assert command.description, name
        for action in command._actions:
            if action.option_strings:
                assert action.help, (name, action.option_strings)

    def check(command: click.Command, route: tuple[str, ...] = ()) -> None:
        assert command.help, route
        for parameter in command.params:
            if isinstance(parameter, click.Option):
                assert parameter.help, (route, parameter.name)
            if isinstance(parameter, click.Argument):
                assert parameter.name.upper() in command.help.upper(), (route, parameter.name)
        if isinstance(command, click.Group):
            for name, child in command.commands.items():
                if not child.hidden:
                    check(child, (*route, name))

    check(control_cli.cli)


def test_help_exposes_control_bridge_and_lifecycle_boundaries(tmp_path: Path) -> None:
    """Root discovery and high-risk command facts stay explicit in help."""

    root_help = _compact(_help(tmp_path, 0, "ha_analysis.cli", (), "--help").stdout)
    assert "ha-analysis control --help" in root_help
    assert "Quick zero-effect example" in root_help
    assert "docs/usage.md" in root_help

    invoke_help = _compact(control_cli.cli.commands["invoke"].help or "")
    for phrase in (
        "exactly one",
        "Current local trust",
        "no service POST",
        "not offline",
        "may act once",
        "no retry",
        "script.<name>",
        "--targets '[]'",
    ):
        assert phrase in invoke_help

    run_help = _compact(control_cli.cli.commands["run"].help or "")
    for phrase in (
        "quoted natural-language",
        "--read-only",
        "--dry-run",
        "read-only wins",
        "Authorized default execution is real control",
        "Model narration is unverified",
    ):
        assert phrase in run_help


def test_hidden_retired_commands_have_direct_help_but_are_not_discoverable(
    tmp_path: Path,
) -> None:
    """Compatibility help names the replacement without exposing retired routes."""

    visible = {route[-1] for route in _visible_click_routes(control_cli.cli) if route}
    assert {"plan", "execute"}.isdisjoint(visible)
    for command in ("plan", "execute"):
        result = _help(tmp_path, 0, "ha_analysis.control_cli", (command,), "--help")
        assert result.returncode == 0
        assert "retired" in result.stdout
        assert "invoke" in result.stdout


def test_help_does_not_construct_operational_runtimes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Help parsing remains metadata-only even on the control bridge."""

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("help constructed an operational runtime")

    monkeypatch.setattr(analysis_cli, "AnalysisRuntime", forbidden)
    monkeypatch.setattr(analysis_cli, "ManagementRuntime", forbidden)
    monkeypatch.setattr(analysis_cli, "load_manifest", forbidden)
    monkeypatch.setattr(control_cli, "ControlRuntime", forbidden)
    monkeypatch.setattr(control_cli, "HouseholdOperator", forbidden)
    monkeypatch.setattr(control_cli, "HouseholdProfile", forbidden)

    analysis_routes = _analysis_routes()
    control_routes = list(_visible_click_routes(control_cli.cli))
    hidden_routes = [("plan",), ("execute",)]
    for route in analysis_routes:
        for flag in ("-h", "--help"):
            with pytest.raises(SystemExit) as raised:
                analysis_cli.main([*route, flag])
            assert raised.value.code == 0
    for route in [*control_routes, *hidden_routes]:
        for flag in ("-h", "--help"):
            assert control_cli.main([*route, flag]) == 0
            assert analysis_cli.main(["control", *route, flag]) == 0
    assert capsys.readouterr().err == ""