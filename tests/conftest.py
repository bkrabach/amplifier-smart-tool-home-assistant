"""Test-wide isolation from the developer's real configuration and secret store.

Two guards, applied to every test including the ones that shell out to the CLI:

* ``XDG_CONFIG_HOME`` is redirected into a per-test temporary directory, so no
  test can read or write the real ``~/.config/ha-analysis/settings.json``;
* ``PYTHON_KEYRING_BACKEND`` is pinned to ``keyring.backends.fail.Keyring``, so
  a test that accidentally reaches a real backend fails closed instead of
  touching the developer's login keyring. The tool's own allow-list refuses the
  fail backend, which is the behavior under test in several cases.

The one opt-in test that exercises a real operating-system secret store runs in
a subprocess with these guards deliberately removed.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolated_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    config_home = tmp_path / "xdg-config"
    config_home.mkdir()
    state_home = tmp_path / "xdg-state"
    state_home.mkdir()
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))
    monkeypatch.setenv("XDG_STATE_HOME", str(state_home))
    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "keyring.backends.fail.Keyring")
    monkeypatch.delenv("HA_ANALYSIS_REAL_SECRET_STORE", raising=False)
    assert os.environ["XDG_CONFIG_HOME"] == str(config_home)
    return config_home
