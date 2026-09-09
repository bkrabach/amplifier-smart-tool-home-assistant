"""Read-only access to historical pre-v0.7 control-plan records.

The old approval journal is never created, migrated, or written by the direct
control implementation.  This accessor exists only so owner history remains
readable after migration.
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from pathlib import Path
from typing import Any


def read_legacy_plan_status(
    plan_id: object, state_home: str | os.PathLike[str] | None = None
) -> dict[str, Any] | None:
    """Return a projected historical record through SQLite's read-only URI."""
    if not isinstance(plan_id, str):
        return None
    root = Path(
        state_home or os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")
    )
    directory = root / "ha-analysis"
    path = directory / "control.sqlite3"
    try:
        directory_info = directory.lstat()
        file_info = path.lstat()
        if (
            not stat.S_ISDIR(directory_info.st_mode)
            or directory_info.st_mode & 0o077
            or not stat.S_ISREG(file_info.st_mode)
            or file_info.st_mode & 0o077
        ):
            return None
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            connection.execute("PRAGMA query_only=ON")
            row = connection.execute(
                "SELECT status, approved_at, intent_at, outcome, observations FROM plans WHERE plan_id=?",
                (plan_id,),
            ).fetchone()
        finally:
            connection.close()
    except (OSError, sqlite3.Error):
        return None
    if row is None:
        return None
    try:
        observations = json.loads(row[4]) if row[4] is not None else None
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if observations is not None and not isinstance(observations, list):
        return None
    return {
        "plan_id": plan_id,
        "state": row[0],
        "approved_at": row[1],
        "intent_at": row[2],
        "outcome": row[3],
        "observations": observations,
    }
