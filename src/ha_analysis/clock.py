"""One UTC timestamp rendering shared by analysis results and management documents."""

from __future__ import annotations

from datetime import datetime, timezone


def utc_timestamp() -> str:
    """Render the current instant as an RFC3339 timestamp with a ``Z`` offset."""

    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
