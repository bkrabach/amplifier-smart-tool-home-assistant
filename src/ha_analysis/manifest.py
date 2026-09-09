"""Packaged smart-tool metadata access without operational side effects."""

from __future__ import annotations

from importlib.resources import files

_REQUIRED_KEYS = {
    "smart_tool_format",
    "name",
    "version",
    "description",
    "use_cases",
    "platforms",
}


def load_manifest() -> dict[str, object]:
    """Load the closed frontmatter from the packaged ``SMART_TOOL.md`` file."""

    text = files("ha_analysis").joinpath("SMART_TOOL.md").read_text(encoding="utf-8")
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        raise ValueError("SMART_TOOL.md must start with closed frontmatter.")

    try:
        end = lines.index("---", 1)
    except ValueError as error:
        raise ValueError("SMART_TOOL.md frontmatter is not closed.") from error

    manifest: dict[str, object] = {}
    current_list: list[str] | None = None
    for line in lines[1:end]:
        if not line.strip():
            continue
        if line.startswith("  - ") and current_list is not None:
            current_list.append(line[4:])
            continue
        key, separator, value = line.partition(":")
        if not separator or not key:
            raise ValueError("SMART_TOOL.md contains invalid frontmatter.")
        value = value.lstrip()
        if key in manifest:
            raise ValueError(f"SMART_TOOL.md repeats frontmatter key {key!r}.")
        if value:
            manifest[key] = int(value) if key == "smart_tool_format" and value.isdecimal() else value
            current_list = None
        else:
            current_list = []
            manifest[key] = current_list

    if set(manifest) != _REQUIRED_KEYS:
        raise ValueError("SMART_TOOL.md frontmatter does not match the closed manifest schema.")
    if not isinstance(manifest["smart_tool_format"], int):
        raise ValueError("SMART_TOOL.md smart_tool_format must be a number.")
    for key in ("name", "version", "description"):
        if not isinstance(manifest[key], str) or not manifest[key]:
            raise ValueError(f"SMART_TOOL.md {key} must be a non-empty string.")
    for key in ("use_cases", "platforms"):
        if not isinstance(manifest[key], list) or not manifest[key] or not all(
            isinstance(item, str) and item for item in manifest[key]
        ):
            raise ValueError(f"SMART_TOOL.md {key} must be a non-empty list of strings.")
    return manifest