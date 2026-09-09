"""Owner-managed, bounded local household mappings for the embedded operator."""

from __future__ import annotations

import json
import os
import stat
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from .control import _ENTITY_ID, _state_path, _validate_data, _validate_service
from .origins import normalize_origin, origin_url
from .redaction import safe_text

_MAX_FILE_BYTES = 128 * 1024
_MAX_RECORDS = 128
_MAX_TEXT = 1000
_MAX_ROUTINE_STEPS = 24
_SUPPORTED_PROVIDERS = frozenset(
    {"anthropic", "azure-openai", "chat-completions", "gemini", "ollama", "openai", "vllm"}
)


class HouseholdProfileError(ValueError):
    """A profile was unavailable, unsafe, or not valid closed-schema data."""


class HouseholdProfile:
    """Persist only owner-authored aliases, facts, routines, and model selection."""

    def __init__(self, state_home: str | os.PathLike[str] | None = None) -> None:
        self.path = _state_path(state_home, "household-profile.json")

    def configure_model(self, provider: str, model: str) -> None:
        if not isinstance(provider, str) or provider not in _SUPPORTED_PROVIDERS or not safe_text(model, 160):
            raise HouseholdProfileError("provider and model must be supported bounded text")
        self._mutate(lambda document: document.update(model={"provider": provider, "model": model}))

    def model_configuration(self) -> dict[str, str] | None:
        def read() -> dict[str, str] | None:
            model = self._read()["model"]
            return dict(model) if model else None
        return self._public(read)

    def status(self) -> dict[str, object]:
        def read() -> dict[str, object]:
            value = self._read()
            return {
                "configured": value["model"] is not None,
                "aliases": sum(len(item["aliases"]) for item in value["origins"].values()),
                "facts": sum(len(item["facts"]) for item in value["origins"].values()),
                "routines": sum(len(item["routines"]) for item in value["origins"].values()),
            }
        return self._public(read)

    def set_alias(self, origin: str, phrase: str, entity_ids: list[str]) -> None:
        if not safe_text(phrase, 160) or not _entity_ids(entity_ids):
            raise HouseholdProfileError("alias requires bounded phrase and exact entity IDs")
        copied = list(entity_ids)
        self._update_origin(
            origin,
            lambda record: record["aliases"].update({phrase.casefold(): {"phrase": phrase, "entity_ids": copied}}),
        )

    def set_fact(self, origin: str, label: str, text: str) -> None:
        if not safe_text(label, 160) or not safe_text(text, _MAX_TEXT):
            raise HouseholdProfileError("fact requires bounded non-credential text")
        self._update_origin(
            origin,
            lambda record: record["facts"].update({label.casefold(): {"label": label, "text": text}}),
        )

    def set_routine(self, origin: str, name: str, description: str, steps: list[object]) -> None:
        if not safe_text(name, 160) or not safe_text(description, _MAX_TEXT):
            raise HouseholdProfileError("routine requires bounded non-credential text")
        checked = _routine_steps(steps)
        self._update_origin(
            origin,
            lambda record: record["routines"].update(
                {name.casefold(): {"name": name, "description": description, "steps": checked}}
            ),
        )

    def forget(self, origin: str, kind: str, name: str) -> bool:
        if kind not in {"aliases", "facts", "routines"} or not safe_text(name, 160):
            raise HouseholdProfileError("unknown profile record")
        def mutate(document: dict[str, Any]) -> bool:
            record = _origin_record(document, origin)
            return record[kind].pop(name.casefold(), None) is not None
        return self._mutate(mutate, write_when=lambda removed: removed)

    def records(self, origin: str, kind: str | None = None) -> dict[str, object]:
        if kind not in {None, "aliases", "facts", "routines"}:
            raise HouseholdProfileError("unknown profile record")
        def read() -> dict[str, object]:
            document = self._read()
            record = document["origins"].get(_origin_key(origin), _empty_origin())
            keys = (kind,) if kind else ("aliases", "facts", "routines")
            return {key: [record[key][name] for name in sorted(record[key])] for key in keys}
        return self._public(read)

    def alias(self, origin: str, phrase: str) -> list[str] | None:
        if not safe_text(phrase, 160):
            raise HouseholdProfileError("alias invalid")
        def read() -> list[str] | None:
            value = self._read()["origins"].get(_origin_key(origin), _empty_origin())["aliases"].get(phrase.casefold())
            return list(value["entity_ids"]) if value else None
        return self._public(read)

    def routine(self, origin: str, name: str) -> dict[str, object] | None:
        if not safe_text(name, 160):
            raise HouseholdProfileError("routine invalid")
        def read() -> dict[str, object] | None:
            value = self._read()["origins"].get(_origin_key(origin), _empty_origin())["routines"].get(name.casefold())
            return json.loads(json.dumps(value)) if value else None
        return self._public(read)

    def _update_origin(self, origin: str, update: Callable[[dict[str, Any]], None]) -> None:
        def mutate(document: dict[str, Any]) -> None:
            update(_origin_record(document, origin))
        self._mutate(mutate)

    def _mutate(self, change: Callable[[dict[str, Any]], Any], write_when: Callable[[Any], bool] | None = None) -> Any:
        try:
            document = self._read()
            result = change(document)
            if write_when is None or write_when(result):
                self._write(document)
            return result
        except HouseholdProfileError:
            raise
        except (OSError, ValueError, TypeError, OverflowError) as error:
            raise HouseholdProfileError("profile update failed") from error

    def _public(self, operation: Callable[[], Any]) -> Any:
        try:
            return operation()
        except HouseholdProfileError:
            raise
        except (OSError, ValueError, TypeError, OverflowError) as error:
            raise HouseholdProfileError("profile unavailable") from error

    def _read(self) -> dict[str, Any]:
        _check_path(self.path, allow_absent=True)
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            return {"model": None, "origins": {}}
        if len(raw) > _MAX_FILE_BYTES:
            raise HouseholdProfileError("profile exceeds its size limit")
        try:
            return _profile(json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object))
        except (UnicodeError, json.JSONDecodeError, ValueError, TypeError) as error:
            raise HouseholdProfileError("profile is invalid") from error

    def _write(self, value: dict[str, Any]) -> None:
        checked = _profile(value)
        encoded = json.dumps(checked, sort_keys=True, separators=(",", ":")).encode()
        if len(encoded) > _MAX_FILE_BYTES:
            raise HouseholdProfileError("profile exceeds its size limit")
        _prepare_directory(self.path.parent)
        _check_path(self.path, allow_absent=True)
        temporary = self.path.with_name(f".{self.path.name}.{uuid.uuid4().hex}.tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            os.chmod(self.path, 0o600)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise


def _origin_key(origin: str) -> str:
    try:
        return origin_url(normalize_origin(origin, "trusted_local_or_vpn"))
    except Exception as error:
        raise HouseholdProfileError("origin is invalid") from error


def _empty_origin() -> dict[str, dict[str, Any]]:
    return {"aliases": {}, "facts": {}, "routines": {}}


def _origin_record(document: dict[str, Any], origin: str) -> dict[str, Any]:
    return document["origins"].setdefault(_origin_key(origin), _empty_origin())


def _profile(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"model", "origins"}:
        raise ValueError("unknown profile schema")
    model, origins = value["model"], value["origins"]
    if model is not None and (
        not isinstance(model, Mapping) or set(model) != {"provider", "model"}
        or not isinstance(model["provider"], str) or model["provider"] not in _SUPPORTED_PROVIDERS or not safe_text(model["model"], 160)
    ):
        raise ValueError("model invalid")
    if not isinstance(origins, Mapping) or len(origins) > _MAX_RECORDS:
        raise ValueError("origins invalid")
    output: dict[str, Any] = {"model": dict(model) if model else None, "origins": {}}
    for origin, record in origins.items():
        if not isinstance(origin, str) or _origin_key(origin) != origin:
            raise ValueError("origin invalid")
        if not isinstance(record, Mapping) or set(record) != {"aliases", "facts", "routines"}:
            raise ValueError("origin data invalid")
        output["origins"][origin] = {
            "aliases": _aliases(record["aliases"]),
            "facts": _facts(record["facts"]),
            "routines": _routines(record["routines"]),
        }
    return output


def _aliases(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or len(value) > _MAX_RECORDS:
        raise ValueError("aliases invalid")
    output = {}
    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, Mapping) or set(item) != {"phrase", "entity_ids"}:
            raise ValueError("alias invalid")
        if not safe_text(item["phrase"], 160) or item["phrase"].casefold() != key or not _entity_ids(item["entity_ids"]):
            raise ValueError("alias invalid")
        output[key] = {"phrase": item["phrase"], "entity_ids": list(item["entity_ids"])}
    return output


def _facts(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or len(value) > _MAX_RECORDS:
        raise ValueError("facts invalid")
    output = {}
    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, Mapping) or set(item) != {"label", "text"}:
            raise ValueError("fact invalid")
        if not safe_text(item["label"], 160) or item["label"].casefold() != key or not safe_text(item["text"], _MAX_TEXT):
            raise ValueError("fact invalid")
        output[key] = {"label": item["label"], "text": item["text"]}
    return output


def _routines(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or len(value) > _MAX_RECORDS:
        raise ValueError("routines invalid")
    output = {}
    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, Mapping) or set(item) != {"name", "description", "steps"}:
            raise ValueError("routine invalid")
        if not safe_text(item["name"], 160) or item["name"].casefold() != key or not safe_text(item["description"], _MAX_TEXT):
            raise ValueError("routine invalid")
        output[key] = {"name": item["name"], "description": item["description"], "steps": _routine_steps(item["steps"])}
    return output


def _routine_steps(steps: object) -> list[dict[str, Any]]:
    if not isinstance(steps, list) or not 1 <= len(steps) <= _MAX_ROUTINE_STEPS:
        raise HouseholdProfileError("routine steps invalid")
    output = []
    for step in steps:
        if not isinstance(step, Mapping) or set(step) != {"service", "targets", "data"}:
            raise HouseholdProfileError("routine step invalid")
        service, service_error = _validate_service(step["service"])
        data, data_error = _validate_data(step["data"])
        if service_error or data_error or not _entity_ids(step["targets"]):
            raise HouseholdProfileError("routine step invalid")
        output.append({"service": service, "targets": list(step["targets"]), "data": data})
    return output


def _entity_ids(value: object) -> bool:
    return isinstance(value, list) and 1 <= len(value) <= 128 and len(set(value)) == len(value) and all(
        isinstance(item, str) and _ENTITY_ID.fullmatch(item) for item in value
    )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate JSON key")
        output[key] = value
    return output


def _prepare_directory(path: Path) -> None:
    if path.is_symlink():
        raise HouseholdProfileError("profile directory unsafe")
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
        raise HouseholdProfileError("profile directory unsafe")


def _check_path(path: Path, *, allow_absent: bool) -> None:
    parent = path.parent
    if parent.is_symlink():
        raise HouseholdProfileError("profile parent unsafe")
    try:
        parent_info = parent.lstat()
    except FileNotFoundError:
        if allow_absent:
            return
        raise
    if not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_mode & 0o077 or parent_info.st_uid != os.getuid():
        raise HouseholdProfileError("profile parent unsafe")
    try:
        info = path.lstat()
    except FileNotFoundError:
        if allow_absent:
            return
        raise
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid() or info.st_size > _MAX_FILE_BYTES:
        raise HouseholdProfileError("profile file unsafe")