"""Which OS keyring entries the configuration names, and whether they are there.

``doctor``'s ``keyring`` section (#1417, decision 5): for each entry a
``keyring:`` MaterialRef or a ``method: keyring`` admin credential names, the
backend in use and whether the entry exists. The same section shape and rules as
``wallet``'s: absent when nothing names an entry, and no effect on the exit
code. A missing entry also fails the vault or the target that needs it, a moment
later, with that failure's own message; this section shows every entry in one
place, before the connections.

**Presence is read, not inferred.** The keyring library has no call that asks
whether an entry exists without reading it, so the survey reads each entry and
keeps only whether it was there. The value is never held past that comparison.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from sopuli import os_keyring
from sopuli.admin import auth_at, uses_keyring
from sopuli.config.errors import MaterialError
from sopuli.config.model import Config, MaterialRef

#: The position a refusal from :func:`sopuli.os_keyring.backend` names. Removed
#: again from its message, because the section says where it comes from.
_WHERE = "doctor"


@dataclass(frozen=True)
class EntryReport:
    """One entry, and the places in the configuration that name it."""

    entry: str
    required_by: tuple[str, ...]
    #: ``None`` when the entry could not be read: no backend, or the read failed.
    present: bool | None
    #: Why it could not be read, when the backend was there and the read failed.
    problem: str | None = None


@dataclass(frozen=True)
class KeyringReport:
    """The backend, or why there is none, and every entry the config names."""

    backend: str | None
    problem: str | None
    entries: tuple[EntryReport, ...]


def sources(config: Config) -> dict[str, list[str]]:
    """Each entry the configuration names, with where it is named, in file order.

    Pure. ``keyring:`` MaterialRefs are found by walking the whole configuration,
    so a MaterialRef added to any block later is found without a change here. The
    admin credential is read from the expanded targets, the ones this run
    selected, as ``doctor`` surveys them.
    """
    found: dict[str, list[str]] = {}
    for path, ref in _material_refs(config, ""):
        if ref.kind == "keyring":
            found.setdefault(ref.location, []).append(path)
    for target in config.expanded_targets:
        auth = target.target.admin.auth if target.target.admin is not None else None
        if uses_keyring(target) and auth is not None and auth.entry is not None:
            # Where the line is written: a generated target's is its set's.
            # Two targets of one set naming one entry are listed once.
            at = str(auth_at(target).key("entry"))
            named = found.setdefault(auth.entry, [])
            if at not in named:
                named.append(at)
    return found


def survey(config: Config) -> KeyringReport | None:
    """The section, or ``None`` when the configuration names no keyring entry."""
    named = sources(config)
    if not named:
        return None
    try:
        chosen = os_keyring.backend(where=_WHERE)
    except MaterialError as error:
        problem = error.message.removeprefix(f"{_WHERE}: ")
        entries = tuple(
            EntryReport(entry=entry, required_by=tuple(by), present=None)
            for entry, by in named.items()
        )
        return KeyringReport(backend=None, problem=problem, entries=entries)
    return KeyringReport(
        backend=os_keyring.name_of(chosen),
        problem=None,
        entries=tuple(_entry(chosen, entry, by) for entry, by in named.items()),
    )


def _entry(chosen: Any, entry: str, required_by: list[str]) -> EntryReport:
    try:
        present = bool(chosen.get_password(os_keyring.SERVICE, entry))
    except Exception as error:  # noqa: BLE001 - os_keyring.read gives the reason
        return EntryReport(
            entry=entry,
            required_by=tuple(required_by),
            present=None,
            problem=f"{type(error).__name__}: {error}",
        )
    return EntryReport(entry=entry, required_by=tuple(required_by), present=present)


def _material_refs(value: Any, path: str) -> Iterator[tuple[str, MaterialRef]]:
    """Every MaterialRef under ``value``, with its key path.

    A sequence element with a ``name`` is named by it, so a path reads
    ``vaults.vault-dev.auth.token`` as a config error would, rather than by its
    position.
    """
    if isinstance(value, MaterialRef):
        yield path, value
        return
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        for field in dataclasses.fields(value):
            yield from _material_refs(getattr(value, field.name), _join(path, field.name))
        return
    if isinstance(value, tuple | list):
        for index, item in enumerate(value):
            name = getattr(item, "name", None)
            key = name if isinstance(name, str) else f"[{index}]"
            yield from _material_refs(item, _join(path, key))
        return
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _material_refs(item, _join(path, str(key)))


def _join(path: str, key: str) -> str:
    if key.startswith("["):
        return f"{path}{key}"
    return f"{path}.{key}" if path else key
