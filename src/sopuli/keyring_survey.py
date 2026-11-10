"""Which OS keyring entries ``doctor`` uses, and whether they are there.

``doctor``'s ``keyring`` section (#1417, decision 5): for each entry that a
vault's auth material or a target's ``method: keyring`` admin credential names,
the backend in use and whether the entry exists. The same section shape and
rules as ``wallet``'s: absent when nothing names an entry, and no effect on the
exit code. Every entry listed is one ``doctor`` itself reads when it opens a
vault or connects to a target, so a missing one also fails that vault or target,
with that failure's own message. This section shows them in one place, before the
connections.

**Only what ``doctor`` uses.** The vaults come from ``config.vaults``, which
already holds the merged result of ``defaults:`` and the active profile, so an
unused profile's entry is not read. A ``keyring:`` source in a delivery block is
not listed: ``doctor`` does not resolve delivery material, so the section could
not keep its promise that a missing entry also fails something.

**Presence is read, not inferred.** The keyring library has no call that asks
whether an entry exists without reading it, so the survey reads each entry and
keeps only whether it was there. The value is never held past that comparison.
The vault or target that needs the entry reads it a second time; on macOS that
can mean a second Keychain prompt for an entry with access control.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass
from typing import Any

from sopuli import os_keyring
from sopuli.admin import auth_at, uses_keyring
from sopuli.config.errors import MaterialError
from sopuli.config.model import AdminAuth, Config, MaterialRef

#: The position a refusal from :func:`sopuli.os_keyring.backend` names. Removed
#: again from its message, because the section says where it comes from.
_WHERE = "doctor"

#: The fields of a vault's ``auth:`` that hold a MaterialRef (``01-configuration.md``
#: §3a, *MaterialRef*).
_VAULT_MATERIAL = ("token", "role_id", "secret_id", "jwt", "password")


@dataclass(frozen=True)
class EntryReport:
    """One entry, and the places in the configuration that name it."""

    entry: str
    required_by: tuple[str, ...]
    #: ``None`` when the entry could not be read: no backend, or the read failed.
    present: bool | None
    #: Why it could not be read, when the backend was there and the read failed.
    problem: str | None = None
    #: What ``keyring set`` or ``keyring delete`` did, or would do: one of
    #: :data:`ACTIONS`. ``None`` in ``doctor``, which changes nothing.
    action: str | None = None
    #: Whether the action was carried out: ``False`` on a dry run.
    applied: bool | None = None


#: The actions of the `keyring` verbs. ``unchanged`` and ``absent`` change
#: nothing, so a second run of either verb reports one of them (invariant 9).
ACTIONS = ("add", "replace", "unchanged", "delete", "absent")


@dataclass(frozen=True)
class KeyringReport:
    """The backend, or why there is none, and every entry ``doctor`` uses."""

    backend: str | None
    problem: str | None
    entries: tuple[EntryReport, ...]
    #: What to do about ``problem``: install the extra, or use another source.
    hint: str | None = None


def sources(config: Config) -> dict[str, list[str]]:
    """Each entry ``doctor`` uses, with the config keys that name it.

    Pure. The vaults' entries first, in ``vaults:`` order, then the admin
    entries, in the order of the selected targets. A target set's entry is
    listed once, at the set's line.
    """
    found: dict[str, list[str]] = {}
    for vault in config.vaults:
        auth = vault.auth
        if auth is None:
            continue
        for field in _VAULT_MATERIAL:
            ref = getattr(auth, field)
            if isinstance(ref, MaterialRef) and ref.kind == "keyring":
                _add(found, ref.location, f"vaults.{vault.name}.auth.{field}")
    for target in config.expanded_targets:
        admin_auth = target.target.admin.auth if target.target.admin is not None else None
        if uses_keyring(target) and admin_auth is not None and admin_auth.entry is not None:
            # Where the line is written: a generated target's is its set's.
            _add(found, admin_auth.entry, str(auth_at(target).key("entry")))
    return found


def named_anywhere(config: Config, entry: str) -> bool:
    """Whether any part of the loaded config names ``entry``.

    Pure. Wider than :func:`sources`: every ``keyring:`` MaterialRef, in a
    delivery block or a profile the run does not use as well, and every
    ``method: keyring`` admin credential. ``keyring set`` notes an entry nothing
    names, which is usually a typo in the entry or in the config.
    """
    seen: set[int] = set()
    pending: list[object] = [config]
    while pending:
        node = pending.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, MaterialRef):
            if node.kind == "keyring" and node.location == entry:
                return True
        elif isinstance(node, AdminAuth):
            if node.method == "keyring" and node.entry == entry:
                return True
        elif is_dataclass(node) and not isinstance(node, type):
            pending.extend(getattr(node, one.name) for one in fields(node))
        elif isinstance(node, tuple | list):
            pending.extend(node)
        elif isinstance(node, Mapping):
            pending.extend(node.values())
    return False


def survey(config: Config) -> KeyringReport | None:
    """The section, or ``None`` when ``doctor`` uses no keyring entry."""
    named = sources(config)
    if not named:
        return None
    try:
        chosen = os_keyring.backend(where=_WHERE)
    except MaterialError as error:
        entries = tuple(
            EntryReport(entry=entry, required_by=tuple(by), present=None)
            for entry, by in named.items()
        )
        return KeyringReport(
            backend=None,
            problem=error.message.removeprefix(f"{_WHERE}: "),
            entries=entries,
            hint=error.hint,
        )
    return KeyringReport(
        backend=os_keyring.name_of(chosen),
        problem=None,
        entries=tuple(_entry(chosen, entry, by) for entry, by in named.items()),
    )


def _add(found: dict[str, list[str]], entry: str, at: str) -> None:
    named = found.setdefault(entry, [])
    if at not in named:
        named.append(at)


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
