"""Vault records that look like this tool's and that no binding declares (#999).

An operator who moves an application's secret path in the config leaves the old
document behind, and its lock record beside it. Nothing the tool does reaches
either again, because the config is the whitelist (invariant 5), and nothing
shows them either. ``sopuli vault orphans`` lists them and prints the command
that removes each one. **It deletes nothing**: the vault is master
(invariant 6), and a delete is the operator's, made after the checks in
``getting-started.md``.

Two kinds of record are found:

- **a secret**: a document whose root holds :data:`~sopuli.payload.ORIGIN` or
  :data:`~sopuli.payload.ROTATED_AT`, at a path no binding names. ``creds
  generate`` writes the first and every promotion writes the second, so a
  document the tool has staged or promoted carries one of them. A document
  without either is somebody else's, and is not reported;
- **a lock**: a record under ``locks/`` at a path no binding names, as ``lock
  status`` already finds them (:func:`sopuli.lock.inspect.discover`).

Paths under the `reset_records:` prefix are left out of both. They are this
estate's, and ``lock status`` reports them.

**Reading a document to see its shape reads its values.** They stay in this
process: only the root keys are looked at, and nothing from the document is
reported except its version.
"""

from __future__ import annotations

import shlex
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from sopuli.config.model import Vault
from sopuli.lock.inspect import LockState, ResetRegion, SkippedPath, discover, survey
from sopuli.lock.keys import LockKey, normalise_path
from sopuli.lock.manager import LOCK_PREFIX, lock_path
from sopuli.payload import ORIGIN, ROTATED_AT
from sopuli.store.protocol import LIST, SecretStore, bounded_prefix

#: :attr:`Orphan.kind` for a secret document.
SECRET = "secret"

#: :attr:`Orphan.kind` for a lock record.
LOCK = "lock"

#: Root keys that only this tool's documents carry.
MARKERS = (ORIGIN, ROTATED_AT)


@dataclass(frozen=True)
class Orphan:
    """One record no binding declares."""

    store: str
    #: The path in the store, as a delete takes it. A lock's starts with
    #: ``locks/``.
    path: str
    kind: str
    #: The store's version of a secret. ``None`` for a lock, whose version is on
    #: :attr:`lock`.
    version: int | None = None
    #: The lock record, as ``lock status`` reads it. ``None`` for a secret.
    lock: LockState | None = None

    @property
    def secret_path(self) -> str:
        """The secret path this record belongs to, without ``locks/``."""
        return self.lock.key.path if self.lock is not None else self.path

    @property
    def is_held(self) -> bool:
        """Whether a lock that has not expired stands on this path."""
        return self.lock is not None and self.lock.is_held and not self.lock.expired


@dataclass(frozen=True)
class Survey:
    """What was found, and where the stores could not be looked at."""

    orphans: tuple[Orphan, ...]
    unlistable: tuple[str, ...] = ()
    skipped: tuple[SkippedPath, ...] = ()

    def held_paths(self) -> frozenset[tuple[str, str]]:
        """(store, secret path) for each path a live lock stands on.

        A delete command is not printed for such a path, for the lock or for
        its secret: somebody may be rotating it.
        """
        return frozenset(
            (orphan.store, orphan.secret_path) for orphan in self.orphans if orphan.is_held
        )


def find(
    declared: Iterable[LockKey],
    *,
    stores: Mapping[str, SecretStore],
    region: ResetRegion | None = None,
) -> Survey:
    """Every orphan in ``stores``, sorted by store and path.

    ``declared`` is the **whole** estate, one key per (store, secret path) any
    binding names. A secret path and its lock share that key, so one set
    answers for both kinds.
    """
    known = set(declared)
    locks = discover(known, stores=stores)
    states = survey(locks.keys, stores=stores, declared=known, region=region)
    found = [
        Orphan(store=state.key.store, path=lock_path(state.key), kind=LOCK, lock=state)
        for state in states
        if state.declared_by is None
    ]
    skipped = list(locks.skipped)
    for name, store in sorted(stores.items()):
        if LIST not in store.supports():
            continue
        secrets, unaddressable = _secrets(name, store, known, region=region)
        found.extend(secrets)
        skipped.extend(unaddressable)
    return Survey(
        orphans=tuple(sorted(found, key=lambda orphan: (orphan.store, orphan.path))),
        unlistable=locks.unlistable,
        skipped=tuple(skipped),
    )


def _secrets(
    name: str,
    store: SecretStore,
    known: set[LockKey],
    *,
    region: ResetRegion | None,
) -> tuple[list[Orphan], list[SkippedPath]]:
    """The undeclared documents in one store that carry a marker."""
    excluded = [bounded_prefix(LOCK_PREFIX)]
    if region is not None and region.store == name:
        excluded.append(bounded_prefix(region.prefix))
    found: list[Orphan] = []
    skipped: list[SkippedPath] = []
    for path in store.list(""):
        if any(path.startswith(prefix) for prefix in excluded):
            continue
        try:
            key = LockKey(store=name, path=normalise_path(path))
        except ValueError:
            skipped.append(SkippedPath(store=name, path=path))
            continue
        if key in known:
            continue
        stored = store.read(path)
        if stored is not None and is_sopuli_document(stored.data):
            found.append(Orphan(store=name, path=path, kind=SECRET, version=stored.version))
    return found, skipped


def is_sopuli_document(data: Any) -> bool:
    """Whether ``data`` has a root key only this tool writes."""
    return isinstance(data, Mapping) and any(marker in data for marker in MARKERS)


def delete_command(vault: Vault, path: str) -> str | None:
    """The vault CLI command that removes ``path`` and its history, or ``None``.

    KV v2 needs ``kv metadata delete``. A plain ``kv delete`` keeps the
    versions and the metadata, and on a lock path it keeps the version counter,
    so a first acquisition at version 0 can never succeed there again.

    ``None`` for a backend this build has no command for.
    """
    if vault.type != "hashicorp":
        return None
    # Imported here: the backend imports httpx, and the base package loads no
    # vendor client (ADR-006). A survey that reached this point has opened the
    # store, so the backend is installed.
    from sopuli.store.hashicorp import DEFAULT_KV_VERSION, DEFAULT_MOUNT

    mount = vault.mount if vault.mount is not None else DEFAULT_MOUNT
    version = vault.kv_version if vault.kv_version is not None else DEFAULT_KV_VERSION
    words = ["vault", "kv", "metadata", "delete"] if version == 2 else ["vault", "kv", "delete"]
    if vault.namespace is not None:
        words.append(f"-namespace={vault.namespace}")
    words.extend([f"-mount={mount}", path])
    return shlex.join(words)


def commands(survey: Survey, vaults: Sequence[Vault]) -> tuple[str | None, ...]:
    """The delete command for each orphan, in order, ``None`` where none is printed.

    No command for a path a live lock stands on (:meth:`Survey.held_paths`).
    """
    by_name = {vault.name: vault for vault in vaults}
    held = survey.held_paths()
    return tuple(
        None
        if (orphan.store, orphan.secret_path) in held
        else delete_command(by_name[orphan.store], orphan.path)
        for orphan in survey.orphans
    )


__all__ = [
    "LOCK",
    "MARKERS",
    "SECRET",
    "Orphan",
    "Survey",
    "commands",
    "delete_command",
    "find",
    "is_sopuli_document",
]
