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
- **a lock**: a record under ``locks/`` at a path no binding names.

Paths under the `reset_records:` prefix are left out of both. They are this
estate's, and ``lock status`` reports them.

**A binding whose store is chosen at run time declares its path in every
store.** Its store comes from ``SOPULI_VAULT`` or a profile's ``vault:``, so a
rotation job may write it to a store this run would not pick. Reporting the
live document there as an orphan, with a delete command beside it, is the
mistake this verb must not make.

**Reading a document to see its shape reads its values.** They stay in this
process: only the root keys are looked at, and nothing from the document is
reported except its version. Each read is in the store's audit log.
"""

from __future__ import annotations

import shlex
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from sopuli.config.model import Binding, Vault
from sopuli.lock.inspect import LockState, ResetRegion, SkippedPath, secret_path, survey
from sopuli.lock.keys import LockKey, lock_key, normalise_path
from sopuli.lock.manager import LOCK_PREFIX
from sopuli.payload import ORIGIN, ROTATED_AT
from sopuli.store.protocol import CAS, LIST, SecretStore, StoreError, bounded_prefix

#: :attr:`Orphan.kind` for a secret document.
SECRET = "secret"

#: :attr:`Orphan.kind` for a lock record.
LOCK = "lock"

#: Root keys that only this tool's documents carry.
MARKERS = (ORIGIN, ROTATED_AT)


@dataclass(frozen=True)
class Orphan:
    """One record no binding declares."""

    #: The store and the secret path, normalised. A lock and its secret share it.
    key: LockKey
    #: The path as the store listed it, which is what a delete takes. A lock's
    #: starts with ``locks/``.
    path: str
    kind: str
    #: The store's version of a secret, ``None`` on a store with no
    #: compare-and-set. ``None`` for a lock, whose version is on :attr:`lock`.
    version: int | None = None
    #: The lock record, as ``lock status`` reads it. ``None`` for a secret.
    lock: LockState | None = None

    @property
    def store(self) -> str:
        return self.key.store

    @property
    def is_held(self) -> bool:
        """Whether a lock that has not expired stands on this path."""
        return self.lock is not None and self.lock.is_held and not self.lock.expired


@dataclass(frozen=True)
class Unread:
    """A document the store listed and would not let this run read."""

    store: str
    path: str
    reason: str


@dataclass(frozen=True)
class Survey:
    """What was found, and where the stores could not be looked at."""

    orphans: tuple[Orphan, ...]
    #: The stores that were listed.
    listed: tuple[str, ...] = ()
    unlistable: tuple[str, ...] = ()
    skipped: tuple[SkippedPath, ...] = ()
    unread: tuple[Unread, ...] = ()

    def held(self) -> frozenset[LockKey]:
        """The keys a live lock stands on.

        A delete command is not printed for such a key, for the lock or for its
        secret: somebody may be rotating it.
        """
        return frozenset(orphan.key for orphan in self.orphans if orphan.is_held)


@dataclass(frozen=True)
class Declared:
    """What the configuration declares, as membership tests.

    ``keys`` are the (store, path) pairs of bindings whose store the file
    fixes. ``anywhere`` are the paths of bindings whose store is chosen at run
    time, which count as declared in every store.
    """

    keys: frozenset[LockKey]
    anywhere: frozenset[str] = frozenset()

    def __contains__(self, key: object) -> bool:
        return isinstance(key, LockKey) and (key in self.keys or key.path in self.anywhere)


def find(
    declared: Declared,
    *,
    stores: Mapping[str, SecretStore],
    region: ResetRegion | None = None,
) -> Survey:
    """Every orphan in ``stores``, sorted by store and path."""
    found: list[Orphan] = []
    listed: list[str] = []
    unlistable: list[str] = []
    skipped: list[SkippedPath] = []
    unread: list[Unread] = []
    for name, store in sorted(stores.items()):
        if LIST not in store.supports():
            unlistable.append(name)
            continue
        listed.append(name)
        locks, bad = _locks(name, store, declared, region=region)
        found.extend(locks)
        skipped.extend(bad)
        secrets, bad, failed = _secrets(name, store, declared, region=region)
        found.extend(secrets)
        skipped.extend(bad)
        unread.extend(failed)
    return Survey(
        orphans=tuple(sorted(found, key=lambda orphan: (orphan.store, orphan.path))),
        listed=tuple(listed),
        unlistable=tuple(unlistable),
        skipped=tuple(skipped),
        unread=tuple(unread),
    )


def _locks(
    name: str, store: SecretStore, declared: Declared, *, region: ResetRegion | None
) -> tuple[list[Orphan], list[SkippedPath]]:
    """The undeclared lock records in one store, at the paths the store listed.

    The listed path is kept rather than rebuilt from the key, because the key is
    normalised and a delete has to name the record as it is stored.
    """
    listed: dict[LockKey, str] = {}
    skipped: list[SkippedPath] = []
    for path in store.list(LOCK_PREFIX):
        try:
            key = LockKey(store=name, path=secret_path(path))
        except ValueError:
            skipped.append(SkippedPath(store=name, path=path))
            continue
        if key in declared or (region is not None and region.covers(key)):
            continue
        listed.setdefault(key, path)
    states = survey(listed, stores={name: store}, declared=set())
    return [
        Orphan(key=state.key, path=listed[state.key], kind=LOCK, lock=state) for state in states
    ], skipped


def _secrets(
    name: str, store: SecretStore, declared: Declared, *, region: ResetRegion | None
) -> tuple[list[Orphan], list[SkippedPath], list[Unread]]:
    """The undeclared documents in one store that carry a marker.

    A document the store will not let this run read is reported in ``Unread``,
    not as a failure of the survey: on a shared mount, another team's path may
    be listable and not readable.
    """
    excluded = [bounded_prefix(LOCK_PREFIX)]
    if region is not None and region.store == name:
        excluded.append(bounded_prefix(region.prefix))
    versioned = CAS in store.supports()
    found: list[Orphan] = []
    skipped: list[SkippedPath] = []
    unread: list[Unread] = []
    for path in store.list(""):
        if any(path.startswith(prefix) for prefix in excluded):
            continue
        try:
            key = LockKey(store=name, path=normalise_path(path))
        except ValueError:
            skipped.append(SkippedPath(store=name, path=path))
            continue
        if key in declared:
            continue
        try:
            stored = store.read(path)
        except StoreError as error:
            unread.append(Unread(store=name, path=path, reason=error.message))
            continue
        if stored is not None and is_sopuli_document(stored.data):
            found.append(
                Orphan(
                    key=key,
                    path=path,
                    kind=SECRET,
                    version=stored.version if versioned else None,
                )
            )
    return found, skipped, unread


def is_sopuli_document(data: Any) -> bool:
    """Whether ``data`` has a root key only this tool writes."""
    return isinstance(data, Mapping) and any(marker in data for marker in MARKERS)


def delete_command(vault: Vault, path: str) -> str | None:
    """The vault CLI command that removes ``path`` and its history, or ``None``.

    KV v2 needs ``kv metadata delete``. A plain ``kv delete`` keeps the
    versions and the metadata, and on a lock path it keeps the version counter,
    so a first acquisition at version 0 can never succeed there again.

    It names the address, so it reaches the store the config names whatever
    ``VAULT_ADDR`` the shell holds. It is quoted for a POSIX shell.

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
    if vault.addr is not None:
        words.append(f"-address={vault.addr}")
    if vault.namespace is not None:
        words.append(f"-namespace={vault.namespace}")
    words.extend([f"-mount={mount}", path])
    return shlex.join(words)


def commands(survey: Survey, vaults: Sequence[Vault]) -> tuple[str | None, ...]:
    """The delete command for each orphan, in order, ``None`` where none is printed.

    No command for a key a live lock stands on (:meth:`Survey.held`).
    """
    by_name = {vault.name: vault for vault in vaults}
    held = survey.held()
    return tuple(
        None if orphan.key in held else delete_command(by_name[orphan.store], orphan.path)
        for orphan in survey.orphans
    )


def declared_by(bindings: Iterable[Binding]) -> Declared:
    """What ``bindings`` declare, as loaded and before a run completes them.

    A binding with no store at load gets one from ``SOPULI_VAULT`` or a
    profile, which a later run may set differently, so its path counts in
    every store (:class:`Declared`).
    """
    keys = set()
    anywhere = set()
    for binding in bindings:
        if binding.secret is None:
            continue
        if binding.vault is None:
            anywhere.add(lock_key(binding.secret, store="").path)
        else:
            keys.add(lock_key(binding.secret, store=binding.vault))
    return Declared(keys=frozenset(keys), anywhere=frozenset(anywhere))


__all__ = [
    "LOCK",
    "MARKERS",
    "SECRET",
    "Declared",
    "Orphan",
    "Survey",
    "Unread",
    "commands",
    "declared_by",
    "delete_command",
    "find",
    "is_sopuli_document",
]
