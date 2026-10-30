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

**Two rules keep a live record out of the report**, because a live document
printed beside a delete command is the mistake this verb must not make:

- **a path any binding declares is declared in every store.** Two ``vaults:``
  entries can name one store in ways no comparison catches: ``127.0.0.1`` and
  ``localhost``, a load balancer and a node, a token entry and an AppRole one.
  A binding whose store comes from ``SOPULI_VAULT`` or a profile may be written
  to any of them. Matching on the path alone gives up one case: an application
  moved to another store at the same path leaves a record this does not report;
- a path a lock that has not expired stands on gets no command, for the lock or
  for its secret.

Entries with the same address, namespace, mount and KV version are listed once,
under the first name, so one store is not reported twice.

**Reading a document to see its shape reads its values.** They stay in this
process: only the root keys are looked at, and nothing from the document is
reported except its version. Each read is in the store's audit log.
"""

from __future__ import annotations

import shlex
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

from sopuli.config.model import Binding, Vault

# The address comparison SOPULI-W051 uses, so "the same server" means the same
# here as there.
from sopuli.config.vault_layers import _same_address
from sopuli.exit_codes import ExitCode
from sopuli.lock.inspect import LockState, ResetRegion, SkippedPath, secret_path, survey
from sopuli.lock.keys import LockKey, lock_key, normalise_path
from sopuli.lock.manager import LOCK_PREFIX, lock_path
from sopuli.payload import ORIGIN, ROTATED_AT
from sopuli.store.protocol import (
    CAS,
    LIST,
    NativeNames,
    SecretStore,
    StoreError,
    bounded_prefix,
)

#: :attr:`Orphan.kind` for a secret document.
SECRET = "secret"

#: :attr:`Orphan.kind` for a lock record.
LOCK = "lock"

#: Root keys that only this tool's documents carry.
MARKERS = (ORIGIN, ROTATED_AT)

#: The category of a store error that is about one path rather than the store.
AUTHORIZATION = "authorization"


class NothingListedError(StoreError):
    """No store in ``vaults:`` can list, so the survey could not look at all.

    Exit 5: the capability is missing, which invariant 4 gives that code. An
    empty report here would read as a clean estate.
    """

    category = "capability"
    exit_code = ExitCode.UNSUPPORTED_CAPABILITY


@dataclass(frozen=True)
class Orphan:
    """One record no binding declares."""

    #: The store and the secret path, normalised. A lock and its secret share it.
    key: LockKey
    #: The path as the store listed it, which is what a HashiCorp delete takes.
    #: A lock's starts with ``locks/``.
    path: str
    kind: str
    #: The store's version of a secret, ``None`` on a store with no
    #: compare-and-set. ``None`` for a lock, whose version is on :attr:`lock`.
    version: int | None = None
    #: The lock record, as ``lock status`` reads it. ``None`` for a secret.
    lock: LockState | None = None
    #: The store's own name for the record, where it has names of its own
    #: (:class:`~sopuli.store.protocol.NativeNames`): an OCI lock's is
    #: ``sopuli-locks.<name>``. ``None`` where the name is :attr:`path`.
    native_name: str | None = None
    #: The store's id for the record, which a delete takes on OCI. ``None``
    #: where the store has none, or its listing did not give one.
    native_id: str | None = None

    @property
    def store(self) -> str:
        return self.key.store

    @property
    def name(self) -> str:
        """The record's name in the store: what an operator looks it up by."""
        return self.native_name if self.native_name is not None else self.path

    @property
    def is_held(self) -> bool:
        """Whether a lock that has not expired stands on this path."""
        return self.lock is not None and self.lock.is_held and not self.lock.expired


@dataclass(frozen=True)
class Unread:
    """What a survey could not look at.

    ``path`` is a document the store refused this run. ``None`` means the store
    stopped answering, at ``reason``, and the rest of it was not looked at.
    ``listing`` marks ``path`` as a subtree the store would not list instead:
    under ``--prefix``, the lock records' (#1016). The rest of the store was
    still surveyed.
    """

    store: str
    path: str | None
    reason: str
    listing: bool = False


@dataclass(frozen=True)
class Survey:
    """What was found, and where the stores could not be looked at."""

    orphans: tuple[Orphan, ...]
    #: The stores that were listed.
    listed: tuple[str, ...] = ()
    unlistable: tuple[str, ...] = ()
    skipped: tuple[SkippedPath, ...] = ()
    unread: tuple[Unread, ...] = ()
    #: The secret path the survey was limited to, normalised; ``None`` for the
    #: whole of each store (#1016).
    prefix: str | None = None
    #: How many paths the listings of the stores in ``listed`` returned, so a
    #: prefix that matched nothing is not reported as a clean survey of it.
    #: ``None`` where a listing failed, so the count is not the whole answer.
    seen: int | None = 0

    def held(self) -> frozenset[LockKey]:
        """The keys a live lock stands on.

        A delete command is not printed for such a key, for the lock or for its
        secret: somebody may be rotating it.
        """
        return frozenset(orphan.key for orphan in self.orphans if orphan.is_held)


@dataclass(frozen=True)
class Declared:
    """The normalised secret paths the configuration's bindings name.

    A path is declared in every store, whichever store its binding names (the
    module note says why).
    """

    paths: frozenset[str]

    def __contains__(self, key: object) -> bool:
        return isinstance(key, LockKey) and key.path in self.paths


def aliases(vaults: Sequence[Vault]) -> dict[str, str]:
    """Each store's name, mapped to the first name of the store it is.

    For listing each store once. Two entries are one store when they have the
    same type, address, namespace, mount and KV version. Credentials and TLS
    settings may differ: they change how a run reaches the store, not what is
    in it. Entries this misses are listed twice, which repeats rows and
    reports nothing live, because a path is declared in every store.
    """
    first: list[Vault] = []
    names: dict[str, str] = {}
    for vault in sorted(vaults, key=lambda one: one.name):
        same = next((one for one in first if _is_same_store(one, vault)), None)
        if same is None:
            first.append(vault)
            names[vault.name] = vault.name
        else:
            names[vault.name] = same.name
    return names


def _is_same_store(one: Vault, two: Vault) -> bool:
    if one.type != "hashicorp" or two.type != "hashicorp":
        return False
    if one.addr is None or two.addr is None:
        return False
    return (
        _same_address(one.addr, two.addr)
        and one.namespace == two.namespace
        and _mount(one) == _mount(two)
        and _kv_version(one) == _kv_version(two)
    )


def declared_by(bindings: Iterable[Binding]) -> Declared:
    """The paths ``bindings`` name, whether or not a store is known for them yet.

    A binding with no store at load gets one from ``SOPULI_VAULT`` or a
    profile at run time, and its path counts all the same.
    """
    return Declared(
        paths=frozenset(
            # The store is not part of the answer, so any name builds the key.
            lock_key(binding.secret, store="").path
            for binding in bindings
            if binding.secret is not None
        )
    )


def find(
    declared: Declared,
    *,
    stores: Mapping[str, SecretStore],
    region: ResetRegion | None = None,
    prefix: str | None = None,
) -> Survey:
    """Every orphan in ``stores``, sorted by store and path.

    ``stores`` holds one entry per store, under the name it was opened
    through. Raises :class:`NothingListedError` when none of them can list.

    ``prefix``, from :func:`survey_prefix`, limits each store to the secret
    paths under it and the lock records under ``locks/<prefix>`` (#1016): two
    listings in place of one of the whole mount, so the documents outside it
    are neither listed nor read.
    """
    found: list[Orphan] = []
    listed: list[str] = []
    unlistable: list[str] = []
    skipped: list[SkippedPath] = []
    unread: list[Unread] = []
    seen: int | None = 0
    for name, store in sorted(stores.items()):
        if LIST not in store.supports():
            unlistable.append(name)
            continue
        try:
            paths: tuple[str, ...] = store.list("" if prefix is None else prefix)
        except StoreError as error:
            unread.append(Unread(store=name, path=None, reason=error.message))
            continue
        if prefix is not None:
            # A listing of its own, so a token that may list the secrets and not
            # their lock records still has its secrets surveyed.
            locks_at = lock_path(LockKey(store=name, path=prefix))
            try:
                paths = (*paths, *store.list(locks_at))
            except StoreError as error:
                unread.append(Unread(store=name, path=locks_at, reason=error.message, listing=True))
                seen = None
        if seen is not None:
            seen += len(paths)
        listed.append(name)
        in_region = region if region is not None and region.store == name else None
        locks, bad = _locks(name, store, paths, declared, region=in_region)
        found.extend(_named(store, locks))
        skipped.extend(bad)
        secrets, bad, failed = _secrets(name, store, paths, declared, region=in_region)
        found.extend(_named(store, secrets))
        skipped.extend(bad)
        unread.extend(failed)
    if stores and not listed and not unread:
        raise NothingListedError(
            f"no store this run surveys can list its paths, so there is nowhere to look: "
            f"{', '.join(sorted(unlistable))}",
            hint="`vault orphans` needs a store with the `list` capability",
        )
    return Survey(
        orphans=tuple(sorted(found, key=lambda orphan: (orphan.store, orphan.path))),
        listed=tuple(listed),
        unlistable=tuple(unlistable),
        skipped=tuple(skipped),
        unread=tuple(unread),
        prefix=prefix,
        seen=seen,
    )


def _named(store: SecretStore, orphans: list[Orphan]) -> list[Orphan]:
    """``orphans`` with the store's own name and id for each, where it has them."""
    if not isinstance(store, NativeNames):
        return orphans
    return [
        replace(
            orphan,
            native_name=store.native_name(orphan.path),
            native_id=store.native_id(orphan.path),
        )
        for orphan in orphans
    ]


def survey_prefix(given: str) -> str:
    """``--prefix``, as the one spelling of a secret path (#1016).

    Checked by :func:`~sopuli.lock.keys.normalise_path`, which a binding's
    path goes through for its lock key, so a prefix the tool could not lock on
    is refused, with ``ValueError``. A prefix under ``locks/`` is refused too:
    lock records are found through their secret's path, and a prefix there
    would list ``locks/locks/...``.
    """
    try:
        path = normalise_path(given)
    except ValueError as error:
        raise ValueError(f"--prefix: {error}") from error
    if not path:
        raise ValueError("--prefix names no path; leave it out to survey every path")
    if path == LOCK_PREFIX or path.startswith(f"{LOCK_PREFIX}/"):
        raise ValueError(
            f"--prefix {given!r} is under `{LOCK_PREFIX}/`: give the secret path, and "
            "its lock records are surveyed with it"
        )
    return path


def _locks(
    name: str,
    store: SecretStore,
    paths: Sequence[str],
    declared: Declared,
    *,
    region: ResetRegion | None,
) -> tuple[list[Orphan], list[SkippedPath]]:
    """The undeclared lock records in one store, one per listed path.

    Each record is read and reported at the path the store listed. The
    normalised key is used only to match it against the declared set and
    against its secret, so two spellings of one path are two records here, as
    they are two records in the store.
    """
    prefix = bounded_prefix(LOCK_PREFIX)
    found: list[Orphan] = []
    skipped: list[SkippedPath] = []
    for path in paths:
        if not path.startswith(prefix):
            continue
        try:
            key = LockKey(store=name, path=secret_path(path))
        except ValueError:
            skipped.append(SkippedPath(store=name, path=path))
            continue
        if key in declared or (region is not None and region.covers(key)):
            continue
        # The listed tail, not the normalised one, so the read is of this record.
        [state] = survey(
            [LockKey(store=name, path=path[len(prefix) :])],
            stores={name: store},
            declared=set(),
        )
        found.append(Orphan(key=key, path=path, kind=LOCK, lock=state))
    return found, skipped


def _secrets(
    name: str,
    store: SecretStore,
    paths: Sequence[str],
    declared: Declared,
    *,
    region: ResetRegion | None,
) -> tuple[list[Orphan], list[SkippedPath], list[Unread]]:
    """The undeclared documents in one store that carry a marker.

    A document the store refuses this run is counted in ``Unread`` and the
    survey goes on: on a shared mount, another team's path may be listable and
    not readable. Any other failure is the store's, such as a seal or a
    timeout, and the rest of the store is not read, so the survey does not wait
    it out once per path.
    """
    excluded = [bounded_prefix(LOCK_PREFIX)]
    if region is not None:
        excluded.append(bounded_prefix(region.prefix))
    versioned = CAS in store.supports()
    found: list[Orphan] = []
    skipped: list[SkippedPath] = []
    unread: list[Unread] = []
    for path in paths:
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
            if error.category != AUTHORIZATION:
                unread.append(Unread(store=name, path=None, reason=error.message))
                break
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


def _mount(vault: Vault) -> str:
    # Imported here: the backend imports httpx, and the base package loads no
    # vendor client (ADR-006). Only a `hashicorp` entry is asked, and a survey
    # that opened one has the backend installed.
    from sopuli.store.hashicorp import DEFAULT_MOUNT

    return vault.mount if vault.mount is not None else DEFAULT_MOUNT


def _kv_version(vault: Vault) -> int:
    from sopuli.store.hashicorp import DEFAULT_KV_VERSION

    return vault.kv_version if vault.kv_version is not None else DEFAULT_KV_VERSION


def delete_command(vault: Vault, path: str, *, native_id: str | None = None) -> str | None:
    """The vault CLI command that removes ``path`` and its history, or ``None``.

    KV v2 needs ``kv metadata delete``. A plain ``kv delete`` keeps the
    versions and the metadata, and on a lock path it keeps the version counter,
    so a first acquisition at version 0 can never succeed there again.

    It names the address this run resolved, so it reaches the store this run
    read, whatever ``VAULT_ADDR`` the shell that runs it holds. The address holds
    no user name or password, because the loader refuses or drops one (#891). It
    is quoted for a POSIX shell.

    On OCI it is :func:`_oci_delete_command`, which needs ``native_id``.

    ``None`` for a backend this build has no command for.
    """
    if vault.type == "oci":
        return _oci_delete_command(vault, native_id)
    if vault.type != "hashicorp":
        return None
    words = (
        ["vault", "kv", "metadata", "delete"]
        if _kv_version(vault) == 2
        else ["vault", "kv", "delete"]
    )
    if vault.addr is not None:
        words.append(f"-address={vault.addr}")
    if vault.namespace is not None:
        words.append(f"-namespace={vault.namespace}")
    words.extend([f"-mount={_mount(vault)}", path])
    return shlex.join(words)


def _oci_delete_command(vault: Vault, secret_id: str | None) -> str | None:
    """The OCI CLI command that schedules the deletion of the secret ``secret_id``.

    OCI deletes a secret only on a schedule, 30 days ahead unless the command
    gives ``--time-of-deletion``, and its name stays taken until then. The
    command takes the secret's OCID, because the CLI has no delete by name.

    It names the store's ``region`` where the config sets one, and the store's
    auth method and profile, so it reaches the store this run read. It names no
    config file: the CLI reads ``OCI_CLI_CONFIG_FILE``, not the
    ``OCI_CONFIG_FILE`` this store reads. ``None`` without an id.
    """
    if secret_id is None:
        return None
    words = ["oci", "vault", "secret", "schedule-secret-deletion", "--secret-id", secret_id]
    if vault.region is not None:
        words.extend(["--region", vault.region])
    method = vault.auth.method if vault.auth is not None else None
    if method in ("instance_principal", "resource_principal"):
        words.extend(["--auth", method])
    else:
        if vault.auth is not None and vault.auth.profile is not None:
            words.extend(["--profile", vault.auth.profile])
        if method == "session_token":
            words.extend(["--auth", "security_token"])
    return shlex.join(words)


def commands(survey: Survey, vaults: Sequence[Vault]) -> tuple[str | None, ...]:
    """The delete command for each orphan, in order, ``None`` where none is printed.

    No command for a key a live lock stands on (:meth:`Survey.held`).
    """
    by_name = {vault.name: vault for vault in vaults}
    held = survey.held()
    return tuple(
        None
        if orphan.key in held
        else delete_command(by_name[orphan.store], orphan.path, native_id=orphan.native_id)
        for orphan in survey.orphans
    )


__all__ = [
    "LOCK",
    "MARKERS",
    "SECRET",
    "Declared",
    "NothingListedError",
    "Orphan",
    "Survey",
    "Unread",
    "aliases",
    "commands",
    "declared_by",
    "delete_command",
    "find",
    "is_sopuli_document",
]
