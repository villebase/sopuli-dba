"""The ``file`` store: one age-encrypted file, read and written whole (#1415).

It joins the three parts of this package: :mod:`._disk` reads and replaces the
file, :mod:`._crypto` decrypts and encrypts it, and :mod:`._document` is what
it holds. The registry does not name this module yet. ``store.py``, which
does, adds ``connect`` with the warning every run gets (#1372, split 4).

**Every call reads the file afresh.** A write reads the file, adds its
version to the one path it writes, and replaces the file, so a write by
another run to another path, made between this run's read and its write, is
kept. A write by another run in between the write's own read and its replace
is refused by :mod:`._disk`'s hash check.

**No ``cas`` capability, and a ``cas`` is still checked.** The callers pass
the version they read, and the store refuses the write when the path's
version has moved since, as :class:`~sopuli.store.memory.MemoryStore` does.
That is not a compare-and-set: the file is not locked between the check and
the replace. So the store reports no ``cas``, and a changing command needs
``locking: advisory-only`` (#1415, decision 4).

What it supports, as P2's table says: ``versioning`` (the last
``max_versions`` of each path) and ``list``. A merge patch is the caller's
read-modify-write.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from sopuli.clock import utc_now
from sopuli.config.errors import ConfigError
from sopuli.config.model import Vault
from sopuli.material import resolve
from sopuli.secrets import Secret
from sopuli.store.file import _crypto, _disk
from sopuli.store.file._document import (
    DEFAULT_MAX_VERSIONS,
    EMPTY,
    Document,
    DocumentError,
    dumps,
    loads,
)
from sopuli.store.protocol import (
    DEGRADED,
    LIST,
    OK,
    UNREACHABLE,
    VERSIONING,
    CasConflictError,
    PathMetadata,
    Stored,
    StoreError,
    StoreHealth,
    VersionHistory,
    VersionInfo,
    bounded_prefix,
)


def open_store(
    vault: Vault, *, env: Mapping[str, str], clock: Callable[[], datetime] = utc_now
) -> FileStore:
    """The file store ``vault`` declares, with its keys read and checked.

    Reads the identity, but not the store's file: a store whose file does not
    exist yet is an empty store, and its first write creates the file.
    """
    # The builder requires both.
    if vault.addr is None or vault.identity is None:  # pragma: no cover
        raise StoreError(f'file store "{vault.name}" has no `addr` or no `identity`')
    return FileStore(
        name=vault.name,
        path=Path(vault.addr).expanduser(),
        keys=_crypto.keys(identity_of(vault, env=env), vault.recipients, store=vault.name),
        max_versions=vault.max_versions,
        clock=clock,
    )


def identity_of(vault: Vault, *, env: Mapping[str, str]) -> Secret:
    """The store's identity, from its MaterialRef.

    A ``file:`` identity's first bytes are read before the file is decoded,
    so a binary ``age -p`` identity is refused as passphrase-protected rather
    than as text that is not UTF-8. A file that cannot be opened here is left
    to :func:`~sopuli.material.resolve`, whose message says why.
    """
    ref = vault.identity
    assert ref is not None
    if ref.kind == "file":
        try:
            with Path(ref.location).expanduser().open("rb") as handle:
                head = handle.read(len(_crypto.BINARY_HEADER))
        except OSError:
            pass
        else:
            _crypto.refuse_binary_identity(head, store=vault.name)
    return resolve(ref, env=env, where=f"vault \"{vault.name}\" key 'identity'")


@dataclass
class FileStore:
    """One ``file`` store. See the module note."""

    name: str
    path: Path
    keys: _crypto.Keys = field(repr=False)
    #: ``None`` keeps the default, 10.
    max_versions: int | None = None
    #: When a version was written, for ``created_at``. Injectable for tests.
    clock: Callable[[], datetime] = utc_now

    def supports(self) -> frozenset[str]:
        return frozenset({VERSIONING, LIST})

    def health(self) -> StoreHealth:
        """Whether the file can be read and decrypted with the store's keys.

        Writes nothing. A store with no file yet is well: its first write
        creates it. A file this run cannot open is ``unreachable``; one it
        opens and cannot decrypt or read is ``degraded``, and a wrong
        identity says so in ``authenticated``. There is no other clock, so
        ``server_time`` is ``None``.
        """
        if not self.path.parent.is_dir():
            return StoreHealth(
                status=UNREACHABLE, detail=f"the directory of {self.path} does not exist"
            )
        try:
            self._load()
        except _crypto.KeysError as error:
            return StoreHealth(status=DEGRADED, detail=error.message, authenticated=False)
        except (StoreError, ConfigError) as error:
            return StoreHealth(status=DEGRADED, detail=_first_line(error))
        return StoreHealth(status=OK, authenticated=True)

    def read(self, path: str, *, version: int | None = None) -> Stored | None:
        """The latest version of ``path``, or version ``version``.

        ``None`` where the path, or that version, is not kept. A version that
        was pruned reads as ``None``, as the protocol says.
        """
        document, _ = self._load()
        found = document.latest(path) if version is None else document.version(path, version)
        if found is None:
            return None
        return Stored(data=found.data, version=found.number)

    def write(self, path: str, data: Any, *, cas: int | None) -> int:
        """Add ``data`` as the next version of ``path``, and return its number.

        A ``cas`` that is not the path's latest version is refused with
        :class:`CasConflictError`, ``0`` meaning a path with no versions. See
        the module note for why the store still reports no ``cas``.
        """
        document, digest = self._load()
        found = document.current(path)
        if cas is not None and cas != found:
            raise CasConflictError(
                f'file store "{self.name}": {path!r} is at version {found}, '
                f"and the write expected {cas}",
                hint="another run wrote the path after this one read it; nothing was written",
            )
        updated, number = document.written(
            path, data, now=self.clock(), max_versions=self.max_versions
        )
        _disk.replace(self.path, _crypto.seal(dumps(updated), self.keys), expected=digest)
        return number

    def patch(self, path: str, changes: Any, *, cas: int | None) -> int:
        """Always a refusal: the store has no merge patch, and the caller reads,
        merges and writes, and reports that it did."""
        raise StoreError(
            f'file store "{self.name}" cannot apply a merge patch, and a write to {path!r} '
            "asked it to",
            hint="read the document, apply the patch, and write it back",
        )

    def metadata(self, path: str) -> PathMetadata | None:
        """``None`` for a path with no versions. A file store sets no
        ``cas_required``, and keeps the same ``max_versions`` for every path."""
        document, _ = self._load()
        if not document.current(path):
            return None
        return PathMetadata(cas_required=False, max_versions=self._keep())

    def versions(self, path: str) -> VersionHistory | None:
        """The kept versions of ``path``, oldest first, or ``None`` if it has none.

        Reads the file, which holds the data, but builds the history from the
        numbers and times alone.
        """
        document, _ = self._load()
        kept = document.paths.get(path)
        if not kept:
            return None
        return VersionHistory(
            current=kept[-1].number,
            oldest_kept=kept[0].number,
            versions=tuple(
                VersionInfo(
                    version=one.number, created_at=one.created_at, deleted=False, destroyed=False
                )
                for one in kept
            ),
        )

    def require_cas(self, path: str) -> None:
        """Always raises: a file store has no per-path setting to make.

        Nothing reaches it, because the store reports no ``cas``.
        """
        raise StoreError(
            f'file store "{self.name}" has no compare-and-set to require on {path!r}',
            hint="a file store needs `locking: advisory-only` (01-configuration.md §3a)",
        )

    def list(self, prefix: str) -> tuple[str, ...]:
        """Every path below ``prefix`` that has a version, sorted."""
        document, _ = self._load()
        under = bounded_prefix(prefix)
        return tuple(sorted(path for path in document.paths if path.startswith(under)))

    def _load(self) -> tuple[Document, str]:
        """The document in the file, and the digest :func:`_disk.replace` checks."""
        found = _disk.read(self.path)
        if found.data is None:
            return EMPTY, found.digest
        plaintext = _crypto.unseal(found.data, self.keys)
        try:
            return loads(plaintext), found.digest
        except DocumentError as error:
            # Named here, where the store's name is known: a config may have
            # two file stores.
            raise StoreError(
                f'file store "{self.name}": {error.message}', hint=error.hint
            ) from None

    def _keep(self) -> int:
        return DEFAULT_MAX_VERSIONS if self.max_versions is None else self.max_versions


def _first_line(error: Exception) -> str:
    """The message without its hint, for ``health``'s one-line detail."""
    return str(error).splitlines()[0]
