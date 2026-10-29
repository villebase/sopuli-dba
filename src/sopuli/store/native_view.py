"""UC-1's documents over a store that keeps the stages as its own versions (#1158).

UC-1 keeps three stages per credential. On most stores they are fields in one
document: the ref's field holds ``current``, and ``pending`` and ``previous``
sit beside it, by the mirror rule of :class:`~sopuli.payload.StageLayout`. A
store that declares :data:`~sopuli.store.protocol.STAGING` can keep them as its
own versions instead (:class:`~sopuli.store.protocol.NativeStaging`), so an
application reading the secret's current version never sees a pending
password.

The verbs read stages in many places and write them through two functions. So
rather than teach each of them a second layout, :class:`NativeStagedStore`
stands between the verbs and such a store, for the paths that use native
staging:

* **reading**, it assembles the document the verbs already read: the field
  holds CURRENT; ``pending`` and ``origin`` come from the PENDING version, when
  its number is the secret's ``pending_version``; ``previous`` from PREVIOUS;
  and the promotion stamps from the secret's attributes;
* **writing**, it compares the new document with the one it assembled and turns
  the difference into :meth:`~NativeStaging.stage` (a new pending),
  :meth:`~NativeStaging.promote` (pending to current, or previous back to
  current for a rollback, or the stamps alone), or ``write`` (a new current).

Decision 3 splits the stamps by when they become true: a version's content
holds the password, ``origin``, ``generated_at`` and ``generated_by``, which
were true when the password was made and never change; ``rotated_at``,
``rotated_by``, ``policy`` and ``targets`` become true at promotion and go in
the attributes, with ``pending_version``.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any, Protocol, cast

from sopuli.clock import to_rfc3339
from sopuli.payload import (
    CURRENT,
    ORIGIN,
    PENDING,
    PREVIOUS,
    STAMPS,
    StageLayout,
    merge,
)
from sopuli.store.protocol import (
    MERGE_PATCH,
    STAGING,
    CasConflictError,
    NativeStaging,
    PathMetadata,
    SecretStore,
    Stored,
    StoreError,
    StoreHealth,
)

#: The mechanism a write through this adapter reports, beside
#: :data:`~sopuli.store.protocol.MERGE_PATCH` and ``read_modify_write``.
NATIVE = "native_staging"

#: The attribute naming the PENDING version that is the live pending. A PENDING
#: version with another number is not a pending for any verb: OCI cannot drop
#: the stage from a version without promoting it (``oci-pending-replace``).
PENDING_VERSION = "pending_version"

#: What a version's content holds besides the password (decision 3).
GENERATED_AT, GENERATED_BY = "generated_at", "generated_by"


class StagingStore(SecretStore, NativeStaging, Protocol):
    """A store that offers both interfaces, as one that declares ``STAGING`` does."""


class LayoutChangedError(StoreError):
    """A secret holds its stages in the other layout from the one it is used in.

    A secret moving between one account and several (an application entry
    gaining or losing an account that shares the ref) has its live stages in
    the mechanism it is leaving. Reading it in the new one would lose them.
    """

    category = "config"


@dataclass(frozen=True)
class _View:
    """One native secret as its stages and attributes stand."""

    layout: StageLayout
    current: Stored
    pending: Stored | None
    previous: Stored | None

    @property
    def attributes(self) -> Mapping[str, Any]:
        return self.current.attributes

    def value(self, stored: Stored | None) -> Any:
        return None if stored is None else self.layout.read(stored.data, CURRENT)

    def keys(self) -> dict[str, Any]:
        """What the assembled document holds at each key the verbs use."""
        found: dict[str, Any] = {
            CURRENT: self.value(self.current),
            PENDING: self.value(self.pending),
            PREVIOUS: self.value(self.previous),
            ORIGIN: None if self.pending is None else _get(self.pending.data, ORIGIN),
        }
        for stamp in STAMPS:
            found[stamp] = self.attributes.get(stamp)
        return found

    def document(self) -> dict[str, Any]:
        return merge(
            *(
                self.layout.patch(key, value)
                for key, value in self.keys().items()
                if value is not None
            )
        )


class NativeStagedStore:
    """A store, seen through the emulated layout for its native-staged paths.

    ``native(path)`` gives the layout of the one credential at ``path`` when the
    path uses native staging, and ``None`` otherwise; every other path, a lock
    included, goes straight to ``inner``. ``by`` and ``now`` stamp a new
    version's content (decision 3).
    """

    def __init__(
        self,
        inner: StagingStore,
        *,
        native: Callable[[str], StageLayout | None],
        by: str,
        now: Callable[[], datetime],
    ) -> None:
        if STAGING not in inner.supports():
            raise StoreError("native staging needs a store that declares `staging_labels`")
        self.inner = inner
        self._native = native
        self._by = by
        self._now = now

    def is_native(self, path: str) -> bool:
        return self._native(path) is not None

    # -- the protocol, passed through --------------------------------------

    def supports(self) -> frozenset[str]:
        """No ``merge_patch``, so every write reaches :meth:`write` whole, and
        no ``staging_labels``: the verbs see the emulated layout."""
        return self.inner.supports() - {MERGE_PATCH, STAGING}

    def health(self) -> StoreHealth:
        return self.inner.health()

    def list(self, prefix: str) -> tuple[str, ...]:
        return self.inner.list(prefix)

    def metadata(self, path: str) -> PathMetadata | None:
        return self.inner.metadata(path)

    def require_cas(self, path: str) -> None:
        self.inner.require_cas(path)

    def patch(self, path: str, changes: Any, *, cas: int | None) -> int:
        if self.is_native(path):
            raise StoreError(f"{path!r} uses native staging, which takes whole documents")
        return self.inner.patch(path, changes, cas=cas)

    # -- reading ------------------------------------------------------------

    def read(self, path: str, *, version: int | None = None) -> Stored | None:
        layout = self._native(path)
        if layout is None:
            return self.inner.read(path, version=version)
        if version is not None:
            stored = self.inner.read(path, version=version)
            if stored is None:
                return None
            return replace(stored, data=layout.patch(CURRENT, layout.read(stored.data, CURRENT)))
        view = self._view(path, layout)
        if view is None:
            return None
        return replace(view.current, data=view.document())

    def _view(self, path: str, layout: StageLayout) -> _View | None:
        current = self.inner.read_stage(path, CURRENT)
        if current is None:
            return None
        if isinstance(current.data, Mapping) and (
            PENDING in current.data or PREVIOUS in current.data
        ):
            raise LayoutChangedError(
                f"{path!r} holds `pending` or `previous` as fields, from when it was staged in "
                f"payload fields, and is now used with native staging",
                hint="finish or discard the rotation it holds with the build that staged it, "
                "or move the fields out by hand",
            )
        pending = self.inner.read_stage(path, PENDING)
        if pending is not None and pending.generation != current.attributes.get(PENDING_VERSION):
            pending = None
        return _View(layout, current, pending, self.inner.read_stage(path, PREVIOUS))

    # -- writing ------------------------------------------------------------

    def write(self, path: str, data: Any, *, cas: int | None) -> int:
        layout = self._native(path)
        if layout is None:
            return self.inner.write(path, data, cas=cas)
        new = {key: layout.read(data, key) for key in (CURRENT, PENDING, PREVIOUS, ORIGIN, *STAMPS)}
        view = self._view(path, layout)
        if view is None:
            # A first version is always CURRENT on OCI (`oci-create-pending`). A
            # document with no current yet starts as an empty one, which reads
            # as having none, as the emulated document did.
            first = new[CURRENT]
            content = {} if first is None else self._content(layout, first, new[ORIGIN])
            cas = self.inner.write(path, content, cas=cas)
            view = self._view(path, layout)
            assert view is not None
            if first is not None:
                return self._finish(path, view, new, cas=cas)
        return self._apply(path, view, new, cas=cas)

    def _apply(self, path: str, view: _View, new: dict[str, Any], *, cas: int | None) -> int:
        old = view.keys()
        if new[CURRENT] != old[CURRENT]:
            if new[PENDING] is not None:
                raise self._unsupported(path, "a new current and a new pending at once")
            if view.pending is not None and new[CURRENT] == old[PENDING]:
                return self._promote(path, view.pending, new, pending=False, cas=cas)
            if view.previous is not None and new[CURRENT] == old[PREVIOUS]:
                # The rollback: PREVIOUS back to CURRENT, by number (Q3).
                return self._promote(path, view.previous, new, pending=False, cas=cas)
            if new[CURRENT] is None:
                raise self._unsupported(path, "removing the current password")
            token = self.inner.write(
                path, self._content(view.layout, new[CURRENT], new[ORIGIN]), cas=cas
            )
            fresh = self._view(path, view.layout)
            assert fresh is not None
            return self._finish(path, fresh, new, cas=token)
        if new[PREVIOUS] != old[PREVIOUS]:
            raise self._unsupported(path, "changing `previous` without a promotion")
        if new[PENDING] != old[PENDING]:
            if new[PENDING] is None:
                # Cleared without a promotion: OCI keeps the version's stage, so
                # the record of which pending is live is what clears it.
                return self._promote(path, view.current, new, pending=False, cas=cas)
            return self._stage(path, view, new, cas=cas)
        if any(new[stamp] != old[stamp] for stamp in STAMPS):
            return self._promote(path, view.current, new, pending=view.pending is not None, cas=cas)
        # Nothing to change; the compare-and-set still has to hold.
        if cas is not None and cas != view.current.version:
            raise CasConflictError(
                f"compare-and-set failed at {path!r}: expected version {cas}, "
                f"found {view.current.version}"
            )
        return view.current.version

    def _finish(self, path: str, view: _View, new: dict[str, Any], *, cas: int | None) -> int:
        """After a new CURRENT: the attributes for it, with no live pending.

        Skipped when there is nothing to record, since each write keeps an OCI
        secret busy for about 20 seconds.
        """
        if not _stamps(new) and PENDING_VERSION not in view.attributes:
            assert cas is not None
            return cas
        return self._promote(path, view.current, new, pending=False, cas=cas)

    def _promote(
        self, path: str, target: Stored, new: dict[str, Any], *, pending: bool, cas: int | None
    ) -> int:
        """``target`` CURRENT, with the stamps ``new`` holds as the attributes.

        ``pending`` keeps the live pending's record, for a promotion that only
        changes the stamps.
        """
        attributes = _stamps(new)
        if pending:
            attributes[PENDING_VERSION] = target.attributes[PENDING_VERSION]
        assert target.generation is not None
        return self._staging().promote(path, target.generation, attributes=attributes, cas=cas)

    def _stage(self, path: str, view: _View, new: dict[str, Any], *, cas: int | None) -> int:
        """A new PENDING version, recorded as the live one."""
        generation = self._next_generation(path, view)
        attributes = {**_stamps(view.keys()), PENDING_VERSION: generation}
        content = self._content(view.layout, new[PENDING], new[ORIGIN])
        token = self._staging().stage(path, content, attributes=attributes, cas=cas)
        staged = self.inner.read_stage(path, PENDING)
        if staged is None or staged.generation != generation:
            # The record would name a version that is not the pending.
            raise StoreError(
                f"{path!r}: the new pending is not version {generation}, which its record names",
                hint="run `creds status` on this secret, then generate again",
            )
        return token

    def _next_generation(self, path: str, view: _View) -> int:
        """The number the store will give the next version: one past the highest.

        The highest is not always one of the three stages, so the store is
        asked for each number past them until one is not there.
        """
        known = [one.generation for one in (view.current, view.pending, view.previous) if one]
        number = max(cast(int, one) for one in known) + 1
        while self.inner.read(path, version=number) is not None:
            number += 1
        return number

    def _content(self, layout: StageLayout, value: Any, origin: Any) -> dict[str, Any]:
        content = merge(
            layout.patch(CURRENT, value),
            {GENERATED_AT: to_rfc3339(self._now()), GENERATED_BY: self._by},
        )
        if origin is not None:
            content[ORIGIN] = origin
        return content

    def _staging(self) -> NativeStaging:
        return self.inner

    @staticmethod
    def _unsupported(path: str, what: str) -> StoreError:
        return StoreError(f"{path!r} uses native staging, which cannot do {what} in one write")


def _stamps(keys: Mapping[str, Any]) -> dict[str, Any]:
    return {stamp: keys[stamp] for stamp in STAMPS if keys.get(stamp) is not None}


def _get(data: Any, key: str) -> Any:
    return data.get(key) if isinstance(data, Mapping) else None
