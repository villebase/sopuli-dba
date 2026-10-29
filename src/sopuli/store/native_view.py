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
from typing import Any, Protocol

from sopuli.clock import to_rfc3339
from sopuli.exit_codes import ExitCode
from sopuli.payload import (
    CURRENT,
    GENERATED_AT,
    GENERATED_BY,
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

#: What the tool adds to each version's content besides the password
#: (decision 3). Not part of the secret's own keys, so neither shown nor
#: carried from one version to the next.
OWN_KEYS = frozenset({ORIGIN, GENERATED_AT, GENERATED_BY})


class StagingStore(SecretStore, NativeStaging, Protocol):
    """A store that offers both interfaces, as one that declares ``STAGING`` does."""


class LayoutChangedError(StoreError):
    """A secret holds its stages in the other layout from the one it is used in.

    A secret moving between one account and several (an application entry
    gaining or losing an account that shares the ref) has its live stages in
    the mechanism it is leaving. Reading it in the new one would lose them.
    """

    category = "config"
    exit_code = ExitCode.CONFIG_INVALID


@dataclass(frozen=True)
class _View:
    """One native secret as its stages and attributes stand.

    ``pending`` is the live pending, the PENDING version ``pending_version``
    names; ``staged`` is whatever version holds PENDING, live or not, which
    only the next version number needs.
    """

    layout: StageLayout
    current: Stored
    pending: Stored | None
    previous: Stored | None
    staged: Stored | None

    @property
    def attributes(self) -> Mapping[str, Any]:
        return self.current.attributes

    def value(self, stored: Stored | None) -> Any:
        return None if stored is None else self.layout.read(stored.data, CURRENT)

    def base(self) -> dict[str, Any]:
        """CURRENT's content without what the tool adds to each version: every
        key a secret the tool did not create brings with it (decision 6), such
        as a ``username`` beside the ``password``, or another account in a
        document of several."""
        data = self.current.data if isinstance(self.current.data, Mapping) else {}
        return {key: value for key, value in data.items() if key not in OWN_KEYS}

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
            self.base(),
            *(
                self.layout.patch(key, value)
                for key, value in self.keys().items()
                if value is not None
            ),
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
        #: The last view each path was read at. ``apply_patch`` reads, then
        #: writes, and the write is computed from that read; reading the
        #: versions again would cost several more round trips on OCI.
        self._seen: dict[str, _View] = {}

    def is_native(self, path: str) -> bool:
        return self._native(path) is not None

    def mechanism_for(self, path: str) -> str | None:
        """:class:`~sopuli.store.protocol.WriteMechanism`: how a write to
        ``path`` reaches the store, for the run to report."""
        return NATIVE if self.is_native(path) else None

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
            data = stored.data if isinstance(stored.data, Mapping) else {}
            return replace(stored, data={k: v for k, v in data.items() if k not in OWN_KEYS})
        view = self._view(path, layout)
        if view is None:
            self._seen.pop(path, None)
            return None
        self._seen[path] = view
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
        staged = self.inner.read_stage(path, PENDING)
        live = staged is not None and staged.generation == current.attributes.get(PENDING_VERSION)
        previous = self.inner.read_stage(path, PREVIOUS)
        return _View(layout, current, staged if live else None, previous, staged)

    # -- writing ------------------------------------------------------------

    def write(self, path: str, data: Any, *, cas: int | None) -> int:
        layout = self._native(path)
        if layout is None:
            return self.inner.write(path, data, cas=cas)
        new = {key: layout.read(data, key) for key in (CURRENT, PENDING, PREVIOUS, ORIGIN, *STAMPS)}
        seen = self._seen.pop(path, None)
        view = (
            seen if seen is not None and seen.current.version == cas else self._view(path, layout)
        )
        if view is None:
            # A first version is always CURRENT on OCI (`oci-create-pending`). A
            # document with no current yet starts as an empty one, which reads
            # as having none, as the emulated document did. If what follows
            # fails, the empty secret still reads as having no current.
            # Whatever else the document holds, a pending or stamps, is then
            # written against that first version, as any later write would be.
            first = new[CURRENT]
            content = {} if first is None else self._content(layout, first, None, {})
            cas = self.inner.write(path, content, cas=cas)
            view = self._view(path, layout)
            assert view is not None
        return self._apply(path, view, new, cas=cas)

    def _apply(self, path: str, view: _View, new: dict[str, Any], *, cas: int | None) -> int:
        old = view.keys()
        moved_previous = new[PREVIOUS] != old[PREVIOUS]
        if (
            view.pending is not None
            and new[PENDING] is None
            and new[CURRENT] == old[PENDING]
            and (new[CURRENT] != old[CURRENT] or moved_previous)
        ):
            # The promotion. Told by `previous` moving as well as by `current`,
            # so a pending equal to the current password is still promoted.
            return self._promote(path, view.pending, new, pending=False, cas=cas)
        if new[CURRENT] != old[CURRENT]:
            if new[PENDING] != old[PENDING] and new[PENDING] is not None:
                raise self._unsupported(path, "a new current and a new pending at once")
            if view.previous is not None and new[CURRENT] == old[PREVIOUS]:
                # The rollback: PREVIOUS back to CURRENT, by number (Q3).
                return self._promote(path, view.previous, new, pending=False, cas=cas)
            if new[CURRENT] is None:
                raise self._unsupported(path, "removing the current password")
            if old[CURRENT] is not None and new[PREVIOUS] != old[CURRENT]:
                # The store always moves the old CURRENT to PREVIOUS; a document
                # that keeps another `previous` asks for what it cannot do.
                raise self._unsupported(path, "a new current that keeps an older `previous`")
            return self._replace(path, view, new, cas=cas)
        if moved_previous:
            raise self._unsupported(path, "changing `previous` without a promotion")
        if new[PENDING] is None and old[PENDING] is not None:
            # Cleared without a promotion: OCI keeps the version's stage, so
            # the record of which pending is live is what clears it.
            return self._promote(path, view.current, new, pending=False, cas=cas)
        if new[PENDING] is not None and (
            new[PENDING] != old[PENDING] or new[ORIGIN] != old[ORIGIN]
        ):
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

    def _replace(self, path: str, view: _View, new: dict[str, Any], *, cas: int | None) -> int:
        """A new CURRENT, as ``creds generate --promote`` writes one.

        With the live pending dropped, as the promotion patch drops it: staged,
        then promoted, rather than written as CURRENT and then given its
        attributes. If the second call fails, CURRENT is untouched and no
        pending reads as live, because the stage already dropped
        ``pending_version``.

        With a live pending kept: written as CURRENT, which leaves the PENDING
        version where it is, then the attributes with its record kept. Staging
        would deprecate the pending.

        Content carries no ``origin``: the promotion patch removes it, and the
        one the document held described the pending, not this password.
        """
        content = self._content(view.layout, new[CURRENT], None, view.base())
        if view.pending is not None and new[PENDING] is not None:
            token = self.inner.write(path, content, cas=cas)
            fresh = self._view(path, view.layout)
            assert fresh is not None
            return self._promote(path, fresh.current, new, pending=True, cas=token)
        token = self.inner.stage(path, content, attributes=_stamps(view.attributes), cas=cas)
        staged = self.inner.read_stage(path, PENDING)
        assert staged is not None
        return self._promote(path, staged, new, pending=False, cas=token)

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
        return self.inner.promote(path, target.generation, attributes=attributes, cas=cas)

    def _stage(self, path: str, view: _View, new: dict[str, Any], *, cas: int | None) -> int:
        """A new PENDING version, recorded as the live one.

        The record names the number the store is expected to give it. If the
        store gave another, an attributes-only promotion corrects the record;
        until then the record names no PENDING version, so no pending reads as
        live, which is the safe side.
        """
        expected = self._next_generation(path, view)
        attributes = {**_stamps(new), PENDING_VERSION: expected}
        content = self._content(view.layout, new[PENDING], new[ORIGIN], view.base())
        token = self.inner.stage(path, content, attributes=attributes, cas=cas)
        staged = self.inner.read_stage(path, PENDING)
        assert staged is not None
        assert staged.generation is not None
        if staged.generation == expected:
            return token
        attributes[PENDING_VERSION] = staged.generation
        assert view.current.generation is not None
        return self.inner.promote(path, view.current.generation, attributes=attributes, cas=token)

    def _next_generation(self, path: str, view: _View) -> int:
        """The number the store will give the next version: one past the highest.

        The highest is not always one of the stages, so the store is asked for
        each number past them until one is not there.
        """
        known = [
            one.generation
            for one in (view.current, view.staged, view.previous)
            if one is not None and one.generation is not None
        ]
        number = max(known, default=0) + 1
        while self.inner.read(path, version=number) is not None:
            number += 1
        return number

    def _content(
        self, layout: StageLayout, value: Any, origin: Any, base: Mapping[str, Any]
    ) -> dict[str, Any]:
        """A version's content: the secret's other keys, the password at the
        ref's field, and what was true when it was made (decision 3)."""
        content = merge(
            base,
            layout.patch(CURRENT, value),
            {GENERATED_AT: to_rfc3339(self._now()), GENERATED_BY: self._by},
        )
        if origin is not None:
            content[ORIGIN] = origin
        return content

    @staticmethod
    def _unsupported(path: str, what: str) -> StoreError:
        return StoreError(f"{path!r} uses native staging, which cannot do {what} in one write")


def _stamps(keys: Mapping[str, Any]) -> dict[str, Any]:
    return {stamp: keys[stamp] for stamp in STAMPS if keys.get(stamp) is not None}


def _get(data: Any, key: str) -> Any:
    return data.get(key) if isinstance(data, Mapping) else None
