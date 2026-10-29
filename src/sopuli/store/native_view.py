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

from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass, replace
from datetime import datetime
from types import MappingProxyType
from typing import Any, Protocol, cast

from sopuli.clock import to_rfc3339
from sopuli.config.secret_refs import normalise_path
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
    WriteMechanism,
)

#: The mechanism a write through this adapter reports, beside
#: :data:`~sopuli.store.protocol.MERGE_PATCH` and ``read_modify_write``.
NATIVE = "native_staging"

#: The attribute naming the PENDING version that is the live pending. A PENDING
#: version with another number is not a pending for any verb: OCI cannot drop
#: the stage from a version without promoting it (``oci-pending-replace``).
PENDING_VERSION = "pending_version"

#: Where a read through the adapter names the PREVIOUS version's number. Only
#: ever read: the store does not keep it, since PREVIOUS is a stage OCI moves.
PREVIOUS_VERSION = "previous_version"

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


class LayoutUnknownError(LayoutChangedError):
    """The config cannot say whether a secret holds one account or several.

    A kind of :class:`LayoutChangedError`, because it is refused at the same
    moments, for the same reason: a stage written in the wrong layout is lost.
    """


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
        document of several.

        Stamps in the content are left out too. Under native staging they live
        in the attributes, so stamps in the content are from when the secret
        held several accounts, and copying them into each new version would
        keep them for good."""
        data = self.current.data if isinstance(self.current.data, Mapping) else {}
        return {
            key: value for key, value in data.items() if key not in OWN_KEYS and key not in STAMPS
        }

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

    def numbers(self) -> Mapping[str, Any]:
        """The attributes a read returns: the secret's own, with
        ``pending_version`` only while that pending is live, and
        ``previous_version``, so a reader can name the version each stage
        came from (:func:`~sopuli.store.credentials.stage_version`)."""
        found = dict(_without(self.attributes, PENDING_VERSION))
        if self.pending is not None and self.pending.generation is not None:
            found[PENDING_VERSION] = self.pending.generation
        if self.previous is not None and self.previous.generation is not None:
            found[PREVIOUS_VERSION] = self.previous.generation
        return MappingProxyType(found)

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
        unsure: Callable[[str], bool] = lambda path: False,
    ) -> None:
        if STAGING not in inner.supports():
            raise StoreError("native staging needs a store that declares `staging_labels`")
        self.inner = inner
        self._native = native
        self._unsure = unsure
        self._by = by
        self._now = now
        #: The last view each path was read at. ``apply_patch`` reads, then
        #: writes, and the write is computed from that read; reading the
        #: versions again would cost several more round trips on OCI.
        self._seen: dict[str, _View] = {}
        #: The version number each native path's last write left current or
        #: staged, for :meth:`generation_of`.
        self._written: dict[str, int] = {}
        #: The token each payload-field write returned, which the read in
        #: :meth:`generation_of` must find for the number to be this write's.
        self._payload: dict[str, int] = {}

    def is_native(self, path: str) -> bool:
        return self._native(path) is not None

    def mechanism_for(self, path: str) -> str | None:
        """:class:`~sopuli.store.protocol.WriteMechanism`: how a write to
        ``path`` reaches the store, for the run to report."""
        return NATIVE if self.is_native(path) else None

    def generation_of(self, path: str) -> int | None:
        """:class:`~sopuli.store.protocol.WriteMechanism`: the store's version
        number of what the last write to ``path`` left, for the run to report.

        A path in payload fields asks the store, which knows the number from
        its own write and gives ``None`` where another writer came in between
        (the OCI store, #1164). A store that cannot say is read again for it,
        and the same holds: a read that finds another token gives ``None``. The
        write has already landed, so this never raises: a failed read gives
        ``None`` too, and the run then shows the token.
        """
        if self.is_native(path):
            return self._written.pop(path, None)
        token = self._payload.pop(path, None)
        if isinstance(self.inner, WriteMechanism):
            return self.inner.generation_of(path)
        try:
            stored = self.inner.read(path)
        except Exception:  # noqa: BLE001 -- the write landed; a number is not worth failing it
            return None
        if stored is None or stored.version != token:
            return None
        return stored.generation

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
        self._refuse_if_unsure(path)
        if self.is_native(path):
            raise StoreError(f"{path!r} uses native staging, which takes whole documents")
        return self.inner.patch(path, changes, cas=cas)

    # -- reading ------------------------------------------------------------

    def read(self, path: str, *, version: int | None = None) -> Stored | None:
        self._refuse_if_unsure(path)
        layout = self._native(path)
        if layout is None:
            stored = self.inner.read(path, version=version)
            if stored is None:
                return None
            if version is None:
                self._refuse_a_native_pending(path, stored)
            # A record left from when the secret was native names no pending
            # here, so a reader must not take it for one.
            return replace(
                stored,
                data=_without_residue(stored.data),
                attributes=_without(stored.attributes, PENDING_VERSION),
            )
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
        return replace(view.current, data=view.document(), attributes=view.numbers())

    def _view(self, path: str, layout: StageLayout) -> _View | None:
        current = self.inner.read_stage(path, CURRENT)
        if current is None:
            return None
        if isinstance(current.data, Mapping) and (
            PENDING in current.data or PREVIOUS in current.data
        ):
            raise LayoutChangedError(
                f"{path!r} holds `pending` or `previous` as fields, from when it held several "
                f"accounts, and now holds one, which uses native staging",
                hint="finish the rotation under the config it was started with, or remove the "
                "fields by hand, then change the config",
            )
        staged = self.inner.read_stage(path, PENDING)
        live = staged is not None and staged.generation == current.attributes.get(PENDING_VERSION)
        previous = self.inner.read_stage(path, PREVIOUS)
        return _View(layout, current, staged if live else None, previous, staged)

    def _refuse_a_native_pending(self, path: str, stored: Stored) -> None:
        """Refuse a path read in payload fields that holds a live native pending.

        The other direction of the layout change: a secret that held one
        account, staged a pending as a version, and now holds several. Read in
        payload fields it has no ``pending``, and the next write would leave
        the staged password unreachable. A PREVIOUS version alone is not
        refused: OCI cannot drop one, so refusing it would refuse the secret
        for good. It stays readable as ``@version=N``.
        """
        recorded = stored.attributes.get(PENDING_VERSION)
        if recorded is None:
            return
        staged = self.inner.read_stage(path, PENDING)
        if staged is not None and staged.generation == recorded:
            raise LayoutChangedError(
                f"{path!r} holds a pending password as version {recorded}, from when it "
                f"held one account, and is now shared by several",
                hint="finish the rotation with `sopuli creds apply` under the config it was "
                "staged with, then add the account",
            )

    def _refuse_if_unsure(self, path: str) -> None:
        """Refuse a path the config cannot say the layout of.

        A binding whose store could not be completed may share the path, so
        the secret may hold one account or several. Either guess can write a
        stage where it does not belong, so a run that touches the path stops.
        """
        if self._unsure(path):
            raise LayoutUnknownError(
                f"cannot tell whether {path!r} holds one account or several: a binding on "
                f"that path has no store, because the default store does not resolve",
                hint="name the store in the binding's ref, or set `SOPULI_VAULT` to a store "
                "`vaults:` declares",
            )

    # -- writing ------------------------------------------------------------

    def write(self, path: str, data: Any, *, cas: int | None) -> int:
        # A write that raised after recording leaves nothing for this one.
        self._written.pop(path, None)
        self._payload.pop(path, None)
        self._refuse_if_unsure(path)
        layout = self._native(path)
        if layout is None:
            token = self.inner.write(path, data, cas=cas)
            self._payload[path] = token
            return token
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
        self._wrote(path, view.current)
        return view.current.version

    def _wrote(self, path: str, left: Stored) -> None:
        if left.generation is not None:
            self._written[path] = left.generation

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
        token = self.inner.promote(path, target.generation, attributes=attributes, cas=cas)
        self._wrote(path, target)
        return token

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
        self._wrote(path, staged)
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


def wrap(
    stores: Mapping[str, SecretStore],
    layouts: Mapping[tuple[str, str], StageLayout],
    *,
    by: str,
    now: Callable[[], datetime],
    unsure: Collection[tuple[str, str]] = (),
) -> dict[str, SecretStore]:
    """``stores``, with each one that declares ``staging_labels`` seen through
    :class:`NativeStagedStore`.

    ``layouts`` is :func:`~sopuli.config.sharing.native_layouts`: the documents
    that use native staging, keyed by store name and normalised path. A staging
    store is wrapped even with none of its documents native, so a document read
    in payload fields is still checked for a native pending. ``unsure`` is
    :func:`~sopuli.config.sharing.unsure_layouts`, keyed the same way.
    """
    wrapped: dict[str, SecretStore] = {}
    for name, store in stores.items():
        if STAGING not in store.supports():
            wrapped[name] = store
            continue
        own = {path: layout for (vault, path), layout in layouts.items() if vault == name}
        doubtful = {path for vault, path in unsure if vault == name}
        adapter = NativeStagedStore(
            cast(StagingStore, store),
            native=_lookup(own),
            by=by,
            now=now,
            unsure=_among(doubtful),
        )
        wrapped[name] = cast(SecretStore, adapter)
    return wrapped


def _among(paths: Collection[str]) -> Callable[[str], bool]:
    """Whether a path is one of ``paths``, under its normalised spelling."""

    def found(path: str) -> bool:
        return normalise_path(path) in paths

    return found


def _lookup(layouts: Mapping[str, StageLayout]) -> Callable[[str], StageLayout | None]:
    """A path's layout, found under the path's normalised spelling."""

    def native(path: str) -> StageLayout | None:
        return layouts.get(normalise_path(path))

    return native


def _without_residue(data: Any) -> Any:
    """A payload-field document without what native staging left in it.

    A secret that held one account, and now holds several, has
    ``generated_at`` and ``generated_by`` in its content, and a bare
    ``origin``. In payload fields ``origin`` is a map by account, and the
    other two are reserved names (``payload.RESERVED``), so none of the three
    is anyone's data, and carrying them into the next version would keep them
    for good.
    """
    if not isinstance(data, Mapping):
        return data
    return {
        key: value
        for key, value in data.items()
        if key not in (GENERATED_AT, GENERATED_BY)
        and not (key == ORIGIN and not isinstance(value, Mapping))
    }


def _without(attributes: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    return MappingProxyType({name: value for name, value in attributes.items() if name != key})


def _stamps(keys: Mapping[str, Any]) -> dict[str, Any]:
    return {stamp: keys[stamp] for stamp in STAMPS if keys.get(stamp) is not None}


def _get(data: Any, key: str) -> Any:
    return data.get(key) if isinstance(data, Mapping) else None
