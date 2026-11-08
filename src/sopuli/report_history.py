"""One account's rotation history, from what the tool wrote (UC-5 §6).

Pure, like the other report modules: the command reads the store and the
database, and this module decides what the history says.

**The history comes from the store's versions.** An application account's
rotation is a change of the account's own ``rotated_at`` stamp; a personal
account's reset is a version of its reset record. Nothing here reads a
password: only the stamps and the record's fields are taken from a document,
and the document is not kept.

**It never looks complete when it is not.** The history starts at the oldest
version that can be read, and says how many earlier versions are gone, so the
oldest version kept is never presented as the first rotation. After that
start, every version number up to the store's current one must be read. A
number the store does not list, a version that is deleted, destroyed or could
not be read, and a stamp that is malformed or has disappeared are each a gap a
rotation could hide in, and the history is then *not checked*. So is a store
that keeps no versions.

**The database's date is information.** It is shown beside the history and
never compared with it (UC-5 §6).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any

from sopuli.clock import from_rfc3339
from sopuli.config.model import Binding
from sopuli.driver.protocol import UserState
from sopuli.lock.record import Holder
from sopuli.payload import GENERATED_AT, GENERATED_BY, ROTATED_AT, ROTATED_BY, stage_layout
from sopuli.report_exit import exit_code_for
from sopuli.status import rotation_stamp
from sopuli.store.protocol import VersionHistory

__all__ = [
    "APPLICATION",
    "GENERATED",
    "NATIVE_NOTE",
    "NOTHING_STORED",
    "NO_ACCOUNT",
    "NO_VERSIONING",
    "PERSONAL",
    "RESET",
    "ROTATION",
    "AccountHistory",
    "Event",
    "Start",
    "application",
    "exit_code",
    "native",
    "personal",
    "with_database",
]

APPLICATION, PERSONAL = "application", "personal"

#: A change of ``current``: a rotation, a rollback, or ``creds generate
#: --promote``. The stamps cannot tell these apart (UC-5 §6).
ROTATION = "rotation"
#: A version of a native-staging secret, by when its password was made.
GENERATED = "generated"
#: A version of a personal account's reset record.
RESET = "reset"

NATIVE_NOTE = (
    "the store keeps the promotion time of the current version only; "
    "the other versions are listed by when each was generated"
)
NO_VERSIONING = "the store keeps no versions (versioning), so only the latest is shown"
#: A store that keeps versions has nothing at the path: a secret not written
#: yet, or a personal account never reset. An empty history, and a true one.
NOTHING_STORED = "the store has nothing at this path"
#: A store that keeps versions holds the path and lists none of them, as OCI
#: does for a secret pending deletion.
NO_VERSIONS_LISTED = "the store holds this secret and lists no versions of it"
MALFORMED_PROMOTION = "the promotion stamp the store keeps is malformed"
NO_ACCOUNT = "no such account on this target"
NO_DATE = "the database gives no date"


@dataclass(frozen=True)
class Event:
    """One change, newest first in a history.

    ``version`` is the first version read that shows it, or ``None`` where no
    version is known: the latest document of a store that keeps no versions, or
    the promotion of a native-staging secret. ``exact`` is ``False`` where the
    version before it was not read, being gone or unreadable: then that earlier
    version may be the one that wrote it.
    """

    kind: str
    at: datetime
    version: int | None
    by: str | None = None
    #: A reset only: whether a DBA saw the password (UC-2).
    seen: bool | None = None
    exact: bool = True


@dataclass(frozen=True)
class Start:
    """Where a history starts: the oldest version read, and what is gone."""

    version: int
    at: datetime | None
    #: The versions below ``version``: pruned, deleted or destroyed.
    gone: int


@dataclass(frozen=True)
class AccountHistory:
    """One account on one target."""

    target: str
    account: str
    kind: str
    events: tuple[Event, ...] = ()
    start: Start | None = None
    #: Versions after :attr:`start` that could not be read: not listed, deleted,
    #: destroyed, unreadable, or with a malformed or missing stamp. Each is a
    #: gap a rotation could hide in.
    unread: tuple[int, ...] = ()
    #: Why the history is not complete, beyond the gaps.
    not_checked: tuple[str, ...] = ()
    note: str | None = None
    db_changed_at: datetime | None = None
    #: Why :attr:`db_changed_at` is ``None``, or ``None`` when it is not.
    db_unknown: str | None = None

    @property
    def complete(self) -> bool:
        return not self.unread and not self.not_checked

    @property
    def reasons(self) -> tuple[str, ...]:
        gaps = tuple(f"version {version} could not be read" for version in self.unread)
        return (*self.not_checked, *gaps)


#: What reading one version gives: its event, or ``None``, and whether the
#: field the event comes from is there at all. A field that is there and gives
#: no event is malformed.
Read = Callable[[Mapping[str, Any], int | None], tuple[Event | None, bool]]


def application(
    target: str,
    binding: Binding,
    history: VersionHistory | None,
    documents: Mapping[int, Any],
    *,
    versioning: bool,
    latest: Any = None,
) -> AccountHistory:
    """An application account's rotations, from its secret's versions.

    ``documents`` maps a version to its document, for the versions that could
    be read. ``history`` is ``None`` where the store keeps no versions
    (``versioning`` false), and then ``latest`` is the document as it is now;
    or where the path is unknown to a store that keeps them.
    """
    empty = AccountHistory(target, binding.account, APPLICATION)
    if binding.secret is None:
        return replace(empty, not_checked=("the config names no secret for this account",))
    layout = stage_layout(binding.secret)

    def event(document: Mapping[str, Any], version: int | None) -> tuple[Event | None, bool]:
        present, moment = rotation_stamp(document, binding)
        if moment is None:
            return None, present
        by = layout.read(document, ROTATED_BY)
        return Event(ROTATION, moment, version, by=by if isinstance(by, str) else None), present

    return _history(empty, history, documents, event, versioning=versioning, latest=latest)


def native(
    target: str,
    binding: Binding,
    history: VersionHistory,
    documents: Mapping[int, Any],
    attributes: Mapping[str, Any],
) -> AccountHistory:
    """A native-staging secret: versions by ``generated_at``, one promotion.

    ``documents`` are the store's own versions, read without the adapter, so
    ``generated_at`` is still in them. The promotion stamps are the secret's
    attributes, which each promotion overwrites (UC-1 §3), so only the current
    version's promotion is known.
    """

    def generated(document: Mapping[str, Any], version: int | None) -> tuple[Event | None, bool]:
        moment = _moment(document.get(GENERATED_AT))
        if moment is None:
            return None, GENERATED_AT in document
        by = document.get(GENERATED_BY)
        return Event(GENERATED, moment, version, by=by if isinstance(by, str) else None), True

    found = _history(
        AccountHistory(target, binding.account, APPLICATION, note=NATIVE_NOTE),
        history,
        documents,
        generated,
        versioning=True,
        own=True,
    )
    promoted = _moment(attributes.get(ROTATED_AT))
    if promoted is None:
        if ROTATED_AT in attributes:
            return replace(found, not_checked=(*found.not_checked, MALFORMED_PROMOTION))
        return found
    by = attributes.get(ROTATED_BY)
    top = Event(ROTATION, promoted, None, by=by if isinstance(by, str) else None)
    return replace(
        found, events=tuple(sorted((top, *found.events), key=lambda one: one.at, reverse=True))
    )


def personal(
    target: str,
    account: str,
    history: VersionHistory | None,
    documents: Mapping[int, Any],
    *,
    versioning: bool,
    latest: Any = None,
) -> AccountHistory:
    """A personal account's resets, from its reset record's versions (UC-2 §3)."""

    def reset(document: Mapping[str, Any], version: int | None) -> tuple[Event | None, bool]:
        moment = _moment(document.get("reset_at"))
        if moment is None:
            return None, "reset_at" in document
        holder = Holder.from_dict(document.get("by"))
        seen = document.get("seen")
        return Event(
            RESET,
            moment,
            version,
            by=f"{holder.os_user}@{holder.host}" if holder else None,
            seen=seen if isinstance(seen, bool) else None,
        ), True

    return _history(
        AccountHistory(target, account, PERSONAL),
        history,
        documents,
        reset,
        versioning=versioning,
        latest=latest,
    )


def with_database(found: AccountHistory, user: UserState | None) -> AccountHistory:
    """``found`` with the database's own date of the last password change.

    Shown beside the history and never compared with it: it does not change
    whether the history is complete.
    """
    if user is None:
        return replace(found, db_changed_at=None, db_unknown=NO_ACCOUNT)
    if user.password_changed_at is not None:
        return replace(found, db_changed_at=user.password_changed_at, db_unknown=None)
    return replace(found, db_changed_at=None, db_unknown=user.password_changed_unknown or NO_DATE)


def exit_code(
    histories: Sequence[AccountHistory],
    *,
    unreachable: int,
    unsupported: int,
    targets: int,
    unanswered: int = 0,
) -> int:
    """UC-5 §3's rule for a report that judges nothing: 5, then 1 for a target
    or store that gave no answer, then 4 for anything not read."""
    return exit_code_for(
        unreachable=unreachable + unanswered,
        unsupported=unsupported,
        targets=targets,
        incomplete=any(not one.complete for one in histories),
    )


def _history(
    empty: AccountHistory,
    history: VersionHistory | None,
    documents: Mapping[int, Any],
    read: Read,
    *,
    versioning: bool,
    latest: Any = None,
    own: bool = False,
) -> AccountHistory:
    if history is None:
        if versioning and latest is None:
            return replace(empty, note=empty.note or NOTHING_STORED)
        found = read(latest, None)[0] if isinstance(latest, Mapping) else None
        why = NO_VERSIONS_LISTED if versioning else NO_VERSIONING
        return replace(empty, events=(found,) if found else (), not_checked=(why,))
    events, start, unread, not_checked = _walk(history, documents, read, own=own)
    return replace(empty, events=events, start=start, unread=unread, not_checked=not_checked)


def _walk(
    history: VersionHistory,
    documents: Mapping[int, Any],
    read: Read,
    *,
    own: bool,
) -> tuple[tuple[Event, ...], Start | None, tuple[int, ...], tuple[str, ...]]:
    """Every version from the oldest one the store keeps to its current one.

    The start is the oldest version listed and neither deleted nor destroyed.
    Versions before it are gone, and :class:`Start` counts them. From it on, a
    number the store does not list, or could not be read, is a gap. An event is
    kept where it differs from the last one read, so a stamp that did not move
    across a gap is not counted twice. ``own`` says each version's event is its
    own, as ``generated_at`` is, so none is inherited.
    """
    listed = {info.version: info for info in history.versions}
    kept = sorted(
        number for number, info in listed.items() if not info.deleted and not info.destroyed
    )
    top = max(history.current, max(listed, default=0))
    if not kept:
        gone = (f"the store keeps none of the {top} versions it has made",) if top else ()
        return (), None, (), gone
    readable = {number for number in kept if isinstance(documents.get(number), Mapping)}
    first = kept[0]
    start = Start(first, listed[first].created_at, gone=first - 1)
    events: list[Event] = []
    unread: list[int] = []
    last: Event | None = None
    previous_ok = 0 if first == 1 else None
    for number in range(first, top + 1):
        if number not in readable:
            unread.append(number)
            continue
        found, present = read(documents[number], number)
        if found is None:
            if present or last is not None:
                # Malformed, or gone after an earlier version had it.
                unread.append(number)
            else:
                previous_ok = number
            continue
        if last is None or found.at != last.at or own:
            exact = own or previous_ok == number - 1
            events.append(replace(found, exact=exact))
        last = found
        previous_ok = number
    return tuple(reversed(events)), start, tuple(unread), ()


def _moment(value: Any) -> datetime | None:
    """A stamp, or ``None`` for anything that is not one."""
    if not isinstance(value, str):
        return None
    try:
        return from_rfc3339(value)
    except ValueError:
        return None
