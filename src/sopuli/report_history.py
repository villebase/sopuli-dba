"""One account's rotation history, from what the tool wrote (UC-5 §6).

Pure, like the other report modules: the command reads the store and the
database, and this module decides what the history says.

**The history comes from the store's versions.** An application account's
rotation is a change of the account's own ``rotated_at`` stamp, in the version
that first shows it; a personal account's reset is a version of its reset
record. Nothing here reads a password: only the stamps and the record's fields
are taken from a document, and the document is not kept.

**It never looks complete when it is not.** A version the store lists and
nobody could read is a gap, and the history is then *not checked*. So is a
store that keeps no versions. The oldest version kept is never presented as
the first rotation: :class:`Start` says where the history starts and how many
earlier versions are gone.

**The database's date is information.** It is shown beside the history and
never compared. UC-5 §6 once flagged a database change after the last
promotion, but the usual first run, ``creds generate --promote`` then
``creds apply``, does exactly that, so the flag would fire on every account
seeded that way (#1398).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any

from sopuli.clock import from_rfc3339
from sopuli.config.model import Binding
from sopuli.driver.protocol import UserState
from sopuli.exit_codes import ExitCode
from sopuli.lock.record import Holder
from sopuli.payload import GENERATED_AT, GENERATED_BY, ROTATED_AT, stage_layout
from sopuli.store.protocol import VersionHistory

__all__ = [
    "APPLICATION",
    "GENERATED",
    "NATIVE_NOTE",
    "NO_ACCOUNT",
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

ROTATED_BY = "rotated_by"

NATIVE_NOTE = (
    "the store keeps the promotion time of the current version only; "
    "the other versions are listed by when each was generated"
)
NO_VERSIONING = "the store keeps no versions (versioning), so only the latest is shown"
NO_ACCOUNT = "no such account on this target"
NO_DATE = "the database gives no date"


@dataclass(frozen=True)
class Event:
    """One change, newest first in a history.

    ``version`` is the store version that first shows it, or ``None`` where no
    version is known: the latest document of a store that keeps no versions, or
    the promotion of a native-staging secret.
    """

    kind: str
    at: datetime
    version: int | None
    by: str | None = None
    #: A reset only: whether a DBA saw the password (UC-2).
    seen: bool | None = None


@dataclass(frozen=True)
class Start:
    """Where a history starts: the oldest version kept, and what is gone."""

    version: int
    at: datetime | None
    #: The versions below ``version``, pruned or never listed.
    gone: int


@dataclass(frozen=True)
class AccountHistory:
    """One account on one target."""

    target: str
    account: str
    kind: str
    events: tuple[Event, ...] = ()
    start: Start | None = None
    #: Listed versions whose stamps could not be read: deleted, destroyed, or
    #: unreadable. Each is a gap a rotation could hide in.
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
        gaps = tuple(
            f"version {version} is listed and could not be read" for version in self.unread
        )
        return (*self.not_checked, *gaps)


def application(
    target: str,
    binding: Binding,
    history: VersionHistory | None,
    documents: Mapping[int, Any],
    *,
    latest: Any = None,
) -> AccountHistory:
    """An application account's rotations, from its secret's versions.

    ``documents`` maps a version to its document, for the versions that could
    be read. ``history`` is ``None`` where the store keeps no versions; then
    ``latest`` is the document as it is now, and only its stamp is shown.
    """
    empty = AccountHistory(target, binding.account, APPLICATION)
    if binding.secret is None:
        return replace(empty, not_checked=("the config names no secret for this account",))
    layout = stage_layout(binding.secret)

    def event(document: Any, version: int | None) -> Event | None:
        moment = _moment(layout.read(document, ROTATED_AT))
        if moment is None:
            return None
        by = layout.read(document, ROTATED_BY)
        return Event(ROTATION, moment, version, by=by if isinstance(by, str) else None)

    if history is None:
        found = event(latest, None) if isinstance(latest, Mapping) else None
        return replace(empty, events=(found,) if found else (), not_checked=(NO_VERSIONING,))
    events, unread = _walk(history, documents, event, same=lambda a, b: a.at == b.at)
    return replace(empty, events=events, start=_start(history), unread=unread)


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

    def generated(document: Any, version: int | None) -> Event | None:
        moment = _moment(document.get(GENERATED_AT))
        if moment is None:
            return None
        by = document.get(GENERATED_BY)
        return Event(GENERATED, moment, version, by=by if isinstance(by, str) else None)

    events, unread = _walk(history, documents, generated, same=lambda a, b: False)
    promoted = _moment(attributes.get(ROTATED_AT))
    if promoted is not None:
        by = attributes.get(ROTATED_BY)
        top = Event(ROTATION, promoted, None, by=by if isinstance(by, str) else None)
        events = tuple(sorted((top, *events), key=lambda one: one.at, reverse=True))
    return AccountHistory(
        target,
        binding.account,
        APPLICATION,
        events=events,
        start=_start(history),
        unread=unread,
        note=NATIVE_NOTE,
    )


def personal(
    target: str,
    account: str,
    history: VersionHistory | None,
    documents: Mapping[int, Any],
    *,
    latest: Any = None,
) -> AccountHistory:
    """A personal account's resets, from its reset record's versions (UC-2 §3)."""
    empty = AccountHistory(target, account, PERSONAL)

    def reset(document: Any, version: int | None) -> Event | None:
        moment = _moment(document.get("reset_at"))
        if moment is None:
            return None
        holder = Holder.from_dict(document.get("by"))
        seen = document.get("seen")
        return Event(
            RESET,
            moment,
            version,
            by=f"{holder.os_user}@{holder.host}" if holder else None,
            seen=seen if isinstance(seen, bool) else None,
        )

    if history is None:
        found = reset(latest, None) if isinstance(latest, Mapping) else None
        return replace(empty, events=(found,) if found else (), not_checked=(NO_VERSIONING,))
    events, unread = _walk(history, documents, reset, same=lambda a, b: a.at == b.at)
    return replace(empty, events=events, start=_start(history), unread=unread)


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
    """5 if no target could run, 1 if a target or store gave no answer, 4 if
    anything was not read. The report judges nothing else (UC-5 §6)."""
    if targets and unsupported == targets:
        return int(ExitCode.UNSUPPORTED_CAPABILITY)
    if unreachable or unanswered:
        return int(ExitCode.FAILURE)
    if unsupported or any(not one.complete for one in histories):
        return int(ExitCode.PARTIAL)
    return int(ExitCode.SUCCESS)


def _walk(
    history: VersionHistory,
    documents: Mapping[int, Any],
    read: Callable[[Mapping[str, Any], int], Event | None],
    *,
    same: Callable[[Event, Event], bool],
) -> tuple[tuple[Event, ...], tuple[int, ...]]:
    """Oldest first: each version's event, kept where it differs from the last.

    A version that is deleted, destroyed or missing from ``documents`` is a
    gap. The last event read before a gap is still compared after it, so a
    stamp that did not move across a gap is not counted twice.
    """
    events: list[Event] = []
    unread: list[int] = []
    last: Event | None = None
    for info in history.versions:
        document = documents.get(info.version)
        if info.deleted or info.destroyed or not isinstance(document, Mapping):
            unread.append(info.version)
            continue
        found = read(document, info.version)
        if found is None:
            continue
        if last is None or not same(found, last):
            events.append(found)
        last = found
    return tuple(reversed(events)), tuple(unread)


def _start(history: VersionHistory) -> Start | None:
    if history.oldest_kept is None:
        return None
    oldest = next((one for one in history.versions if one.version == history.oldest_kept), None)
    return Start(
        version=history.oldest_kept,
        at=oldest.created_at if oldest else None,
        gone=history.oldest_kept - 1,
    )


def _moment(value: Any) -> datetime | None:
    """A stamp, or ``None`` for anything that is not one.

    A malformed stamp is somebody else's string in somebody else's document,
    as ``creds status`` reads it: skipped, not a crash.
    """
    if not isinstance(value, str):
        return None
    try:
        return from_rfc3339(value)
    except ValueError:
        return None
