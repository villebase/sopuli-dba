"""`report history`'s text and its ``results[]`` entries (UC-5 §6).

Per target, per account: each rotation or reset newest first, where the history
starts, and the database's own date of the last password change beside it.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sopuli.clock import to_rfc3339
from sopuli.output import report_view
from sopuli.output.document import Error, Summary
from sopuli.output.palette import Role, paint
from sopuli.output.table import Column, render_table
from sopuli.report_accounts import ACCOUNT_MISSING, NOT_CHECKED, REPORT_OK
from sopuli.report_history import RESET, AccountHistory, Event

ABSENT = "-"
ERROR = "ERROR"


@dataclass(frozen=True)
class StoreFailure:
    """An account whose store gave no answer, so it has no history at all."""

    account: str
    kind: str
    error: Error


@dataclass(frozen=True)
class TargetHistory:
    """One target's part of the report.

    ``error`` with ``unsupported`` is a target of another product: nothing is
    read for it. ``error`` alone is a target that could not be reached: its
    accounts' histories come from the store and are still shown, with no
    database date.
    """

    target: str
    release: str | None = None
    accounts: tuple[AccountHistory, ...] = ()
    failures: tuple[StoreFailure, ...] = ()
    error: Error | None = None
    unsupported: bool = False
    read_failed: bool = False
    #: The name ``--account`` gave, where nothing on this target has it.
    absent: str | None = None


#: Shared with the other reports, so their exit codes cannot drift apart.
target_counts = report_view.target_counts


def render(reports: Sequence[TargetHistory]) -> str:
    if not reports:
        return "no targets selected"
    return "\n\n".join("\n".join(_section(report)) for report in reports)


def _section(report: TargetHistory) -> list[str]:
    heading = paint(report.target, Role.HEADING)
    if report.error is not None and report.unsupported:
        return [f"{heading}  not supported: {report.error.message}"]
    count = len(report.accounts) + len(report.failures)
    lines = [
        f"{heading}  ({report.release or 'release unknown'}, "
        f"{count} account{'' if count == 1 else 's'})"
    ]
    if report.error is not None:
        what = "could not read" if report.read_failed else "could not connect"
        lines.append(f"  {what}: {report.error.message}; database dates not read")
    if report.absent is not None:
        lines.append(f"  no managed account {report.absent} on this target")
    elif not count:
        lines.append("  no account here has a password the tool manages")
    for failure in report.failures:
        lines.append(f"  {failure.account}  ({failure.kind})")
        lines.append(f"    not checked: the store gave no answer: {failure.error.message}")
    for one in report.accounts:
        lines.extend(_account(one, reached=report.error is None))
    return lines


def _account(one: AccountHistory, *, reached: bool) -> list[str]:
    lines = [f"  {one.account}  ({one.kind})"]
    if one.db_changed_at is not None:
        lines.append(f"    database changed: {_when(one.db_changed_at)}")
    elif reached:
        lines.append(f"    database changed: unknown, {one.db_unknown}")
    if one.events:
        lines.extend(
            "    " + line
            for line in render_table(
                [Column("WHEN"), Column("CHANGE"), Column("VERSION"), Column("BY")],
                [_cells(event) for event in one.events],
            )
        )
    else:
        lines.append("    nothing recorded")
    if one.start is not None:
        gone = one.start.gone
        lines.append(
            f"    history from v{one.start.version}"
            f" ({_when(one.start.at) if one.start.at else 'date unknown'});"
            f" {gone} earlier version{'' if gone == 1 else 's'} gone"
        )
    if one.note is not None:
        lines.append(f"    note: {one.note}")
    lines.extend(f"    not checked: {reason}" for reason in one.reasons)
    return lines


def _cells(event: Event) -> list[str]:
    change = event.kind
    if event.kind == RESET and event.seen is not None:
        change = f"reset ({'seen' if event.seen else 'not seen'})"
    if event.version is None:
        version = ABSENT
    elif event.exact:
        version = f"v{event.version}"
    else:
        version = f"v{event.version} or earlier"
    return [_when(event.at), change, version, event.by or ABSENT]


def _when(moment: datetime) -> str:
    """To the second: the text compares dates, and the JSON keeps the rest."""
    return to_rfc3339(moment.replace(microsecond=0))


def build_results(reports: Sequence[TargetHistory]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for report in reports:
        if report.error is not None and report.unsupported:
            results.append(
                {
                    "account": ABSENT,
                    "target": report.target,
                    "state": NOT_CHECKED,
                    "changed": False,
                    "error": report.error.to_dict(),
                }
            )
            continue
        if report.absent is not None:
            results.append(
                {
                    "account": report.absent,
                    "target": report.target,
                    "state": ACCOUNT_MISSING,
                    "changed": False,
                }
            )
        results.extend(
            {
                "account": failure.account,
                "target": report.target,
                "state": ERROR,
                "changed": False,
                "kind": failure.kind,
                "error": failure.error.to_dict(),
            }
            for failure in report.failures
        )
        results.extend(_result(one) for one in report.accounts)
        if report.error is not None:
            # Unreachable: the histories above are still shown, and the target's
            # own failure is one more result, as in `report accounts`.
            results.append(
                {
                    "account": ABSENT,
                    "target": report.target,
                    "state": ERROR,
                    "changed": False,
                    "error": report.error.to_dict(),
                }
            )
    return results


def _result(one: AccountHistory) -> dict[str, Any]:
    return {
        "account": one.account,
        "target": one.target,
        "state": REPORT_OK if one.complete else NOT_CHECKED,
        "changed": False,
        "kind": one.kind,
        "history": {
            "events": [
                {
                    "kind": event.kind,
                    "at": to_rfc3339(event.at),
                    "version": event.version,
                    "exact": event.exact,
                    "by": event.by,
                    "seen": event.seen,
                }
                for event in one.events
            ],
            "start": (
                None
                if one.start is None
                else {
                    "version": one.start.version,
                    "at": to_rfc3339(one.start.at) if one.start.at else None,
                    "gone": one.start.gone,
                }
            ),
            "unread": list(one.unread),
            "not_checked": list(one.not_checked),
            "note": one.note,
            "db_changed_at": to_rfc3339(one.db_changed_at) if one.db_changed_at else None,
            "db_unknown": one.db_unknown,
        },
    }


def summarise(reports: Sequence[TargetHistory]) -> Summary:
    """The run's counts, from :func:`build_results` itself, so the two never disagree."""
    by_state: dict[str, int] = {}
    for entry in build_results(reports):
        by_state[entry["state"]] = by_state.get(entry["state"], 0) + 1
    return Summary(
        total=sum(by_state.values()),
        ok=by_state.get(REPORT_OK, 0),
        changed=0,
        failed=by_state.get(ERROR, 0),
        by_state=by_state,
    )
