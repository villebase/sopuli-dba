"""`report accounts`' text table and its ``results[]`` entries (UC-5 §4).

One section per target, in the config's order. The head line names the target,
the release it reported, and the counts. Problems come first, worst first; then
the accounts not checked, with no rule, and undeclared; then a count of the
accounts that passed every check. ``--all`` lists those too.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from sopuli.output.document import Error, Summary
from sopuli.output.palette import Role, paint, state_cell
from sopuli.output.table import Cell, Column, render_table
from sopuli.report_accounts import (
    ACCOUNT_MISSING,
    NO_RULE,
    NOT_CHECKED,
    PROFILE_MISSING,
    REPORT_OK,
    REPORT_PROBLEM,
    UNDECLARED,
    AccountRow,
    MissingProfile,
)

#: The `account` of a result that is about a target and no account.
ABSENT = "-"
ERROR = "ERROR"

_ACCOUNT = 30
_PROFILE = 24
_STATUS = 18


@dataclass(frozen=True)
class TargetReport:
    """One target's part of the report: what it said, or why it said nothing."""

    target: str
    release: str | None = None
    read: int = 0
    rows: tuple[AccountRow, ...] = ()
    #: Each profile the file expects here that the target does not have: one
    #: problem for the target, not one per account (#1390).
    missing: tuple[MissingProfile, ...] = ()
    error: Error | None = None
    #: The target is of a product this report is not written for, refused
    #: before connecting. Not checked, rather than unreachable (UC-5 §3).
    unsupported: bool = False
    #: The target answered the login and then failed the survey, such as a
    #: refused dictionary read. Still a target with no answer, but not one that
    #: could not be reached.
    read_failed: bool = False


class TargetAnswer(Protocol):
    """What a report knows of one target's answer, whichever report it is."""

    @property
    def error(self) -> Error | None: ...

    @property
    def unsupported(self) -> bool: ...


def target_counts(reports: Sequence[TargetAnswer]) -> tuple[int, int]:
    """How many targets gave no answer, and how many of another product.

    The one place both are counted, for every report, so a report's exit code
    and its summary agree, and the reports agree with each other.
    """
    unsupported = sum(1 for report in reports if report.unsupported)
    unanswered = sum(1 for report in reports if report.error is not None) - unsupported
    return unanswered, unsupported


def render(reports: Sequence[TargetReport], *, show_all: bool) -> str:
    """The whole text view."""
    if not reports:
        return "no targets selected"
    sections = [_section(report, show_all=show_all) for report in reports]
    return "\n\n".join("\n".join(lines) for lines in sections)


def _section(report: TargetReport, *, show_all: bool) -> list[str]:
    if report.error is not None:
        if report.unsupported:
            what = "not supported"
        elif report.read_failed:
            what = "could not read"
        else:
            what = "could not connect"
        return [f"{paint(report.target, Role.HEADING)}  {what}: {report.error.message}"]
    lines = [f"{paint(report.target, Role.HEADING)}  ({_head(report)})"]
    lines.extend(
        f"  {paint('profile missing', Role.BAD)}: {_missing_detail(missing)}"
        for missing in report.missing
    )
    shown = [row for row in report.rows if show_all or row.state != REPORT_OK]
    if shown:
        lines.extend(
            "  " + line
            for line in render_table(
                [
                    Column("ACCOUNT", _ACCOUNT),
                    Column("KIND"),
                    Column("PROFILE", _PROFILE),
                    Column("STATUS", _STATUS),
                    Column("FAILED LOGINS"),
                    Column("STATE"),
                    Column("FINDING"),
                ],
                [_cells(row) for row in shown],
            )
        )
    ok = sum(1 for row in report.rows if row.state == REPORT_OK)
    if not show_all:
        lines.append(f"  {_count(ok, 'account')} OK")
    # Why a count is `unknown`, said once for each distinct reason rather than
    # on every row that shares it, such as a missing SYS.USER$ grant.
    reasons = sorted(
        {row.failed_logins_reason for row in report.rows if row.failed_logins_reason is not None}
    )
    lines.extend(f"  failed logins unknown: {reason}" for reason in reasons)
    return lines


def _head(report: TargetReport) -> str:
    counts = _counts(report.rows)
    parts = [report.release or "release unknown", f"{_count(report.read, 'account')} read"]
    if report.missing:
        parts.append(f"{_count(len(report.missing), 'profile')} missing")
    parts.extend(
        f"{counts[state]} {label}"
        for state, label in (
            (REPORT_PROBLEM, "with a problem"),
            (NOT_CHECKED, "not checked"),
            (NO_RULE, "no rule"),
            (UNDECLARED, "undeclared"),
        )
        if counts[state]
    )
    return ", ".join(parts)


def _counts(rows: Sequence[AccountRow]) -> dict[str, int]:
    counts = dict.fromkeys((REPORT_PROBLEM, NOT_CHECKED, NO_RULE, UNDECLARED, REPORT_OK), 0)
    for row in rows:
        # A missing account is a problem in the head line's count.
        counts[REPORT_PROBLEM if row.state == ACCOUNT_MISSING else row.state] += 1
    return counts


def _missing_detail(missing: MissingProfile) -> str:
    """What a missing profile's finding says, in the table and in the JSON."""
    return (
        f"{missing.profile} does not exist on this target; "
        f"expected by {' and '.join(missing.expected_by)}"
    )


def _count(number: int, noun: str) -> str:
    return f"{number} {noun}{'' if number == 1 else 's'}"


def _cells(row: AccountRow) -> list[Cell | str]:
    return [
        row.account,
        row.kind,
        row.profile or "-",
        row.status or "-",
        _failed(row),
        state_cell(row.state),
        _finding(row),
    ]


def _failed(row: AccountRow) -> str:
    if row.state == ACCOUNT_MISSING:
        return "-"
    return "unknown" if row.failed_logins is None else str(row.failed_logins)


def _finding(row: AccountRow) -> str:
    """The findings worth reading: problems first, then what could not be checked."""
    if row.state == UNDECLARED:
        return "not in config"
    picked = [f for f in row.findings if f.outcome == "problem"]
    picked += [f for f in row.findings if f.outcome == "not_checked"]
    if not picked:
        picked = [f for f in row.findings if f.outcome == "no_rule"]
    return "; ".join(f"{finding.check}: {finding.detail}" for finding in picked) or "-"


def build_results(reports: Sequence[TargetReport]) -> list[dict[str, Any]]:
    """Every ``results[]`` entry: one per account, and one per unreachable target."""
    results: list[dict[str, Any]] = []
    for report in reports:
        if report.error is not None:
            results.append(
                {
                    "account": ABSENT,
                    "target": report.target,
                    # Another product is not checked there (UC-5 §3), as the exit
                    # code says; only an unreached target is an error.
                    "state": NOT_CHECKED if report.unsupported else ERROR,
                    "changed": False,
                    "error": report.error.to_dict(),
                }
            )
            continue
        results.extend(_missing_result(missing) for missing in report.missing)
        results.extend(_result(row) for row in report.rows)
    return results


def _missing_result(missing: MissingProfile) -> dict[str, Any]:
    """A profile missing on a target: about the target, so no account."""
    return {
        "account": ABSENT,
        "target": missing.target,
        "state": PROFILE_MISSING,
        "changed": False,
        "profile": missing.profile,
        "expected_by": list(missing.expected_by),
        "findings": [
            {"check": "profile", "outcome": "problem", "detail": _missing_detail(missing)}
        ],
    }


def _result(row: AccountRow) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "account": row.account,
        "target": row.target,
        "state": row.state,
        "changed": False,
        "kind": row.kind,
        "findings": [
            {"check": f.check, "outcome": f.outcome, "detail": f.detail} for f in row.findings
        ],
    }
    if row.status is not None:
        entry["account_status"] = row.status
    if row.state != ACCOUNT_MISSING:
        entry["failed_logins"] = row.failed_logins
    if row.failed_logins_reason is not None:
        entry["failed_logins_reason"] = row.failed_logins_reason
    return entry


def summarise(reports: Sequence[TargetReport]) -> Summary:
    """The run's counts. ``failed`` counts unreachable targets and problems."""
    rows = [row for report in reports for row in report.rows]
    unreachable, unsupported = target_counts(reports)
    missing = sum(len(report.missing) for report in reports)
    problems = sum(1 for row in rows if row.state in (REPORT_PROBLEM, ACCOUNT_MISSING)) + missing
    counts: dict[str, int] = {}
    for row in rows:
        counts[row.state] = counts.get(row.state, 0) + 1
    if missing:
        counts[PROFILE_MISSING] = missing
    if unreachable:
        counts[ERROR] = unreachable
    if unsupported:
        counts[NOT_CHECKED] = counts.get(NOT_CHECKED, 0) + unsupported
    return Summary(
        total=len(rows) + missing + unreachable + unsupported,
        ok=sum(1 for row in rows if row.state == REPORT_OK),
        changed=0,
        failed=problems + unreachable,
        by_state=counts,
    )
