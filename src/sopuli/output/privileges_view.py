"""`report privileges`' text and its ``results[]`` entries (UC-5 §5).

The summary, per account: its roles, its system privileges with where each
comes from, and its object and column privileges as counts by privilege and
object type. ``--detail`` lists every privilege instead, one row each, with
every role path.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from sopuli.driver.grants import RoleGrant
from sopuli.output.document import Error, Summary
from sopuli.output.palette import Role, paint
from sopuli.output.table import Column, render_table
from sopuli.report_accounts import NOT_CHECKED, REPORT_OK
from sopuli.report_privileges import AccountPrivileges, Privilege, counts

ABSENT = "-"
ERROR = "ERROR"

#: Said once under the report: 23ai schema privileges are not read yet (#1389),
#: so a list without them must not read as complete.
SCHEMA_PRIVILEGES_NOTE = (
    "schema privileges (GRANT ... ON SCHEMA, 23ai) are not read yet, so they are not listed"
)


@dataclass(frozen=True)
class TargetPrivileges:
    """One target's part of the report: what it said, or why it said nothing."""

    target: str
    release: str | None = None
    accounts: tuple[AccountPrivileges, ...] = ()
    unreadable: tuple[str, ...] = ()
    error: Error | None = None
    unsupported: bool = False
    read_failed: bool = False


def target_counts(reports: Sequence[TargetPrivileges]) -> tuple[int, int]:
    """How many targets gave no answer, and how many of another product."""
    unsupported = sum(1 for report in reports if report.unsupported)
    unanswered = sum(1 for report in reports if report.error is not None) - unsupported
    return unanswered, unsupported


def render(reports: Sequence[TargetPrivileges], *, detail: bool) -> str:
    if not reports:
        return "no targets selected"
    sections = ["\n".join(_section(report, detail=detail)) for report in reports]
    return "\n\n".join([*sections, SCHEMA_PRIVILEGES_NOTE])


def _section(report: TargetPrivileges, *, detail: bool) -> list[str]:
    heading = paint(report.target, Role.HEADING)
    if report.error is not None:
        if report.unsupported:
            what = "not supported"
        elif report.read_failed:
            what = "could not read"
        else:
            what = "could not connect"
        return [f"{heading}  {what}: {report.error.message}"]
    lines = [
        f"{heading}  ({report.release or 'release unknown'}, "
        f"{len(report.accounts)} account{'' if len(report.accounts) == 1 else 's'})"
    ]
    for one in report.accounts:
        lines.extend(_detail(one) if detail else _summary(one))
    lines.extend(f"  not checked: {reason}" for reason in report.unreadable)
    return lines


def _summary(one: AccountPrivileges) -> list[str]:
    lines = [f"  {one.account}  ({one.kind})"]
    lines.append(f"    roles: {_roles(one.roles) or 'none'}")
    lines.append(f"    system: {_system(one.system)}")
    lines.append(f"    objects: {_counts(one.objects)}")
    lines.append(f"    columns: {_counts(one.columns, noun='column')}")
    return lines


def _roles(roles: Sequence[RoleGrant]) -> str:
    def one(role: RoleGrant) -> str:
        marks = ["default" if role.default_role else "not default"]
        if role.admin_option:
            marks.append("admin option")
        if role.authentication not in ("NONE", ""):
            marks.append(f"authentication {role.authentication}")
        return f"{role.role} ({', '.join(marks)})"

    return ", ".join(one(role) for role in roles)


def _system(privileges: Sequence[Privilege] | None) -> str:
    if privileges is None:
        return "not checked"
    if not privileges:
        return "none"
    return "; ".join(f"{p.privilege} ({_sources(p)})" for p in privileges)


def _counts(privileges: Sequence[Privilege] | None, *, noun: str | None = None) -> str:
    """``SELECT on 42 table (30 direct, 12 via roles)``; ``noun`` overrides the type."""
    if privileges is None:
        return "not checked"
    if not privileges:
        return "none"
    parts = []
    for (privilege, object_type), (direct, via) in counts(privileges).items():
        what = noun or (object_type.lower() if object_type != "-" else "object")
        parts.append(f"{privilege} on {direct + via} {what} ({direct} direct, {via} via roles)")
    return "; ".join(parts)


def _sources(privilege: Privilege) -> str:
    sources = ["direct" if path == () else "via " + " > ".join(path) for path in privilege.paths]
    if not privilege.via_default_role:
        sources.append("not a default role")
    return ", ".join(sources)


def _detail(one: AccountPrivileges) -> list[str]:
    lines = [f"  {one.account}  ({one.kind})"]
    if one.roles:
        lines.append(f"    roles: {_roles(one.roles)}")
    rows: list[list[str]] = []
    for label, part in (("system", one.system), ("object", one.objects), ("column", one.columns)):
        if part is None:
            rows.append([label, "not checked", "", "", "", ""])
            continue
        rows.extend(
            [
                label,
                p.privilege,
                ".".join(x for x in (p.owner, p.name, p.column) if x) or ABSENT,
                p.object_type or ABSENT,
                _sources(p),
                "yes" if p.grantable else "no",
            ]
            for p in part
        )
    lines.extend(
        "    " + line
        for line in render_table(
            [
                Column("KIND"),
                Column("PRIVILEGE"),
                Column("OBJECT"),
                Column("TYPE"),
                Column("FROM"),
                Column("GRANTABLE"),
            ],
            rows,
        )
    )
    return lines


def build_results(reports: Sequence[TargetPrivileges]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for report in reports:
        if report.error is not None:
            results.append(
                {
                    "account": ABSENT,
                    "target": report.target,
                    "state": NOT_CHECKED if report.unsupported else ERROR,
                    "changed": False,
                    "error": report.error.to_dict(),
                }
            )
            continue
        results.extend(_result(one) for one in report.accounts)
    return results


def _result(one: AccountPrivileges) -> dict[str, Any]:
    return {
        "account": one.account,
        "target": one.target,
        "state": REPORT_OK if one.complete else NOT_CHECKED,
        "changed": False,
        "kind": one.kind,
        "privileges": {
            "roles": [
                {
                    "role": role.role,
                    "admin_option": role.admin_option,
                    "default_role": role.default_role,
                    "authentication": role.authentication,
                }
                for role in one.roles
            ],
            "system": _privileges_json(one.system),
            "objects": _privileges_json(one.objects),
            "columns": _privileges_json(one.columns),
        },
    }


def _privileges_json(part: Sequence[Privilege] | None) -> list[dict[str, Any]] | None:
    if part is None:
        return None
    return [
        {
            "privilege": p.privilege,
            "owner": p.owner,
            "name": p.name,
            "object_type": p.object_type,
            "column": p.column,
            "paths": [list(path) for path in p.paths],
            "via_default_role": p.via_default_role,
            "grantable": p.grantable,
        }
        for p in part
    ]


def summarise(reports: Sequence[TargetPrivileges]) -> Summary:
    accounts = [one for report in reports for one in report.accounts]
    unreachable, unsupported = target_counts(reports)
    complete = sum(1 for one in accounts if one.complete)
    by_state: dict[str, int] = {}
    if complete:
        by_state[REPORT_OK] = complete
    if len(accounts) - complete + unsupported:
        by_state[NOT_CHECKED] = len(accounts) - complete + unsupported
    if unreachable:
        by_state[ERROR] = unreachable
    return Summary(
        total=len(accounts) + unreachable + unsupported,
        ok=complete,
        changed=0,
        failed=unreachable,
        by_state=by_state,
    )
