"""`report privileges`' text and its ``results[]`` entries (UC-5 §5).

The summary, per account: its roles, its system privileges with where each
comes from, its object and column privileges as counts by privilege and
object type, and its schema privileges with each schema. ``--detail`` lists
every privilege instead, one row each, with every role path.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from sopuli.driver.grants import RoleGrant
from sopuli.output import report_view
from sopuli.output.document import Error, Summary
from sopuli.output.palette import Role, paint
from sopuli.output.table import Column, render_table
from sopuli.report_accounts import ACCOUNT_MISSING, NOT_CHECKED, REPORT_OK
from sopuli.report_privileges import PUBLIC_KIND, AccountPrivileges, Privilege, counts

ABSENT = "-"
ERROR = "ERROR"

#: ``--detail``'s TYPE for a schema privilege, whose OBJECT is the schema.
SCHEMA_TYPE = "SCHEMA"


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
    #: The name ``--account`` gave, where this target has no such account.
    absent: str | None = None


#: The one count of unanswered and unsupported targets, shared with
#: ``report accounts`` so the two reports' exit codes cannot drift apart.
target_counts = report_view.target_counts


def render(reports: Sequence[TargetPrivileges], *, detail: bool) -> str:
    if not reports:
        return "no targets selected"
    return "\n\n".join("\n".join(_section(report, detail=detail)) for report in reports)


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
    # PUBLIC is not an account, so the head line does not count it.
    real = sum(1 for one in report.accounts if one.kind != PUBLIC_KIND)
    lines = [
        f"{heading}  ({report.release or 'release unknown'}, "
        f"{real} account{'' if real == 1 else 's'})"
    ]
    if report.absent is not None:
        lines.append(f"  no account {report.absent} on this target")
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
    lines.append(f"    schemas: {_schemas(one.schemas)}")
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


def _schemas(privileges: Sequence[Privilege] | None) -> str:
    """``SELECT ANY TABLE on ACME_OWNER (direct)``, one per privilege and schema."""
    if privileges is None:
        return "not checked"
    if not privileges:
        return "none"
    return "; ".join(f"{p.privilege} on {p.owner} ({_sources(p)})" for p in privileges)


def _counts(privileges: Sequence[Privilege] | None, *, noun: str | None = None) -> str:
    """``SELECT on 42 table (30 direct, 12 via roles)``; ``noun`` overrides the type."""
    if privileges is None:
        return "not checked"
    if not privileges:
        return "none"
    parts = []
    for (privilege, object_type), (direct, via) in counts(privileges).items():
        what = noun or (object_type.lower() if object_type != "-" else "object")
        total = direct + via
        plural = what if total == 1 else _plural(what)
        # Held only through a role that is not a default role: counted, and
        # said, because the account has it only after SET ROLE (UC-5 §5).
        inactive = sum(
            1
            for p in privileges
            if p.privilege == privilege
            and (p.object_type or "-") == object_type
            and not p.via_default_role
        )
        note = f", {inactive} through a role that is not a default role" if inactive else ""
        parts.append(f"{privilege} on {total} {plural} ({direct} direct, {via} via roles{note})")
    return "; ".join(parts)


def _plural(noun: str) -> str:
    """``tables``, ``directories``, ``libraries``: Oracle's object types in English."""
    if noun.endswith("y") and not noun.endswith(("ay", "ey", "oy", "uy")):
        return noun[:-1] + "ies"
    if noun.endswith(("s", "x", "ch", "sh")):
        return noun + "es"
    return noun + "s"


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
    parts = (
        ("system", one.system),
        ("object", one.objects),
        ("column", one.columns),
        ("schema", one.schemas),
    )
    for label, part in parts:
        if part is None:
            rows.append([label, "not checked", "", "", "", ""])
            continue
        rows.extend(
            [
                label,
                p.privilege,
                ".".join(x for x in (p.owner, p.name, p.column) if x) or ABSENT,
                SCHEMA_TYPE if label == "schema" else p.object_type or ABSENT,
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
        if report.absent is not None:
            # `--account` named an account this target does not have. Said in
            # JSON as in the text, so a job can tell it from a clean report.
            results.append(
                {
                    "account": report.absent,
                    "target": report.target,
                    "state": ACCOUNT_MISSING,
                    "changed": False,
                }
            )
        results.extend(_result(one, report.unreadable) for one in report.accounts)
    return results


def _result(one: AccountPrivileges, unreadable: Sequence[str]) -> dict[str, Any]:
    complete = one.complete and not unreadable
    return {
        "account": one.account,
        "target": one.target,
        "state": REPORT_OK if complete else NOT_CHECKED,
        "changed": False,
        "kind": one.kind,
        "privileges": {
            # Why a part is null, as the target's survey said it.
            "unreadable": list(unreadable),
            "schema_privileges_read": one.schemas is not None,
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
            "schemas": _privileges_json(one.schemas),
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
