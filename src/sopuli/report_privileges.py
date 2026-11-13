"""UC-5's privilege report: each account's effective privileges (§5).

Pure: the accounts report's rows and a target's grant survey come in, one
:class:`AccountPrivileges` per account comes out. Nothing here connects.

**Effective, with every path.** The survey returns one row per path, as probe
19 measured: a privilege granted directly and through two roles arrives three
times. :func:`collapse` merges them into one privilege and keeps every path, so
a count never counts a privilege twice and the detailed list still says how
each one is reached (U5).

**The report judges nothing.** The auditor does (U4), so there is no problem
state and no exit 3. A part the target could not read is ``None``, never an
empty tuple: an account whose object grants were not read is not an account
with none.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from sopuli.driver.grants import GrantRow, GrantSurvey, RoleGrant
from sopuli.report_accounts import ACCOUNT_MISSING, AccountRow
from sopuli.report_exit import exit_code_for

#: The pseudo-account grants to ``PUBLIC`` are listed under, once per target.
PUBLIC = "PUBLIC"
PUBLIC_KIND = "public"


@dataclass(frozen=True)
class Privilege:
    """One privilege on one object (or a system privilege), and every path to it."""

    kind: str
    privilege: str
    owner: str | None
    name: str | None
    object_type: str | None
    column: str | None
    #: Each path from the account down through its roles; ``()`` is a direct grant.
    paths: tuple[tuple[str, ...], ...]
    #: Whether the account is shown to hold it without ``SET ROLE``: directly,
    #: or through a role active at login.
    via_default_role: bool
    grantable: bool
    #: The product's word for its level inside the part, such as ``global
    #: dynamic`` on MySQL; ``None`` where the part has one level, as on Oracle.
    level: str | None = None
    #: ``False`` where ``via_default_role`` is false and a path's first role is
    #: not known to be active or not, such as a MySQL role whose default status
    #: was not read: whether it is held without ``SET ROLE`` was not checked.
    active_at_login_checked: bool = True
    #: The schemas a MySQL partial revoke takes this global privilege away on,
    #: on every path (#1502); empty elsewhere.
    except_schemas: tuple[str, ...] = ()


@dataclass(frozen=True)
class AccountPrivileges:
    """One account's privileges on one target. ``None`` parts were not checked."""

    target: str
    account: str
    kind: str
    roles: tuple[RoleGrant, ...]
    system: tuple[Privilege, ...] | None
    objects: tuple[Privilege, ...] | None
    columns: tuple[Privilege, ...] | None
    #: Schema privileges (23ai), each with its schema as ``owner``. ``()`` on a
    #: release that has none.
    schemas: tuple[Privilege, ...] | None

    @property
    def complete(self) -> bool:
        """Whether every part was read."""
        return None not in (self.system, self.objects, self.columns, self.schemas)


def collapse(rows: Sequence[GrantRow]) -> tuple[Privilege, ...]:
    """One :class:`Privilege` per (kind, level, privilege, object, column), every path kept."""
    grouped: dict[tuple[object, ...], list[GrantRow]] = {}
    for row in rows:
        key = (
            row.kind,
            row.level,
            row.privilege,
            row.owner,
            row.name,
            row.object_type,
            row.column,
        )
        grouped.setdefault(key, []).append(row)
    collapsed = []
    for (kind, level, privilege, owner, name, object_type, column), group in grouped.items():
        active = _active(group)
        collapsed.append(
            Privilege(
                kind=str(kind),
                level=_text(level),
                privilege=str(privilege),
                owner=_text(owner),
                name=_text(name),
                object_type=_text(object_type),
                column=_text(column),
                paths=tuple(sorted({row.path for row in group})),
                via_default_role=active is True,
                active_at_login_checked=active is not None,
                grantable=any(row.grantable for row in group),
                except_schemas=_excepted(group),
            )
        )
    return tuple(
        sorted(
            collapsed,
            key=lambda p: (p.level or "", p.privilege, p.owner or "", p.name or "", p.column or ""),
        )
    )


def _excepted(group: Sequence[GrantRow]) -> tuple[str, ...]:
    """The schemas every path active at login revokes the grant on (#1502).

    A schema that one active path still reaches is not an exception, because
    the privileges of an account and its active roles add up: measured on
    8.4.13. A role known not to be active at login gives nothing back then,
    so a path whose first role is not a default role does not count. A path
    whose first role may or may not be active (``first_role_default`` is
    ``None``, such as a mandatory role 9.7.4 activates and 8.4.13 does not)
    counts: the report then shows the wider reach, and the row already says
    whether it is held at login was not checked. Where no path counts, every
    path does: the privilege is held only after ``SET ROLE``, and the row says
    so.
    """
    active = [row for row in group if row.path == () or row.first_role_default is not False]
    paths = active or list(group)
    schemas = set(paths[0].except_schemas)
    for row in paths[1:]:
        schemas &= set(row.except_schemas)
    return tuple(sorted(schemas))


def _active(group: Sequence[GrantRow]) -> bool | None:
    """True if one path is direct or starts with a role active at login;
    otherwise ``None`` if one path's first role is not known either way;
    otherwise False."""
    if any(row.path == () or row.first_role_default is True for row in group):
        return True
    if any(row.first_role_default is None for row in group):
        return None
    return False


def _text(value: object) -> str | None:
    return None if value is None else str(value)


def counts(objects: Sequence[Privilege]) -> dict[tuple[str, str, str], tuple[int, int]]:
    """``(level, privilege, object type) -> (direct, through roles only)``.

    A privilege held both directly and through a role counts as direct, once.
    The level is ``""`` where the part has one, as on Oracle; two levels of one
    privilege and type are counted apart, so a PostgreSQL default privilege is
    never counted as a grant on a table that exists.
    """
    tally: dict[tuple[str, str, str], list[int]] = {}
    for privilege in objects:
        key = (privilege.level or "", privilege.privilege, privilege.object_type or "-")
        slot = tally.setdefault(key, [0, 0])
        slot[0 if () in privilege.paths else 1] += 1
    return {key: (direct, via) for key, (direct, via) in sorted(tally.items())}


def per_account(
    target: str, rows: Sequence[AccountRow], survey: GrantSurvey, *, public: bool = False
) -> tuple[AccountPrivileges, ...]:
    """Each account the accounts report covers, then ``PUBLIC`` when asked for.

    The accounts are exactly ``report accounts``' rows, less the missing ones,
    so the two reports never disagree about which accounts a target has.
    ``PUBLIC`` is listed whenever ``public`` is asked for, also when its grants
    could not be read: then its parts are not checked, never absent.
    """
    built = [
        _one(target, row.account, row.kind, survey) for row in rows if row.state != ACCOUNT_MISSING
    ]
    if public:
        built.append(_one(target, PUBLIC, PUBLIC_KIND, survey))
    return tuple(built)


def _one(target: str, account: str, kind: str, survey: GrantSurvey) -> AccountPrivileges:
    # Exact, as the dictionary spells it: the survey is asked for the names the
    # accounts survey read, and two users whose names differ only in case
    # (`ACME` and a quoted `"acme"`) are two accounts.
    name = account

    def part(rows: tuple[GrantRow, ...] | None) -> tuple[Privilege, ...] | None:
        if rows is None:
            return None
        return collapse([row for row in rows if row.grantee == name])

    return AccountPrivileges(
        target=target,
        account=account,
        kind=kind,
        roles=tuple(role for role in survey.roles if role.grantee == name),
        system=part(survey.system),
        objects=part(survey.objects),
        columns=part(survey.columns),
        schemas=part(survey.schemas),
    )


def exit_code(
    reports: Sequence[AccountPrivileges],
    *,
    unreachable: int,
    unsupported: int,
    targets: int,
    unreadable: bool = False,
) -> int:
    """5 if no target could run, 1 if one gave no answer, 4 if anything was not read.

    ``unreadable`` is any target's survey saying it could not read something,
    such as ``DBA_ROLES`` for the roles' authentication, even where every
    account's four parts were read.
    """
    return exit_code_for(
        unreachable=unreachable,
        unsupported=unsupported,
        targets=targets,
        incomplete=unreadable or any(not one.complete for one in reports),
    )
