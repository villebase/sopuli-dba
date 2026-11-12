"""Every privilege an account holds, one row per path, from the grant tables
MySQL and MariaDB read the same way (UC-5, #1482). Tier 0.

Pure: each product's driver reads its own tables and hands the rows in, and
this builds the :class:`~sopuli.driver.grants.GrantSurvey` the privilege report
takes. Nothing here connects or imports PyMySQL.

- **A role is an account.** It is a user name and a host, and on MariaDB the
  host is empty. A grant table names the holder by both, so every holder is a
  :class:`~sopuli.driver.mysql_family.accounts.Principal`, compared by its key,
  the host without ASCII case.
- **One row per path.** An account holds what is granted to it, and what is
  granted to each role it reaches: granted to it, or to a role it reaches,
  followed to the end. Each path from the account down to the role that holds
  a privilege gives one row, as Oracle's survey does. A role reached twice on
  one path stops that path, so a circular grant cannot loop.
- **A mandatory role** (MySQL's ``@@mandatory_roles``) goes to every account
  and has no row in ``role_edges``, so it is handed in apart. A role that is
  also granted is followed as a granted role.
- **Active without ``SET ROLE``** is :attr:`GrantRow.first_role_default`, for
  the first role of the path, by :class:`Activation`
  (``11_role_activation_probe.py``): every role when all roles are activated
  at login, otherwise a default role. A role a default role holds is active
  too, which the path's first role already says. ``None`` where nothing read
  says: the default roles were not read, or the role is a mandatory role that
  is not a default role, which one release activates at login and two do not.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

from sopuli.driver.grants import COLUMN, OBJECT, SCHEMA, SYSTEM, GrantRow, GrantSurvey, RoleGrant
from sopuli.driver.mysql_family.accounts import Principal, split

#: A role has no authentication of its own on MySQL or MariaDB.
NO_AUTHENTICATION = "NONE"

PARTS = (SYSTEM, SCHEMA, OBJECT, COLUMN)


@dataclass(frozen=True)
class Held:
    """One privilege that ``holder`` holds itself, as a grant table names it.

    ``kind`` is the report's part (:data:`~sopuli.driver.grants.SYSTEM` and the
    rest), and ``level`` the product's word for the table it came from, such
    as ``global dynamic``. ``owner`` is the schema, ``name`` the object.
    """

    holder: Principal
    kind: str
    level: str
    privilege: str
    owner: str | None = None
    name: str | None = None
    object_type: str | None = None
    column: str | None = None
    grantable: bool = False

    def __post_init__(self) -> None:
        if self.kind not in PARTS:
            raise ValueError(f"a held privilege's kind is one of {PARTS}, not {self.kind!r}")


@dataclass(frozen=True)
class Edge:
    """``role`` is granted to ``member``, an account or another role."""

    member: Principal
    role: Principal
    admin_option: bool


@dataclass(frozen=True)
class Activation:
    """What makes a role active at login.

    ``defaults`` holds a ``(member key, role key)`` pair for each default
    role, or is ``None`` where the default roles were not read. ``all_active``
    is MySQL's ``@@activate_all_roles_on_login``. ``mandatory`` are the roles
    every account holds: only those that exist, because MySQL takes a name
    in ``@@mandatory_roles`` that names no role, and ignores it at login.
    """

    defaults: frozenset[tuple[tuple[str, str], tuple[str, str]]] | None
    all_active: bool = False
    mandatory: tuple[Principal, ...] = ()


@dataclass(frozen=True, order=True)
class _FirstRole:
    """A role ``account`` holds itself, by a grant or as a mandatory role."""

    role: Principal
    admin_option: bool
    #: Whether it is a default role, as read; ``False`` where not read.
    default: bool
    #: Whether it is active at login; ``None`` where nothing read says.
    active: bool | None


def survey(
    accounts: Sequence[str],
    edges: Iterable[Edge],
    held: Iterable[Held],
    activation: Activation,
    *,
    unread: Mapping[str, str] | None = None,
    reasons: Sequence[str] = (),
) -> GrantSurvey:
    """Every grant ``accounts`` hold, one row per path.

    ``accounts`` are ``user@host`` as the accounts survey spelled them, and
    each row's grantee is that spelling. ``unread`` maps a part that could not
    be read to the reason, and the part is ``None``. ``reasons`` are added to
    :attr:`GrantSurvey.unreadable` as they are, such as default roles that
    could not be read.
    """
    unread = dict(unread or {})
    by_member: dict[tuple[str, str], list[Edge]] = {}
    for edge in edges:
        by_member.setdefault(edge.member.key(), []).append(edge)
    by_holder: dict[tuple[str, str], list[Held]] = {}
    for grant in held:
        by_holder.setdefault(grant.holder.key(), []).append(grant)

    roles: list[RoleGrant] = []
    rows: dict[str, list[GrantRow]] = {part: [] for part in PARTS}
    unknown_activation = False
    for name in accounts:
        account = Principal(*split(name))
        firsts = _first_roles(account, by_member, activation)
        for first in firsts:
            unknown_activation = unknown_activation or first.active is None
            roles.append(
                RoleGrant(
                    grantee=name,
                    role=str(first.role),
                    admin_option=first.admin_option,
                    default_role=first.default,
                    authentication=NO_AUTHENTICATION,
                )
            )
        for path, active in _paths(account, firsts, by_member):
            holder = path[-1] if path else account
            for grant in by_holder.get(holder.key(), ()):
                if grant.kind not in unread:
                    rows[grant.kind].append(_row(name, grant, path, active))

    unreadable = [*reasons]
    if unknown_activation and activation.defaults is not None:
        unreadable.append(MANDATORY_UNKNOWN)
    unreadable += [unread[part] for part in PARTS if part in unread]

    def part(kind: str) -> tuple[GrantRow, ...] | None:
        return None if kind in unread else tuple(rows[kind])

    return GrantSurvey(
        roles=tuple(roles),
        system=part(SYSTEM),
        objects=part(OBJECT),
        columns=part(COLUMN),
        schemas=part(SCHEMA),
        unreadable=tuple(unreadable),
    )


#: Why a mandatory role's paths are not known to be active without SET ROLE.
MANDATORY_UNKNOWN = (
    "whether a mandatory role that is not a default role is active at login: MySQL "
    "8.0.46 and 8.4.13 leave it inactive and 9.7.4 activates it, and nothing the tool "
    "account reads says which this server does"
)


def _first_roles(
    account: Principal,
    by_member: Mapping[tuple[str, str], list[Edge]],
    activation: Activation,
) -> list[_FirstRole]:
    """The roles granted to ``account``, then each mandatory role not also
    granted, sorted by role, each with whether it is active at login."""
    granted = {
        edge.role.key(): (edge.role, edge.admin_option, False)
        for edge in by_member.get(account.key(), ())
    }
    for role in activation.mandatory:
        if role.key() != account.key():
            granted.setdefault(role.key(), (role, False, True))
    firsts = []
    for role, admin_option, mandatory in granted.values():
        default = (
            activation.defaults is not None and (account.key(), role.key()) in activation.defaults
        )
        active: bool | None
        if activation.all_active or default:
            active = True
        elif activation.defaults is None or mandatory:
            # Not read, or a mandatory role that one release activates at
            # login and two do not (11_role_activation_probe.py).
            active = None
        else:
            active = False
        firsts.append(_FirstRole(role, admin_option, default, active))
    return sorted(firsts)


def _paths(
    account: Principal,
    firsts: Sequence[_FirstRole],
    by_member: Mapping[tuple[str, str], list[Edge]],
) -> list[tuple[tuple[Principal, ...], bool | None]]:
    """Every path from ``account``, ``()`` first, each with whether its first
    role is active at login (``None`` for the account's own grants).

    One path per row is the contract, as Oracle's recursive query gives it,
    so a role reached by two paths gives two."""
    found: list[tuple[tuple[Principal, ...], bool | None]] = [((), None)]
    for first in firsts:
        active = first.active
        pending: list[tuple[Principal, ...]] = [(first.role,)]
        while pending:
            path = pending.pop()
            found.append((path, active))
            seen = {step.key() for step in path} | {account.key()}
            onward = sorted(by_member.get(path[-1].key(), ()), key=lambda e: e.role, reverse=True)
            for edge in onward:
                if edge.role.key() not in seen:
                    pending.append((*path, edge.role))
    return found


def _row(grantee: str, grant: Held, path: tuple[Principal, ...], active: bool | None) -> GrantRow:
    return GrantRow(
        grantee=grantee,
        kind=grant.kind,
        privilege=grant.privilege,
        owner=grant.owner,
        name=grant.name,
        object_type=grant.object_type,
        column=grant.column,
        path=tuple(str(role) for role in path),
        first_role_default=active if path else None,
        grantable=grant.grantable,
        level=grant.level,
    )
