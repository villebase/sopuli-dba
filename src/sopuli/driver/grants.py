"""Every privilege an account holds, as a report reads it (UC-5).

Product-neutral types. A session that serves the privilege report implements
:class:`PrivilegeSurvey`, and the registry lists ``report.privileges`` for its
product. The
:class:`~sopuli.driver.protocol.Session` protocol does not list it, so the
report checks for it per target (#1480).

A privilege can reach an account by several paths: granted directly, and
through one or more roles. The driver returns **one row per path**, as the
dictionary does (``02-oracle-privileges.md`` §2). Merging the rows per
privilege is the report's job, not the driver's.

**Four parts on every product**, each in that product's own terms (#1411,
question 4). ``system`` holds what applies to the whole database or cluster,
``schemas`` what applies to one schema or database, ``objects`` what applies
to one object, and ``columns`` what applies to one column. Where a product has
more than one level inside a part, such as MySQL's static and dynamic global
privileges, each row names its level in :attr:`GrantRow.level`, in the
product's own words. Oracle's parts each hold one level, so its rows have
none.

A part the target cannot read is ``None``, never ``()``. An empty tuple says
the account holds no such privilege; ``None`` says nobody could look.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

#: :attr:`GrantRow.kind` for a system privilege, such as ``CREATE SESSION``.
SYSTEM = "system"
#: :attr:`GrantRow.kind` for a privilege on a whole object.
OBJECT = "object"
#: :attr:`GrantRow.kind` for a privilege on one column of a table or view.
COLUMN = "column"
#: :attr:`GrantRow.kind` for a system privilege on one schema, such as Oracle
#: 23ai's ``SELECT ANY TABLE ON SCHEMA``. :attr:`GrantRow.owner` is the schema.
SCHEMA = "schema"


@dataclass(frozen=True)
class GrantRow:
    """One path by which one privilege reaches ``grantee``.

    ``path`` lists the roles from the grantee down to the role that holds the
    privilege, and is ``()`` for a direct grant. ``first_role_default`` is
    whether the privilege is active without ``SET ROLE``: on Oracle and MySQL,
    whether ``path[0]`` is active at login, as a default role of the grantee or
    any role where the product activates every role at login, as MySQL's
    ``activate_all_roles_on_login`` does; on PostgreSQL, whether every grant on
    the path inherits. It is ``None`` for a direct grant, and for a path the
    target cannot say this for, such as one whose default roles were not read.
    ``grantable`` is whether the holder may grant it on: ``GRANTABLE`` for an
    object or column privilege, ``ADMIN_OPTION`` for a system or schema
    privilege, on the last grant of the path. ``level`` is the product's own
    word for the level inside ``kind``'s part, such as ``global dynamic`` on
    MySQL, and ``None`` where the part has one level, as each of Oracle's does.
    """

    grantee: str
    kind: str
    privilege: str
    owner: str | None
    name: str | None
    object_type: str | None
    column: str | None
    path: tuple[str, ...]
    first_role_default: bool | None
    grantable: bool
    level: str | None = None


@dataclass(frozen=True)
class RoleGrant:
    """One role granted directly to ``grantee``.

    ``authentication`` is the role's own: ``NONE`` for an ordinary role, or
    the database's word for one that needs more to enable, such as Oracle's
    ``PASSWORD`` and ``APPLICATION``.

    ``default_role`` is whether the role's privileges are active without
    ``SET ROLE``: Oracle's and MySQL's default role, and PostgreSQL's
    ``INHERIT`` option. ``default_role_checked`` is ``False`` where whether it
    is a default role could not be read, such as on MySQL without ``SELECT`` on
    ``mysql.default_roles``; ``default_role`` is then ``False`` and says
    nothing. ``set_option`` is PostgreSQL's ``SET`` option, whether the member
    may ``SET ROLE`` to it, and ``None`` on a product that has no such option.
    """

    grantee: str
    role: str
    admin_option: bool
    default_role: bool
    authentication: str
    default_role_checked: bool = True
    set_option: bool | None = None


@dataclass(frozen=True)
class GrantSurvey:
    """What the target says about the surveyed accounts' privileges.

    ``system``, ``objects``, ``columns`` and ``schemas`` are ``None`` where the
    view that holds them cannot be read, and ``unreadable`` then holds one
    reason for each, naming the grant that would make it readable. ``schemas``
    is ``()`` on a database that has no schema privileges. ``roles`` is always
    read, because the baseline grants cover it.
    """

    roles: tuple[RoleGrant, ...]
    system: tuple[GrantRow, ...] | None
    objects: tuple[GrantRow, ...] | None
    columns: tuple[GrantRow, ...] | None
    schemas: tuple[GrantRow, ...] | None
    unreadable: tuple[str, ...] = ()


@runtime_checkable
class PrivilegeViewState(Protocol):
    """A privilege survey that reads an optional view a DBA creates: MariaDB's
    ``sopuli.global_privileges`` (#1483)."""

    def privilege_view_broken(self) -> str | None:
        """What is wrong with a view that exists and cannot be used, for
        ``SOPULI-W074``; ``None`` where it is absent or was read."""
        ...


@runtime_checkable
class PrivilegeSurvey(Protocol):
    """A session that can survey accounts' privileges, for `report privileges`.

    ``accounts`` are the names the accounts survey read, exactly as it spelled
    them. ``public`` asks for the grants to everyone too, once, under the
    product's name for them. A part the session could not read is ``None``,
    with one reason in :attr:`GrantSurvey.unreadable` naming what would make it
    readable. So is a scope the session could not reach at all, such as another
    database of a PostgreSQL cluster: the reason names it, and the report shows
    it as not checked on that target.
    """

    def survey_privileges(self, accounts: Sequence[str], *, public: bool) -> GrantSurvey:
        """Every grant ``accounts`` hold, one row per path."""
        ...
