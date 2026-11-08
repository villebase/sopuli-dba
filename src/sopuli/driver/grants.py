"""Every privilege an account holds, as a report reads it (UC-5).

Product-neutral types. Only Oracle fills them, through
``OracleSession.survey_privileges``, which a caller finds with ``getattr``: the
:class:`~sopuli.driver.protocol.Session` protocol does not list it.

A privilege can reach an account by several paths: granted directly, and
through one or more roles. The driver returns **one row per path**, as the
dictionary does (``02-oracle-privileges.md`` §2). Merging the rows per
privilege is the report's job, not the driver's.

A part the target cannot read is ``None``, never ``()``. An empty tuple says
the account holds no such privilege; ``None`` says nobody could look.
"""

from __future__ import annotations

from dataclasses import dataclass

#: :attr:`GrantRow.kind` for a system privilege, such as ``CREATE SESSION``.
SYSTEM = "system"
#: :attr:`GrantRow.kind` for a privilege on a whole object.
OBJECT = "object"
#: :attr:`GrantRow.kind` for a privilege on one column of a table or view.
COLUMN = "column"


@dataclass(frozen=True)
class GrantRow:
    """One path by which one privilege reaches ``grantee``.

    ``path`` lists the roles from the grantee down to the role that holds the
    privilege, and is ``()`` for a direct grant. ``first_role_default`` is
    whether ``path[0]`` is a default role of the grantee, so the privilege is
    active without ``SET ROLE``; it is ``None`` for a direct grant.
    ``grantable`` is whether the holder may grant it on: ``GRANTABLE`` for an
    object or column privilege, ``ADMIN_OPTION`` for a system privilege, on
    the last grant of the path.
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


@dataclass(frozen=True)
class RoleGrant:
    """One role granted directly to ``grantee``.

    ``authentication`` is the role's own: ``NONE`` for an ordinary role, or
    the database's word for one that needs more to enable, such as Oracle's
    ``PASSWORD`` and ``APPLICATION``.
    """

    grantee: str
    role: str
    admin_option: bool
    default_role: bool
    authentication: str


@dataclass(frozen=True)
class GrantSurvey:
    """What the target says about the surveyed accounts' privileges.

    ``system``, ``objects`` and ``columns`` are ``None`` where the view that
    holds them cannot be read, and ``unreadable`` then holds one reason for
    each, naming the grant that would make it readable. ``roles`` is always
    read, because the baseline grants cover it.
    """

    roles: tuple[RoleGrant, ...]
    system: tuple[GrantRow, ...] | None
    objects: tuple[GrantRow, ...] | None
    columns: tuple[GrantRow, ...] | None
    unreadable: tuple[str, ...] = ()
