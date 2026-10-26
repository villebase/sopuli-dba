"""One PostgreSQL role as the cluster describes it. Tier 0.

``describe_user`` on PostgreSQL. One statement over ``pg_roles``, which any role
can read, so describing a role needs no grant. The guardrails read the result
(``02-oracle-privileges.md`` §4, with the PostgreSQL facts in
``02-postgres-privileges.md`` §5): this module reports facts and refuses nothing.

**How the facts map onto** :class:`~sopuli.driver.protocol.UserState`:

==============================  ===============================================
field                           PostgreSQL
==============================  ===============================================
``superuser``                   ``rolsuper`` (check 6)
``vendor_maintained``           an oid below 16384, ``FirstNormalObjectId``:
                                the bootstrap superuser and every ``pg_*`` role
                                (check 2)
``admin_roles``                 ``REPLICATION``, ``BYPASSRLS``, ``CREATEROLE``,
                                and membership in a role of
                                :data:`GUARDED_ROLES` (check 4)
``session_account``             the role is ``session_user`` (check 7)
``password_file_member``        ``False``: PostgreSQL has no password file
``locked``                      ``rolcanlogin`` is false (``NOLOGIN``)
``expired``                     ``rolvaliduntil`` is in the past
``password_expires_at``         ``rolvaliduntil``, where it is finite
``password_changed_at``         ``None``: PostgreSQL does not record it
==============================  ===============================================

**``NOLOGIN`` is reported as locked**, so `check` does not try a login that
cannot succeed and `apply` does not change a password it cannot confirm. It is
not a lock in Oracle's sense, and nothing here unlocks it.

**A past ``VALID UNTIL`` is reported as expired.** The role cannot log in with
any password until somebody moves the date, so a new password does not fix it.

**The name is matched by** ``upper()``, as the config compares account names
(invariant 5), and the role keeps the spelling ``pg_roles`` gives back: that is
the only spelling that may reach a statement. Two roles whose names differ only
in case are refused rather than guessed between.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol

from sopuli.driver.protocol import DriverError, UserState

#: The built-in roles whose members guardrail 4 refuses (design §5.6). Each one
#: reaches past the database: server files, server programs, every table's data,
#: or other sessions. ``pg_monitor`` and ``pg_read_all_stats`` are not here: an
#: application account in them is ordinary, unlike the tool account, which
#: :data:`~sopuli.driver.postgres.privileges.FORBIDDEN_ROLES` covers.
GUARDED_ROLES = frozenset(
    {
        "pg_execute_server_program",
        "pg_read_server_files",
        "pg_write_server_files",
        "pg_read_all_data",
        "pg_write_all_data",
        "pg_signal_backend",
    }
)

#: The attributes guardrail 4 refuses, spelled as ``ALTER ROLE`` spells them.
GUARDED_ATTRIBUTES = ("REPLICATION", "BYPASSRLS", "CREATEROLE")

#: ``FirstNormalObjectId``: every oid below it was made by ``initdb``.
FIRST_NORMAL_OID = 16384

#: Why :attr:`UserState.password_changed_at` is always ``None`` here.
NO_CHANGE_DATE = "PostgreSQL does not record when a role's password was changed"

#: Status words, for `creds status` and the messages that quote the status.
OPEN = "OPEN"
NOLOGIN = "NOLOGIN"
EXPIRED = "EXPIRED"

#: One row per role whose name matches by ``upper()``. ``isfinite`` keeps
#: ``infinity`` out of the date column, which Python's ``datetime`` cannot hold.
#: ``pg_has_role(..., 'MEMBER')`` follows every chain of grants, whatever their
#: ``INHERIT`` and ``SET`` options, because a member can reach a role's powers
#: either way. It is true of every role for a superuser, which check 6 refuses
#: anyway.
ROLE_QUERY = (
    "select r.rolname, r.rolsuper, r.rolcanlogin, r.rolreplication, r.rolbypassrls, "
    f"r.rolcreaterole, r.oid < {FIRST_NORMAL_OID}, r.rolname = session_user, "
    "case when isfinite(r.rolvaliduntil) then r.rolvaliduntil end, "
    "coalesce(r.rolvaliduntil < now(), false), "
    "array(select b.rolname from pg_roles b "
    "where b.oid <> r.oid and pg_has_role(r.oid, b.oid, 'MEMBER') order by b.rolname) "
    "from pg_roles r where upper(r.rolname) = upper(%s)"
)


class Cursor(Protocol):
    """The part of a psycopg cursor this module uses."""

    def execute(self, query: Any, params: Any = None, /) -> Any: ...

    def fetchall(self) -> Any: ...


class AmbiguousRoleError(DriverError):
    """Two roles answer to one declared name, differing only in case."""

    category = "config"


def describe(cursor: Cursor, account: str) -> UserState | None:
    """The role ``account`` names, or ``None`` if there is none.

    ``None`` is UC-1's ``ACCOUNT_MISSING``, as on Oracle: the tool does not
    create roles.
    """
    cursor.execute(ROLE_QUERY, (account,))
    rows = cursor.fetchall()
    if not rows:
        return None
    if len(rows) > 1:
        names = ", ".join(sorted(f'"{row[0]}"' for row in rows))
        raise AmbiguousRoleError(
            f'"{account}" matches more than one role: {names}',
            hint=(
                "the config compares account names by upper(), so it cannot tell these "
                "apart; rename one of the roles, or leave both out of the config"
            ),
        )
    return state_of(rows[0])


def state_of(row: tuple[Any, ...]) -> UserState:
    """One :data:`ROLE_QUERY` row as a :class:`UserState`."""
    (
        name,
        superuser,
        can_login,
        replication,
        bypassrls,
        createrole,
        built_in,
        session_account,
        valid_until,
        expired,
        member_of,
    ) = row
    attributes = dict(zip(GUARDED_ATTRIBUTES, (replication, bypassrls, createrole), strict=True))
    held = frozenset(str(role) for role in member_of or ())
    return UserState(
        name=str(name),
        status=_status(can_login=bool(can_login), expired=bool(expired)),
        locked=not can_login,
        expired=bool(expired),
        password_expires_at=valid_until if isinstance(valid_until, datetime) else None,
        password_changed_unknown=NO_CHANGE_DATE,
        vendor_maintained=bool(built_in),
        password_file_member=False,
        roles=frozenset(role.upper() for role in held),
        admin_roles=frozenset(word for word, has in attributes.items() if has)
        | frozenset(role.upper() for role in held & GUARDED_ROLES),
        superuser=bool(superuser),
        session_account=bool(session_account),
    )


def _status(*, can_login: bool, expired: bool) -> str:
    """``NOLOGIN`` before ``EXPIRED``: a role that cannot log in is that first,
    whatever its date says."""
    if not can_login:
        return NOLOGIN
    if expired:
        return EXPIRED
    return OPEN
