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
``reserved_by``                 ``supautils.reserved_roles`` names the role
                                (check 8)
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
``-infinity`` is expired with no date, because no ``datetime`` holds it: the
status still says ``EXPIRED``.

**A role in ``supautils.reserved_roles`` is reserved.** supautils is a
library Supabase preloads, so it is not in ``pg_extension``. It refuses any
change to a role on that list by anyone but a superuser, and the tool never
connects as one. Reading the setting is the capability probe: any role can
read it, and it is ``NULL`` on a server where nothing defines it (invariant 3).
An entry may end in ``*``, which lets the privileged role change the role's
settings. The role is reserved either way, so the ``*`` is dropped. The list is
read as supautils reads it (:func:`reserved_names`): a list of identifiers, as
``search_path`` is, so an unquoted name is lower-cased, and the result is
compared exactly.

**The name is matched by Python's** ``str.upper()``, the comparison the config
uses (invariant 5), and the role keeps the spelling ``pg_roles`` gives back:
that is the only spelling that may reach a statement. The server's ``upper()``
follows the database's ``LC_CTYPE`` and can disagree on a non-ASCII name, so
the query returns the ASCII candidates by the server's ``upper()`` and every
non-ASCII name besides, and the match is made here. Two roles that match one
declared name are refused rather than guessed between.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol

from sopuli.driver.protocol import DriverError, UserState
from sopuli.exit_codes import ExitCode

#: The built-in roles whose members guardrail 4 refuses
#: (``02-postgres-privileges.md`` §5). Each one
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

#: The supautils setting that lists the roles only a superuser may change.
RESERVED_ROLES = "supautils.reserved_roles"

#: Why :attr:`UserState.password_changed_at` is always ``None`` here.
NO_CHANGE_DATE = "PostgreSQL does not record when a role's password was changed"

#: Status words, for `creds status` and the messages that quote the status.
OPEN = "OPEN"
NOLOGIN = "NOLOGIN"
EXPIRED = "EXPIRED"

#: One row per candidate role: an ASCII name that matches by the server's
#: ``upper()``, and every non-ASCII name, which :func:`describe` matches itself
#: (module docstring). A multibyte character makes ``octet_length`` and
#: ``char_length`` differ. ``isfinite`` keeps ``infinity`` and ``-infinity``
#: out of the date column, which Python's ``datetime`` cannot hold.
#:
#: The memberships walk ``pg_auth_members`` up from the role, through every
#: chain of grants whatever their ``INHERIT`` and ``SET`` options, because a
#: member can reach a role's powers either way. Walking the grants that exist,
#: rather than asking ``pg_has_role`` of every role in the cluster, costs the
#: role's own memberships, and does not report a superuser as a member of
#: everything.
#:
#: The last column is :data:`RESERVED_ROLES`, ``missing_ok`` so that a server
#: without supautils gives ``NULL`` rather than an error.
ROLE_QUERY = (
    "select r.rolname, r.rolsuper, r.rolcanlogin, r.rolreplication, r.rolbypassrls, "
    f"r.rolcreaterole, r.oid < {FIRST_NORMAL_OID}, r.rolname = session_user, "
    "case when isfinite(r.rolvaliduntil) then r.rolvaliduntil end, "
    "coalesce(r.rolvaliduntil < now(), false), "
    "array(with recursive held(oid) as ("
    "select m.roleid from pg_auth_members m where m.member = r.oid "
    "union select m.roleid from pg_auth_members m join held on m.member = held.oid"
    ") select b.rolname from held join pg_roles b on b.oid = held.oid order by b.rolname), "
    f"current_setting('{RESERVED_ROLES}', true) "
    "from pg_roles r where upper(r.rolname) = upper(%s) "
    "or octet_length(r.rolname) <> char_length(r.rolname)"
)


class Cursor(Protocol):
    """The part of a psycopg cursor this module uses."""

    def execute(self, query: Any, params: Any = None, /) -> Any: ...

    def fetchall(self) -> Any: ...


class AmbiguousRoleError(DriverError):
    """Two roles answer to one declared name, differing only in case.

    ``config`` and exit 9, as every configuration error a driver raises: the
    fix is in the config or the cluster, and running again changes nothing.
    """

    category = "config"
    exit_code = ExitCode.CONFIG_INVALID


def describe(cursor: Cursor, account: str, *, target: str) -> UserState | None:
    """The role ``account`` names on ``target``, or ``None`` if there is none.

    ``None`` is UC-1's ``ACCOUNT_MISSING``, as on Oracle: the tool does not
    create roles. ``target`` is for the message only.
    """
    cursor.execute(ROLE_QUERY, (account,))
    folded = account.upper()
    rows = [row for row in cursor.fetchall() if str(row[0]).upper() == folded]
    if not rows:
        return None
    if len(rows) > 1:
        names = ", ".join(sorted(f'"{row[0]}"' for row in rows))
        raise AmbiguousRoleError(
            f'target "{target}": "{account}" matches more than one role: {names}',
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
        reserved_roles,
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
        reserved_by=RESERVED_ROLES if str(name) in reserved_names(reserved_roles) else None,
    )


def reserved_names(setting: str | None) -> frozenset[str]:
    """The role names in a ``supautils.reserved_roles`` value, read as
    supautils reads them.

    supautils splits the value with PostgreSQL's ``SplitIdentifierString``,
    removes one trailing ``*`` from each name, and compares the result with
    ``strcmp``. This follows ``SplitIdentifierString``: spaces around a name are
    dropped, a name in double quotes keeps its case and ``""`` inside it is one
    quote, and an unquoted name is lower-cased. Only ``A`` to ``Z`` are
    lower-cased, as the server does in a multibyte encoding such as UTF-8. Each
    name is cut to 63 bytes. A syntax error stops the split, and supautils keeps
    the names read before it. ``None`` and ``''`` reserve nothing.
    """
    names: list[str] = []
    text = setting or ""
    at = _skip_spaces(text, 0)
    while at < len(text):
        if text[at] == '"':
            name, at = _quoted(text, at)
            if name is None:
                break
        else:
            end = at
            while end < len(text) and text[end] != "," and text[end] not in _SPACES:
                end += 1
            if end == at:
                break
            name, at = _ascii_lower(text[at:end]), end
        at = _skip_spaces(text, at)
        if at < len(text) and text[at] != ",":
            break
        names.append(_without_wildcard(_truncate(name)))
        if at == len(text):
            break
        at = _skip_spaces(text, at + 1)
        if at == len(text):
            break
    return frozenset(names)


#: ``NAMEDATALEN`` less one: the longest name the server keeps, in bytes.
_NAME_BYTES = 63

#: What the server's ``scanner_isspace`` counts as a space.
_SPACES = " \t\n\r\f"


def _skip_spaces(text: str, at: int) -> int:
    while at < len(text) and text[at] in _SPACES:
        at += 1
    return at


def _without_wildcard(name: str) -> str:
    """supautils' ``remove_ending_wildcard``: one trailing ``*`` goes, except
    from a name that is only ``*``."""
    return name[:-1] if len(name.encode("utf-8")) > 1 and name.endswith("*") else name


def _quoted(text: str, at: int) -> tuple[str | None, int]:
    """The name in the double quotes that open at ``at``, and where it ends.
    ``None`` where the quote is not closed."""
    parts: list[str] = []
    start = at + 1
    while True:
        close = text.find('"', start)
        if close == -1:
            return None, len(text)
        parts.append(text[start:close])
        if close + 1 < len(text) and text[close + 1] == '"':
            parts.append('"')
            start = close + 2
            continue
        return "".join(parts), close + 1


def _ascii_lower(name: str) -> str:
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in name)


def _truncate(name: str) -> str:
    """``name`` cut to :data:`_NAME_BYTES` bytes of UTF-8, on a character boundary."""
    encoded = name.encode("utf-8")
    if len(encoded) <= _NAME_BYTES:
        return name
    return encoded[:_NAME_BYTES].decode("utf-8", errors="ignore")


def _status(*, can_login: bool, expired: bool) -> str:
    """``NOLOGIN`` before ``EXPIRED``: a role that cannot log in is that first,
    whatever its date says."""
    if not can_login:
        return NOLOGIN
    if expired:
        return EXPIRED
    return OPEN
