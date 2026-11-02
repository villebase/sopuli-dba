"""What the tool account on a MySQL server holds, needs and should not hold.
Tier 0.

``02-mysql-privileges.md`` §2 says what the tool account is granted, and §3
what it must not hold. The audit reads the grants that
:mod:`~sopuli.driver.mysql.grants` reads, with every role expanded, so it needs
no grant of its own. It reports and never refuses: over-granting warns (P5).
``SYSTEM_USER`` never reaches it: the scope refuses such an account first.

**Everything outside §2 is over-granted.** The tool account needs
``CREATE USER`` and ``SELECT`` on seven columns of ``mysql.user``, and nothing
else. So the audit has no list of dangerous privileges to keep current as
MySQL adds dynamic ones: any privilege it does not need is reported, also one
that comes through a role. §3 explains the ones that matter most.
"""

from __future__ import annotations

from collections.abc import Iterable

from sopuli.driver.mysql.grants import ALL_PRIVILEGES, GLOBAL, Cursor, Grant, Grants
from sopuli.driver.mysql.grants import read as read_grants
from sopuli.driver.protocol import PrivilegeAudit

DOCUMENT = "02-mysql-privileges.md"

CREATE_USER = "CREATE USER"
#: ``USAGE`` is "no privilege": every account has it.
USAGE = "USAGE"
#: The table §2's column grant is on, as the parser spells it.
USER_TABLE = "mysql.user"

#: §2's columns of ``mysql.user``, as ``SHOW GRANTS`` spells them. MySQL
#: compares column names without case, and so does the audit.
COLUMNS = (
    "User",
    "Host",
    "plugin",
    "account_locked",
    "password_expired",
    "password_last_changed",
    "password_lifetime",
)

#: The account the session runs as, for the hint.
SELF = "select current_user()"

#: Every role the tool account reaches, through any chain of grants, default
#: or not, mandatory included (``07_own_grants_probe.py``).
ALL_ROLES = (
    "select distinct ROLE_NAME, ROLE_HOST from information_schema.APPLICABLE_ROLES "
    "order by ROLE_NAME, ROLE_HOST"
)

OVER_GRANTED_REMEDY = (
    "revoke each over-granted privilege from the tool account, or from the role "
    "that gives it: a privilege a role gives is held as much as one granted "
    "directly. `privileges.roles` in --output json lists every role it reaches"
)


def classify(*, user: str, grants: Grants, roles: Iterable[str]) -> PrivilegeAudit:
    """§2's list against what was read. Pure, and the whole judgement.

    ``grants`` is every grant the tool account holds or can activate, and
    ``roles`` every role it reaches, as ``name@host``.
    """
    held: set[str] = set()
    over: set[str] = set()
    # A line the parser cannot read may be a `partial_revokes` REVOKE that
    # takes `mysql` out of a broader grant. Then only the exact column grant
    # counts as held: the tool cannot tell what the broader one still covers.
    broad = not grants.unparsed
    for grant in grants.grants:
        _sort(grant, held, over, broad=broad)

    no_create_user = CREATE_USER not in held
    columns = [name for name in COLUMNS if _column(name) not in held]
    missing = ([CREATE_USER] if no_create_user else []) + [_column(name) for name in columns]
    unaudited = tuple(
        f"a SHOW GRANTS line the tool cannot read: {line}" for line in grants.unparsed
    )
    return PrivilegeAudit(
        over_granted=tuple(sorted(over)),
        held=tuple(sorted(held)),
        missing=tuple(sorted(missing)),
        roles=tuple(sorted(set(roles))),
        unaudited=unaudited,
        remedies=(OVER_GRANTED_REMEDY,) if over else (),
        hint=_hint(user, create_user=no_create_user, columns=columns),
    )


def _hint(user: str, *, create_user: bool, columns: list[str]) -> str:
    """Where §2 is, and the statements that grant what is missing."""
    hint = f"{DOCUMENT} section 2 has the grants for the tool account `{user}`"
    name, _, host = user.rpartition("@")
    account = f"{_quote(name)}@{_quote(host)}"
    statements = []
    if create_user:
        statements.append(f"GRANT CREATE USER ON *.* TO {account};")
    if columns:
        statements.append(f"GRANT SELECT ({', '.join(columns)}) ON {USER_TABLE} TO {account};")
    return f"{hint}: {' '.join(statements)}" if statements else hint


def _quote(text: str) -> str:
    """``text`` as a MySQL string literal, so a pasted statement names that
    account."""
    return "'" + text.replace("\\", "\\\\").replace("'", "''") + "'"


#: Objects on which a privilege without a column list covers every column of
#: ``mysql.user``. Database and table names are compared exactly: on Linux
#: they are case-sensitive, and the server prints the system schema in lower
#: case.
COVERS_USER_TABLE = (GLOBAL, "mysql.*", USER_TABLE)


def _sort(grant: Grant, held: set[str], over: set[str], *, broad: bool = True) -> None:
    """Put each privilege of one ``SHOW GRANTS`` line in ``held``, ``over``
    or both.

    A broader grant that includes §2's, such as ``SELECT ON mysql.*``, counts
    as held, because the tool can read what it needs, and as over-granted,
    because it reads more. Not where ``broad`` is false: then it is only
    over-granted.

    A role grant gives nothing itself: its roles' privileges are on lines of
    their own, because the read names every role in ``USING``. Its ``ADMIN
    OPTION`` lets the tool account grant the role to others, so it is
    over-granted.
    """
    if grant.on is None:
        if grant.admin_option:
            over.update(f"ADMIN OPTION ON {role}" for role in grant.roles)
        return
    on = _object(grant)
    if grant.grant_option:
        over.add(f"GRANT OPTION ON {on}")
    for privilege in grant.privileges:
        if privilege.name == USAGE:
            continue
        if grant.on == GLOBAL and privilege.name == CREATE_USER:
            held.add(CREATE_USER)
            continue
        if grant.on == USER_TABLE and privilege.name == "SELECT" and privilege.columns:
            for column in privilege.columns:
                needed = _needed_column(column)
                if needed is None:
                    over.add(f"SELECT ({column}) ON {USER_TABLE}")
                else:
                    held.add(_column(needed))
            continue
        if grant.on == GLOBAL and privilege.name == ALL_PRIVILEGES:
            held.add(CREATE_USER)
        if (
            broad
            and grant.on in COVERS_USER_TABLE
            and privilege.name in ("SELECT", ALL_PRIVILEGES)
            and not privilege.columns
        ):
            held.update(_column(name) for name in COLUMNS)
        columns = f" ({', '.join(privilege.columns)})" if privilege.columns else ""
        over.add(f"{privilege.name}{columns} ON {on}")


def _object(grant: Grant) -> str:
    """The object as a reader can name it again. A proxy grant is on an
    account, and an empty user or host, as in the anonymous ``''@''``, is
    written as ``''``."""
    if grant.on is None or grant.names() != frozenset({"PROXY"}):
        return grant.on or ""
    name, _, host = grant.on.rpartition("@")
    empty = "''"
    return f"{name or empty}@{host or empty}"


def _needed_column(column: str) -> str | None:
    """§2's spelling of ``column``, or ``None`` where §2 does not grant it."""
    for name in COLUMNS:
        if name.lower() == column.lower():
            return name
    return None


def _column(name: str) -> str:
    return f"SELECT ({name}) ON {USER_TABLE}"


def audit(cursor: Cursor) -> PrivilegeAudit:
    """Read the tool account's grants and roles, and classify them.

    Four reads, none needing a grant: the account's name, its own roles and
    its grants with every role expanded (:func:`~sopuli.driver.mysql.grants.read`),
    and every role it reaches.
    """
    cursor.execute(SELF)
    user = str(cursor.fetchone()[0])
    grants = read_grants(cursor)
    cursor.execute(ALL_ROLES)
    roles = [f"{name}@{host}" for name, host in cursor.fetchall()]
    return classify(user=user, grants=grants, roles=roles)
