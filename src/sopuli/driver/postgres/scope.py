"""What a PostgreSQL session finds when it looks at itself. Tier 0.

Two reads, both open to any role that can log in: the session's settings,
recovery state and role, and its own row in ``pg_stat_ssl``. Nothing here
branches on the server's version (invariant 3); the version is read only to
report it.

**A superuser is refused here**, in the first read every command makes, so no
command acts as one. ``02-postgres-privileges.md`` §1 has the reason. This is
the PostgreSQL form of the Oracle rule that the tool never connects ``AS
SYSDBA``.

**No capability is reported.** Each one in P1's table names something a driver
does on this target, and this build of the PostgreSQL driver does none of them
yet. Connecting proves none of them either.
"""

from __future__ import annotations

from typing import Any, Protocol

from sopuli.driver.protocol import (
    CLUSTER,
    ENCRYPTION_NONE,
    ENCRYPTION_TLS,
    UNKNOWN,
    DriverError,
    Encryption,
    Scope,
)
from sopuli.exit_codes import ExitCode

#: ``error.code`` for a tool account that is a superuser.
SUPERUSER_REFUSED = "SOPULI-20007"

#: ``scope.open_mode``, in the words P1 uses for an Oracle database, and a third
#: for a standby, in PostgreSQL's own word for it.
READ_WRITE = "READ WRITE"
READ_ONLY = "READ ONLY"
IN_RECOVERY = "IN RECOVERY"

#: The last three columns are the role that logged in (``session_user``),
#: whether it or ``current_user`` is a superuser, and the first superuser role
#: either is a member of, through any chain of grants. Both are asked because a
#: role's ``SET role`` default makes ``current_user`` another role at login,
#: and ``RESET ROLE`` takes the session back. A member can ``SET ROLE`` to a
#: superuser role, or holds its privileges, so it is refused as a superuser is.
#: ``MEMBER`` counts a grant whatever its options, which refuses more rather
#: than less.
SESSION_FACTS = (
    "select current_setting('server_version'), pg_is_in_recovery(), "
    "current_setting('default_transaction_read_only'), session_user, "
    "exists (select 1 from pg_roles where rolsuper "
    "and rolname in (session_user, current_user)), "
    "(select min(r.rolname) from pg_roles r where r.rolsuper "
    "and r.rolname not in (session_user, current_user) "
    "and (pg_has_role(session_user, r.oid, 'MEMBER') "
    "or pg_has_role(current_user, r.oid, 'MEMBER')))"
)

#: The session's own row. ``pg_stat_ssl`` shows every role its own backend.
SSL_ROW = "select ssl from pg_stat_ssl where pid = pg_backend_pid()"

#: The cluster's identity. ``EXECUTE`` on the function is granted to ``PUBLIC``
#: by default (``pg-system-identifier`` in ``docs/README.md``).
SYSTEM_IDENTIFIER = "select system_identifier from pg_control_system()"

#: The connection reaches the server over TCP: `dsn:` is always host:port, and
#: the config refuses a socket directory as the host.
TCP = "tcp"

UNENCRYPTED_HINT = (
    "set `postgres.sslmode` to verify-full, and give the server a certificate (`ssl = on`)"
)
NO_ROW_HINT = "pg_stat_ssl has no row for this session's backend"


class Cursor(Protocol):
    """The part of a psycopg cursor this module uses."""

    def execute(self, query: Any, params: Any = None, /) -> Any: ...

    def fetchone(self) -> Any: ...


def encryption_of(row: Any) -> Encryption:
    """The session's encryption, from its ``pg_stat_ssl`` row.

    ``protocol`` is the transport, ``tcp``. TLS runs inside the TCP connection,
    so there is no second transport name as Oracle's ``tcps``. ``algorithm`` is
    for a product's own encryption, which PostgreSQL has none of.
    """
    if row is None:
        return Encryption(method=UNKNOWN, protocol=TCP, hint=NO_ROW_HINT)
    if row[0]:
        return Encryption(method=ENCRYPTION_TLS, protocol=TCP)
    return Encryption(method=ENCRYPTION_NONE, protocol=TCP, hint=UNENCRYPTED_HINT)


class SuperuserError(DriverError):
    """The target's admin is a superuser, and the tool connects only as an
    ordinary role.

    ``config``, exit 9: the fix is in the config, which names another role.
    """

    category = "config"
    exit_code = ExitCode.CONFIG_INVALID

    def __init__(self, target: str, user: str, *, through: str | None = None) -> None:
        what = f'a member of the superuser role "{through}"' if through else "a superuser"
        super().__init__(
            f'target "{target}" connects as "{user}", {what}, and sopuli does '
            "not run as a superuser",
            hint=(
                "point the target's admin at a role with CREATEROLE that is not a "
                "superuser; 02-postgres-privileges.md section 2 has its grants"
            ),
            code=SUPERUSER_REFUSED,
        )


def observe(cursor: Cursor, *, target: str) -> Scope:
    """This session's scope: a cluster, whether it takes writes, and how it is
    encrypted. Raises :class:`SuperuserError` for a superuser, or a member of a
    superuser role, before the second read.

    ``read_write`` is false on a standby, where ``pg_is_in_recovery()`` is true,
    and where ``default_transaction_read_only`` is on. The second can be set for
    one role or one database, and a write then fails with ``25006`` as on a
    standby.

    ``db_version`` is the first word of ``server_version``. A packaged build
    adds its own after it, such as ``16.4 (Debian 16.4-1.pgdg120+1)``.
    """
    cursor.execute(SESSION_FACTS)
    version, in_recovery, read_only, user, superuser, superuser_role = cursor.fetchone()
    if superuser:
        raise SuperuserError(target, str(user))
    if superuser_role is not None:
        raise SuperuserError(target, str(user), through=str(superuser_role))
    if in_recovery:
        open_mode = IN_RECOVERY
    elif read_only == "on":
        open_mode = READ_ONLY
    else:
        open_mode = READ_WRITE

    cursor.execute(SSL_ROW)
    encryption = encryption_of(cursor.fetchone())

    return Scope(
        type=CLUSTER,
        db_version=str(version).split()[0],
        open_mode=open_mode,
        read_write=open_mode == READ_WRITE,
        encryption=encryption,
    )


class ReadOnlyTargetError(DriverError):
    """A write was about to start on a session that cannot take one.

    The PostgreSQL :class:`sopuli.driver.oracle.capabilities.ReadOnlyTargetError`:
    exit 1, category ``database``, raised before anything is sent.
    """


def require_read_write(scope: Scope, *, target: str) -> None:
    """Refuse a write where :func:`observe` found the session read-only."""
    if scope.read_write is not False:
        return
    if scope.open_mode == IN_RECOVERY:
        hint = "this cluster is a standby; point the target at the primary"
    else:
        hint = (
            "default_transaction_read_only is on for this role or database; "
            "the tool's role needs it off"
        )
    raise ReadOnlyTargetError(
        f'target "{target}" is {scope.open_mode} and cannot be written to', hint=hint
    )
