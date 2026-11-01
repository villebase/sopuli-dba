"""What a MySQL session finds when it looks at itself. Tier 0.

Two reads, both open to any account that can log in: the server's version and
read-only settings, and the session's own TLS version. Nothing here branches on
the server's version (invariant 3); it is read to report it, and to tell MySQL
from MariaDB, which answers the same protocol and gets a driver of its own
(#1202, decision 2).

**No capability is reported.** Each one in P1's table names something a driver
does on this target, and this build of the MySQL driver does none of them yet.
Connecting proves none of them either.
"""

from __future__ import annotations

from typing import Any, Protocol

from sopuli.driver.protocol import (
    ENCRYPTION_NONE,
    ENCRYPTION_TLS,
    SERVER,
    DriverError,
    Encryption,
    Scope,
)
from sopuli.exit_codes import ExitCode

#: ``scope.open_mode``, in the words P1 uses for an Oracle database.
READ_WRITE = "READ WRITE"
READ_ONLY = "READ ONLY"

#: The server's version and the three settings that stop the tool account
#: writing. `read_only` stops every account without `CONNECTION_ADMIN`, which
#: the tool account does not hold; `super_read_only` stops every account; a
#: session's `transaction_read_only` stops that session. Readable by any account.
SESSION_FACTS = (
    "select version(), @@global.read_only, @@global.super_read_only, "
    "@@session.transaction_read_only"
)

#: The session's TLS version, or an empty string on a plain connection. Any
#: account reads its own session status. Measured on 8.4.13 with PyMySQL 1.2.3:
#: `TLSv1.3` under `REQUIRED` and `PREFERRED`.
TLS_VERSION = "show session status like 'Ssl_version'"

#: The connection reaches the server over TCP: `dsn:` is always host:port.
TCP = "tcp"

UNENCRYPTED_HINT = "set `mysql.ssl_mode` to VERIFY_IDENTITY, and give the server a certificate"


class Cursor(Protocol):
    """The part of a PyMySQL cursor this module uses."""

    def execute(self, query: Any, args: Any = None, /) -> Any: ...

    def fetchone(self) -> Any: ...


class NotMysqlError(DriverError):
    """A `type: mysql` target reached a server that is not MySQL.

    MariaDB speaks MySQL's protocol and answers to the same client, and it
    stores and changes passwords differently (#1220), so it gets a driver of
    its own. ``config``, exit 9: the file names the wrong type.
    """

    category = "config"
    exit_code = ExitCode.CONFIG_INVALID


def encryption_of(row: Any) -> Encryption:
    """The session's encryption, from its ``Ssl_version`` status row.

    ``protocol`` is the transport, ``tcp``: TLS runs inside the TCP connection.
    """
    version = "" if row is None else str(row[1] or "")
    if version:
        return Encryption(method=ENCRYPTION_TLS, protocol=TCP)
    return Encryption(method=ENCRYPTION_NONE, protocol=TCP, hint=UNENCRYPTED_HINT)


def observe(cursor: Cursor, *, target: str) -> Scope:
    """This session's scope: a server, whether it takes writes, and how the
    session is encrypted.

    ``db_version`` is the part of ``VERSION()`` before the first ``-``, so
    ``8.0.46-log`` is reported as ``8.0.46``. A server whose version names
    MariaDB is refused (:class:`NotMysqlError`).
    """
    cursor.execute(SESSION_FACTS)
    version, read_only, super_read_only, transaction_read_only = cursor.fetchone()
    version = str(version)
    if "mariadb" in version.lower():
        raise NotMysqlError(
            f'target "{target}" declares type "mysql", and the server is MariaDB ({version})',
            hint=(
                "MariaDB gets a driver of its own, which is not written yet (#1202). "
                "It stores and changes passwords differently from MySQL"
            ),
        )
    writable = not (read_only or super_read_only or transaction_read_only)
    open_mode = READ_WRITE if writable else READ_ONLY

    cursor.execute(TLS_VERSION)
    encryption = encryption_of(cursor.fetchone())

    return Scope(
        type=SERVER,
        db_version=version.split("-")[0],
        open_mode=open_mode,
        read_write=writable,
        encryption=encryption,
    )


class ReadOnlyTargetError(DriverError):
    """A write was about to start on a session that cannot take one: exit 1,
    category ``database``, raised before anything is sent."""


def require_read_write(scope: Scope, *, target: str) -> None:
    """Refuse a write where :func:`observe` found the session read-only."""
    if scope.read_write is not False:
        return
    raise ReadOnlyTargetError(
        f'target "{target}" is {scope.open_mode} and cannot be written to',
        hint=(
            "the server has read_only or super_read_only on, as a replica does, or the "
            "session's transaction_read_only is on. Point the target at the writable "
            "primary"
        ),
    )
