"""What a MySQL session finds when it looks at itself. Tier 0.

Every read is open to any account that can log in: the server's version, the
tool account's own grants (:mod:`~sopuli.driver.mysql.grants`), the read-only
settings, and the session's own TLS version. An account that can use
``SYSTEM_USER`` is refused after the version, before anything else is read
(``02-mysql-privileges.md`` §1). Nothing here branches on
the server's version (invariant 3); it is read to report it, and to tell MySQL
from MariaDB, which answers the same protocol and has a driver of its own
(#1202, decision 2).

**No capability is read here.** The session adds them
(:meth:`~sopuli.driver.mysql.session.MysqlSession.scope`): ``role_lookup``
always, and ``password_rollover`` and ``expire_password`` where the server has
``caching_sha2_password_digest_rounds``.
"""

from __future__ import annotations

from sopuli.driver import protocol
from sopuli.driver.mysql import grants
from sopuli.driver.mysql_family.encryption import read_encryption
from sopuli.driver.protocol import (
    ADMIN_REFUSED,
    SERVER,
    Cursor,
    DriverError,
    Encryption,
    Scope,
)
from sopuli.driver.protocol import ReadOnlyTargetError as ReadOnlyTargetError
from sopuli.exit_codes import ExitCode

#: ``scope.open_mode``, in the words P1 uses for an Oracle database.
READ_WRITE = "READ WRITE"
READ_ONLY = "READ ONLY"

#: The server's version, read alone and first: another product that speaks the
#: protocol may lack the settings below, and is refused by name before they are
#: read. MariaDB 10.11.19 has no `super_read_only` (measured: `1193`).
VERSION = "select version()"

#: The three settings that stop the tool account writing. `read_only` stops
#: every account without `CONNECTION_ADMIN` or `SUPER`, which the tool account
#: holds neither of; `super_read_only` stops every account; a session's
#: `transaction_read_only` stops that session. Readable by any account, on
#: 8.0, 8.4 and 9 (#1202).
READ_ONLY_SETTINGS = (
    "select @@global.read_only, @@global.super_read_only, @@session.transaction_read_only"
)

#: Products that speak MySQL's protocol and are not MySQL, as their
#: ``VERSION()`` names them. MariaDB has a driver of its own (#1202, decision
#: 2). TiDB's version names it, as `8.0.11-TiDB-v7.5.0`, and it is not measured.
OTHER_PRODUCTS = {"mariadb": "MariaDB", "tidb": "TiDB"}


class NotMysqlError(DriverError):
    """A `type: mysql` target reached a server that is not MySQL.

    MariaDB speaks MySQL's protocol and answers to the same client, and it
    stores and changes passwords differently (#1220), so it gets a driver of
    its own. TiDB is refused for the same reason, unmeasured. ``config``, exit
    9: the file names the wrong type.
    """

    category = "config"
    exit_code = ExitCode.CONFIG_INVALID


class SystemUserError(DriverError):
    """The target's admin can use ``SYSTEM_USER``, and the tool does not run
    with it.

    ``SYSTEM_USER`` is what keeps an account with ``CREATE USER`` off root's
    password and the ``mysql.*`` accounts (``05_identity_grants_probe.py``,
    TG1 and TG6). ``config``, exit 9: the fix is in the config, which names
    another account.
    """

    category = "config"
    exit_code = ExitCode.CONFIG_INVALID

    def __init__(self, target: str) -> None:
        super().__init__(
            f'target "{target}" connects as an account that can use SYSTEM_USER, and '
            "sopuli does not run with it",
            hint=(
                "SYSTEM_USER lets the tool change root's password. Revoke it from the "
                "account and from every role granted to it, or point the target's admin "
                "at another account; 02-mysql-privileges.md section 2 has its grants. "
                "SHOW GRANTS FOR CURRENT_USER() USING <each role> shows where it comes from"
            ),
            code=ADMIN_REFUSED,
        )


def refuse_system_user(cursor: Cursor, *, target: str) -> None:
    """Raise :class:`SystemUserError` where the session's account holds
    ``SYSTEM_USER``, itself or through any role granted to it, active or not.

    A role that is not active counts: the account can ``SET ROLE`` to it, as a
    PostgreSQL member of a superuser role can, which is refused too. A
    ``GRANT`` line that cannot be parsed and names ``SYSTEM_USER`` or ``ALL
    PRIVILEGES`` is refused as well: where the answer is unknown, the tool
    refuses (:meth:`~sopuli.driver.mysql.grants.Grants.holds_system_user`).
    """
    if grants.read(cursor).holds_system_user():
        raise SystemUserError(target)


def observe(cursor: Cursor, *, target: str, encryption: Encryption | None = None) -> Scope:
    """This session's scope: a server, whether it takes writes, and how the
    session is encrypted.

    ``db_version`` is the part of ``VERSION()`` before the first ``-``, so
    ``8.0.46-log`` is reported as ``8.0.46``. It is also ``db_release``: the
    number is already the full release. A server whose version names
    another product is refused (:class:`NotMysqlError`), before anything else is
    read. Then an account that can use ``SYSTEM_USER`` is refused
    (:class:`SystemUserError`). ``encryption`` is the session's, where :func:`read_encryption`
    already read it; otherwise it is read here.
    """
    cursor.execute(VERSION)
    version = str(cursor.fetchone()[0])
    for word, product in OTHER_PRODUCTS.items():
        if word in version.lower():
            raise NotMysqlError(
                f'target "{target}" declares type "mysql", and the server is {product} ({version})',
                hint=(
                    f"{product} speaks MySQL's protocol and handles passwords differently; "
                    "the MySQL driver does not support it"
                    + (". For MariaDB, set `type: mariadb`" if product == "MariaDB" else "")
                ),
            )
    refuse_system_user(cursor, target=target)
    cursor.execute(READ_ONLY_SETTINGS)
    read_only, super_read_only, transaction_read_only = cursor.fetchone()
    writable = not (read_only or super_read_only or transaction_read_only)
    open_mode = READ_WRITE if writable else READ_ONLY

    if encryption is None:
        encryption = read_encryption(cursor)

    release = version.split("-")[0]
    return Scope(
        type=SERVER,
        db_version=release,
        db_release=release,
        open_mode=open_mode,
        read_write=writable,
        encryption=encryption,
    )


READ_ONLY_HINT = (
    "the server has read_only or super_read_only on, as a replica does, or the "
    "session's transaction_read_only is on. Point the target at the writable "
    "primary"
)


def require_read_write(scope: Scope, *, target: str) -> None:
    """Refuse a write where :func:`observe` found the session read-only, as
    :func:`sopuli.driver.protocol.require_read_write`."""
    protocol.require_read_write(scope, target=target, hint=READ_ONLY_HINT)
