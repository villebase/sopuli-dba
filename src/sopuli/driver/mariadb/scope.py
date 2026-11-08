"""What a MariaDB session finds when it looks at itself. Tier 0.

Every read is open to any account that can log in: the server's version, the
read-only settings and the session's own TLS version. Nothing here branches on
the server's version (invariant 3); it is read to report it, and to tell
MariaDB from MySQL, which answers the same protocol and has a driver of its own
(#1202, decision 2).

No capability is read in :func:`observe`. The session adds the ones it always
has (:data:`~sopuli.driver.mariadb.session.CAPABILITIES`), and
``password_value`` from :func:`read_password_checks`, read on its own so that
a failed read refuses only the verbs that send a password (#1310).
"""

from __future__ import annotations

from sopuli.driver import protocol
from sopuli.driver.mysql_family.accounts import text
from sopuli.driver.mysql_family.encryption import read_encryption
from sopuli.driver.protocol import SERVER, Cursor, DriverError, Encryption, Scope
from sopuli.exit_codes import ExitCode

#: ``scope.open_mode``, in the words P1 uses for an Oracle database.
READ_WRITE = "READ WRITE"
READ_ONLY = "READ ONLY"

#: The server's version, read alone and first, so that a MySQL server is
#: refused by name before anything else is read.
VERSION = "select version()"

#: The settings that stop the tool account writing: the server's `read_only`
#: and the session's `tx_read_only`. Measured on 10.11.19, 11.4.13, 11.8.9 and
#: 12.3.3: `tx_read_only` exists on all four, and `transaction_read_only` not
#: on 10.11.19 (`1193`). `read_only` reads `0` on the first three and `OFF` on
#: 12.3.3, where it takes a word (#1268).
READ_ONLY_SETTINGS = "select @@global.read_only, @@session.tx_read_only"

#: How `read_only` reads when it is off, as a number or as 12.3's word.
OFF = frozenset({"0", "OFF"})

#: The server's `strict_password_validation`, a global variable only (a
#: session read is `1238`), and the password validation plugins the server has
#: active. The tool account reads both with only `CREATE USER`
#: (`12_password_check_probe.py`, PC4, #1310).
PASSWORD_CHECKS = (
    "select @@global.strict_password_validation, (select group_concat(plugin_name "
    "order by plugin_name) from information_schema.plugins where plugin_type = "
    "'PASSWORD VALIDATION' and plugin_status = 'ACTIVE')"
)

#: The word ``VERSION()`` carries on every MariaDB release measured, as in
#: ``11.8.9-MariaDB-ubu2404-log``.
MARIADB = "mariadb"

READ_ONLY_HINT = (
    "the server has read_only on, as a replica does, or the session's "
    "tx_read_only is on. Point the target at the writable primary"
)


class NotMariadbError(DriverError):
    """A `type: mariadb` target reached a server that is not MariaDB.

    MySQL speaks the same protocol and stores and changes passwords
    differently (#1220). ``config``, exit 9: the file names the wrong type.
    """

    category = "config"
    exit_code = ExitCode.CONFIG_INVALID


def writable(read_only: object, tx_read_only: object) -> bool:
    """Whether neither setting stops a write. Pure. Each may come as a number,
    a word or bytes; anything that is not plainly off counts as on, so an
    unknown spelling reports the server read-only rather than writable."""
    return _off(read_only) and _off(tx_read_only)


def _off(value: object) -> bool:
    return text(value).strip().upper() in OFF


def refusing_checks(strict: object, plugins: object) -> tuple[str, ...]:
    """The password validation plugins that refuse the value the driver
    sends: every active one while ``strict_password_validation`` is on, and
    none while it is off (PC1 to PC3). Pure. A setting that is not plainly
    off counts as on."""
    if _off(strict) or plugins is None:
        return ()
    return tuple(name for name in text(plugins).split(",") if name)


def observe(cursor: Cursor, *, target: str, encryption: Encryption | None = None) -> Scope:
    """This session's scope: a server, whether it takes writes, and how the
    session is encrypted.

    ``db_version`` is the part of ``VERSION()`` before the first ``-``, so
    ``11.8.9-MariaDB-ubu2404-log`` is reported as ``11.8.9``. It is also
    ``db_release``: the number is already the full release. A server whose
    version does not name MariaDB is refused (:class:`NotMariadbError`) before
    anything else is read. ``encryption`` is the session's, where the session
    already read it; otherwise it is read here.
    """
    cursor.execute(VERSION)
    version = text(cursor.fetchone()[0])
    if MARIADB not in version.lower():
        raise NotMariadbError(
            f'target "{target}" declares type "mariadb", and the server is not MariaDB ({version})',
            hint=(
                "set `type: mysql` if this is a MySQL server: the two speak one protocol "
                "and handle passwords differently, and each has its own driver. A "
                "MariaDB server whose version string was changed, or a proxy that "
                "rewrites it, is not supported: the tool reaches MariaDB directly"
            ),
        )
    cursor.execute(READ_ONLY_SETTINGS)
    read_only, tx_read_only = cursor.fetchone()
    can_write = writable(read_only, tx_read_only)

    if encryption is None:
        encryption = read_encryption(cursor, block="mariadb")

    release = version.split("-")[0]
    return Scope(
        type=SERVER,
        db_version=release,
        db_release=release,
        open_mode=READ_WRITE if can_write else READ_ONLY,
        read_write=can_write,
        encryption=encryption,
    )


def read_password_checks(cursor: Cursor) -> tuple[str, ...]:
    """The active password validation plugins that refuse the value the
    driver sends, by name, or none (:func:`refusing_checks`)."""
    cursor.execute(PASSWORD_CHECKS)
    strict, plugins = cursor.fetchone()
    return refusing_checks(strict, plugins)


def require_read_write(scope: Scope, *, target: str) -> None:
    """Refuse a write where :func:`observe` found the session read-only."""
    protocol.require_read_write(scope, target=target, hint=READ_ONLY_HINT)
