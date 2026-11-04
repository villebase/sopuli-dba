"""How a MySQL or MariaDB session is encrypted, read from the session. Tier 0.

Both products answer ``SHOW SESSION STATUS LIKE 'Ssl_version'`` for any account,
with the TLS version or an empty string (measured on MySQL 8.4.13, and on
MariaDB 11.8.9 with ``TLSv1.3``). Shared by both drivers (#1267, decision 7).
"""

from __future__ import annotations

from typing import Any

from sopuli.driver.protocol import ENCRYPTION_NONE, ENCRYPTION_TLS, UNKNOWN, Cursor, Encryption

#: The session's TLS version, or an empty string on a plain connection.
TLS_VERSION = "show session status like 'Ssl_version'"

#: The connection reaches the server over TCP: `dsn:` is always host:port.
TCP = "tcp"

NO_ROW_HINT = "SHOW SESSION STATUS has no Ssl_version row for this session"


def unencrypted_hint(block: str) -> str:
    """What to do about a plain session, naming the target's block, ``mysql``
    or ``mariadb``."""
    return f"set `{block}.ssl_mode` to VERIFY_IDENTITY, and give the server a certificate"


def encryption_of(row: Any, *, block: str = "mysql") -> Encryption:
    """The session's encryption, from its ``Ssl_version`` status row.

    ``protocol`` is the transport, ``tcp``: TLS runs inside the TCP connection.
    No row is ``unknown``, not ``none``: not knowing is not a finding.
    """
    if row is None:
        return Encryption(method=UNKNOWN, protocol=TCP, hint=NO_ROW_HINT)
    if row[1]:
        return Encryption(method=ENCRYPTION_TLS, protocol=TCP)
    return Encryption(method=ENCRYPTION_NONE, protocol=TCP, hint=unencrypted_hint(block))


def read_encryption(cursor: Cursor, *, block: str = "mysql") -> Encryption:
    """The session's encryption alone: what a session reads at connect, to
    hold a mode that requires TLS to it."""
    cursor.execute(TLS_VERSION)
    return encryption_of(cursor.fetchone(), block=block)
