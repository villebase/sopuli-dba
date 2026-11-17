"""What a SQL Server target can do, read per session (#1550). Tier 0.

Two capabilities, each read once and cached by the session (invariant 3):

- **the host's platform**, ``Linux`` or ``Windows``, from
  ``sys.dm_os_host_info``, which the tool login reads with ``ALTER ANY
  LOGIN`` alone (``09_windows_policy_probe.py``, WP0). On Windows the
  password policy can lock a login at a threshold the tool cannot read
  (`02-mssql-privileges.md` §7);
- **the password value's version**: ``0x0300``, PBKDF2-HMAC-SHA512, where the
  server takes it, and ``0x0200``, SHA-512, where it does not
  (`02-mssql-privileges.md` §6.2, #1564).

**The version is read with a statement that changes nothing.** ``CREATE
LOGIN`` with a ``0x0300`` value, under a random name, inside a transaction
that is rolled back, answers ``ok`` where the server takes the value, and
``15021`` where it does not, and leaves no login (``11_hash_version_probe.py``,
HV6). Any other answer means nothing about the value: a release that checks
the name first answers a clash, ``15025``, and the tool cannot see every name
a login would clash with. So any other answer fails the check, and the verb
refuses the target before it draws a password (#1564). The value is computed
from a random password nobody holds, and is never used again.

The check is a write, rolled back, so the session runs it only where a
password will be set, and never on a target that is read-only (#1564). What a
server audit or Extended Events keep of the rolled-back statement is not
measured (unverified: mssql-hash-check-audit).
"""

from __future__ import annotations

import secrets

from sopuli.driver.mssql.password import (
    PBKDF2_SHA512,
    SHA512,
    hex_literal,
    password_value,
)
from sopuli.driver.mssql.statements import quoted_name
from sopuli.driver.protocol import PASSWORD_VALUE, Cursor, UnsupportedCapabilityError
from sopuli.secrets import Secret

#: The host's platform, ``Linux`` or ``Windows`` (WP0).
HOST_PLATFORM = "SELECT host_platform FROM sys.dm_os_host_info"

#: The answer of a server that takes the ``0x0300`` value, and the number of
#: one that does not (HV6).
TAKES_IT = "ok"
REFUSES_IT = "15021"

#: The prefix of the check's random login name. It is rolled back, so no
#: login of this name is ever left; the prefix says what it was in a trace.
CHECK_PREFIX = "sopuli_hash_check_"

#: Ends a transaction a refused statement left open. A statement-level error
#: does not end the batch, so the batch's own ROLLBACK runs too; this is for a
#: batch that was cut short.
END_TRANSACTION = "IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION"


def host_platform(cursor: Cursor) -> str | None:
    """``Linux`` or ``Windows``, as ``sys.dm_os_host_info`` gives it, or
    ``None`` where it gives no row or no name. Unknown is not Linux: a caller
    treats it as Windows, whose lockout the tool cannot see."""
    cursor.execute(HOST_PLATFORM)
    row = cursor.fetchone()
    if row is None or row[0] is None or not str(row[0]).strip():
        return None
    return str(row[0]).strip()


def check_name() -> str:
    """A login name no one has: the prefix and 16 random hex digits."""
    return CHECK_PREFIX + secrets.token_hex(8)


def check_statement(name: str) -> str:
    """The rolled-back ``CREATE LOGIN`` of the check, with a ``0x0300``
    value of a random password."""
    value = password_value(Secret(secrets.token_urlsafe(24)), PBKDF2_SHA512)
    return (
        "BEGIN TRANSACTION;\n"
        f"CREATE LOGIN {quoted_name(name)} WITH PASSWORD = {hex_literal(value)} HASHED, "
        "CHECK_POLICY = OFF;\n"
        "ROLLBACK TRANSACTION"
    )


def version_from(answer: str, *, target: str, message: str | None = None) -> int:
    """The version the server takes, from the check's answer: ``ok`` or the
    first server error's number, with ``message`` its text. Any other answer
    refuses the target as lacking ``password_value`` (#1564), with the
    server's own words."""
    if answer == TAKES_IT:
        return PBKDF2_SHA512
    if answer == REFUSES_IT:
        return SHA512
    said = f" ({message})" if message else ""
    raise UnsupportedCapabilityError(
        PASSWORD_VALUE,
        target=target,
        hint=(
            f"the server answered {answer}{said} to the check that tells whether it takes "
            "a 0x0300 password value, where only ok or 15021 says which value to send; "
            "nothing was changed. Run the command again, and if the answer stays, "
            "report it (02-mssql-privileges.md §6.2)"
        ),
    )
