"""The statements that change a SQL Server login's password for UC-1. Tier 0.

``02-mssql-privileges.md`` §6.2 has the order they are sent in:

1. read the login's ``is_policy_checked`` and ``is_expiration_checked`` and
   record them in the vault. Where the vault already holds recorded flags,
   keep them and do not read again: a run that stopped after step 2 left the
   policy off, and a second read would record that;
2. :func:`set_password_value`: send the value with ``HASHED``, and turn the
   policy off in the same statement. The server refuses ``HASHED`` on a login
   with ``CHECK_POLICY = ON``, ``33020``, and takes the two together
   (``02_client_hash_probe.py``, CH4);
3. log in with the new password;
4. :func:`restore_policy`: set both flags back to the values of step 1.

Each statement carries a value, never a password (:mod:`.password`).
``ALTER LOGIN`` takes no bind parameters, so the login is named in the text,
as :func:`quoted_name` writes it (§6.4).
"""

from __future__ import annotations

from sopuli.config import charsets
from sopuli.driver.mssql.password import hex_literal
from sopuli.driver.protocol import DriverError
from sopuli.exit_codes import ExitCode

#: The longest name ``sysname`` holds, in UTF-16 code units, which is also the
#: longest ``QUOTENAME`` takes.
MAX_NAME_CHARACTERS = 128


class LoginNameError(DriverError):
    """A declared login name that no statement can address. ``config`` and
    exit 9, as Oracle's ``IdentifierError``: the fix is in the config."""

    category = "config"
    exit_code = ExitCode.CONFIG_INVALID


def quoted_name(login: str) -> str:
    """``login`` between brackets, with each ``]`` doubled, as ``QUOTENAME``
    writes it. A ``]`` needs no refusal: the doubled bracket escapes it (§6.4).

    Refuses a name no login has: an empty one, one with a control character,
    one UTF-16 cannot encode, and one longer than ``sysname`` holds. Refuses a
    name with a space at either end too: SQL Server ignores trailing spaces
    when it compares names, so ``[acme_app ]`` would reach ``acme_app`` under
    a second spelling (invariant 5), and the MySQL driver refuses a padded
    name for the same reason.
    """
    if not login:
        raise LoginNameError("a login name is empty")
    if any(charsets.is_control(character) for character in login):
        raise LoginNameError(f"the login name {login!r} contains control characters")
    if login != login.strip(" "):
        raise LoginNameError(
            f"the login name {login!r} starts or ends with a space",
            hint="SQL Server ignores trailing spaces in a name; declare it without them",
        )
    try:
        units = len(login.encode("utf-16-le")) // 2
    except UnicodeEncodeError:
        raise LoginNameError(f"the login name {login!r} cannot be encoded as UTF-16") from None
    if units > MAX_NAME_CHARACTERS:
        raise LoginNameError(f"a login name is at most {MAX_NAME_CHARACTERS} characters")
    return "[" + login.replace("]", "]]") + "]"


def set_password_value(login: str, value: bytes) -> str:
    """Step 2: the value, as a hex literal, with the policy turned off.

    Turning the policy off also turns ``CHECK_EXPIRATION`` off, sets
    ``BadPasswordCount`` to 0 and ends a lockout (§6.2), which is why step 4
    sets both flags back.
    """
    return (
        f"ALTER LOGIN {quoted_name(login)} WITH PASSWORD = {hex_literal(value)} HASHED, "
        "CHECK_POLICY = OFF"
    )


def restore_policy(login: str, *, policy: bool, expiration: bool) -> str:
    """Step 4: ``CHECK_POLICY`` and ``CHECK_EXPIRATION`` as step 1 read them.

    Both are sent, also when the policy stays off: turning the policy on again
    leaves ``CHECK_EXPIRATION`` off (§6.2). The server keeps expiration only
    with the policy on, so a pair with expiration alone is not a state step 1
    can have read. Where step 1 read both off, step 2 left nothing to set
    back, and the caller need not send this.
    """
    if expiration and not policy:
        raise ValueError("CHECK_EXPIRATION is on only with CHECK_POLICY on")
    return (
        f"ALTER LOGIN {quoted_name(login)} WITH CHECK_POLICY = {_on(policy)}, "
        f"CHECK_EXPIRATION = {_on(expiration)}"
    )


def disable(login: str) -> str:
    """`account suspend`'s statement: the lock a person sets, which a reset
    refuses (H4, #1554). It carries no password (LK1)."""
    return f"ALTER LOGIN {quoted_name(login)} DISABLE"


def _on(flag: bool) -> str:
    return "ON" if flag else "OFF"
