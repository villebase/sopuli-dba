"""The statements that change a SQL Server login's password for UC-1. Tier 0.

``02-mssql-privileges.md`` §6.2 has the order they are sent in:

1. read the login's ``is_policy_checked`` and ``is_expiration_checked`` and
   record them in the vault;
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

#: The longest name ``sysname`` holds, in UTF-16 code units, which is also the
#: longest ``QUOTENAME`` takes.
MAX_NAME_CHARACTERS = 128


def quoted_name(login: str) -> str:
    """``login`` between brackets, with each ``]`` doubled, as ``QUOTENAME``
    writes it. A ``]`` needs no refusal: the doubled bracket escapes it (§6.4).

    Refuses an empty name, a control character, and a name longer than
    ``sysname`` holds: no login has one, and a control character in the
    statement's text is at best unusable.
    """
    if not login:
        raise ValueError("a login name is empty")
    if any(charsets.is_control(character) for character in login):
        raise ValueError("a login name contains control characters")
    if len(login.encode("utf-16-le", "surrogatepass")) // 2 > MAX_NAME_CHARACTERS:
        raise ValueError(f"a login name is at most {MAX_NAME_CHARACTERS} characters")
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
    can have read.
    """
    if expiration and not policy:
        raise ValueError("CHECK_EXPIRATION is on only with CHECK_POLICY on")
    return (
        f"ALTER LOGIN {quoted_name(login)} WITH CHECK_POLICY = {_on(policy)}, "
        f"CHECK_EXPIRATION = {_on(expiration)}"
    )


def _on(flag: bool) -> str:
    return "ON" if flag else "OFF"
