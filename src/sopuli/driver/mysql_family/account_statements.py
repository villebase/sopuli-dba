"""The account statements MySQL and MariaDB both send. Tier 0.

``ACCOUNT LOCK``, ``ACCOUNT UNLOCK`` and ``PASSWORD EXPIRE``, which `account
suspend`, `account reset-password` and `account expire-password` send. Both
servers take them from an account with only ``CREATE USER``: on MySQL
``04_lock_expiry_probe.py``, LE2 to LE9; on MariaDB its own
``04_lock_expiry_probe.py``, LK1 to LK3. What each server answers afterwards
differs, and each driver's verb says so.

The account is named as the server spells it, each part between backquotes
(:meth:`~sopuli.driver.mysql_family.accounts.Principal.sql`): ``ALTER USER``
takes no bind parameters.
"""

from __future__ import annotations

from sopuli.driver.mysql_family.accounts import Principal


def lock(user: str, host: str) -> str:
    """``ACCOUNT LOCK``. A locked account's password then answers ``3118`` on
    MySQL and ``4151`` on MariaDB."""
    return f"ALTER USER {Principal(user, host).sql()} ACCOUNT LOCK"


def unlock(user: str, host: str) -> str:
    """``ACCOUNT UNLOCK``. It ends a lock, and a block after failed logins,
    which a new password does not end."""
    return f"ALTER USER {Principal(user, host).sql()} ACCOUNT UNLOCK"


def expire(user: str, host: str) -> str:
    """``PASSWORD EXPIRE``. The password then logs in only to set another."""
    return f"ALTER USER {Principal(user, host).sql()} PASSWORD EXPIRE"
