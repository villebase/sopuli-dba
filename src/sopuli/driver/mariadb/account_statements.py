"""The statements `account suspend` and `account expire-password` send on
MariaDB (#1272). Tier 0.

An account with only ``CREATE USER`` locks, unlocks and expires another
(``04_lock_expiry_probe.py``, LK1 to LK3, on 10.11.19 to 12.3.3). The account
is named as the view spells it, each part between backquotes
(:meth:`~sopuli.driver.mysql_family.accounts.Principal.sql`): ``ALTER USER``
takes no bind parameters.

**A lock is never read** (#1267, decision 2): it is only in
``mysql.global_priv``, beside the stored value. So ``account suspend`` sends
``ACCOUNT LOCK`` every time and reports ``changed: true``; a second lock is
accepted (LK1). **An expiry is read**: ``PASSWORD EXPIRE`` sets the view's
``password_expired`` to ``Y`` (LK3), so ``account expire-password`` sends
nothing where it already is.
"""

from __future__ import annotations

from sopuli.driver.mysql_family.accounts import Principal

#: What a suspension reports, since the lock it replaces cannot be read.
LOCK_UNREAD = (
    "sent ACCOUNT LOCK; whether the account was already locked cannot be read on "
    "MariaDB, so this reports a change every time"
)


def lock(user: str, host: str) -> str:
    """``ACCOUNT LOCK``. The password then answers ``4151`` (LK1)."""
    return f"ALTER USER {Principal(user, host).sql()} ACCOUNT LOCK"


def expire(user: str, host: str) -> str:
    """``PASSWORD EXPIRE``. The password then logs in only to set another,
    and the server answers ``1820`` to anything else until it is set (LK3)."""
    return f"ALTER USER {Principal(user, host).sql()} PASSWORD EXPIRE"
