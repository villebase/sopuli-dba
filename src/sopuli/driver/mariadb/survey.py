"""Every account on a MariaDB server, as `report accounts` reads it (UC-5, #1462).

One row per ``user@host``: one user name at three hosts is three accounts
(``15_report_read_probe.py``, #1448). The read is §2.4 of
``02-mariadb-privileges.md``, with §2.1's column grant on the ``mysql.user``
view, which reads no stored value. Nothing is bound and no pattern is sent: the
report matches names in the tool.

- **A role is left out.** It is a row with ``is_role = 'Y'`` and an empty
  host, so it is never mistaken for an account.
- **The expiry** is the view's ``password_expired``, which ``PASSWORD EXPIRE``
  sets. A lifetime that has run out does not set it, so such an account reads
  ``OPEN``.
- **The lock and the lifetime are not read** (#1411, R2). MariaDB keeps them in
  ``mysql.global_priv`` beside the stored value, and in ``SHOW CREATE USER``,
  which prints it. So ``locked`` and ``password_lifetime`` are ``None``, and a
  rule's ``login:`` and ``password_lifetime`` are *not checked*. A view a DBA
  creates could expose them; that is #1457.
- **There is no failed-login limit per account** (R1). The server-wide
  ``max_password_errors`` is not one, and the registry makes the check *not
  applicable*.
- **The count of failed logins** is ``PASSWORD_ERRORS`` in
  ``information_schema.USERS`` from 11.8, which shows the tool account only its
  own row, so it is unknown.
"""

from __future__ import annotations

from typing import Any

from sopuli.driver.mariadb.accounts import SYSTEM_ACCOUNTS, status
from sopuli.driver.mysql_family.accounts import text
from sopuli.driver.survey import SurveyedAccount

#: Every account, by §2.1's column grant, roles left out. No stored value.
ACCOUNTS = (
    "select User, Host, password_expired from mysql.user where is_role = 'N' order by User, Host"
)

NO_LOCK_READ = (
    "MariaDB keeps the lock in mysql.global_priv, beside the stored value, which the tool "
    "account does not read"
)
NO_LIFETIME_READ = (
    "MariaDB keeps the password lifetime in mysql.global_priv, beside the stored value, "
    "which the tool account does not read"
)
NO_LIMIT = "MariaDB has no failed-login limit per account, only the server's max_password_errors"
NO_COUNT_READ = (
    "MariaDB shows an account's failed logins, PASSWORD_ERRORS in information_schema.USERS, "
    "only to the account itself"
)


def survey(cursor: Any) -> tuple[SurveyedAccount, ...]:
    """Every account, roles left out, ordered by name, ``user@host``."""
    cursor.execute(ACCOUNTS)
    surveyed = [
        _account(text(user), text(host), expired=text(expired) == "Y")
        for user, host, expired in cursor.fetchall()
    ]
    # The server sorts by its column collations; the contract is by name.
    return tuple(sorted(surveyed, key=lambda account: account.name))


def _account(user: str, host: str, *, expired: bool) -> SurveyedAccount:
    name = f"{user}@{host}"
    return SurveyedAccount(
        name=name,
        # The words `account list` shows; the lock finding says the lock was
        # not checked.
        status=status(expired=expired),
        locked=None,
        profile="",
        common=False,
        # MariaDB's own account, left out unless the file names it, as
        # Oracle's are.
        vendor_maintained=name in SYSTEM_ACCOUNTS,
        password_lifetime=None,
        failed_login_limit=None,
        failed_logins=None,
        unreadable=(NO_LOCK_READ, NO_LIFETIME_READ, NO_LIMIT, NO_COUNT_READ),
    )
