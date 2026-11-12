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
- **The lock and the lifetime come from the optional view** ``sopuli.account_state``
  (:mod:`~sopuli.driver.mariadb.account_state`, #1491), where a DBA has
  created it and it passes its column check. MariaDB keeps them in
  ``mysql.global_priv`` beside the stored value, and in ``SHOW CREATE USER``,
  which prints it, so without the view ``locked`` and ``password_lifetime``
  are ``None``, and a rule's ``login:`` and ``password_lifetime`` are *not
  checked*, with the view's reason (#1411, R2). The view's lock is only the
  one ``ACCOUNT LOCK`` sets, so it is a lock somebody set.
- **There is no failed-login limit per account** (R1). The server-wide
  ``max_password_errors`` is not one, and the registry makes the check *not
  applicable*.
- **The count of failed logins** is ``PASSWORD_ERRORS`` in
  ``information_schema.USERS`` from 11.8, which shows the tool account only its
  own row, so it is unknown.
"""

from __future__ import annotations

from typing import Any

from sopuli.driver.mariadb.account_state import NO_ROW, AccountStates
from sopuli.driver.mariadb.accounts import SYSTEM_ACCOUNTS
from sopuli.driver.mysql_family.accounts import locked_status, text
from sopuli.driver.survey import Limit, SurveyedAccount

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


def survey(cursor: Any, states: AccountStates | None = None) -> tuple[SurveyedAccount, ...]:
    """Every account, roles left out, ordered by name, ``user@host``. The lock
    and the lifetime come from ``states``, the optional view's rows, where it
    was read (#1491)."""
    states = states or AccountStates(rows=None, reason=None)
    cursor.execute(ACCOUNTS)
    surveyed = []
    for user, host, expired in cursor.fetchall():
        user, host = text(user), text(host)
        surveyed.append(_account(user, host, expired=text(expired) == "Y", states=states))
    # The server sorts by its column collations; the contract is by name.
    return tuple(sorted(surveyed, key=lambda account: account.name))


def _account(user: str, host: str, *, expired: bool, states: AccountStates) -> SurveyedAccount:
    name = f"{user}@{host}"
    state = states.get(user, host)
    locked: bool | None = None
    lifetime: Limit = None
    if state is not None:
        # Only ACCOUNT LOCK sets account_locked: a block after failed logins
        # (max_password_errors) is not in the view (#1479).
        locked, lifetime = state.locked, state.lifetime
        unread: tuple[str, ...] = ()
    elif states.rows is not None:
        unread = (NO_ROW, NO_ROW)
    elif states.reason is not None:
        unread = (states.reason, states.reason)
    else:
        unread = (NO_LOCK_READ, NO_LIFETIME_READ)
    return SurveyedAccount(
        name=name,
        # The words `account list` shows; without the view the lock finding
        # says the lock was not checked.
        status=locked_status(locked=bool(locked), expired=expired),
        locked=locked,
        deliberately_locked=locked,
        profile="",
        common=False,
        # MariaDB's own account, left out unless the file names it, as
        # Oracle's are.
        vendor_maintained=name in SYSTEM_ACCOUNTS,
        password_lifetime=lifetime,
        failed_login_limit=None,
        failed_logins=None,
        unreadable=(*unread, NO_LIMIT, NO_COUNT_READ),
    )
