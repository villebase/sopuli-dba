"""Every account on a MySQL server, as `report accounts` reads it (UC-5, #1461).

One row per ``user@host``: one user name at three hosts is three accounts, each
with its own lock, expiry and lifetime (``10_report_read_probe.py``, RE0). The
reads are §2.4 of ``02-mysql-privileges.md``, with §2.1's grants: the named
columns of ``mysql.user``, which hold no hash, ``mysql.role_edges`` and
``@@default_password_lifetime``. Nothing is bound and no pattern is sent: the
report matches names in the tool.

- **A role is left out.** It reads as a locked account with an expired
  password, and only a row in ``mysql.role_edges`` tells it apart (#1411, M3),
  or its place in ``@@global.mandatory_roles``, which any account reads. A role
  nobody holds has neither, so it shows as an undeclared account.
- **The lock** is ``account_locked``, which only ``ACCOUNT LOCK`` sets. A block
  after failed logins is not in it: the server answers ``3955`` and changes no
  column the tool account reads (RE1). On a server with
  ``performance_schema.temporary_account_locks`` (9.7.4) and ``SELECT`` on it,
  a row with ``LOCKED`` ``YES`` is such a block, and the account reads as
  locked, not by somebody.
- **The lifetime** is ``password_lifetime`` in days, ``0`` for never, and
  NULL for the server's ``@@default_password_lifetime``, where ``0`` is never.
- **The failed-login limit is never read** (M1). ``FAILED_LOGIN_ATTEMPTS`` is
  kept in ``User_attributes`` beside a retained password's hash, which the tool
  account is refused (``1143``).
- **The failed-login count** is ``FAILED_LOGIN_ATTEMPTS`` less
  ``REMAINING_LOGIN_ATTEMPTS`` in ``temporary_account_locks``, read under an
  optional grant the survey tries (M2). Without the grant the server answers
  ``1142``, also where it has no such table: it checks the grant first. On
  8.0.46 and 8.4.13 the table does not exist, so the grant itself fails,
  ``1146``, and a broader grant reads ``1146`` (measured on 8.4.13, #1461).
  Either way, and for an account with no row there, the count is unknown.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sopuli.config.products import fold_mysql_host
from sopuli.driver.mysql.accounts import DEFAULT_LIFETIME, EXPIRED, SYSTEM_ACCOUNTS, status
from sopuli.driver.mysql.admin import read_mandatory_roles
from sopuli.driver.mysql_family.accounts import text
from sopuli.driver.survey import Limit, SurveyedAccount

#: Every account and role, by §2.1's column grant. No hash column.
ACCOUNTS = (
    "select User, Host, account_locked, password_expired, password_lifetime "
    "from mysql.user order by User, Host"
)
#: Each role granted to somebody, as ``role_edges`` names it.
ROLES = "select distinct FROM_USER, FROM_HOST from mysql.role_edges"
#: The optional read of M2. Holds no hash.
LOCKS_TABLE = "performance_schema.temporary_account_locks"
LOCKS = (
    f"select USER, HOST, LOCKED, FAILED_LOGIN_ATTEMPTS, REMAINING_LOGIN_ATTEMPTS from {LOCKS_TABLE}"
)

#: ``ER_NO_SUCH_TABLE``: a server older than the table.
NO_SUCH_TABLE = 1146

#: A block after failed logins, in the words Oracle uses for it, as
#: :mod:`~sopuli.driver.mysql.accounts` words the other states.
LOCKED_TIMED = "LOCKED(TIMED)"

NO_LIMIT_READ = (
    "MySQL keeps FAILED_LOGIN_ATTEMPTS only in mysql.user.User_attributes, beside a "
    "retained password's hash, which the tool account does not read"
)
NO_GRANT = (
    f"the tool account has no SELECT on {LOCKS_TABLE}, or the server has no such table, "
    "as 8.0 and 8.4 have not"
)
NO_TABLE = f"this server has no {LOCKS_TABLE}"
NO_ROW = f"{LOCKS_TABLE} has no row for the account"


@dataclass(frozen=True)
class Locks:
    """``temporary_account_locks`` as read: per account key, ``(blocked,
    failed)``, or ``None`` with the reason it could not be read."""

    rows: dict[tuple[str, str], tuple[bool, int]] | None
    reason: str = ""


def read_locks(cursor: Any) -> Locks:
    cursor.execute(LOCKS)
    rows: dict[tuple[str, str], tuple[bool, int]] = {}
    for user, host, locked, attempts, remaining in cursor.fetchall():
        failed = int(attempts) - int(remaining)
        rows[(text(user), fold_mysql_host(text(host)))] = (text(locked) == "YES", failed)
    return Locks(rows)


def survey(cursor: Any, locks: Locks) -> tuple[SurveyedAccount, ...]:
    """Every account, roles left out, ordered by name, ``user@host``."""
    cursor.execute(DEFAULT_LIFETIME)
    (default,) = cursor.fetchone()
    cursor.execute(ROLES)
    roles = {(text(user), fold_mysql_host(text(host))) for user, host in cursor.fetchall()}
    # A mandatory role goes to every account and has no row in role_edges.
    roles.update((role.user, fold_mysql_host(role.host)) for role in read_mandatory_roles(cursor))
    cursor.execute(ACCOUNTS)
    surveyed = []
    for user, host, account_locked, expired, lifetime in cursor.fetchall():
        user, host = text(user), text(host)
        key = (user, fold_mysql_host(host))
        if key in roles:
            continue
        surveyed.append(
            _account(
                user,
                host,
                locked=text(account_locked) == "Y",
                expired=text(expired) == "Y",
                lifetime=_lifetime(lifetime if lifetime is not None else default),
                locks=locks,
                key=key,
            )
        )
    # The server sorts by its column collations; the contract is by name.
    return tuple(sorted(surveyed, key=lambda account: account.name))


def _lifetime(days: Any) -> Limit:
    value = int(days)
    return "unlimited" if value == 0 else value


def _account(
    user: str,
    host: str,
    *,
    locked: bool,
    expired: bool,
    lifetime: Limit,
    locks: Locks,
    key: tuple[str, str],
) -> SurveyedAccount:
    blocked, failed, count_reason = False, None, locks.reason
    if locks.rows is not None:
        row = locks.rows.get(key)
        if row is None:
            count_reason = NO_ROW
        else:
            blocked, failed = row
    name = f"{user}@{host}"
    return SurveyedAccount(
        name=name,
        status=_status(locked=locked, blocked=blocked, expired=expired),
        locked=locked or blocked,
        # Only ACCOUNT LOCK sets account_locked, so a lock read there is one
        # somebody set. A block after failed logins is not.
        deliberately_locked=locked,
        profile="",
        common=False,
        # MySQL's own accounts, left out unless the file names one, as
        # Oracle's are.
        vendor_maintained=name in SYSTEM_ACCOUNTS,
        password_lifetime=lifetime,
        failed_login_limit=None,
        failed_logins=failed,
        unreadable=(NO_LIMIT_READ,) if failed is not None else (NO_LIMIT_READ, count_reason),
    )


def _status(*, locked: bool, blocked: bool, expired: bool) -> str:
    """The verbs' words (:func:`~sopuli.driver.mysql.accounts.status`), and
    ``LOCKED(TIMED)`` for a block nobody set."""
    if blocked and not locked:
        return f"{EXPIRED} & {LOCKED_TIMED}" if expired else LOCKED_TIMED
    return status(locked=locked, expired=expired)
