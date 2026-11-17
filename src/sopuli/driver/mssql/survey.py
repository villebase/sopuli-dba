"""Every login on a SQL Server instance, as `report accounts` reads it (UC-5,
#1555). Tier 0.

One read, with §2.1's grant alone (``02-mssql-privileges.md``): every login's
row in ``sys.server_principals`` and ``sys.sql_logins``, and
``LOGINPROPERTY``'s values (``07_report_reads_probe.py``, RP1 and RP2).
Nothing is bound, and no hash column is read. The decisions are #1555's:

- **Every login is listed** (decision 2): SQL logins, Windows logins and
  groups, Entra logins and groups, and logins mapped to a certificate or an
  asymmetric key. A server role is not a login, and is left out. The
  ``##MS_…##`` logins setup makes are the product's own, left out unless a
  rule names one, as Oracle's own accounts are. ``sa`` is listed.
- **The lock** (decision 3, as #1554 maps it): ``is_disabled`` is a lock
  somebody set, ``LOCKED``, and ``IsLocked`` a lockout after failed logins,
  ``LOCKED(TIMED)``.
- **The password lifetime** is ``unlimited`` where ``CHECK_EXPIRATION`` is
  off. Where it is on, the host's policy sets the maximum age, which
  ``LOGINPROPERTY`` does not give (``09_windows_policy_probe.py``, WP1), so
  it is *not checked*.
- **The failed-login limit** is ``unlimited`` where ``CHECK_POLICY`` is off:
  nothing counts and nothing locks (WP5). It is ``unlimited`` on a Linux host
  with the policy on too, because no login locks there (LK2). On Windows, or
  a host that names no platform, the threshold is the host's, and it is *not
  checked*.
- **The failed-login count** is ``BadPasswordCount`` on a Windows host (WP2).
  On Linux it is unknown: it does not count past 1 there (LK2).

A login with no password has no lifetime, limit or count, and each is
``None`` with the reason that it has no password.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sopuli.driver.mssql.accounts import OTHER_KINDS, SQL_LOGIN, status
from sopuli.driver.survey import Limit, SurveyedAccount

#: The host platform on which no login locks (LK2).
LINUX = "Linux"

#: Every login: every kind of server principal but a server role (``R``). No
#: hash column. ``LOGINPROPERTY`` gives ``sql_variant``, which pyodbc cannot
#: fetch, so each value is cast. It is NULL for a login with no password.
LOGINS = (
    "SELECT p.name, p.type, p.is_disabled, "
    "l.is_policy_checked, l.is_expiration_checked, "
    "CAST(LOGINPROPERTY(p.name, 'IsLocked') AS int), "
    "CAST(LOGINPROPERTY(p.name, 'IsExpired') AS int), "
    "CAST(LOGINPROPERTY(p.name, 'IsMustChange') AS int), "
    "CAST(LOGINPROPERTY(p.name, 'BadPasswordCount') AS int) "
    "FROM sys.server_principals AS p "
    "LEFT JOIN sys.sql_logins AS l ON l.principal_id = p.principal_id "
    "WHERE p.type <> 'R'"
)

LIFETIME_FROM_POLICY = (
    "CHECK_EXPIRATION is on, so the host's password policy sets the maximum age, "
    "which the tool login cannot read"
)
LIMIT_FROM_POLICY = (
    "CHECK_POLICY is on, so the host's account policy sets the lockout threshold, "
    "which the tool login cannot read"
)
COUNT_ON_LINUX = "BadPasswordCount does not count past 1 on a Linux host"
NO_COUNT = "LOGINPROPERTY gave no BadPasswordCount for this login"
NO_FLAGS = "the login has no row in sys.sql_logins that the tool login can read"


def product_owned(name: str) -> bool:
    """A login setup makes, such as ``##MS_PolicyEventProcessingLogin##``:
    left out unless a rule names it (#1555, decision 2)."""
    return name.startswith("##") and name.endswith("##")


def survey(cursor: Any, *, platform: str | None) -> tuple[SurveyedAccount, ...]:
    """Every login, ordered by name. ``platform`` is the host's
    (:func:`~sopuli.driver.mssql.capabilities.host_platform`); ``None``
    counts as Windows, whose lockout the tool cannot see."""
    cursor.execute(LOGINS)
    surveyed = [_login(row, linux=platform == LINUX) for row in cursor.fetchall()]
    # The server sorts by its collation; the contract is by name.
    return tuple(sorted(surveyed, key=lambda account: account.name))


def _login(row: Sequence[Any], *, linux: bool) -> SurveyedAccount:
    name, kind, disabled, policy, expiration, locked_out, expired, must_change, bad = row
    name, kind = str(name), str(kind).strip()
    disabled, locked_out = bool(disabled), bool(locked_out)
    lifetime: Limit
    limit: Limit
    count: int | None
    if kind != SQL_LOGIN:
        none = f"{OTHER_KINDS.get(kind, f'a server principal of type {kind}')} has no password"
        lifetime, limit, count = None, None, None
        unreadable: tuple[str, ...] = (none, none, none)
    else:
        lifetime, lifetime_reason = _lifetime(expiration)
        limit, limit_reason = _limit(policy, linux=linux)
        count = None if linux or bad is None else int(bad)
        count_reason = COUNT_ON_LINUX if linux else (NO_COUNT if count is None else None)
        unreadable = tuple(
            reason for reason in (lifetime_reason, limit_reason, count_reason) if reason
        )
    return SurveyedAccount(
        name=name,
        status=status(
            disabled=disabled, locked_out=locked_out, expired=bool(expired) or bool(must_change)
        ),
        locked=disabled or locked_out,
        # A person sends ALTER LOGIN ... DISABLE; a lockout ends by itself.
        deliberately_locked=disabled,
        profile="",
        common=False,
        vendor_maintained=product_owned(name),
        password_lifetime=lifetime,
        failed_login_limit=limit,
        failed_logins=count,
        unreadable=unreadable,
    )


def _lifetime(expiration: Any) -> tuple[Limit, str | None]:
    if expiration is None:
        return None, NO_FLAGS
    if not expiration:
        return "unlimited", None
    return None, LIFETIME_FROM_POLICY


def _limit(policy: Any, *, linux: bool) -> tuple[Limit, str | None]:
    if policy is None:
        return None, NO_FLAGS
    if not policy or linux:
        return "unlimited", None
    return None, LIMIT_FROM_POLICY
