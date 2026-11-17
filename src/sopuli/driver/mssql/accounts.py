"""Reading one declared SQL Server login. Tier 0.

A login with only ``ALTER ANY LOGIN`` reads every column here: a login's row
in ``sys.server_principals`` and ``sys.sql_logins``, and ``LOGINPROPERTY``
(``02_client_hash_probe.py``, CH7; ``03_lock_expiry_probe.py``, LK1 to LK6;
``07_report_reads_probe.py``, RP1 and RP2).

**The server compares the name.** The row is found by ``name = ?``, under the
server's collation, so ``ACME_APP`` finds ``acme_app`` under the default one,
and the state carries the server's spelling (``05_identity_probe.py``, ID1).

**Only a login with a password is managed** (#1538, decision 1). Every other
kind of server principal is refused, before anything is changed
(:class:`NotAPasswordLoginError`). A name with no login is ``None``: a
contained database user is not a login, and ``ALTER ANY LOGIN`` does not see
one (ID3).

**The two locks** (#1554, H4). ``is_disabled`` is set by ``ALTER LOGIN …
DISABLE``, which a person sends: the status is ``LOCKED``, and a reset
refuses it. ``LOGINPROPERTY``'s ``IsLocked`` is a lockout after failed
logins under the host's policy, which ends by itself: ``LOCKED(TIMED)``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sopuli.driver.protocol import Cursor, DriverError, UserState
from sopuli.exit_codes import ExitCode

#: ``UserState.status``, in the words Oracle uses for the same states, as the
#: MySQL driver words them.
OPEN = "OPEN"
LOCKED = "LOCKED"
LOCKED_TIMED = "LOCKED(TIMED)"
EXPIRED = "EXPIRED"

#: ``sys.server_principals.type`` of a login with a password.
SQL_LOGIN = "S"

#: The other kinds of server principal, by Microsoft's documentation of
#: ``sys.server_principals``. Only a SQL login (``S``) and, in a matrix
#: server, the certificate-mapped ``##MS_…##`` logins (``C``) were seen.
OTHER_KINDS = {
    "U": "a Windows login",
    "G": "a Windows group",
    "E": "an Entra login",
    "X": "an Entra group",
    "C": "a login mapped to a certificate",
    "K": "a login mapped to an asymmetric key",
    "R": "a server role",
}

NOT_A_PASSWORD_LOGIN_HINT = (
    "sopuli changes only logins with a password (SQL Server authentication). Take the "
    "account out of the config, or declare the SQL login that the application uses"
)

#: Why ``password_changed_at`` is ``None`` for a login that has one.
NO_CHANGE_DATE = "LOGINPROPERTY gave no PasswordLastSetTime for this login"

#: One login by name. ``LOGINPROPERTY`` gives ``sql_variant``, which pyodbc
#: cannot fetch, so each value is cast. ``PasswordLastSetTime`` is the
#: server's local time, and is moved to UTC by the server's own offset. The
#: last column is whether the login is the session's own.
LOGIN = (
    "SELECT p.name, p.type, p.principal_id, p.is_disabled, "
    "l.is_policy_checked, l.is_expiration_checked, "
    "CAST(LOGINPROPERTY(p.name, 'IsLocked') AS int), "
    "CAST(LOGINPROPERTY(p.name, 'IsMustChange') AS int), "
    "CAST(LOGINPROPERTY(p.name, 'IsExpired') AS int), "
    "CAST(LOGINPROPERTY(p.name, 'DaysUntilExpiration') AS int), "
    "DATEADD(minute, DATEDIFF(minute, GETDATE(), GETUTCDATE()), "
    "CAST(LOGINPROPERTY(p.name, 'PasswordLastSetTime') AS datetime)), "
    "CASE WHEN p.name = SUSER_SNAME() THEN 1 ELSE 0 END "
    "FROM sys.server_principals AS p "
    "LEFT JOIN sys.sql_logins AS l ON l.principal_id = p.principal_id "
    "WHERE p.name = ?"
)

#: ``principal_id`` of ``sa``, the login the server supplies.
SA_PRINCIPAL_ID = 1


class NotAPasswordLoginError(DriverError):
    """A declared account is a server principal with no password, such as a
    Windows login (#1538, decision 1). ``config``, exit 9, before anything is
    changed (invariant 4)."""

    category = "config"
    exit_code = ExitCode.CONFIG_INVALID
    about_account = True

    def __init__(self, account: str, kind: str, *, target: str) -> None:
        super().__init__(
            f'account "{account}" on target "{target}" is {kind}, which has no password '
            "on the server",
            hint=NOT_A_PASSWORD_LOGIN_HINT,
        )


@dataclass(frozen=True)
class Login:
    """One row of :data:`LOGIN`, for a SQL login."""

    name: str
    principal_id: int
    disabled: bool
    policy_checked: bool
    expiration_checked: bool
    locked_out: bool
    must_change: bool
    expired: bool
    days_until_expiration: int | None
    changed_at: datetime | None
    session_login: bool


def _flag(value: Any) -> bool:
    return bool(value) if value is not None else False


def read_one(cursor: Cursor, account: str, *, target: str) -> Login | None:
    """The declared login's row, ``None`` where no server principal has the
    name. Raises :class:`NotAPasswordLoginError` for any principal but a SQL
    login."""
    cursor.execute(LOGIN, (account,))
    row = cursor.fetchone()
    if row is None:
        return None
    name, kind, principal_id, disabled, policy, expiration = row[:6]
    locked_out, must_change, expired, days, changed_at, own = row[6:]
    kind = str(kind).strip()
    if kind != SQL_LOGIN:
        raise NotAPasswordLoginError(
            str(name), OTHER_KINDS.get(kind, f"a server principal of type {kind}"), target=target
        )
    return Login(
        name=str(name),
        principal_id=int(principal_id),
        disabled=_flag(disabled),
        policy_checked=_flag(policy),
        expiration_checked=_flag(expiration),
        locked_out=_flag(locked_out),
        must_change=_flag(must_change),
        expired=_flag(expired),
        days_until_expiration=int(days) if days is not None else None,
        changed_at=changed_at.replace(tzinfo=UTC) if isinstance(changed_at, datetime) else None,
        session_login=_flag(own),
    )


def status(*, disabled: bool, locked_out: bool, expired: bool) -> str:
    """``UserState.status`` in Oracle's words. A disabled login is
    ``LOCKED`` whatever its lockout, because a person set it."""
    if disabled:
        lock = LOCKED
    elif locked_out:
        lock = LOCKED_TIMED
    else:
        lock = ""
    if expired and lock:
        return f"{EXPIRED} & {lock}"
    return EXPIRED if expired else (lock or OPEN)


def state_of(login: Login, *, now: datetime, admin_unread: str | None) -> UserState:
    """One login as a :class:`~sopuli.driver.protocol.UserState`.

    The password has stopped working where ``IsExpired`` says so, or where
    ``IsMustChange`` does: the server then answers its owner ``18488`` until
    it is changed (LK5). The expiry date is ``DaysUntilExpiration`` days from
    ``now``, to the day, because the server gives whole days, and ``None``
    where the login's expiry is off.

    The failed-login count is left unknown. ``BadPasswordCount`` does not
    count past 1 on the Linux images (LK2), and no lockout threshold is
    readable on any host (``09_windows_policy_probe.py``).

    ``admin_unread`` is guardrail 9's: why the paths to an administrative
    grant were not read (:attr:`~sopuli.driver.protocol.UserState.admin_unread`).
    """
    expired = login.expired or login.must_change
    expires_at = None
    if login.expiration_checked and login.days_until_expiration is not None:
        expires_at = now + timedelta(days=login.days_until_expiration)
    locked = login.disabled or login.locked_out
    return UserState(
        name=login.name,
        status=status(disabled=login.disabled, locked_out=login.locked_out, expired=expired),
        locked=locked,
        deliberately_locked=login.disabled,
        expired=expired,
        password_changed_at=login.changed_at,
        password_changed_unknown=None if login.changed_at else NO_CHANGE_DATE,
        password_expires_at=expires_at,
        vendor_maintained=login.principal_id == SA_PRINCIPAL_ID,
        password_file_member=False,
        admin_unread=admin_unread,
        session_account=login.session_login,
    )
