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

from sopuli.driver.mysql_family.accounts import EXPIRED, LOCKED, OPEN, locked_status
from sopuli.driver.protocol import Cursor, DriverError, UserState
from sopuli.exit_codes import ExitCode

__all__ = ["EXPIRED", "LOCKED", "LOCKED_TIMED", "OPEN"]

#: A lockout after failed logins, in Oracle's word for it, as the MySQL survey
#: spells it. The Oracle module's constant cannot be imported from here:
#: ``tests/test_driver_seam.py`` keeps Oracle's modules inside its driver.
LOCKED_TIMED = "LOCKED(TIMED)"

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

#: ``UserState.lockout_evidence`` of a disabled login that is also locked out.
ALSO_LOCKED_OUT = "IsLocked reads 1: the login is also locked out after failed logins"

#: Why ``password_changed_at`` is ``None`` for a login that has one.
NO_CHANGE_DATE = "LOGINPROPERTY gave no PasswordLastSetTime for this login"

#: One login by name. ``LOGINPROPERTY`` gives ``sql_variant``, which pyodbc
#: cannot fetch, so each value is cast. ``PasswordLastSetTime`` is the
#: server's local time. It is moved to UTC by the server's offset now, read
#: once from ``SYSDATETIMEOFFSET()``: no release before 2022 names the server's
#: time zone, so on a host whose zone keeps daylight saving, a time set in the
#: other season is an hour off. The last column is whether the login is the
#: session's own.
LOGIN = (
    "SELECT p.name, p.type, p.principal_id, p.is_disabled, "
    "l.is_policy_checked, l.is_expiration_checked, "
    "CAST(LOGINPROPERTY(p.name, 'IsLocked') AS int), "
    "CAST(LOGINPROPERTY(p.name, 'IsMustChange') AS int), "
    "CAST(LOGINPROPERTY(p.name, 'IsExpired') AS int), "
    "CAST(LOGINPROPERTY(p.name, 'DaysUntilExpiration') AS int), "
    "DATEADD(minute, -DATEPART(tzoffset, SYSDATETIMEOFFSET()), "
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


def read_one(cursor: Cursor, account: str, *, target: str) -> Login | None:
    """The declared login's row, ``None`` where no server principal has the
    name. Raises :class:`NotAPasswordLoginError` for any principal but a SQL
    login, and :class:`~sopuli.driver.protocol.DriverError` for a SQL login
    whose ``sys.sql_logins`` row was not read: its flags would otherwise read
    as off."""
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
    if policy is None or expiration is None:
        raise DriverError(
            f'login "{name}" on target "{target}" has no row in sys.sql_logins that the '
            "tool login can read",
            hint="sopuli cannot read the login's policy flags, so it does not guess them",
        )
    return Login(
        name=str(name),
        principal_id=int(principal_id),
        disabled=bool(disabled),
        policy_checked=bool(policy),
        expiration_checked=bool(expiration),
        locked_out=bool(locked_out),
        must_change=bool(must_change),
        expired=bool(expired),
        days_until_expiration=int(days) if days is not None else None,
        changed_at=changed_at.replace(tzinfo=UTC) if isinstance(changed_at, datetime) else None,
        session_login=bool(own),
    )


def status(*, disabled: bool, locked_out: bool, expired: bool) -> str:
    """``UserState.status`` in Oracle's words, as the MySQL driver words its
    states (:func:`~sopuli.driver.mysql_family.accounts.locked_status`), and
    ``LOCKED(TIMED)`` for a lockout nobody set, as its survey does. A
    disabled login is ``LOCKED`` whatever its lockout, because a person set
    it."""
    if locked_out and not disabled:
        return f"{EXPIRED} & {LOCKED_TIMED}" if expired else LOCKED_TIMED
    return locked_status(locked=disabled, expired=expired)


def login_status(login: Login) -> str:
    """:func:`status` of one login. Its password has stopped working where
    ``IsExpired`` says so, or where ``IsMustChange`` does (LK5): the one rule,
    for :func:`state_of` and the verbs that change a login alike."""
    return status(
        disabled=login.disabled,
        locked_out=login.locked_out,
        expired=login.expired or login.must_change,
    )


def state_of(
    login: Login,
    *,
    now: datetime,
    admin_unread: str | None,
    global_privileges: frozenset[str] = frozenset(),
) -> UserState:
    """One login as a :class:`~sopuli.driver.protocol.UserState`.

    The password has stopped working where ``IsExpired`` says so, or where
    ``IsMustChange`` does: the server then answers its owner ``18488`` until
    it is changed (LK5). The server gives ``DaysUntilExpiration`` in whole
    days, so the expiry date is the latest it can be: that many days and one
    more from ``now``. An earlier bound would show a date already past for a
    password with hours left. It is ``None`` where the login's expiry is off.

    The failed-login count is left unknown. ``BadPasswordCount`` does not
    count past 1 on the Linux images (LK2), and no lockout threshold is
    readable on any host (``09_windows_policy_probe.py``).

    ``admin_unread`` and ``global_privileges`` are guardrail 9's: why the
    paths to an administrative grant were not read, and the grants they reach
    (:class:`~sopuli.driver.mssql.admin.Assessment`).
    """
    expired = login.expired or login.must_change
    expires_at = None
    if login.expiration_checked and login.days_until_expiration is not None:
        expires_at = now + timedelta(days=login.days_until_expiration + 1)
    locked = login.disabled or login.locked_out
    return UserState(
        name=login.name,
        status=login_status(login),
        locked=locked,
        deliberately_locked=login.disabled,
        lockout_evidence=ALSO_LOCKED_OUT if login.disabled and login.locked_out else None,
        expired=expired,
        password_changed_at=login.changed_at,
        password_changed_unknown=None if login.changed_at else NO_CHANGE_DATE,
        password_expires_at=expires_at,
        vendor_maintained=login.principal_id == SA_PRINCIPAL_ID,
        password_file_member=False,
        admin_unread=admin_unread,
        global_privileges=global_privileges,
        session_account=login.session_login,
    )
