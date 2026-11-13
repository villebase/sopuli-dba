"""The optional view ``sopuli.account_state`` on MySQL, as the reports read it (#1502). Tier 0.

MySQL keeps an account's failed-login limit only in
``mysql.user.User_attributes``, beside a retained password's hash, which the
tool account never reads (#1411, M1). A DBA may create a read-only view over
the keys the tool needs alone, with ``SQL SECURITY DEFINER``, and grant the
tool account ``SELECT`` on it (#1457). ``sql/mysql/account_state_view.sql``
creates it. What it gives was measured by ``12_definer_view_probe.py``
(#1490; ``02-mysql-privileges.md`` §2.4). It has MariaDB's name (#1502), and
the columns MySQL keeps.

**Who reads it.** `report accounts` only, for the failed-login limit, through
:meth:`~sopuli.driver.mysql.session.MysqlSession.account_states`.
``describe_user`` does not, so no verb that changes an account acts on what
the view says.

**Its shape is checked first, every session**, and a refusal is read, as
:mod:`~sopuli.driver.mysql_family.optional_view` says. An absent view leaves
the limit *not checked*, with the reason. A view that exists and cannot be used
is **broken**: the limit is *not checked* too, and the caller warns, naming
what is wrong (``SOPULI-W073``). So is a column that holds something other
than an integer. Neither the server's message nor the value is repeated.
"""

from __future__ import annotations

from dataclasses import dataclass

from sopuli.config.products import fold_mysql_host
from sopuli.driver.mysql_family.accounts import text
from sopuli.driver.mysql_family.optional_view import integer, refusal, shape_problem
from sopuli.driver.protocol import Cursor
from sopuli.driver.survey import Limit

SCHEMA = "sopuli"
NAME = "account_state"
VIEW = f"{SCHEMA}.{NAME}"
INSTALL_SCRIPT = "sql/mysql/account_state_view.sql"
#: What the view's definer reads.
SOURCE = "mysql.user"

#: The columns the view may have. ``restrictions`` and ``retained_password``
#: are in the install script for later reads (#1502, #1457) and are not read
#: here.
EXPECTED = frozenset(
    {
        "User",
        "Host",
        "failed_login_attempts",
        "password_lock_time_days",
        "restrictions",
        "retained_password",
    }
)
#: The columns `report accounts` reads.
READ = ("User", "Host", "failed_login_attempts", "password_lock_time_days")
ROWS_QUERY = f"select {', '.join(READ)} from {VIEW}"

ABSENT = (
    "MySQL keeps FAILED_LOGIN_ATTEMPTS in mysql.user.User_attributes, beside a retained "
    f"password's hash, and the optional view {VIEW} that reads it without the hash is "
    f"absent or not granted to the tool account: run {INSTALL_SCRIPT} as an administrator"
)
#: An account the server has and the view does not show, such as one created
#: after the session read the view.
NO_ROW = f"the optional view {VIEW} has no row for this account"


@dataclass(frozen=True)
class AccountStates:
    """What the view gave this session: each account's failed-login limit, by
    ``(user, host)`` with the host folded as the server compares it, or why
    there is none."""

    rows: dict[tuple[str, str], Limit] | None
    #: Why ``rows`` is ``None``: the reason a report gives for *not checked*.
    reason: str | None = None
    #: What is wrong with a view that exists and cannot be used, for the
    #: warning; ``None`` where the view is absent or was read.
    broken: str | None = None

    def limit(self, key: tuple[str, str]) -> tuple[Limit, str | None]:
        """The failed-login limit of the account whose key is ``key``, ``(user,
        host)`` with the host folded, or ``None`` and why."""
        if self.rows is None:
            return None, self.reason
        found = self.rows.get(key)
        return (None, NO_ROW) if found is None else (found, None)


def read(cursor: Cursor) -> AccountStates:
    """The view's rows, after its columns are checked."""
    try:
        listed, problem = shape_problem(cursor, SCHEMA, NAME, expected=EXPECTED, read=READ)
        if not listed:
            return AccountStates(rows=None, reason=ABSENT)
        if problem is not None:
            return _broken(problem)
        cursor.execute(ROWS_QUERY)
        rows = cursor.fetchall()
    except Exception as error:  # noqa: BLE001 -- a server's answer is classified
        what = refusal(error, source=SOURCE)
        return AccountStates(rows=None, reason=ABSENT) if what is None else _broken(what)
    try:
        return AccountStates(
            rows={
                (text(user), fold_mysql_host(text(host))): _limit(attempts, lock_days)
                for user, host, attempts, lock_days in rows
            }
        )
    except (TypeError, ValueError):
        # A column with the right name holds something else. Its value is never
        # repeated: it may be a stored one (invariant 2).
        return _broken("a column holds values the tool does not expect")


def _broken(what: str) -> AccountStates:
    return AccountStates(
        rows=None,
        reason=f"the optional view {VIEW} is not used: {what}",
        broken=what,
    )


def _limit(attempts: object, lock_days: object) -> Limit:
    """``FAILED_LOGIN_ATTEMPTS``, where it blocks. No key, or 0, is no limit
    (DV2: the server removes the key when it is set to 0). So is a limit
    without ``PASSWORD_LOCK_TIME``: the server counts and blocks only when
    both are non-zero, and with the lock time at 0 an account answers
    ``1045`` to every wrong password and is never blocked (measured on
    8.4.13, #1508). ``-1`` is ``UNBOUNDED``, which blocks."""
    value = integer(attempts)
    days = integer(lock_days)
    if value is None or value == 0 or days is None or days == 0:
        return "unlimited"
    if value < 0 or days < -1:
        raise ValueError("not a limit")
    return value
