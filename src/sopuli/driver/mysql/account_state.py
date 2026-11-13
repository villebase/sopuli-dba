"""The optional view ``sopuli.account_state`` on MySQL, as the reports read it (#1502). Tier 0.

MySQL keeps an account's failed-login limit only in
``mysql.user.User_attributes``, beside a retained password's hash, which the
tool account never reads (#1411, M1). A DBA may create a read-only view over
the keys the tool needs alone, with ``SQL SECURITY DEFINER``, and grant the
tool account ``SELECT`` on it (#1457). ``sql/mysql/account_state_view.sql``
creates it. What it gives was measured by ``12_definer_view_probe.py``
(#1490; ``02-mysql-privileges.md`` §2.4). It has MariaDB's name (#1502), and
the columns MySQL keeps.

**Who reads it.** `report accounts`, for the failed-login limit, through
:meth:`~sopuli.driver.mysql.session.MysqlSession.account_states`, and `report
privileges`, for the partial revokes (:func:`read_restrictions`), only where
``@@partial_revokes`` is on. ``describe_user`` does not, so no verb that
changes an account acts on what the view says.

**A partial revoke** is one entry of ``Restrictions`` per schema, such as
``[{"Database": "acme", "Privileges": ["SELECT"]}]`` (DV4): the global
privileges named are taken away on that schema. Roles have them too.

**Its shape is checked first, every session**, and a refusal is read, as
:mod:`~sopuli.driver.mysql_family.optional_view` says. An absent view leaves
the limit *not checked*, with the reason. A view that exists and cannot be used
is **broken**: the limit is *not checked* too, and the caller warns, naming
what is wrong (``SOPULI-W073``). So is a column that holds something other
than an integer. Neither the server's message nor the value is repeated.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

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

#: The columns the view may have. `report accounts` reads the limit and the
#: lock time, and `report privileges` reads ``restrictions``.
#: ``retained_password`` is in the install script for a later read (#1457)
#: and is not read here.
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


#: What a value of the wrong shape makes the view: broken, the value never
#: repeated, as it may be a stored one (invariant 2).
WRONG_VALUES = "a column holds values the tool does not expect"


def _fetch(
    cursor: Cursor, columns: tuple[str, ...], query: str
) -> tuple[list[Any] | None, str | None]:
    """The view's rows, ``query`` over ``columns``, after its columns are
    checked, or ``None`` and what is wrong: ``None`` too where the view is
    absent or not granted. One path for both readers, so they cannot answer
    differently."""
    try:
        listed, problem = shape_problem(cursor, SCHEMA, NAME, expected=EXPECTED, read=columns)
        if not listed:
            return None, None
        if problem is not None:
            return None, problem
        cursor.execute(query)
        return list(cursor.fetchall()), None
    except Exception as error:  # noqa: BLE001 -- a server's answer is classified
        return None, refusal(error, source=SOURCE)


def _not_used(what: str) -> str:
    return f"the optional view {VIEW} is not used: {what}"


def read(cursor: Cursor) -> AccountStates:
    """Each account's failed-login limit, for `report accounts`."""
    rows, broken = _fetch(cursor, READ, ROWS_QUERY)
    if rows is None:
        if broken is None:
            return AccountStates(rows=None, reason=ABSENT)
        return AccountStates(rows=None, reason=_not_used(broken), broken=broken)
    try:
        return AccountStates(
            rows={
                (text(user), fold_mysql_host(text(host))): _limit(attempts, lock_days)
                for user, host, attempts, lock_days in rows
            }
        )
    except (TypeError, ValueError):
        return AccountStates(rows=None, reason=_not_used(WRONG_VALUES), broken=WRONG_VALUES)


#: The columns `report privileges` reads.
RESTRICTIONS_READ = ("User", "Host", "restrictions")
RESTRICTIONS_QUERY = f"select {', '.join(RESTRICTIONS_READ)} from {VIEW}"

#: Per ``(user, host)``, the host folded: each global privilege and the
#: schemas it is revoked on. Every principal the view lists has an entry,
#: empty where it has no revoke.
Revoked = dict[tuple[str, str], dict[str, frozenset[str]]]

ABSENT_RESTRICTIONS = (
    "MySQL keeps a partial revoke in mysql.user.User_attributes, beside a retained "
    f"password's hash, and the optional view {VIEW} that reads it without the hash is "
    f"absent or not granted to the tool account: run {INSTALL_SCRIPT} as an administrator"
)
#: A principal ``mysql.user`` has and the view does not show, such as one
#: created between the two reads, or a view that filters rows.
NO_PRINCIPAL_ROW = (
    f"the optional view {VIEW} has no row for an account or role that mysql.user has, "
    "so its partial revokes are not known"
)
#: A revoke of a privilege the tool has no name for: it cannot be placed on
#: any global row, and dropping it would claim every schema.
UNKNOWN_PRIVILEGE = (
    "a partial revoke names a privilege the tool does not know, so the schemas a "
    "global privilege reaches are not known"
)
#: How ``Restrictions`` spells a privilege the tool names otherwise: measured
#: on 8.4.13, ``REVOKE GRANT OPTION ON acme_hr.*`` is stored as ``GRANT``. The
#: other static privileges, multi-word ones among them, are stored as the tool
#: names them.
RESTRICTION_NAMES = {"GRANT": "GRANT OPTION"}


class RevokesNotKnownError(Exception):
    """The partial revokes of some principal are not known: the view has no
    row for it, or names a privilege the tool does not know. The message is
    the reason."""


@dataclass(frozen=True)
class Restrictions:
    """What the view gave for the partial revokes, or why there is none."""

    rows: Revoked | None
    reason: str | None = None
    broken: str | None = None

    def of(self, user: str, host: str) -> dict[str, frozenset[str]]:
        """Each privilege ``user@host`` has revoked on some schemas, and those
        schemas; empty where it has none. Raises :class:`RevokesNotKnownError`
        where the view does not list it: no row is not the same as no revoke."""
        if self.rows is None:
            return {}
        found = self.rows.get((user, fold_mysql_host(host)))
        if found is None:
            raise RevokesNotKnownError(NO_PRINCIPAL_ROW)
        return found


def read_restrictions(cursor: Cursor) -> Restrictions:
    """Every principal's partial revokes, for `report privileges`. Read only
    where ``@@partial_revokes`` is on."""
    rows, broken = _fetch(cursor, RESTRICTIONS_READ, RESTRICTIONS_QUERY)
    if rows is None:
        if broken is None:
            return Restrictions(rows=None, reason=ABSENT_RESTRICTIONS)
        return Restrictions(rows=None, reason=_not_used(broken), broken=broken)
    try:
        return Restrictions(
            rows={
                (text(user), fold_mysql_host(text(host))): _restrictions(value)
                for user, host, value in rows
            }
        )
    except (TypeError, ValueError, KeyError):
        return Restrictions(rows=None, reason=_not_used(WRONG_VALUES), broken=WRONG_VALUES)


def _restrictions(value: object) -> dict[str, frozenset[str]]:
    """``[{"Database": "acme", "Privileges": ["SELECT"]}]`` as each privilege
    and its schemas. NULL is none (DV4). Raises for any other shape."""
    if value is None:
        return {}
    entries = json.loads(text(value))
    if not isinstance(entries, list):
        raise ValueError("not a list")
    schemas: dict[str, set[str]] = {}
    for entry in entries:
        database = entry["Database"]
        privileges = entry["Privileges"]
        if not isinstance(database, str) or not isinstance(privileges, list):
            raise ValueError("not a restriction")
        for privilege in privileges:
            if not isinstance(privilege, str):
                raise ValueError("not a privilege")
            name = privilege.upper()
            schemas.setdefault(RESTRICTION_NAMES.get(name, name), set()).add(database)
    return {privilege: frozenset(names) for privilege, names in schemas.items()}


def _limit(attempts: object, lock_days: object) -> Limit:
    """``FAILED_LOGIN_ATTEMPTS``, where it blocks. No key, or 0, is no limit
    (DV2: the server removes the key when it is set to 0). So is a limit
    without ``PASSWORD_LOCK_TIME``: the server counts and blocks only when
    both are non-zero, and with the lock time at 0 an account answers
    ``1045`` to every wrong password and is never blocked (measured on
    8.4.13, #1508). ``-1`` is ``UNBOUNDED``, which blocks."""
    value = integer(attempts)
    days = integer(lock_days)
    # Checked first, so one bad value reads the same with any partner.
    if (value is not None and value < 0) or (days is not None and days < -1):
        raise ValueError("not a limit")
    if not value or not days:
        return "unlimited"
    return value
