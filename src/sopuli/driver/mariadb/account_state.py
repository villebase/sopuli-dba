"""The optional view ``sopuli.account_state``, as the reports read it (#1491). Tier 0.

MariaDB keeps an account's lock, password lifetime and the time of its last
password change only in ``mysql.global_priv``, beside the stored value, which
the tool account never reads (#1411, R2). A DBA may create a read-only view
over those keys alone, with ``SQL SECURITY DEFINER``, and grant the tool
account ``SELECT`` on it (#1457). ``sql/mariadb/account_state_view.sql``
creates it. What it gives was measured by ``16_definer_view_probe.py``
(#1479; ``02-mariadb-privileges.md`` §2.4).

**Who reads it.** `report accounts`, `report history` and `account list`
(the lock) only, through
:meth:`~sopuli.driver.mariadb.session.MariadbSession.account_states`.
``describe_user`` does not, so no verb that changes an account acts on what the
view says (#1491).

**Its shape is checked first, every session.** The column names come from
``information_schema.COLUMNS`` before any row is read. A view with a column
outside :data:`EXPECTED` is not read at all: a view the tool did not create
could expose a stored value by mistake (invariant 2, P2). Under a column grant
only the granted columns are listed, and the others cannot be read either.

**What the server answers** where the view cannot be used:

- no row in ``COLUMNS``: the view is absent, its schema is absent, or the tool
  account has no grant on it. The server answers all three alike (``1142``),
  so the reason names both fixes;
- ``1142`` or ``1146`` on reading it: the grant was revoked, or the view
  dropped with the grant left, after its columns were read. Absent too;
- ``1045`` on reading it, in a session already logged in: its definer has been
  dropped;
- ``1356``: its definer cannot read ``mysql.global_priv``.

An absent view leaves the fields *not checked*, with the reason. A view that
exists and cannot be used is **broken**: the fields are *not checked* too, and
the caller warns, naming what is wrong (#1491). So is any other refusal of the
read, and a column that holds something other than an integer, such as another
key of ``Priv`` under an expected name. Neither the server's message nor the
value is repeated, as either could carry a stored value. The check and the
refusals are :mod:`~sopuli.driver.mysql_family.optional_view`'s, which MySQL's
view uses too (#1509).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sopuli.driver.mysql_family.accounts import DEFAULT_LIFETIME, text
from sopuli.driver.mysql_family.optional_view import (
    columns_query,
    integer,
    refusal,
    shape_problem,
)
from sopuli.driver.protocol import Cursor
from sopuli.driver.survey import Limit

SCHEMA = "sopuli"
NAME = "account_state"
VIEW = f"{SCHEMA}.{NAME}"
INSTALL_SCRIPT = "sql/mariadb/account_state_view.sql"

#: The columns the view may have. ``rollover_open`` is in the install script
#: for a later decision (#1457) and is not read.
EXPECTED = frozenset(
    {
        "User",
        "Host",
        "account_locked",
        "password_lifetime",
        "password_last_changed",
        "rollover_open",
    }
)
#: The columns the reports read.
READ = ("User", "Host", "account_locked", "password_lifetime", "password_last_changed")

COLUMNS_QUERY = columns_query(SCHEMA, NAME)
ROWS_QUERY = f"select {', '.join(READ)} from {VIEW}"

ABSENT = (
    f"MariaDB keeps it in mysql.global_priv, beside the stored value, and the optional "
    f"view {VIEW} that reads it without the value is absent or not granted to the tool "
    f"account: run {INSTALL_SCRIPT} as an administrator"
)


@dataclass(frozen=True)
class State:
    """One account's row of the view."""

    locked: bool
    #: The days; ``"unlimited"`` for none.
    lifetime: Limit
    #: ``None`` where the view gives no time, with :attr:`no_time` saying why.
    changed_at: datetime | None
    no_time: str | None = None


@dataclass(frozen=True)
class AccountStates:
    """What the view gave this session: each account's state, by ``(user,
    host)`` as the server spells them, or why there is none."""

    rows: dict[tuple[str, str], State] | None
    #: Why ``rows`` is ``None``: the reason a report gives for *not checked*.
    reason: str | None = None
    #: What is wrong with a view that exists and cannot be used, for the
    #: warning; ``None`` where the view is absent or was read.
    broken: str | None = None

    def get(self, user: str, host: str) -> State | None:
        return None if self.rows is None else self.rows.get((user, host))


#: ``PASSWORD EXPIRE`` sets the time of the last change to 0, and so does an
#: account created expired (#1479).
NO_TIME = "MariaDB keeps no time of the last change after PASSWORD EXPIRE"
#: An account whose ``Priv`` has no time key at all, such as one carried over
#: from before 10.4: not an expiry.
NO_TIME_KEY = f"the optional view {VIEW} gives no time of the last change for this account"
#: An account the server has and the view does not show, such as one created
#: after the session read the view.
NO_ROW = f"the optional view {VIEW} has no row for this account"


def read(cursor: Cursor) -> AccountStates:
    """The view's rows, after its columns are checked."""
    try:
        listed, problem = shape_problem(cursor, SCHEMA, NAME, expected=EXPECTED, read=READ)
        if not listed:
            return AccountStates(rows=None, reason=ABSENT)
        if problem is not None:
            return _broken(problem)
        cursor.execute(DEFAULT_LIFETIME)
        (default,) = cursor.fetchone()
        cursor.execute(ROWS_QUERY)
        rows = cursor.fetchall()
    except Exception as error:  # noqa: BLE001 -- a server's answer is classified
        # A client error, such as a lost connection, is raised again.
        what = refusal(error, source="mysql.global_priv")
        return AccountStates(rows=None, reason=ABSENT) if what is None else _broken(what)
    try:
        default_days = int(default or 0)
        return AccountStates(
            rows={
                (text(user), text(host)): _state(locked, lifetime, changed, default_days)
                for user, host, locked, lifetime, changed in rows
            }
        )
    except (TypeError, ValueError):
        # A column the right name holds something else, such as another key of
        # Priv. Its value is never repeated: it may be a stored one (invariant 2).
        return _broken("a column holds values the tool does not expect")


def _broken(what: str) -> AccountStates:
    return AccountStates(
        rows=None,
        reason=f"the optional view {VIEW} is not used: {what}",
        broken=what,
    )


def _state(locked: Any, lifetime: Any, changed: Any, default_days: int) -> State:
    days = integer(lifetime)
    # NULL or -1 is the server's default_password_lifetime, where 0 is none.
    if days is None or days < 0:
        days = default_days
    seconds = integer(changed)
    return State(
        locked=integer(locked) == 1,
        lifetime="unlimited" if days == 0 else days,
        changed_at=datetime.fromtimestamp(seconds, UTC) if seconds else None,
        # 0 is how PASSWORD EXPIRE marks it (#1479); NULL is no key at all.
        no_time=None if seconds else NO_TIME if seconds == 0 else NO_TIME_KEY,
    )
