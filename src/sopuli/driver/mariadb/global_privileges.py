"""The optional view ``sopuli.global_privileges``, as the privilege report reads it (#1483). Tier 0.

MariaDB keeps an account's global privileges in ``mysql.global_priv``, beside
the stored value, and the tool account's grants show it no other account's
row of ``information_schema.USER_PRIVILEGES``. Its ``access`` bits cannot be
decoded by the tool: an upgrade does not rewrite them, and each release reads
them its own way. A DBA may create a read-only view over
``information_schema.USER_PRIVILEGES``, with ``SQL SECURITY DEFINER`` and a
definer that holds ``SELECT`` on ``mysql.*``, which gives each account's
global privileges as the server applies them (#1483, option C).
``sql/mariadb/global_privileges_view.sql`` creates it. What it gives was
measured by ``17_global_privileges_view_probe.py``
(``02-mariadb-privileges.md`` §2.4).

**Its shape is checked first, every session**, as ``sopuli.account_state``'s
is, by :mod:`~sopuli.driver.mysql_family.optional_view`: a view with a column
outside :data:`EXPECTED` is not read.

**What the server answers** where the view cannot be used:

- no row in ``COLUMNS``, or ``1142``: absent, its schema absent, or not
  granted; ``1146``: dropped, with the tool account's grant left. Each is
  *absent*, with the reason naming the script;
- ``1045``: its definer is gone; ``1356``: it cannot be read; any other
  number: refused. Each is **broken**;
- **the tool account's own row is missing**: the definer holds less than
  ``SELECT`` on ``mysql.*``, and the server then answers with the definer's
  row alone, with no error (probe 17, GP3). Broken too.

**Accounts only.** A role has no row, and a member shows ``USAGE`` for what
it holds through a role. ``GRANTEE`` is ``'user'@'host'`` with a quote in the
name left unescaped, so it is compared with the string :func:`grantee` builds,
and never split.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from sopuli.driver.grants import SYSTEM
from sopuli.driver.mysql_family.accounts import Principal, text
from sopuli.driver.mysql_family.optional_view import columns_query, refusal, shape_problem
from sopuli.driver.mysql_family.privilege_survey import Held
from sopuli.driver.protocol import Cursor

SCHEMA = "sopuli"
NAME = "global_privileges"
VIEW = f"{SCHEMA}.{NAME}"
INSTALL_SCRIPT = "sql/mariadb/global_privileges_view.sql"

#: The view's columns, exactly.
EXPECTED = ("GRANTEE", "PRIVILEGE_TYPE", "IS_GRANTABLE")

COLUMNS_QUERY = columns_query(SCHEMA, NAME)
ROWS_QUERY = f"select {', '.join(EXPECTED)} from {VIEW}"

#: The privilege every account holds, which says it holds nothing.
USAGE = "USAGE"

#: Why the view gave nothing, where it is absent or not granted. Follows the
#: privilege survey's own reason, after a semicolon.
ABSENT = (
    f"the optional view {VIEW} that reads them is absent or not granted to the tool "
    f"account: run {INSTALL_SCRIPT} as an administrator"
)


@dataclass(frozen=True)
class GlobalPrivileges:
    """What the view gave this session: each grantee's global privileges, by
    the ``GRANTEE`` string :func:`grantee` builds, or why there are none."""

    #: ``(privilege, grantable)`` per grantee, ``USAGE`` left out.
    rows: dict[str, tuple[tuple[str, bool], ...]] | None
    reason: str | None = None
    #: What is wrong with a view that exists and cannot be used.
    broken: str | None = None

    def of(self, user: str, host: str) -> tuple[tuple[str, bool], ...] | None:
        """One account's privileges, ``()`` where it holds none, ``None``
        where the view was not read."""
        if self.rows is None:
            return None
        return self.rows.get(grantee(user, host), ())


def grantee(user: str, host: str) -> str:
    """``GRANTEE`` as the server writes it: each part in single quotes, a quote
    inside left as it is (probe 17)."""
    return f"'{user}'@'{host}'"


def read(cursor: Cursor, *, user: str, host: str) -> GlobalPrivileges:
    """The view's rows, after its columns are checked. ``user`` and ``host`` are
    the tool account's own, whose row proves the definer reads every account."""
    try:
        listed, problem = shape_problem(cursor, SCHEMA, NAME, expected=EXPECTED, read=EXPECTED)
        if not listed:
            return GlobalPrivileges(rows=None, reason=ABSENT)
        if problem is not None:
            return _broken(problem)
        cursor.execute(ROWS_QUERY)
        rows = cursor.fetchall()
    except Exception as error:  # noqa: BLE001 -- a server's answer is classified
        # A client error, such as a lost connection, is raised again. The
        # view reads information_schema, so 1356 names no table.
        what = refusal(error, source=None)
        return GlobalPrivileges(rows=None, reason=ABSENT) if what is None else _broken(what)
    found: dict[str, list[tuple[str, bool]]] = {}
    for who, privilege, grantable in rows:
        held = found.setdefault(text(who), [])
        name, option = text(privilege), text(grantable).upper() == "YES"
        if name != USAGE:
            held.append((name, option))
        if option and (GRANT_OPTION, True) not in held:
            # The grant option covers the whole global level, so it is one
            # privilege of its own, as on the other levels: also where it is
            # held alone, as USAGE ... WITH GRANT OPTION.
            held.append((GRANT_OPTION, True))
    if grantee(user, host) not in found:
        # A definer below SELECT on mysql.* answers with its own row alone,
        # and no error (probe 17, GP3).
        return _broken("the tool account's own row is missing, so its definer cannot read mysql.*")
    return GlobalPrivileges(rows={who: tuple(sorted(held)) for who, held in found.items()})


#: The level a global privilege the view gave is shown at.
LEVEL = "global"

#: Why a role's global privileges are not checked, where the view was read:
#: ``USER_PRIVILEGES`` has no row for a role (probe 17).
NO_ROLE_ROWS = (
    "the global privileges of a role and of PUBLIC: information_schema.USER_PRIVILEGES, "
    f"which the optional view {VIEW} reads, has no row for either"
)
#: The privilege a grantable global grant gives, listed as the other levels
#: list it (``privilege_reads``), as ``SHOW GRANTS`` spells it.
GRANT_OPTION = "GRANT OPTION"


def held(found: GlobalPrivileges, holders: Iterable[Principal]) -> list[Held]:
    """Each holder's global privileges from the view, as the survey's
    :class:`~sopuli.driver.mysql_family.privilege_survey.Held` rows."""
    rows: list[Held] = []
    for holder in holders:
        for privilege, grantable in found.of(holder.user, holder.host) or ():
            rows.append(
                Held(
                    holder=holder,
                    kind=SYSTEM,
                    level=LEVEL,
                    privilege=privilege,
                    grantable=grantable,
                )
            )
    return rows


def _broken(what: str) -> GlobalPrivileges:
    return GlobalPrivileges(
        rows=None,
        reason=f"the optional view {VIEW} is not used: {what}",
        broken=what,
    )
