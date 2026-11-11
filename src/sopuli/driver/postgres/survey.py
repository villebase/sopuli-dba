"""Every role on a PostgreSQL cluster, as UC-5's `report accounts` reads it. Tier 0.

One statement over ``pg_roles``, which any role can read, so the survey needs
no grant (``02-postgres-privileges.md`` §2.5, #1443). Nothing is bound, and no
password column is read: ``rolpassword`` is a mask to the tool account anyway.

**How the facts map onto** :class:`~sopuli.driver.survey.SurveyedAccount`
(#1459):

==============================  ===============================================
field                           PostgreSQL
==============================  ===============================================
``locked``                      ``rolcanlogin`` is false (``NOLOGIN``), with
                                ``lock_is_login_attribute``: judged only
                                against a rule's ``login:``
``deliberately_locked``         the same: ``NOLOGIN`` is always set by somebody
``status``                      ``NOLOGIN``, ``EXPIRED`` or ``OPEN``, as
                                `creds status` shows a role
``valid_until``                 ``rolvaliduntil``, and whether it has passed
``vendor_maintained``           an oid below 16384: the bootstrap superuser and
                                every ``pg_*`` role
``profile``                     ``""``: a cluster has no profiles
``password_lifetime``,          ``None``: PostgreSQL has none. The registry
``failed_login_limit``          makes those checks *not applicable*
``failed_logins``               ``None``: PostgreSQL keeps no count
==============================  ===============================================

The expiry is compared on the server, ``rolvaliduntil < now()``, as
:mod:`sopuli.driver.postgres.roles` compares it, so the report and `creds
status` agree on which role has expired.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sopuli.driver.postgres.roles import EXPIRED, FIRST_NORMAL_OID, NOLOGIN, OPEN
from sopuli.driver.protocol import Cursor
from sopuli.driver.survey import SurveyedAccount, ValidUntil

#: Why each field PostgreSQL has no value for is ``None``, in
#: :attr:`SurveyedAccount.unreadable`'s order.
NO_LIFETIME = "PostgreSQL has no password lifetime"
NO_LIMIT = "PostgreSQL has no failed-login limit"
NO_COUNT = "PostgreSQL keeps no failed-login count"

#: One row per role, ordered by name. ``isfinite`` keeps ``infinity`` and
#: ``-infinity`` out of the date column, which Python's ``datetime`` cannot
#: hold; the text column names them instead.
SURVEY_QUERY = (
    "select r.rolname, r.rolcanlogin, "
    f"r.oid < {FIRST_NORMAL_OID}, "
    "case when isfinite(r.rolvaliduntil) then r.rolvaliduntil end, "
    "case when not isfinite(r.rolvaliduntil) then r.rolvaliduntil::text end, "
    "coalesce(r.rolvaliduntil < now(), false) "
    "from pg_roles r order by r.rolname"
)


def survey(cursor: Cursor) -> tuple[SurveyedAccount, ...]:
    """Every role on the cluster, ordered by name."""
    cursor.execute(SURVEY_QUERY)
    return tuple(surveyed_of(row) for row in cursor.fetchall())


def surveyed_of(row: tuple[Any, ...]) -> SurveyedAccount:
    """One :data:`SURVEY_QUERY` row as a :class:`SurveyedAccount`."""
    name, can_login, built_in, finite, infinite, expired = row
    if isinstance(finite, datetime):
        text: str | None = finite.isoformat(sep=" ")
    elif infinite is not None:
        text = str(infinite)
    else:
        text = None
    status = NOLOGIN if not can_login else EXPIRED if expired else OPEN
    return SurveyedAccount(
        name=str(name),
        status=status,
        locked=not can_login,
        profile="",
        common=False,
        vendor_maintained=bool(built_in),
        password_lifetime=None,
        failed_login_limit=None,
        failed_logins=None,
        unreadable=(NO_LIFETIME, NO_LIMIT, NO_COUNT),
        deliberately_locked=not can_login,
        lock_is_login_attribute=True,
        valid_until=ValidUntil(text=text, expired=bool(expired)),
    )
