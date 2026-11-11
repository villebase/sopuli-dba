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

The expiry is compared on the server, with the expression
:mod:`sopuli.driver.postgres.roles` uses, so the report and `creds status`
agree on which role has expired.

``password_lifetime``, ``failed_login_limit`` and ``failed_logins`` are
``None`` because PostgreSQL has no such value, and each reason says so. The
registry's ``not_applicable`` turns the two checks into *not applicable*. The
count is information, and shows as ``unknown`` with that reason.
"""

from __future__ import annotations

from typing import Any

from sopuli.driver.postgres.roles import BUILT_IN, EXPIRED, EXPIRED_NOW, NOLOGIN, OPEN
from sopuli.driver.protocol import Cursor
from sopuli.driver.survey import SurveyedAccount, ValidUntil

#: Why each field PostgreSQL has no value for is ``None``, in
#: :attr:`SurveyedAccount.unreadable`'s order.
NO_LIFETIME = "PostgreSQL has no password lifetime"
NO_LIMIT = "PostgreSQL has no failed-login limit"
NO_COUNT = "PostgreSQL keeps no failed-login count"

#: One row per role, ordered by name. The date comes as text, in UTC, and
#: ``infinity`` or ``-infinity`` as the server spells them: the expiry is
#: compared on the server, so no ``datetime`` is built, and a date Python's
#: ``datetime`` cannot hold, such as one after the year 9999, cannot fail the
#: read (#1464 review).
SURVEY_QUERY = (
    f"select r.rolname, r.rolcanlogin, {BUILT_IN}, "
    "case when isfinite(r.rolvaliduntil) "
    "then to_char(r.rolvaliduntil at time zone 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') "
    "else r.rolvaliduntil::text end, "
    f"{EXPIRED_NOW} "
    "from pg_roles r order by r.rolname"
)


def survey(cursor: Cursor) -> tuple[SurveyedAccount, ...]:
    """Every role on the cluster, ordered by name."""
    cursor.execute(SURVEY_QUERY)
    return tuple(surveyed_of(row) for row in cursor.fetchall())


def surveyed_of(row: tuple[Any, ...]) -> SurveyedAccount:
    """One :data:`SURVEY_QUERY` row as a :class:`SurveyedAccount`."""
    name, can_login, built_in, valid_until, expired = row
    text = None if valid_until is None else str(valid_until)
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
