"""Every account on a target, as a report reads it (UC-5).

Product-neutral types. A driver that can survey its accounts returns
:class:`SurveyedAccount` values. Only Oracle can, through
``OracleSession.survey_accounts``, and ``OracleSession.survey_with_profiles``,
which adds the target's profile names for ``report accounts``. A caller finds
them with ``getattr``: the :class:`~sopuli.driver.protocol.Session` protocol
does not list them.

A field the target cannot read truthfully is ``None``, never a guess, and
:attr:`SurveyedAccount.unreadable` says why. On an Oracle PDB, for example, a
common account's ``ACCOUNT_STATUS`` reads ``OPEN`` while the account is locked
in the root (``02-oracle-privileges.md`` §2), so its ``locked`` is ``None``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

#: A password limit: a whole number, ``"unlimited"``, or ``None`` where the
#: target cannot read the limit that applies.
Limit = int | Literal["unlimited"] | None


@dataclass(frozen=True)
class SurveyedAccount:
    """One account, with the settings a report checks.

    ``status`` is the account status this container shows, as read. It is not
    the account's lock where ``locked`` is ``None``: an Oracle PDB shows a
    common account as ``OPEN`` while the root has it locked. Decide on
    ``locked``, never on ``status``.

    ``locked``, ``password_lifetime``, ``failed_login_limit`` and
    ``failed_logins`` are ``None`` where the target cannot read them.
    ``unreadable`` then holds one reason for each field that is ``None``, in
    that field order. The reasons are sentences for a person; which fields are
    ``None`` says which checks cannot run.

    ``kept_in_root`` is whether ``CDB$ROOT`` keeps the account's lock, limits
    and failed-login count: true for a common account read in an Oracle PDB
    that is not an application container. No check that decides a state can
    run on such an account there, so the accounts report leaves it out unless
    a rule names it (UC-5 §4, #1438). In an application container it is false:
    where the values are kept there was not measured, and an
    application-common user's own container may be the target itself.
    """

    name: str
    status: str
    locked: bool | None
    profile: str
    common: bool
    vendor_maintained: bool
    password_lifetime: Limit
    failed_login_limit: Limit
    failed_logins: int | None
    unreadable: tuple[str, ...] = ()
    kept_in_root: bool = False
