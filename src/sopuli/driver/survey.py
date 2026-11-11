"""Every account on a target, as a report reads it (UC-5).

Product-neutral types. A driver that can survey its accounts returns
:class:`SurveyedAccount` values through :class:`AccountSurvey`, which
``report accounts`` asks for. Only Oracle's session implements it yet. The
:class:`~sopuli.driver.protocol.Session` protocol does not list it, so a
session that lacks it is a target the report does not check (UC-5 §3). The
privilege report also needs ``survey_accounts`` and ``survey_privileges``,
which a caller finds with ``getattr``.

**For a new product** (#1458): implement :class:`AccountSurvey`, fill each
field the product reads, set a field it cannot read truthfully to ``None``
with a reason, and list ``report.accounts`` in the driver registry's
``commands``. A check the product has no concept of is the registry's
``not_applicable``, not a ``None`` here: ``None`` means a gap somebody could
close, such as a missing grant.

A field the target cannot read truthfully is ``None``, never a guess, and
:attr:`SurveyedAccount.unreadable` says why. On an Oracle PDB, for example, a
common account's ``ACCOUNT_STATUS`` reads ``OPEN`` while the account is locked
in the root (``02-oracle-privileges.md`` §2), so its ``locked`` is ``None``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

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

    ``deliberately_locked`` is whether somebody set the lock, as against a
    lockout after failed logins: on Oracle, ``LOCKED`` rather than
    ``LOCKED(TIMED)``. It asks what
    :attr:`~sopuli.driver.protocol.UserState.deliberately_locked` asks, and
    answers it more closely: UC-2's reset reads the status alone, so under an
    ``UNLIMITED`` lock time it takes a lockout as a lock somebody set and
    refuses the reset, which errs toward the safe side. A rule's
    ``login: refused`` is met only by a deliberate lock (#1447). ``None`` where
    ``locked`` is ``None``, or where the product cannot tell the two apart.
    Under a profile whose ``PASSWORD_LOCK_TIME`` is
    ``UNLIMITED``, Oracle shows a lockout as ``LOCKED``, as it does a lock
    somebody set (measured on 23.26.3.0.0). There the Oracle survey takes a
    failed-login count that has reached the profile's limit as a lockout, and
    answers ``None`` where it cannot read the count or the limit.

    ``no_authentication`` is whether nobody can log in to the account with a
    password, whatever its lock: on Oracle, an account made ``NO
    AUTHENTICATION`` (18c and later), the usual way to make a schema owner. A
    proxy login (``GRANT CONNECT THROUGH``) can still reach such an account;
    the survey does not read proxy grants.
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
    deliberately_locked: bool | None = None
    no_authentication: bool = False


@runtime_checkable
class AccountSurvey(Protocol):
    """A session that can survey every account on its target, for `report accounts`.

    One read of the target, with nothing bound and no password or verifier
    column. The accounts come ordered by name. The second value is every
    profile the target has, by name, which `report accounts` compares with the
    profiles the config expects (#1390). A product with no profiles returns an
    empty set, and its driver registry entry lists ``profile`` in
    ``not_applicable``: the registry, not the empty set, makes the check *not
    applicable* and stops a missing profile being reported (#1458).
    """

    def survey_with_profiles(self) -> tuple[tuple[SurveyedAccount, ...], frozenset[str]]:
        """Every account on the target, and every profile it has."""
        ...
