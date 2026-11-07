"""Every account on a target, as a report reads it (UC-5).

Product-neutral types. A driver that can survey its accounts returns
:class:`SurveyedAccount` values. Only Oracle can, through
``OracleSession.survey_accounts``, which a caller finds with ``getattr``: the
:class:`~sopuli.driver.protocol.Session` protocol does not list it.

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

    ``status`` is the database's own word, as read. ``locked``,
    ``password_lifetime``, ``failed_login_limit`` and ``failed_logins`` are
    ``None`` where the target cannot read them, and ``unreadable`` then holds
    one reason for each field that is ``None``.
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
