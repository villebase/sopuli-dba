"""The reset's lockout evidence on Oracle, read from the database (#1454). Tier 0.

The reset still refuses a ``LOCKED`` account. Under a ``PASSWORD_LOCK_TIME``
of ``UNLIMITED`` that the profile sets itself, an ``LCOUNT`` at the profile's
own ``FAILED_LOGIN_ATTEMPTS`` only changes what the refusal says. Fictional
names only.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.driver.oracle import accounts
from sopuli.driver.oracle.accounts import (
    COMMON_QUERY,
    LCOUNT_QUERY,
    OWN_LOCK_LIMITS_QUERY,
    read_lockout_evidence,
)

NAME = "ACME_DEV_ALICE"
PROFILE = "ACME_LOCK_PROF"
OWN_LIMITS = [("PASSWORD_LOCK_TIME", "UNLIMITED"), ("FAILED_LOGIN_ATTEMPTS", "2")]


class _Cursor:
    """Answers per statement; an exception given as the answer is raised."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.asked: list[str] = []
        self.sql = ""

    def execute(self, sql: str, parameters: Any = None, /) -> _Cursor:
        self.asked.append(sql)
        self.sql = sql
        answer = self.answers.get(sql)
        if isinstance(answer, Exception):
            raise answer
        return self

    def fetchone(self) -> Any:
        rows = self.answers.get(self.sql) or []
        return rows[0] if rows else None

    def fetchall(self) -> Any:
        return self.answers.get(self.sql) or []


def cursor(common: Any = None, own: Any = None) -> _Cursor:
    """A local account, locked out at its profile's own limit, unless told otherwise."""
    return _Cursor(
        {
            COMMON_QUERY: [("NO",)] if common is None else common,
            OWN_LOCK_LIMITS_QUERY: OWN_LIMITS if own is None else own,
            LCOUNT_QUERY: [(2,)],
        }
    )


def test_a_local_account_at_its_profiles_own_limit_is_named() -> None:
    found = read_lockout_evidence(cursor(), NAME, "LOCKED", PROFILE)

    assert found is not None
    assert "count, 2," in found


def test_an_open_account_reads_nothing() -> None:
    asked = cursor()
    assert read_lockout_evidence(asked, NAME, "OPEN", PROFILE) is None
    assert asked.asked == []


@pytest.mark.parametrize("common", [[("YES",)], []])
def test_a_common_account_or_an_unread_one_gives_none(common: Any) -> None:
    """A PDB cannot read a common account's count and limits (§2)."""
    asked = cursor(common=common)
    assert read_lockout_evidence(asked, NAME, "LOCKED", PROFILE) is None
    assert LCOUNT_QUERY not in asked.asked


@pytest.mark.parametrize(
    "own",
    [
        [("PASSWORD_LOCK_TIME", "DEFAULT"), ("FAILED_LOGIN_ATTEMPTS", "2")],
        [("PASSWORD_LOCK_TIME", "UNLIMITED"), ("FAILED_LOGIN_ATTEMPTS", "DEFAULT")],
    ],
)
def test_a_limit_the_profile_takes_from_default_gives_none(own: Any) -> None:
    """In a PDB the DEFAULT that applies to a common profile is the root's."""
    assert read_lockout_evidence(cursor(own=own), NAME, "LOCKED", PROFILE) is None


def test_a_read_that_fails_gives_none_rather_than_an_error() -> None:
    failing = cursor(own=RuntimeError("ORA-00600: internal error"))
    assert read_lockout_evidence(failing, NAME, "LOCKED", PROFILE) is None


@pytest.mark.parametrize("user_dollar", [True, False])
def test_login_state_reads_evidence_only_behind_the_grant(
    monkeypatch: pytest.MonkeyPatch, user_dollar: bool
) -> None:
    calls: list[str] = []

    def evidence(cursor: Any, name: str, status: str, profile: str | None) -> str:
        calls.append(name)
        return "the count shows a lockout"

    row = (NAME, "LOCKED", PROFILE, None, None, None, None, None, None, None)
    monkeypatch.setattr(accounts, "_user_row", lambda cursor, account: ("q", row))
    monkeypatch.setattr(accounts, "_limits", lambda cursor, profile: {})
    monkeypatch.setattr(accounts, "_password_changed", lambda *a, **k: (None, None))
    monkeypatch.setattr(accounts, "read_lockout_evidence", evidence)

    state = accounts.login_state(_Cursor({}), NAME.lower(), user_dollar=user_dollar)

    assert state is not None
    assert state.lockout_evidence == ("the count shows a lockout" if user_dollar else None)
    assert calls == ([NAME] if user_dollar else [])
