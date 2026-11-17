"""Every login on a SQL Server instance, as `report accounts` reads it
(:mod:`sopuli.driver.mssql.survey`, #1555). Tier 0."""

from __future__ import annotations

from typing import Any

from sopuli.driver.mssql import survey
from sopuli.driver.mssql.accounts import EXPIRED, LOCKED, LOCKED_TIMED, OPEN
from sopuli.driver.mssql.survey import (
    COUNT_ON_LINUX,
    LIFETIME_FROM_POLICY,
    LIMIT_FROM_POLICY,
    NO_FLAGS,
)
from sopuli.driver.survey import SurveyedAccount


class FakeCursor:
    """Answers :data:`~sopuli.driver.mssql.survey.LOGINS` with its rows, and
    keeps what it was sent."""

    def __init__(self, *rows: tuple[Any, ...]) -> None:
        self.rows = list(rows)
        self.sent: list[tuple[str, Any]] = []

    def execute(self, statement: Any, parameters: Any = None, /) -> None:
        self.sent.append((statement, parameters))

    def fetchall(self) -> Any:
        return self.rows


def row(**changes: Any) -> tuple[Any, ...]:
    values: dict[str, Any] = {
        "name": "acme_app",
        "type": "S",
        "disabled": False,
        "policy": True,
        "expiration": False,
        "locked_out": 0,
        "expired": 0,
        "must_change": 0,
        "bad": 2,
    }
    values.update(changes)
    return tuple(values.values())


def one(platform: str | None = "Windows", **changes: Any) -> SurveyedAccount:
    (account,) = survey.survey(FakeCursor(row(**changes)), platform=platform)
    return account


def test_one_read_with_nothing_bound_and_no_hash_column() -> None:
    cursor = FakeCursor()
    survey.survey(cursor, platform="Linux")

    assert cursor.sent == [(survey.LOGINS, None)]
    assert "password_hash" not in survey.LOGINS
    assert "PasswordHash" not in survey.LOGINS


def test_logins_come_ordered_by_name() -> None:
    cursor = FakeCursor(row(name="acme_web"), row(name="acme_app"), row(name="EXAMPLE\\acme_ops"))

    names = [account.name for account in survey.survey(cursor, platform="Linux")]

    assert names == sorted(names)


def test_an_open_sql_login_on_windows_reads_its_count() -> None:
    account = one()

    assert account.status == OPEN
    assert account.locked is False
    assert account.deliberately_locked is False
    assert account.failed_logins == 2
    assert account.password_lifetime == "unlimited"
    assert account.failed_login_limit is None
    assert account.unreadable == (LIMIT_FROM_POLICY,)
    assert account.profile == ""
    assert account.vendor_maintained is False


def test_a_disabled_login_is_a_lock_somebody_set() -> None:
    """`is_disabled` is `ALTER LOGIN … DISABLE` (#1554, H4)."""
    account = one(disabled=True)

    assert account.status == LOCKED
    assert account.locked is True
    assert account.deliberately_locked is True


def test_a_lockout_is_a_lock_nobody_set() -> None:
    account = one(locked_out=1)

    assert account.status == LOCKED_TIMED
    assert account.locked is True
    assert account.deliberately_locked is False


def test_must_change_reads_as_expired() -> None:
    """The server answers `18488` until the password is changed (LK5)."""
    assert one(must_change=1).status == EXPIRED
    assert one(expired=1).status == EXPIRED


def test_expiration_on_leaves_the_lifetime_not_checked() -> None:
    """The host's policy sets the maximum age, which `LOGINPROPERTY` does
    not give (#1555, decision 3)."""
    account = one(expiration=True, policy=False)

    assert account.password_lifetime is None
    assert account.failed_login_limit == "unlimited"
    assert account.unreadable == (LIFETIME_FROM_POLICY,)


def test_policy_off_is_no_limit_on_any_host() -> None:
    """Nothing counts and nothing locks with the policy off (WP5)."""
    assert one(policy=False).failed_login_limit == "unlimited"
    assert one("Linux", policy=False).failed_login_limit == "unlimited"


def test_on_linux_the_limit_is_unlimited_and_the_count_unknown() -> None:
    """No login locks on Linux, and `BadPasswordCount` stops at 1 (LK2)."""
    account = one("Linux")

    assert account.failed_login_limit == "unlimited"
    assert account.failed_logins is None
    assert account.unreadable == (COUNT_ON_LINUX,)


def test_a_host_that_names_no_platform_is_treated_as_windows() -> None:
    account = one(None)

    assert account.failed_login_limit is None
    assert account.failed_logins == 2


def test_a_windows_login_has_no_password_values() -> None:
    """Listed (#1555, decision 2), with a reason for each value it lacks."""
    account = one(
        name="EXAMPLE\\acme_ops",
        type="U",
        policy=None,
        expiration=None,
        locked_out=None,
        expired=None,
        must_change=None,
        bad=None,
    )

    assert account.status == OPEN
    assert account.locked is False
    assert account.password_lifetime is None
    assert account.failed_login_limit is None
    assert account.failed_logins is None
    assert account.unreadable == ("a Windows login has no password",) * 3


def test_a_disabled_windows_group_is_locked() -> None:
    account = one(name="EXAMPLE\\acme_admins", type="G", disabled=True, policy=None)

    assert account.status == LOCKED
    assert account.deliberately_locked is True


def test_a_sql_login_whose_flags_were_not_read_is_not_guessed() -> None:
    account = one(policy=None, expiration=None)

    assert account.password_lifetime is None
    assert account.failed_login_limit is None
    assert account.unreadable == (NO_FLAGS, NO_FLAGS)


def test_the_products_own_logins_are_left_out_unless_named_and_sa_is_listed() -> None:
    assert one(name="##MS_PolicyEventProcessingLogin##").vendor_maintained is True
    assert one(name="##MS_SQLResourceSigningCertificate##", type="C").vendor_maintained
    assert one(name="sa").vendor_maintained is False
