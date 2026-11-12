"""The MariaDB survey for `report accounts` (#1462). Tier 0: a fake cursor
answers the survey's read with rows in the shape of `15_report_read_probe.py`'s
(#1448). Fictional names only."""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.loading import build_config
from sopuli.driver.mariadb import survey
from sopuli.driver.mariadb.session import MariadbSession
from sopuli.driver.protocol import DriverError
from sopuli.driver.survey import AccountSurvey
from sopuli.exit_codes import ExitCode
from sopuli.report_accounts import (
    NOT_APPLICABLE_OUTCOME,
    NOT_CHECKED,
    NOT_CHECKED_OUTCOME,
    evaluate,
    exit_code,
)


class _Cursor:
    def __init__(self, users: list[tuple[Any, ...]]) -> None:
        self.users = users
        self.queries: list[str] = []

    def execute(self, query: str, args: Any = None, /) -> None:
        assert args is None, "the survey binds nothing"
        self.queries.append(query)

    def fetchall(self) -> Any:
        assert self.queries[-1] == survey.ACCOUNTS
        return list(self.users)


def surveyed(users: list[tuple[Any, ...]]) -> dict[str, Any]:
    return {one.name: one for one in survey.survey(_Cursor(users))}


def test_one_row_per_user_at_host() -> None:
    found = surveyed(
        [("acme_app", "%", "N"), ("acme_app", "192.0.2.%", "N"), ("acme_app", "localhost", "Y")]
    )

    assert list(found) == ["acme_app@%", "acme_app@192.0.2.%", "acme_app@localhost"]
    assert found["acme_app@%"].status == "OPEN"
    assert found["acme_app@localhost"].status == "EXPIRED"


def test_the_read_holds_no_stored_value_and_leaves_roles_out() -> None:
    """§2.1's column grant: a role is a row with `is_role = 'Y'`."""
    lowered = survey.ACCOUNTS.lower()
    for column in ("authentication_string", "password,", "global_priv", "default_role"):
        assert column not in lowered
    assert "is_role = 'n'" in lowered


def test_the_accounts_come_ordered_by_name() -> None:
    """The contract's order, not the server's collation: `.` sorts before `@`."""
    read = survey.survey(_Cursor([("acme", "%", "N"), ("acme.x", "%", "N")]))
    assert [one.name for one in read] == ["acme.x@%", "acme@%"]


def test_the_lock_lifetime_limit_and_count_are_not_read() -> None:
    """R2: the lock and the lifetime are beside the stored value. R1: there is
    no limit per account. The count shows only to the account itself."""
    found = surveyed([("acme_app", "%", "N")])["acme_app@%"]

    assert found.locked is None
    assert found.deliberately_locked is None
    assert found.password_lifetime is None
    assert found.failed_login_limit is None
    assert found.failed_logins is None
    # One reason per None field, in the field order the report reads them by.
    assert found.unreadable == (
        survey.NO_LOCK_READ,
        survey.NO_LIFETIME_READ,
        survey.NO_LIMIT,
        survey.NO_COUNT_READ,
    )


def test_a_rule_reads_the_lock_and_lifetime_not_checked_and_the_limit_not_applicable() -> None:
    """R2 and R1 through the report: the account is *not checked*, exit 4."""
    cfg = build_config(
        {
            "version": 1,
            "targets": [{"name": "mariadb-dev", "type": "mariadb", "dsn": "db.example.com:3306"}],
            "reports": {
                "accounts": [
                    {
                        "accounts": ["acme_owner@%"],
                        "login": "refused",
                        "settings": {"password_lifetime": 90, "failed_login_limit": 5},
                    }
                ]
            },
        }
    )
    (row,) = evaluate("mariadb-dev", cfg, survey.survey(_Cursor([("acme_owner", "%", "N")])))

    outcomes = {f.check: (f.outcome, f.detail) for f in row.findings}
    assert outcomes["lock"] == (NOT_CHECKED_OUTCOME, survey.NO_LOCK_READ)
    assert outcomes["password_lifetime"][0] == NOT_CHECKED_OUTCOME
    assert survey.NO_LIFETIME_READ in outcomes["password_lifetime"][1]
    assert outcomes["failed_login_limit"][0] == NOT_APPLICABLE_OUTCOME
    assert row.state == NOT_CHECKED
    assert row.failed_logins_reason == survey.NO_COUNT_READ
    assert exit_code([row], unreachable=0) == ExitCode.PARTIAL


def test_mariadbs_own_account_is_vendor_maintained() -> None:
    found = surveyed([("mariadb.sys", "localhost", "N"), ("mariadb.sys", "%", "N")])
    assert found["mariadb.sys@localhost"].vendor_maintained
    # A site's own account at another host is not MariaDB's.
    assert not found["mariadb.sys@%"].vendor_maintained


def test_the_session_reads_by_the_grants_and_has_no_profiles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = MariadbSession.__new__(MariadbSession)
    assert isinstance(session, AccountSurvey)

    def read(reader: Any) -> Any:
        return reader(_Cursor([("acme_app", "%", "N")]))

    monkeypatch.setattr(session, "_read_grants", read)
    accounts, profiles = session.survey_with_profiles()

    assert [one.name for one in accounts] == ["acme_app@%"]
    assert profiles == frozenset()


def test_the_session_raises_a_refused_read(monkeypatch: pytest.MonkeyPatch) -> None:
    session = MariadbSession.__new__(MariadbSession)

    def read(reader: Any) -> Any:
        raise DriverError("refused", code="1143")

    monkeypatch.setattr(session, "_read_grants", read)
    with pytest.raises(DriverError, match="refused"):
        session.survey_with_profiles()
