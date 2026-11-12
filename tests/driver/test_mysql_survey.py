"""The MySQL survey for `report accounts` (#1461). Tier 0: a fake cursor answers
the survey's reads with rows in the shape of `10_report_read_probe.py`'s
(RE0, RE1), and the session's optional read fails as the server fails it.
Fictional names only."""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.driver.mysql import survey
from sopuli.driver.mysql.accounts import DEFAULT_LIFETIME
from sopuli.driver.mysql.admin import MANDATORY_ROLES
from sopuli.driver.mysql.session import MysqlSession
from sopuli.driver.protocol import DriverError
from sopuli.driver.survey import AccountSurvey

APP = ("acme_app", "%", "N", "N", None)


class _Cursor:
    def __init__(
        self,
        users: list[tuple[Any, ...]],
        *,
        roles: list[tuple[str, str]] | None = None,
        default_lifetime: int = 0,
        locks: list[tuple[Any, ...]] | None = None,
        mandatory: str = "",
    ) -> None:
        self.mandatory = mandatory
        self.answers = {
            survey.ACCOUNTS: list(users),
            survey.ROLES: list(roles or []),
            survey.LOCKS: list(locks or []),
        }
        self.default_lifetime = default_lifetime
        self.queries: list[str] = []

    def execute(self, query: str, args: Any = None, /) -> None:
        assert args is None, "the survey binds nothing"
        self.queries.append(query)

    def fetchone(self) -> Any:
        if self.queries[-1] == MANDATORY_ROLES:
            return (self.mandatory,)
        assert self.queries[-1] == DEFAULT_LIFETIME
        return (self.default_lifetime,)

    def fetchall(self) -> Any:
        return self.answers[self.queries[-1]]


def surveyed(cursor: _Cursor, locks: survey.Locks | None = None) -> dict[str, Any]:
    read = survey.survey(cursor, locks or survey.Locks(None, survey.NO_GRANT))
    return {one.name: one for one in read}


def test_one_row_per_user_at_host() -> None:
    cursor = _Cursor(
        [APP, ("acme_app", "192.0.2.%", "Y", "N", 90), ("acme_app", "localhost", "N", "Y", 0)]
    )
    found = surveyed(cursor)

    assert list(found) == ["acme_app@%", "acme_app@192.0.2.%", "acme_app@localhost"]
    assert found["acme_app@%"].status == "OPEN"
    assert found["acme_app@192.0.2.%"].status == "LOCKED"
    assert found["acme_app@localhost"].status == "EXPIRED"


def test_the_reads_hold_no_hash_column() -> None:
    for query in (survey.ACCOUNTS, survey.ROLES, survey.LOCKS):
        lowered = query.lower()
        for column in ("authentication_string", "user_attributes", "password_reuse_history"):
            assert column not in lowered


def test_a_role_is_left_out() -> None:
    """M3: a role reads as locked and expired; only `role_edges` tells it apart."""
    cursor = _Cursor(
        [APP, ("acme_role", "%", "Y", "Y", None), ("acme_unheld", "%", "Y", "Y", None)],
        roles=[("acme_role", "%")],
    )
    found = surveyed(cursor)

    assert "acme_role@%" not in found
    # A role nobody holds cannot be told from a locked account.
    assert found["acme_unheld@%"].locked is True


def test_a_mandatory_role_is_left_out() -> None:
    """It goes to every account and has no row in `role_edges`."""
    cursor = _Cursor(
        [APP, ("acme_reader", "%", "Y", "Y", None), ("acme_audit", "10.%", "Y", "Y", None)],
        mandatory="acme_reader,`acme_audit`@`10.%`",
    )
    assert list(surveyed(cursor)) == ["acme_app@%"]


def test_the_accounts_come_ordered_by_name() -> None:
    """The contract's order, not the server's collation: `.` sorts before `@`."""
    cursor = _Cursor([("acme", "%", "N", "N", None), ("acme.x", "%", "N", "N", None)])
    read = survey.survey(cursor, survey.Locks(None, survey.NO_GRANT))
    assert [one.name for one in read] == ["acme.x@%", "acme@%"]


def test_a_role_is_matched_by_host_without_case() -> None:
    cursor = _Cursor(
        [("acme_role", "Example.COM", "Y", "Y", None)], roles=[("acme_role", "example.com")]
    )
    assert surveyed(cursor) == {}


@pytest.mark.parametrize(
    ("lifetime", "default", "expected"),
    [(90, 0, 90), (0, 30, "unlimited"), (None, 0, "unlimited"), (None, 30, 30)],
)
def test_the_lifetime(lifetime: int | None, default: int, expected: object) -> None:
    """RE1: the days, 0 for never, NULL for the server's default, where 0 is never."""
    cursor = _Cursor([("acme_app", "%", "N", "N", lifetime)], default_lifetime=default)
    assert surveyed(cursor)["acme_app@%"].password_lifetime == expected


def test_the_failed_login_limit_is_never_read() -> None:
    """M1: it is beside a retained hash in `User_attributes`."""
    found = surveyed(_Cursor([APP]))["acme_app@%"]
    assert found.failed_login_limit is None
    assert found.unreadable[0] == survey.NO_LIMIT_READ


def test_a_lock_somebody_set_is_deliberate() -> None:
    found = surveyed(_Cursor([("acme_app", "%", "Y", "N", None)]))["acme_app@%"]
    assert (found.locked, found.deliberately_locked) == (True, True)


def test_mysqls_own_accounts_are_vendor_maintained() -> None:
    cursor = _Cursor(
        [("mysql.sys", "localhost", "Y", "N", None), ("mysql.sys", "%", "N", "N", None)]
    )
    found = surveyed(cursor)
    assert found["mysql.sys@localhost"].vendor_maintained
    # A site's own account at another host is not MySQL's.
    assert not found["mysql.sys@%"].vendor_maintained


def test_without_the_locks_table_the_count_is_unknown() -> None:
    found = surveyed(_Cursor([APP]), survey.Locks(None, survey.NO_TABLE))["acme_app@%"]
    assert found.failed_logins is None
    assert found.unreadable == (survey.NO_LIMIT_READ, survey.NO_TABLE)


def test_the_locks_table_gives_the_count_and_a_block() -> None:
    """RE1 on 9.7.4: after three wrong passwords, YES, 3, 0."""
    cursor = _Cursor(
        [APP, ("acme_api", "%", "N", "N", None), ("acme_web", "%", "N", "N", None)],
        locks=[("acme_app", "%", "YES", 3, 0), ("acme_api", "%", "NO", 3, 2)],
    )
    found = surveyed(cursor, survey.read_locks(cursor))

    blocked = found["acme_app@%"]
    assert (blocked.locked, blocked.deliberately_locked) == (True, False)
    assert blocked.status == "LOCKED(TIMED)"
    assert blocked.failed_logins == 3
    assert blocked.unreadable == (survey.NO_LIMIT_READ,)
    assert found["acme_api@%"].failed_logins == 1
    assert found["acme_api@%"].locked is False
    # No row: the server keeps no count for it, or none was measured.
    assert found["acme_web@%"].failed_logins is None
    assert found["acme_web@%"].unreadable[-1] == survey.NO_ROW


@pytest.mark.parametrize(
    ("code", "reason"),
    [(1142, survey.NO_GRANT), (survey.NO_SUCH_TABLE, survey.NO_TABLE)],
)
def test_the_session_takes_a_refused_locks_read_as_unknown(
    monkeypatch: pytest.MonkeyPatch, code: int, reason: str
) -> None:
    session = MysqlSession.__new__(MysqlSession)
    assert isinstance(session, AccountSurvey)
    reads: list[Any] = []

    def read(reader: Any, **_: Any) -> Any:
        if reader is survey.read_locks:
            raise DriverError("refused", code=str(code))
        reads.append(reader)
        return reader(_Cursor([APP]))

    monkeypatch.setattr(session, "_read", read)
    monkeypatch.setattr(session, "_read_grants", read)
    accounts, profiles = session.survey_with_profiles()

    assert profiles == frozenset()
    assert accounts[0].unreadable[-1] == reason


def test_the_session_raises_any_other_error(monkeypatch: pytest.MonkeyPatch) -> None:
    session = MysqlSession.__new__(MysqlSession)

    def read(reader: Any, **_: Any) -> Any:
        raise DriverError("gone", code="2013")

    monkeypatch.setattr(session, "_read", read)
    with pytest.raises(DriverError, match="gone"):
        session.survey_with_profiles()
