"""How the optional view `sopuli.account_state` is checked and read (#1491). Tier 0.

A cursor answers each statement in turn. The server's answers are
`16_definer_view_probe.py`'s (#1479); the live test runs the same reads.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from sopuli.driver.mariadb.account_state import (
    ABSENT,
    COLUMNS_QUERY,
    DEFAULT_LIFETIME,
    EXPECTED,
    ROWS_QUERY,
    read,
)
from sopuli.driver.mariadb.survey import survey

ALL = [(column,) for column in sorted(EXPECTED)]


class ServerError(Exception):
    """PyMySQL's errors carry the server's number first."""


class Answers:
    def __init__(self, *answers: Any) -> None:
        self.answers = list(answers)
        self.executed: list[str] = []
        self.last: Any = None

    def execute(self, statement: Any, parameters: Any = None, /) -> None:
        self.executed.append(statement)
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        self.last = answer

    def fetchone(self) -> Any:
        return self.last

    def fetchall(self) -> Any:
        return self.last


def test_no_columns_is_an_absent_or_ungranted_view() -> None:
    cursor = Answers([])
    states = read(cursor)
    assert (states.rows, states.reason, states.broken) == (None, ABSENT, None)
    assert cursor.executed == [COLUMNS_QUERY]


def test_a_column_outside_the_set_is_never_read() -> None:
    cursor = Answers([*ALL, ("authentication_string",)])
    states = read(cursor)
    assert states.rows is None
    assert states.broken == "it has columns the tool does not expect (authentication_string)"
    # Its rows were never asked for.
    assert cursor.executed == [COLUMNS_QUERY]


def test_a_column_grant_that_hides_a_read_column_is_broken() -> None:
    cursor = Answers([("User",), ("Host",), ("account_locked",)])
    states = read(cursor)
    assert states.broken == (
        "the tool account cannot read its columns password_lifetime, password_last_changed"
    )


@pytest.mark.parametrize(
    ("number", "broken"),
    [
        (1045, "its definer no longer exists (1045)"),
        (1356, "its definer cannot read mysql.global_priv (1356)"),
    ],
)
def test_a_definer_that_is_gone_or_cannot_read_is_broken(number: int, broken: str) -> None:
    states = read(Answers(ALL, (0,), ServerError(number, "refused")))
    assert (states.rows, states.broken) == (None, broken)


def test_a_grant_revoked_between_the_two_reads_is_absent() -> None:
    states = read(Answers(ALL, (0,), ServerError(1142, "denied")))
    assert (states.rows, states.reason, states.broken) == (None, ABSENT, None)


def test_any_other_error_is_raised() -> None:
    with pytest.raises(ServerError):
        read(Answers(ALL, (0,), ServerError(2013, "lost connection")))


def test_the_rows_as_the_probe_read_them() -> None:
    cursor = Answers(
        ALL,
        (180,),
        [
            ("acme_lock", "%", "1", None, "1762905600"),
            ("acme_unlocked", "%", "0", "90", "1762905600"),
            ("acme_never", "%", None, "0", "1762905600"),
            ("acme_default", "%", None, "-1", "0"),
            ("acme_unset", "%", None, None, None),
        ],
    )
    states = read(cursor)
    assert cursor.executed == [COLUMNS_QUERY, DEFAULT_LIFETIME, ROWS_QUERY]
    at = datetime(2025, 11, 12, tzinfo=UTC)
    assert states.get("acme_lock", "%") is not None
    assert [
        (s.locked, s.lifetime, s.changed_at)
        for s in (states.get(n, "%") for n in ("acme_lock", "acme_unlocked", "acme_never"))
        if s is not None
    ] == [(True, 180, at), (False, 90, at), (False, "unlimited", at)]
    # NULL or -1 is the server's default; a time of 0 is no time.
    default = states.get("acme_default", "%")
    assert default is not None
    assert (default.lifetime, default.changed_at) == (180, None)
    unset = states.get("acme_unset", "%")
    assert unset is not None
    assert (unset.locked, unset.lifetime) == (False, 180)


def test_a_server_default_of_zero_is_no_lifetime() -> None:
    states = read(Answers(ALL, (0,), [("acme_app", "%", None, None, "1762905600")]))
    found = states.get("acme_app", "%")
    assert found is not None
    assert found.lifetime == "unlimited"


def test_the_survey_reads_the_lock_and_lifetime_from_the_view() -> None:
    states = read(Answers(ALL, (0,), [("acme_lock", "%", "1", "90", "1762905600")]))
    accounts = survey(Answers([("acme_lock", "%", "N"), ("acme_gone", "%", "N")]), states)
    by_name = {account.name: account for account in accounts}
    lock = by_name["acme_lock@%"]
    assert (lock.locked, lock.deliberately_locked, lock.status, lock.password_lifetime) == (
        True,
        True,
        "LOCKED",
        90,
    )
    # An account the view has no row for is not checked, with that reason.
    gone = by_name["acme_gone@%"]
    assert gone.locked is None
    assert (
        gone.unreadable[0] == "the optional view sopuli.account_state has no row for this account"
    )


def test_without_the_view_the_survey_gives_its_reason() -> None:
    states = read(Answers([]))
    (account,) = survey(Answers([("acme_app", "%", "Y")]), states)
    assert (account.locked, account.password_lifetime) == (None, None)
    assert account.unreadable[:2] == (ABSENT, ABSENT)
    assert account.status == "EXPIRED"
