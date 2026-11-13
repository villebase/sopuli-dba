"""How MySQL's optional view `sopuli.account_state` is checked and read (#1502). Tier 0.

The server's answers are `12_definer_view_probe.py`'s (DV2, DV6, DV7); the
live test runs the same reads.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.driver.mysql.account_state import (
    ABSENT,
    EXPECTED,
    NO_ROW,
    ROWS_QUERY,
    read,
)
from sopuli.driver.mysql_family.optional_view import columns_query

ALL = [(column,) for column in EXPECTED]
COLUMNS_QUERY = columns_query("sopuli", "account_state")


class ServerError(Exception):
    """PyMySQL's errors carry the number first."""


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


def test_each_accounts_limit_keyed_by_user_and_folded_host() -> None:
    # DV2: NULL for none set, the number as set; 0 removes the key (NULL).
    cursor = Answers(
        ALL,
        [
            ("acme_app", "%", "3", "2"),
            ("acme_web", "Example.COM", None, None),
            ("acme_ops", "localhost", 5, -1),
        ],
    )
    states = read(cursor)
    assert cursor.executed == [COLUMNS_QUERY, ROWS_QUERY]
    assert states.limit(("acme_app", "%")) == (3, None)
    assert states.limit(("acme_web", "example.com")) == ("unlimited", None)
    # UNBOUNDED reads -1, and blocks.
    assert states.limit(("acme_ops", "localhost")) == (5, None)
    assert states.limit(("acme_new", "%")) == (None, NO_ROW)


@pytest.mark.parametrize("lock_days", [None, 0, "0"])
def test_a_limit_without_a_lock_time_never_blocks(lock_days: object) -> None:
    """The server counts and blocks only when both are non-zero (#1508)."""
    states = read(Answers(ALL, [("acme_app", "%", 3, lock_days)]))
    assert states.limit(("acme_app", "%")) == ("unlimited", None)


def test_the_rows_read_no_hash_column() -> None:
    assert ROWS_QUERY == (
        "select User, Host, failed_login_attempts, password_lock_time_days "
        "from sopuli.account_state"
    )


def test_no_columns_is_absent() -> None:
    states = read(Answers([]))
    assert (states.rows, states.reason, states.broken) == (None, ABSENT, None)
    assert states.limit(("acme_app", "%")) == (None, ABSENT)


def test_a_column_outside_the_six_is_never_read() -> None:
    # DV6: a wider view lists authentication_string before any row is read.
    cursor = Answers([*ALL, ("authentication_string",)])
    states = read(cursor)
    assert states.broken == "it has columns the tool does not expect (authentication_string)"
    assert cursor.executed == [COLUMNS_QUERY]
    assert states.limit(("acme_app", "%"))[1] == (
        "the optional view sopuli.account_state is not used: "
        "it has columns the tool does not expect (authentication_string)"
    )


def test_a_column_grant_without_the_limit_is_broken() -> None:
    # DV8: under a column grant only the granted columns are listed.
    states = read(Answers([("User",), ("Host",), ("retained_password",)]))
    assert states.broken == (
        "the tool account cannot read its columns failed_login_attempts, password_lock_time_days"
    )


def test_column_names_are_compared_without_case() -> None:
    lower = [(column.lower(),) for column in EXPECTED]
    assert read(Answers(lower, [])).broken is None


def test_a_value_that_is_no_limit_is_broken_and_never_repeated() -> None:
    states = read(Answers(ALL, [("acme_app", "%", "$A$005$secret", 1)]))
    assert states.broken == "a column holds values the tool does not expect"
    assert "secret" not in (states.reason or "")


@pytest.mark.parametrize(
    ("number", "broken"),
    [
        (1045, "its definer no longer exists (1045)"),
        (1356, "its definer cannot read mysql.user (1356)"),
        (1449, "the server refused to read it (1449)"),
    ],
)
def test_a_refusal_is_broken_and_names_only_the_number(number: int, broken: str) -> None:
    # DV7: a dropped definer answers 1045 in a session already logged in.
    states = read(Answers(ALL, ServerError(number, "the server's words ... secret")))
    assert (states.rows, states.broken) == (None, broken)
    assert "secret" not in (states.reason or "")


def test_no_grant_is_absent() -> None:
    # DV7: no view, no schema and no grant all answer 1142.
    states = read(Answers(ALL, ServerError(1142, "denied")))
    assert (states.rows, states.reason, states.broken) == (None, ABSENT, None)


@pytest.mark.parametrize(
    "error",
    [ServerError("no number"), ServerError(2013, "Lost connection to server during query")],
)
def test_a_client_fault_is_the_targets(error: ServerError) -> None:
    with pytest.raises(ServerError):
        read(Answers(ALL, error))
