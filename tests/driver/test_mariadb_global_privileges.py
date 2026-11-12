"""How the optional view `sopuli.global_privileges` is checked and read (#1483). Tier 0.

The server's answers are `17_global_privileges_view_probe.py`'s; the live test
runs the same reads.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.driver.mariadb.global_privileges import (
    ABSENT,
    COLUMNS_QUERY,
    EXPECTED,
    ROWS_QUERY,
    grantee,
    read,
)

ALL = [(column,) for column in EXPECTED]
TOOL = ("sopuli_admin", "%")
TOOL_ROW = ("'sopuli_admin'@'%'", "CREATE USER", "NO")


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


def _read(*answers: Any) -> Any:
    user, host = TOOL
    return read(Answers(*answers), user=user, host=host)


def test_the_grantee_is_built_never_parsed() -> None:
    # A quote in the name is not escaped by the server (probe 17).
    assert grantee("acme_o'q", "192.0.2.%") == "'acme_o'q'@'192.0.2.%'"


def test_each_accounts_privileges_with_usage_left_out() -> None:
    cursor = Answers(
        ALL,
        [
            TOOL_ROW,
            ("'acme_ops'@'localhost'", "PROCESS", "YES"),
            ("'acme_ops'@'localhost'", "CONNECTION ADMIN", "NO"),
            ("'acme_app'@'%'", "USAGE", "NO"),
        ],
    )
    states = read(cursor, user="sopuli_admin", host="%")
    assert cursor.executed == [COLUMNS_QUERY, ROWS_QUERY]
    assert states.of("acme_ops", "localhost") == (("CONNECTION ADMIN", False), ("PROCESS", True))
    # USAGE alone is no privilege; an account with no row holds none.
    assert states.of("acme_app", "%") == ()
    assert states.of("acme_nobody", "%") == ()


def test_no_columns_is_absent() -> None:
    states = _read([])
    assert (states.rows, states.reason, states.broken) == (None, ABSENT, None)


def test_a_column_outside_the_three_is_never_read() -> None:
    cursor = Answers([*ALL, ("authentication_string",)])
    states = read(cursor, user="sopuli_admin", host="%")
    assert states.broken == "it has columns the tool does not expect (authentication_string)"
    assert cursor.executed == [COLUMNS_QUERY]


def test_column_names_are_compared_without_case() -> None:
    lower = [(column.lower(),) for column in EXPECTED]
    assert _read(lower, [TOOL_ROW]).broken is None


def test_without_the_tool_accounts_own_row_the_definer_cannot_read_mysql() -> None:
    # A definer below SELECT on mysql.* answers with its own row alone.
    states = _read(ALL, [("'sopuli_grants_definer'@'localhost'", "USAGE", "NO")])
    assert states.rows is None
    assert states.broken == (
        "the tool account's own row is missing, so its definer cannot read mysql.*"
    )


@pytest.mark.parametrize(
    ("number", "broken"),
    [
        (1045, "its definer no longer exists (1045)"),
        (1356, "it cannot be read (1356)"),
        (1449, "the server refused to read it (1449)"),
    ],
)
def test_a_refusal_is_broken_and_names_only_the_number(number: int, broken: str) -> None:
    states = _read(ALL, ServerError(number, "the server's words ... secret"))
    assert (states.rows, states.broken) == (None, broken)
    assert "secret" not in (states.reason or "")


@pytest.mark.parametrize("number", [1142, 1146])
def test_no_grant_or_a_dropped_view_is_absent(number: int) -> None:
    states = _read(ALL, ServerError(number, "denied"))
    assert (states.rows, states.reason, states.broken) == (None, ABSENT, None)


@pytest.mark.parametrize(
    "error",
    [ServerError("no number"), ServerError(2013, "Lost connection to server during query")],
)
def test_a_client_fault_is_the_targets(error: ServerError) -> None:
    with pytest.raises(ServerError):
        _read(ALL, error)
