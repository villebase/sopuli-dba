"""`OracleSession.run_statement` without a database (UC-3, #1661). Tier 0."""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.driver.protocol import DriverError
from sopuli.sql.guard import RowGuard
from sopuli.sql.statement import classify

session_module = pytest.importorskip("sopuli.driver.oracle.session")


class _Untouched:
    """A connection that fails the test if anything is sent on it."""

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"the lost session used its connection: {name}")


def _lost_session() -> Any:
    session = session_module.OracleSession(
        connection=_Untouched(), target=None, correlation_id="test"
    )
    session._connection_lost = True
    return session


def test_a_lost_session_refuses_a_statement_before_sending_anything() -> None:
    session = _lost_session()
    assert session.connection_lost is True

    with pytest.raises(DriverError) as raised:
        session.run_statement(
            classify("SELECT 1 FROM dual"), guard=None, commit=False, max_rows=1, timeout_ms=0
        )

    assert "closed" in raised.value.message
    assert "ORA-03156" in raised.value.message


def test_a_lost_session_does_not_send_its_identity_queries() -> None:
    session = _lost_session()

    with pytest.raises(DriverError):
        session.database_identity()


class _Detail:
    full_code = "ORA-03113"
    code = 3113
    message = "ORA-03113: end-of-file on communication channel"


class _Cursor:
    rowcount = 1

    def __init__(self, fail: bool) -> None:
        self.fail = fail

    def __enter__(self) -> Any:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def execute(self, *_: object, **__: object) -> None:
        if self.fail:
            raise RuntimeError(_Detail())


class _CommitFails:
    """A connection whose statement changes one row and whose commit fails,
    or, with ``fail_statement``, whose statement fails."""

    call_timeout = 0

    def __init__(self, *, fail_statement: bool = False) -> None:
        self.fail_statement = fail_statement
        self.rolled_back = 0

    def cursor(self) -> Any:
        return _Cursor(self.fail_statement)

    def rollback(self) -> None:
        self.rolled_back += 1

    def commit(self) -> None:
        raise RuntimeError(_Detail())

    def is_healthy(self) -> bool:
        return True


def test_a_failed_commit_says_its_outcome_is_unknown() -> None:
    connection = _CommitFails()
    session = session_module.OracleSession(
        connection=connection, target=None, correlation_id="test"
    )

    with pytest.raises(DriverError) as raised:
        session.run_statement(
            classify("UPDATE t SET x = 1"),
            guard=RowGuard(expect=1),
            commit=True,
            max_rows=0,
            timeout_ms=1000,
        )

    assert raised.value.commit_failed is True
    assert raised.value.code == "ORA-03113"


def test_a_failed_statement_is_not_a_failed_commit() -> None:
    connection = _CommitFails(fail_statement=True)
    session = session_module.OracleSession(
        connection=connection, target=None, correlation_id="test"
    )

    with pytest.raises(DriverError) as raised:
        session.run_statement(
            classify("UPDATE t SET x = 1"),
            guard=RowGuard(expect=1),
            commit=True,
            max_rows=0,
            timeout_ms=1000,
        )

    assert raised.value.commit_failed is False


def test_a_long_column_is_cut_at_the_lob_limit() -> None:
    limit = session_module.LOB_LIMIT

    cut, was_cut = session_module._cell("x" * (limit + 1), long=True)
    assert (len(str(cut)), was_cut) == (limit, True)

    cut, was_cut = session_module._cell(b"\x01" * (limit + 1), long=True)
    assert (len(str(cut)), was_cut) == (limit * 2, True)

    short, was_cut = session_module._cell("x" * limit, long=True)
    assert (len(str(short)), was_cut) == (limit, False)
