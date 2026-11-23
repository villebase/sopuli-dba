"""`OracleSession.run_statement` without a database (UC-3, #1661). Tier 0."""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.driver.protocol import DriverError
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


def test_a_long_column_is_cut_at_the_lob_limit() -> None:
    limit = session_module.LOB_LIMIT

    cut, was_cut = session_module._cell("x" * (limit + 1), long=True)
    assert (len(str(cut)), was_cut) == (limit, True)

    cut, was_cut = session_module._cell(b"\x01" * (limit + 1), long=True)
    assert (len(str(cut)), was_cut) == (limit * 2, True)

    short, was_cut = session_module._cell("x" * limit, long=True)
    assert (len(str(short)), was_cut) == (limit, False)
