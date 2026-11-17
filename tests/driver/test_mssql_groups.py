"""The Availability Group reads of the SQL Server driver, over fakes
(`02-mssql-privileges.md` §4, `14_availability_group_reads_probe.py`).

A group forms only on 2019 and 2025 in the matrix, never in the tier-1 lane,
so the reads against a real group are the probe's. The tier-1 test reads a
server in no group.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Target
from sopuli.driver.mssql.groups import (
    PHYSICAL_NAME,
    REPLICAS,
    ContainedGroupLoginError,
    contained_master,
    replicas,
)
from sopuli.exit_codes import ExitCode


class FakeCursor:
    def __init__(self, answers: dict[str, list[tuple[Any, ...]]]) -> None:
        self.answers = answers
        self.sent: list[str] = []
        self.rows: list[tuple[Any, ...]] = []

    def execute(self, statement: str, *params: Any) -> None:
        assert not params
        self.sent.append(statement)
        self.rows = self.answers.get(statement, [])

    def fetchone(self) -> Any:
        return self.rows[0] if self.rows else None

    def fetchall(self) -> Any:
        return self.rows

    def close(self) -> None:
        pass


def test_the_replicas_are_read_by_name() -> None:
    """AR1: both replicas, the instance itself among them."""
    cursor = FakeCursor({REPLICAS: [("sopuli2025ag1",), ("sopuli2025ag2",)]})
    assert replicas(cursor) == ("sopuli2025ag1", "sopuli2025ag2")


def test_a_server_in_no_group_has_no_replicas() -> None:
    assert replicas(FakeCursor({})) == ()


@pytest.mark.parametrize("name", ["master", "MASTER"])
def test_the_instances_own_master_is_not_a_group(name: str) -> None:
    """AR6: on a server in no group, on every release, it is master."""
    assert contained_master(FakeCursor({PHYSICAL_NAME: [(name,)]})) is None


def test_a_contained_groups_master_is_named() -> None:
    """AR6: DB_NAME() says master there; the physical name does not."""
    cursor = FakeCursor({PHYSICAL_NAME: [("sopuli_probe_cag_master",)]})
    assert contained_master(cursor) == "sopuli_probe_cag_master"


@pytest.mark.parametrize("answer", [[], [(None,)], [("",)]])
def test_a_read_that_cannot_say_counts_as_a_group(answer: list[tuple[Any, ...]]) -> None:
    """Fails closed: a login is never let through as the instance's on a
    read that did not say so."""
    assert contained_master(FakeCursor({PHYSICAL_NAME: answer})) == "(unnamed)"


def test_the_refusal_is_a_config_error_about_the_account() -> None:
    error = ContainedGroupLoginError("acme_app_user", "acme_cag_master", target="mssql-dev")
    assert error.category == "config"
    assert error.exit_code == ExitCode.CONFIG_INVALID
    assert error.about_account
    assert 'account "acme_app_user" on target "mssql-dev"' in str(error)
    assert "acme_cag_master" in str(error)


def _session(answers: dict[str, list[tuple[Any, ...]]]) -> Any:
    session = pytest.importorskip("sopuli.driver.mssql.session")
    cursor = FakeCursor(answers)

    class Connection:
        def cursor(self) -> FakeCursor:
            return cursor

    opened = session.MssqlSession(
        connection=Connection(),
        target=ExpandedTarget(target=Target(name="mssql-dev", type="mssql", dsn="h:1433")),
    )
    return opened, cursor


def test_the_session_reads_each_once() -> None:
    opened, cursor = _session({REPLICAS: [("a",), ("b",)], PHYSICAL_NAME: [("master",)]})
    for _ in range(2):
        assert opened.availability_replicas() == ("a", "b")
        assert opened.contained_master() is None
    assert cursor.sent == [REPLICAS, PHYSICAL_NAME]


def test_describe_user_refuses_a_login_in_a_contained_groups_master(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sopuli.driver.mssql import accounts

    opened, _ = _session({PHYSICAL_NAME: [("acme_cag_master",)]})
    login = type("Login", (), {"name": "acme_app_user", "principal_id": 300})()
    monkeypatch.setattr(accounts, "read_one", lambda cursor, account, target: login)

    with pytest.raises(ContainedGroupLoginError):
        opened.describe_user("acme_app_user")
