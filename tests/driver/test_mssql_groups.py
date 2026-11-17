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
    REPLICAS,
    ContainedGroupMasterError,
    MasterUnreadError,
    replicas,
    require_instance_master,
)
from sopuli.driver.mssql.scope import SCOPE
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


def test_the_scope_reads_the_physical_name_in_its_own_round_trip() -> None:
    assert "physical_database_name" in SCOPE


@pytest.mark.parametrize("name", ["master", "MASTER", " master "])
def test_the_instances_own_master_passes(name: str) -> None:
    """AR6: on a server in no group, on every release, it is master."""
    require_instance_master(name, target="mssql-dev")


def test_another_physical_name_is_refused_for_what_was_read() -> None:
    """AR6: only a contained group's master was measured to give another
    name. The message says what was read, and claims no more."""
    with pytest.raises(ContainedGroupMasterError) as caught:
        require_instance_master("acme_cag_master", target="mssql-dev")
    assert caught.value.category == "config"
    assert caught.value.exit_code == ExitCode.CONFIG_INVALID
    first = str(caught.value).splitlines()[0]
    assert first == (
        'target "mssql-dev" connects to a database whose physical name is acme_cag_master, '
        "not the instance's master, as a contained Availability Group's own master does"
    )


@pytest.mark.parametrize("answer", [None, "", "  "])
def test_a_name_that_cannot_be_read_is_refused_as_the_databases_fault(answer: Any) -> None:
    """Fails closed, as an unknown is, but the config is not at fault: exit 1,
    and no group is claimed."""
    with pytest.raises(MasterUnreadError) as caught:
        require_instance_master(answer, target="mssql-dev")
    assert caught.value.category == "database"
    assert caught.value.exit_code == ExitCode.FAILURE
    message = str(caught.value)
    assert message.startswith('target "mssql-dev" did not say which database its session is in')
    assert "contained" not in message.splitlines()[0]


def _session(physical: Any = "master", **answers: list[tuple[Any, ...]]) -> Any:
    """A session over a fake whose scope reads a 2025 server whose master
    takes writes, and the physical name given."""
    session = pytest.importorskip("sopuli.driver.mssql.session")
    cursor = FakeCursor({SCOPE: [("17.0.5065.9", 3, "READ_WRITE", physical)], **answers})

    class Connection:
        def cursor(self) -> FakeCursor:
            return cursor

    opened = session.MssqlSession(
        connection=Connection(),
        target=ExpandedTarget(target=Target(name="mssql-dev", type="mssql", dsn="h:1433")),
    )
    return opened, cursor


def test_the_replicas_are_read_once() -> None:
    opened, cursor = _session(**{REPLICAS: [("a",), ("b",)]})
    for _ in range(2):
        assert opened.availability_replicas() == ("a", "b")
    assert cursor.sent == [REPLICAS]


def test_a_refused_scope_is_kept_and_raised_again_without_a_read() -> None:
    opened, cursor = _session("acme_cag_master")
    for _ in range(2):
        with pytest.raises(ContainedGroupMasterError):
            opened.scope()
    assert cursor.sent == [SCOPE]


def test_the_scope_of_the_instances_master_is_read_once() -> None:
    opened, cursor = _session()
    assert opened.scope().read_write is True
    opened.scope()
    assert cursor.sent == [SCOPE]


def _with_login(monkeypatch: pytest.MonkeyPatch, physical: str) -> Any:
    from sopuli.driver.mssql import accounts

    opened, _ = _session(physical)
    read: list[str] = []

    def read_one(cursor: Any, account: str, target: str) -> None:
        read.append(account)

    monkeypatch.setattr(accounts, "read_one", read_one)
    return opened, read


def test_describe_user_refuses_before_reading_any_login(monkeypatch: pytest.MonkeyPatch) -> None:
    """A login the group's master does not have is refused too, not read as
    missing: the scope refuses before the login is looked up."""
    opened, read = _with_login(monkeypatch, "acme_cag_master")
    with pytest.raises(ContainedGroupMasterError):
        opened.describe_user("acme_app_user")
    assert read == []


def test_describe_user_reads_a_login_in_the_instances_master(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened, read = _with_login(monkeypatch, "master")
    assert opened.describe_user("acme_app_user") is None
    assert read == ["acme_app_user"]


def test_admin_assessment_reads_the_scope_first() -> None:
    """Guardrail 9's catalog is a read of logins too: refused first."""
    opened, cursor = _session("acme_cag_master")
    with pytest.raises(ContainedGroupMasterError):
        opened.admin_assessment(300)
    assert cursor.sent == [SCOPE]
