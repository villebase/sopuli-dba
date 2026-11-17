"""The SQL Server tool login's audit, over a fake cursor (`02-mssql-privileges.md`
§2.1, §3). The live reads are in `test_mssql_privileges_live.py`."""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Target
from sopuli.driver.mssql.privileges import (
    LOGIN_GRANT_ROWS,
    LOGIN_GRANTS_HIDDEN,
    MSDB_READ,
    MSDB_ROW,
    MSDB_USER,
    SELF_COLUMNS,
    SELF_ROW,
    audit,
    read_msdb_user,
    read_self,
)
from sopuli.driver.protocol import DriverError


class FakeCursor:
    def __init__(
        self, self_row: tuple[Any, ...], grants: list[tuple[Any, ...]] | None = None
    ) -> None:
        self.answers: dict[str, list[tuple[Any, ...]]] = {
            SELF_ROW: [self_row],
            LOGIN_GRANT_ROWS: grants or [],
            MSDB_ROW: [(1,)],
        }
        self.sent: list[str] = []
        self.rows: list[tuple[Any, ...]] = []

    def execute(self, statement: str, *params: Any) -> None:
        assert not params
        self.sent.append(statement)
        self.rows = self.answers[statement]

    def fetchone(self) -> Any:
        return self.rows[0]

    def fetchall(self) -> Any:
        return self.rows


def row(
    alter_any_login: int = 1,
    view_any_definition: int = 0,
    security_definitions: int = 1,
    forbidden: tuple[int, ...] = (0, 0, 0, 0, 0, 0),
    name: str = "sopuli_admin",
) -> tuple[Any, ...]:
    """A :data:`SELF_ROW` answer: the name, ALTER ANY LOGIN, VIEW ANY
    DEFINITION, the tool login's own CONNECT SQL rows, the four server
    permissions of §3, sysadmin and securityadmin."""
    return (name, alter_any_login, view_any_definition, security_definitions, *forbidden)


def test_the_row_has_a_column_for_each_name() -> None:
    assert len(row()) == len(SELF_COLUMNS)


def test_a_row_of_another_shape_is_refused() -> None:
    with pytest.raises(ValueError, match="shorter"):
        read_self(FakeCursor(row()[:-1]))


def test_the_documented_grant_alone_holds_it_and_names_the_password_grant() -> None:
    found = audit(FakeCursor(row()), msdb_user=False)
    assert found.held == ("ALTER ANY LOGIN",)
    assert found.missing == ()
    assert found.over_granted == ()
    assert found.unaudited == ()
    assert found.unreadable == ()
    (remedy,) = found.remedies
    assert "GRANT VIEW ANY DEFINITION TO [sopuli_admin]" in remedy
    assert "guardrail 9 refuses every managed login" in remedy


def test_with_view_any_definition_no_remedy_is_given() -> None:
    found = audit(FakeCursor(row(view_any_definition=1)), msdb_user=False)
    assert found.held == ("ALTER ANY LOGIN", "VIEW ANY DEFINITION")
    assert found.remedies == ()


def test_a_visible_connect_sql_row_reads_the_grants_on_one_login() -> None:
    cursor = FakeCursor(row(), [("IMPERSONATE", "acme_app_user", 300)])
    found = audit(cursor, msdb_user=False)
    assert found.over_granted == ("IMPERSONATE ON LOGIN::[acme_app_user]",)
    assert found.unaudited == ()


def test_a_denied_view_any_security_definition_leaves_the_login_grants_unchecked() -> None:
    """FR5: the denial hides the rows, the tool login's own CONNECT SQL row
    among them, so an empty read would read as clean."""
    cursor = FakeCursor(row(security_definitions=0), [("IMPERSONATE", "acme_app_user", 300)])
    found = audit(cursor, msdb_user=False)
    assert found.over_granted == ()
    assert found.unaudited == (LOGIN_GRANTS_HIDDEN,)
    assert any("denied VIEW ANY SECURITY DEFINITION" in remedy for remedy in found.remedies)
    assert LOGIN_GRANT_ROWS not in cursor.sent


def test_without_alter_any_login_the_grant_is_missing() -> None:
    found = audit(FakeCursor(row(alter_any_login=0)), msdb_user=False)
    assert found.missing == ("GRANT ALTER ANY LOGIN TO [sopuli_admin]",)
    assert found.hint is not None


def test_every_row_of_section_3_is_reported() -> None:
    found = audit(
        FakeCursor(
            row(view_any_definition=1, forbidden=(1, 1, 1, 1, 1, 1)),
            [("IMPERSONATE", "acme_app_user", 300), ("CONTROL", None, 999)],
        ),
        msdb_user=True,
    )
    assert found.over_granted == (
        "ALTER ANY SERVER ROLE",
        "CONTROL ON principal #999",
        "CONTROL SERVER",
        "IMPERSONATE ANY LOGIN",
        "IMPERSONATE ON LOGIN::[acme_app_user]",
        "VIEW SERVER STATE",
        MSDB_USER,
        "securityadmin",
        "sysadmin",
    )


def test_a_user_in_msdb_alone_is_over_granted() -> None:
    found = audit(FakeCursor(row(view_any_definition=1)), msdb_user=True)
    assert found.over_granted == (MSDB_USER,)


def test_an_unreadable_msdb_leaves_the_rest_of_the_audit() -> None:
    found = audit(FakeCursor(row()), msdb_user=None)
    assert found.unreadable == (MSDB_READ,)
    assert found.held == ("ALTER ANY LOGIN",)


def test_the_msdb_read_counts_the_tool_logins_sid() -> None:
    assert read_msdb_user(FakeCursor(row())) is True


def test_a_name_with_a_bracket_is_quoted_in_the_grant() -> None:
    found = audit(FakeCursor(row(alter_any_login=0, name="acme]admin")), msdb_user=False)
    assert found.missing == ("GRANT ALTER ANY LOGIN TO [acme]]admin]",)


class MsdbRefusing(FakeCursor):
    """A cursor whose msdb read raises ``error``."""

    def __init__(self, error: Exception) -> None:
        super().__init__(row())
        self.error = error

    def execute(self, statement: str, *params: Any) -> None:
        if statement == MSDB_ROW:
            raise self.error
        super().execute(statement, *params)

    def close(self) -> None:
        pass


def _session_over(cursor: FakeCursor) -> Any:
    session = pytest.importorskip("sopuli.driver.mssql.session")

    class Connection:
        def cursor(self) -> FakeCursor:
            return cursor

    return session.MssqlSession(
        connection=Connection(),
        target=ExpandedTarget(target=Target(name="mssql-dev", type="mssql", dsn="h:1433")),
    )


def test_a_refused_msdb_read_leaves_the_audit() -> None:
    pyodbc = pytest.importorskip("pyodbc")
    refused = pyodbc.ProgrammingError(
        "42000",
        "[42000] [Microsoft][ODBC Driver 18 for SQL Server][SQL Server]The server principal "
        '"sopuli_admin" is not able to access the database "msdb" under the current security '
        "context. (916) (SQLExecDirectW)",
    )
    found = _session_over(MsdbRefusing(refused)).privileges(accounts=())
    assert found.unreadable == (MSDB_READ,)
    assert found.held == ("ALTER ANY LOGIN",)


def test_a_lost_connection_on_the_msdb_read_is_raised() -> None:
    """Only a refusal says msdb is closed; anything else is not hidden."""
    pyodbc = pytest.importorskip("pyodbc")
    lost = pyodbc.OperationalError(
        "08S01",
        "[08S01] [Microsoft][ODBC Driver 18 for SQL Server]TCP Provider: An existing connection "
        "was forcibly closed by the remote host. (10054) (SQLExecDirectW)",
    )
    with pytest.raises(DriverError) as caught:
        _session_over(MsdbRefusing(lost)).privileges(accounts=())
    assert caught.value.category == "connectivity"
