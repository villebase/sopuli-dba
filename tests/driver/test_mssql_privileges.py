"""The SQL Server tool login's audit, over a fake cursor (`02-mssql-privileges.md`
§2.1, §3). The live reads are in `test_mssql_privileges_live.py`."""

from __future__ import annotations

from typing import Any

from sopuli.driver.mssql.privileges import (
    LOGIN_GRANT_ROWS,
    MSDB_USER,
    SELF_ROW,
    audit,
)


class FakeCursor:
    def __init__(self, self_row: tuple[Any, ...], grants: list[tuple[Any, ...]]) -> None:
        self.answers = {SELF_ROW: [self_row], LOGIN_GRANT_ROWS: grants}
        self.rows: list[tuple[Any, ...]] = []

    def execute(self, statement: str, *params: Any) -> None:
        assert not params
        self.rows = self.answers[statement]

    def fetchone(self) -> Any:
        return self.rows[0]

    def fetchall(self) -> Any:
        return self.rows


#: The tool login of §2.1: ALTER ANY LOGIN, and nothing of §3. The columns are
#: the name, ALTER ANY LOGIN, VIEW ANY DEFINITION, the four server permissions
#: of §3, sysadmin, securityadmin, and the user in msdb.
BARE = ("sopuli_admin", 1, 0, 0, 0, 0, 0, 0, 0, 0)


def test_the_documented_grant_alone_holds_it_and_names_the_password_grant() -> None:
    found = audit(FakeCursor(BARE, []))
    assert found.held == ("ALTER ANY LOGIN",)
    assert found.missing == ()
    assert found.over_granted == ()
    assert found.unaudited == ()
    (remedy,) = found.remedies
    assert "GRANT VIEW ANY DEFINITION TO [sopuli_admin]" in remedy
    assert "guardrail 9 refuses every managed login" in remedy


def test_with_view_any_definition_no_remedy_is_given() -> None:
    found = audit(FakeCursor(("sopuli_admin", 1, 1, 0, 0, 0, 0, 0, 0, 0), []))
    assert found.held == ("ALTER ANY LOGIN", "VIEW ANY DEFINITION")
    assert found.remedies == ()


def test_without_alter_any_login_the_grant_is_missing() -> None:
    found = audit(FakeCursor(("sopuli_admin", 0, 0, 0, 0, 0, 0, 0, 0, 0), []))
    assert found.missing == ("GRANT ALTER ANY LOGIN TO [sopuli_admin]",)
    assert found.hint is not None


def test_every_row_of_section_3_is_reported() -> None:
    found = audit(
        FakeCursor(
            ("sopuli_admin", 1, 1, 1, 1, 1, 1, 1, 1, 1),
            [("IMPERSONATE", "acme_app_user", 300), ("CONTROL", None, 999)],
        )
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
    found = audit(FakeCursor(("sopuli_admin", 1, 1, 0, 0, 0, 0, 0, 0, 1), []))
    assert found.over_granted == (MSDB_USER,)


def test_a_name_with_a_bracket_is_quoted_in_the_grant() -> None:
    found = audit(FakeCursor(("acme]admin", 0, 0, 0, 0, 0, 0, 0, 0, 0), []))
    assert found.missing == ("GRANT ALTER ANY LOGIN TO [acme]]admin]",)
