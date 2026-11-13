"""The MySQL privilege survey for `report privileges` (#1482). Tier 0: a fake
cursor answers each grant table's read with rows in the shape of
`10_report_read_probe.py`'s (RE2, RE3), and the session's optional read of the
default roles fails as the server fails it. Fictional names only."""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.driver.grants import COLUMN, OBJECT, SCHEMA, SYSTEM, GrantSurvey, PrivilegeSurvey
from sopuli.driver.mysql import privilege_survey as reads
from sopuli.driver.mysql.account_state import (
    ABSENT_RESTRICTIONS,
    EXPECTED,
    NO_PRINCIPAL_ROW,
    RESTRICTIONS_QUERY,
    UNKNOWN_PRIVILEGE,
)
from sopuli.driver.mysql.admin import DB_PRIV_COLUMNS, MANDATORY_ROLES, PRIV_COLUMNS
from sopuli.driver.mysql.session import MysqlSession
from sopuli.driver.mysql_family import privilege_reads as shared
from sopuli.driver.mysql_family.optional_view import columns_query
from sopuli.driver.mysql_family.privilege_survey import MANDATORY_UNKNOWN
from sopuli.driver.protocol import DriverError


def flags(*held: str) -> tuple[str, ...]:
    """The ``*_priv`` columns of one ``mysql.user`` row, ``Y`` where named."""
    return tuple("Y" if column in held else "N" for column in PRIV_COLUMNS)


def db_flags(*held: str) -> tuple[str, ...]:
    return tuple("Y" if column in held else "N" for column in DB_PRIV_COLUMNS)


class _Cursor:
    def __init__(
        self,
        *,
        partial: str = "0",
        all_active: str = "0",
        mandatory: str = "",
        defaults: list[tuple[str, ...]] | None = None,
        **tables: list[tuple[Any, ...]],
    ) -> None:
        self.one = {
            reads.SETTINGS: (partial, all_active),
            MANDATORY_ROLES: (mandatory,),
        }
        self.answers: dict[str, list[tuple[Any, ...]]] = {
            reads.EDGES: tables.get("edges", []),
            reads.DEFAULTS: defaults or [],
            reads.GLOBAL_ROWS: tables.get("users", []),
            reads.PRINCIPALS: [row[:2] for row in tables.get("users", [])],
            reads.DYNAMIC: tables.get("dynamic", []),
            reads.SCHEMA_ROWS: tables.get("db", []),
            shared.TABLES: tables.get("tables", []),
            shared.COLUMNS: tables.get("columns", []),
            shared.ROUTINES: tables.get("routines", []),
            shared.PROXIES: tables.get("proxies", []),
            # The optional view: absent unless a test gives its columns.
            columns_query("sopuli", "account_state"): tables.get("view_columns", []),
            RESTRICTIONS_QUERY: tables.get("restrictions", []),
        }
        self.queries: list[str] = []

    def execute(self, query: str, args: Any = None, /) -> None:
        assert args is None, "the survey binds nothing"
        self.queries.append(query)

    def fetchone(self) -> Any:
        return self.one[self.queries[-1]]

    def fetchall(self) -> Any:
        return self.answers[self.queries[-1]]


APP = ("acme_app", "%", *flags())
REPORT = ("acme_report", "%", *flags())
OPS = ("acme_ops", "localhost", *flags("Process_priv", "Grant_priv"))


def survey(cursor: _Cursor, *, refuse_defaults: bool = False) -> GrantSurvey:
    session = MysqlSession.__new__(MysqlSession)

    def read(reader: Any, **_: Any) -> Any:
        if reader is reads.read_defaults and refuse_defaults:
            raise DriverError("SELECT command denied", code="1142")
        return reader(cursor)

    session._read = read  # type: ignore[method-assign]
    session._read_grants = read  # type: ignore[method-assign]
    return session.survey_privileges(["acme_app@%", "acme_ops@localhost"], public=False)


def test_the_session_is_a_privilege_survey() -> None:
    assert isinstance(MysqlSession.__new__(MysqlSession), PrivilegeSurvey)


def test_each_level_is_read_into_its_part_with_its_level() -> None:
    cursor = _Cursor(
        users=[APP, OPS],
        dynamic=[("acme_ops", "localhost", "connection_admin", "N")],
        db=[("acme_app", "%", "acme%", *db_flags("Select_priv"))],
        tables=[("acme_app", "%", "acme", "orders", "Insert,Grant")],
        columns=[("acme_app", "%", "acme", "orders", "total", "Update")],
        routines=[("acme_app", "%", "acme", "close_day", "PROCEDURE", "Execute")],
        proxies=[("acme_ops", "localhost", "acme_app", "%", 1)],
    )
    found = survey(cursor)

    assert [(r.grantee, r.level, r.privilege, r.grantable) for r in found.system or ()] == [
        ("acme_ops@localhost", "global static", "PROCESS", True),
        ("acme_ops@localhost", "global static", "GRANT OPTION", True),
        ("acme_ops@localhost", "global dynamic", "CONNECTION_ADMIN", False),
    ]
    assert [(r.level, r.privilege, r.owner) for r in found.schemas or ()] == [
        ("database", "SELECT", "acme%")
    ]
    objects = {(r.level, r.privilege, r.owner, r.name, r.object_type, r.grantable)
               for r in found.objects or ()}  # fmt: skip
    assert objects == {
        ("table", "INSERT", "acme", "orders", "TABLE", True),
        ("table", "GRANT OPTION", "acme", "orders", "TABLE", True),
        ("routine", "EXECUTE", "acme", "close_day", "PROCEDURE", False),
        ("proxy", "PROXY", None, "acme_app@%", "ACCOUNT", True),
    }
    assert [(r.level, r.privilege, r.column) for r in found.columns or ()] == [
        ("column", "UPDATE", "total")
    ]
    assert {row.kind for row in found.system or ()} == {SYSTEM}
    assert {row.kind for row in found.schemas or ()} == {SCHEMA}
    assert {row.kind for row in found.objects or ()} == {OBJECT}
    assert {row.kind for row in found.columns or ()} == {COLUMN}
    assert found.unreadable == ()


def test_a_role_path_and_its_default_role() -> None:
    cursor = _Cursor(
        users=[APP, REPORT],
        edges=[("acme_report", "%", "acme_app", "%", "Y")],
        defaults=[("acme_app", "%", "acme_report", "%")],
        tables=[("acme_report", "%", "acme", "orders", "Select")],
    )
    found = survey(cursor)

    (row,) = found.objects or ()
    assert (row.grantee, row.path, row.first_role_default) == (
        "acme_app@%",
        ("acme_report@%",),
        True,
    )
    (role,) = found.roles
    assert (role.role, role.admin_option, role.default_role) == ("acme_report@%", True, True)


def test_partial_revokes_without_the_view_leave_global_privileges_not_checked() -> None:
    cursor = _Cursor(
        partial="1", users=[OPS], db=[("acme_app", "%", "acme", *db_flags("Select_priv"))]
    )
    found = survey(cursor)

    assert found.system is None
    assert found.schemas is not None
    assert reads.GLOBAL_ROWS not in cursor.queries
    assert found.unreadable == (f"{reads.PARTIAL_REVOKES}; {ABSENT_RESTRICTIONS}",)


VIEW = [(column,) for column in EXPECTED]


def test_partial_revokes_with_the_view_name_the_schemas_each_privilege_is_revoked_on() -> None:
    """#1502: DV4's shape, one entry per schema. A dynamic privilege has none."""
    app = ("acme_app", "%", *flags("Select_priv", "Insert_priv"))
    cursor = _Cursor(
        partial="1",
        users=[app],
        dynamic=[("acme_app", "%", "connection_admin", "N")],
        view_columns=VIEW,
        restrictions=[
            (
                "acme_app",
                "%",
                '[{"Database": "acme_hr", "Privileges": ["SELECT"]}, '
                '{"Database": "acme_pay", "Privileges": ["SELECT", "INSERT"]}]',
            ),
            ("acme_ops", "localhost", None),
        ],
    )
    found = survey(cursor)

    assert found.unreadable == ()
    assert [(r.privilege, r.level, r.except_schemas) for r in found.system or ()] == [
        ("SELECT", "global static", ("acme_hr", "acme_pay")),
        ("INSERT", "global static", ("acme_pay",)),
        ("CONNECTION_ADMIN", "global dynamic", ()),
    ]


def test_partial_revokes_off_read_no_view() -> None:
    cursor = _Cursor(users=[APP])
    survey(cursor)
    assert RESTRICTIONS_QUERY not in cursor.queries
    assert columns_query("sopuli", "account_state") not in cursor.queries


def test_a_broken_view_leaves_global_privileges_not_checked_and_says_so() -> None:
    session = MysqlSession.__new__(MysqlSession)
    cursor = _Cursor(partial="1", users=[APP], view_columns=[*VIEW, ("authentication_string",)])

    def read(reader: Any, **_: Any) -> Any:
        return reader(cursor)

    session._read = read  # type: ignore[method-assign]
    session._read_grants = read  # type: ignore[method-assign]
    found = session.survey_privileges(["acme_app@%"], public=False)

    assert found.system is None
    assert session.privilege_view_broken() == (
        "it has columns the tool does not expect (authentication_string)"
    )


def test_a_restriction_of_another_shape_is_broken_and_never_repeated() -> None:
    cursor = _Cursor(
        partial="1",
        users=[APP],
        view_columns=VIEW,
        restrictions=[("acme_app", "%", '{"secret": "$A$005$x"}')],
    )
    found = survey(cursor)
    assert found.system is None
    assert "secret" not in " ".join(found.unreadable)


def test_a_holder_the_view_does_not_list_leaves_global_privileges_not_checked() -> None:
    """No row is not the same as no revoke: reading none would claim every
    schema (#1510)."""
    cursor = _Cursor(partial="1", users=[OPS], view_columns=VIEW, restrictions=[])
    found = survey(cursor)
    assert found.system is None
    assert found.unreadable == (f"{reads.PARTIAL_REVOKES}; {NO_PRINCIPAL_ROW}",)


def test_a_revoked_grant_option_is_stored_as_grant() -> None:
    """Measured on 8.4.13: REVOKE GRANT OPTION ON acme_hr.* is `GRANT` in
    Restrictions; multi-word names are stored as the tool names them."""
    cursor = _Cursor(
        partial="1",
        users=[OPS],
        view_columns=VIEW,
        restrictions=[
            (
                "acme_ops",
                "localhost",
                '[{"Database": "acme_hr", "Privileges": ["GRANT", "PROCESS"]}]',
            )
        ],
    )
    found = survey(cursor)
    assert [(r.privilege, r.except_schemas) for r in found.system or ()] == [
        ("PROCESS", ("acme_hr",)),
        ("GRANT OPTION", ("acme_hr",)),
    ]


def test_a_revoke_of_a_privilege_the_tool_does_not_know_is_not_dropped() -> None:
    cursor = _Cursor(
        partial="1",
        users=[OPS],
        view_columns=VIEW,
        restrictions=[
            ("acme_ops", "localhost", '[{"Database": "acme_hr", "Privileges": ["NEW THING"]}]')
        ],
    )
    found = survey(cursor)
    assert found.system is None
    assert found.unreadable == (f"{reads.PARTIAL_REVOKES}; {UNKNOWN_PRIVILEGE}",)


def test_a_holder_with_no_static_privilege_needs_no_row() -> None:
    cursor = _Cursor(partial="1", users=[APP], view_columns=VIEW, restrictions=[])
    found = survey(cursor)
    assert found.system == ()
    assert found.unreadable == ()


def test_a_later_survey_with_partial_revokes_off_warns_of_nothing() -> None:
    session = MysqlSession.__new__(MysqlSession)
    broken = _Cursor(partial="1", users=[APP], view_columns=[*VIEW, ("authentication_string",)])
    current = [broken]

    def read(reader: Any, **_: Any) -> Any:
        return reader(current[0])

    session._read = read  # type: ignore[method-assign]
    session._read_grants = read  # type: ignore[method-assign]
    session.survey_privileges(["acme_app@%"], public=False)
    assert session.privilege_view_broken() is not None
    current[0] = _Cursor(users=[APP])
    session.survey_privileges(["acme_app@%"], public=False)
    assert session.privilege_view_broken() is None


def test_refused_default_roles_are_not_checked() -> None:
    cursor = _Cursor(
        users=[APP, REPORT],
        edges=[("acme_report", "%", "acme_app", "%", "N")],
        tables=[("acme_report", "%", "acme", "orders", "Select")],
    )
    found = survey(cursor, refuse_defaults=True)

    (row,) = found.objects or ()
    assert row.first_role_default is None
    assert found.unreadable == (reads.NO_DEFAULTS,)


def test_any_other_error_on_the_default_roles_fails_the_read() -> None:
    session = MysqlSession.__new__(MysqlSession)

    def read(reader: Any, **_: Any) -> Any:
        if reader is reads.read_defaults:
            raise DriverError("gone", code="2013")
        return reader(_Cursor())

    session._read = read  # type: ignore[method-assign]
    session._read_grants = read  # type: ignore[method-assign]
    with pytest.raises(DriverError, match="gone"):
        session.survey_privileges(["acme_app@%"], public=False)


def test_with_every_role_active_the_default_roles_are_still_read() -> None:
    cursor = _Cursor(
        all_active="ON",
        users=[APP, REPORT],
        edges=[("acme_report", "%", "acme_app", "%", "N")],
        tables=[("acme_report", "%", "acme", "orders", "Select")],
    )
    found = survey(cursor)

    assert [row.first_role_default for row in found.objects or ()] == [True]
    (role,) = found.roles
    assert (role.default_role, role.default_role_checked) == (False, True)
    assert found.unreadable == ()


def test_with_every_role_active_a_refused_default_roles_read_has_its_reason() -> None:
    cursor = _Cursor(
        all_active="ON",
        users=[APP, REPORT],
        edges=[("acme_report", "%", "acme_app", "%", "N")],
        tables=[("acme_report", "%", "acme", "orders", "Select")],
    )
    found = survey(cursor, refuse_defaults=True)

    # Every role is active, so each path is; only the default status is unread.
    assert [row.first_role_default for row in found.objects or ()] == [True]
    assert found.roles[0].default_role_checked is False
    assert found.unreadable == (reads.NO_DEFAULTS,)


def test_a_column_grant_with_grant_option_is_grantable() -> None:
    # GRANT SELECT (total) ON acme.orders ... WITH GRANT OPTION, as 8.4.13 keeps it.
    cursor = _Cursor(
        users=[APP],
        tables=[("acme_app", "%", "acme", "orders", "Grant")],
        columns=[("acme_app", "%", "acme", "orders", "total", "Select")],
    )
    found = survey(cursor)

    (column,) = found.columns or ()
    assert (column.privilege, column.column, column.grantable) == ("SELECT", "total", True)


def test_a_mandatory_role_reaches_every_account_and_one_that_does_not_exist_is_left_out() -> None:
    mand = ("acme_mand", "%", *flags())
    cursor = _Cursor(
        mandatory="acme_mand,`acme_ghost`@`%`",
        users=[APP, OPS, mand],
        tables=[("acme_mand", "%", "acme", "orders", "Select")],
    )
    found = survey(cursor)

    assert [(row.grantee, row.path) for row in found.objects or ()] == [
        ("acme_app@%", ("acme_mand@%",)),
        ("acme_ops@localhost", ("acme_mand@%",)),
    ]
    assert {role.role for role in found.roles} == {"acme_mand@%"}
    assert found.unreadable == (MANDATORY_UNKNOWN,)
