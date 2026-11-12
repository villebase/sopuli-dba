"""The MySQL privilege survey for `report privileges` (#1482). Tier 0: a fake
cursor answers each grant table's read with rows in the shape of
`10_report_read_probe.py`'s (RE2, RE3), and the session's optional read of the
default roles fails as the server fails it. Fictional names only."""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.driver.grants import COLUMN, OBJECT, SCHEMA, SYSTEM, GrantSurvey, PrivilegeSurvey
from sopuli.driver.mysql import privilege_survey as reads
from sopuli.driver.mysql.admin import DB_PRIV_COLUMNS, MANDATORY_ROLES, PRIV_COLUMNS
from sopuli.driver.mysql.session import MysqlSession
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
            reads.TABLES: tables.get("tables", []),
            reads.COLUMNS: tables.get("columns", []),
            reads.ROUTINES: tables.get("routines", []),
            reads.PROXIES: tables.get("proxies", []),
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


def test_partial_revokes_leave_global_privileges_not_checked() -> None:
    cursor = _Cursor(
        partial="1", users=[OPS], db=[("acme_app", "%", "acme", *db_flags("Select_priv"))]
    )
    found = survey(cursor)

    assert found.system is None
    assert found.schemas is not None
    assert reads.GLOBAL_ROWS not in cursor.queries
    assert found.unreadable == (reads.PARTIAL_REVOKES,)


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
