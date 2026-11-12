"""The MariaDB privilege survey for `report privileges` (#1483). Tier 0: a fake
cursor answers each grant table's read with rows in the shape of
`15_report_read_probe.py`'s (RE2, RE3), and the session's optional read of the
default roles fails as the server fails it. Fictional names only."""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.driver.grants import COLUMN, OBJECT, SCHEMA, GrantSurvey, PrivilegeSurvey
from sopuli.driver.mariadb import privilege_survey as reads
from sopuli.driver.mariadb.admin import DB_COLUMNS
from sopuli.driver.mariadb.session import MariadbSession
from sopuli.driver.mysql_family import privilege_reads as shared
from sopuli.driver.protocol import DriverError

#: ``mysql.db``'s ``*_priv`` columns, a short set: the reader takes what the
#: table has.
DB_PRIV = ("Select_priv", "Insert_priv", "Grant_priv", "Show_create_routine_priv")
SCHEMA_ROWS = reads.SCHEMA_ROWS.format(columns=", ".join(DB_PRIV))


def db_flags(*held: str) -> tuple[str, ...]:
    return tuple("Y" if column in held else "N" for column in DB_PRIV)


class _Cursor:
    def __init__(self, **tables: list[tuple[Any, ...]]) -> None:
        self.answers: dict[str, list[tuple[Any, ...]]] = {
            reads.EDGES: tables.get("edges", []),
            reads.DEFAULTS: tables.get("defaults", []),
            DB_COLUMNS: [(column,) for column in DB_PRIV],
            SCHEMA_ROWS: tables.get("db", []),
            shared.TABLES: tables.get("tables", []),
            shared.COLUMNS: tables.get("columns", []),
            shared.ROUTINES: tables.get("routines", []),
            shared.PROXIES: tables.get("proxies", []),
        }
        self.queries: list[str] = []

    def execute(self, query: str, args: Any = None, /) -> None:
        assert args is None, "the survey binds nothing"
        self.queries.append(query)

    def fetchall(self) -> Any:
        return self.answers[self.queries[-1]]


ACCOUNTS = ["acme_app@%", "acme_ops@localhost"]


def survey(
    cursor: _Cursor, *, public: bool = False, refuse_defaults: str | None = None
) -> GrantSurvey:
    session = MariadbSession.__new__(MariadbSession)

    def read(reader: Any, **_: Any) -> Any:
        if reader is reads.read_defaults and refuse_defaults:
            raise DriverError("SELECT command denied", code=refuse_defaults)
        return reader(cursor)

    session._read = read  # type: ignore[method-assign]
    session._read_grants = read  # type: ignore[method-assign]
    return session.survey_privileges(ACCOUNTS, public=public)


def test_the_session_is_a_privilege_survey() -> None:
    assert isinstance(MariadbSession.__new__(MariadbSession), PrivilegeSurvey)


def test_each_level_below_the_global_one_is_read_with_its_level() -> None:
    found = survey(
        _Cursor(
            db=[("acme_app", "%", "acme%", *db_flags("Select_priv", "Show_create_routine_priv"))],
            tables=[("acme_app", "%", "acme", "orders", "Insert,Grant")],
            columns=[("acme_app", "%", "acme", "orders", "total", "Update")],
            routines=[("acme_app", "%", "acme", "close_day", "PROCEDURE", "Execute")],
            proxies=[("acme_ops", "localhost", "acme_app", "%", "Y")],
        )
    )

    assert [(r.level, r.privilege, r.owner) for r in found.schemas or ()] == [
        ("database", "SELECT", "acme%"),
        ("database", "SHOW CREATE ROUTINE", "acme%"),
    ]
    objects = {(r.level, r.privilege, r.name, r.object_type, r.grantable)
               for r in found.objects or ()}  # fmt: skip
    assert objects == {
        ("table", "INSERT", "orders", "TABLE", True),
        ("table", "GRANT OPTION", "orders", "TABLE", True),
        ("routine", "EXECUTE", "close_day", "PROCEDURE", False),
        ("proxy", "PROXY", "acme_app@%", "ACCOUNT", True),
    }
    assert [(r.privilege, r.column, r.grantable) for r in found.columns or ()] == [
        ("UPDATE", "total", True)
    ]
    assert {row.kind for row in found.schemas or ()} == {SCHEMA}
    assert {row.kind for row in found.objects or ()} == {OBJECT}
    assert {row.kind for row in found.columns or ()} == {COLUMN}


def test_the_global_level_is_not_checked() -> None:
    """The privileges split from SUPER set no column the tool account reads,
    so the level is not checked rather than shown incomplete (#1483, A)."""
    found = survey(_Cursor())

    assert found.system is None
    assert found.unreadable == (reads.GLOBAL_NOT_CHECKED,)


def test_a_default_role_and_the_role_it_holds_are_active_and_another_is_not() -> None:
    """RE2's shape: a role has no host, and one role holds another."""
    found = survey(
        _Cursor(
            edges=[
                ("acme_app", "%", "acme_mid", "N"),
                ("acme_mid", "", "acme_top", "N"),
                ("acme_ops", "localhost", "acme_top", "Y"),
            ],
            defaults=[("acme_app", "%", "acme_mid")],
            tables=[("acme_top", "", "acme", "orders", "Select")],
        )
    )

    paths = {(r.grantee, r.path, r.first_role_default) for r in found.objects or ()}
    assert paths == {
        ("acme_app@%", ("acme_mid", "acme_top"), True),
        ("acme_ops@localhost", ("acme_top",), False),
    }
    roles = {(r.grantee, r.role, r.admin_option, r.default_role, r.default_role_checked)
             for r in found.roles}  # fmt: skip
    assert roles == {
        ("acme_app@%", "acme_mid", False, True, True),
        ("acme_ops@localhost", "acme_top", True, False, True),
    }


@pytest.mark.parametrize("code", ["1143", "1142"])
def test_refused_default_roles_are_not_checked(code: str) -> None:
    """Without the optional column grant the server answers 1143 (RE2); 1142
    is the table's refusal and fails the read."""
    cursor = _Cursor(
        edges=[("acme_app", "%", "acme_mid", "N")],
        tables=[("acme_mid", "", "acme", "orders", "Select")],
    )
    if code != "1143":
        with pytest.raises(DriverError):
            survey(cursor, refuse_defaults=code)
        return
    found = survey(cursor, refuse_defaults=code)

    (row,) = found.objects or ()
    assert row.first_role_default is None
    (role,) = found.roles
    assert (role.default_role, role.default_role_checked) == (False, False)
    assert reads.NO_DEFAULTS in found.unreadable


def test_public_is_listed_once_when_asked_for() -> None:
    """RE3: PUBLIC's grant is a row at user PUBLIC and an empty host. Its
    grants and a role granted to it are always active (RR3)."""
    cursor = _Cursor(
        edges=[("PUBLIC", "", "acme_read", "N")],
        tables=[
            ("PUBLIC", "", "acme", "notices", "Select"),
            ("acme_read", "", "acme", "orders", "Select"),
        ],
    )

    without = survey(cursor)
    assert {r.grantee for r in without.objects or ()} == set()

    found = survey(_Cursor(**{"edges": cursor.answers[reads.EDGES],
                              "tables": cursor.answers[shared.TABLES]}), public=True)  # fmt: skip
    rows = {(r.grantee, r.name, r.path, r.first_role_default) for r in found.objects or ()}
    assert rows == {
        ("PUBLIC", "notices", (), None),
        ("PUBLIC", "orders", ("acme_read",), True),
    }
    (role,) = found.roles
    assert (role.grantee, role.role, role.default_role) == ("PUBLIC", "acme_read", True)
