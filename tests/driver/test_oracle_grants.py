"""The Oracle privilege survey for UC-5's reports, against a fake cursor (tier 0).

The fixtures follow probe 19's RR4 (``sql/oracle/19_report_read_probe.sql``):
one account, ACME_RR_APP, holding privileges directly and through nested
roles, so one privilege arrives by several paths.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Target
from sopuli.driver.grants import COLUMN, OBJECT, SYSTEM, GrantRow, GrantSurvey, RoleGrant
from sopuli.driver.oracle.accounts import DictionaryUnreadableError
from sopuli.driver.oracle.grants import (
    COL_PRIVS_QUERY,
    ROLE_GRANTS_QUERY,
    ROLE_GRANTS_QUERY_LEGACY,
    ROLE_GRANTS_QUERY_NO_ROLES,
    SYS_PRIVS_QUERY,
    TAB_PRIVS_QUERY,
    TAB_PRIVS_QUERY_LEGACY,
    UNKNOWN_AUTHENTICATION,
    survey_grants,
)
from sopuli.driver.protocol import ROLE_LOOKUP, DriverError, Scope

APP = "ACME_RR_APP"
OWNER = "ACME_RR_OWNER"
SEP = "\x00"


class _Cursor:
    """Answers per (statement, grantee). An exception is raised on fetch."""

    def __init__(self, answers: dict[tuple[str, str], Any]) -> None:
        self.answers = answers
        self.asked: list[tuple[str, Any]] = []
        self.current: tuple[str, str] = ("", "")

    def execute(self, sql: str, parameters: Any = None, /) -> _Cursor:
        self.asked.append((sql, parameters))
        self.current = (sql, (parameters or {}).get("grantee", ""))
        return self

    def fetchall(self) -> Any:
        answer = self.answers.get(self.current, [])
        if isinstance(answer, Exception):
            raise answer
        return answer

    def fetchone(self) -> Any:
        raise AssertionError("the survey reads every row")

    def __enter__(self) -> _Cursor:
        return self

    def __exit__(self, *_: object) -> None:
        return None


def _ora(code: str, message: str = "") -> RuntimeError:
    return RuntimeError(f"{code}: {message or 'something the server said'}")


def _path(*roles: str) -> str:
    return SEP.join(roles)


#: RR4's object rows, one per path: 11 for ACME_RR_APP and 2 for PUBLIC, so 13
#: rows for 9 distinct privileges, as the probe printed.
#: (path, first_default, privilege, owner, table, type, grantable)
RR4_OBJECTS = [
    (None, None, "SELECT", OWNER, "T1", "TABLE", "NO"),
    (None, None, "SELECT", OWNER, "T2", "TABLE", "NO"),
    (_path("ACME_RR_DUP"), "YES", "SELECT", OWNER, "T2", "TABLE", "NO"),
    (_path("ACME_RR_OUTER", "ACME_RR_DUP"), "YES", "SELECT", OWNER, "T2", "TABLE", "NO"),
    (_path("ACME_RR_DUP"), "YES", "SELECT", OWNER, "T3", "TABLE", "NO"),
    (_path("ACME_RR_OUTER", "ACME_RR_DUP"), "YES", "SELECT", OWNER, "T3", "TABLE", "NO"),
    (_path("ACME_RR_OUTER", "ACME_RR_READ"), "YES", "SELECT", OWNER, "T3", "TABLE", "NO"),
    (_path("ACME_RR_OUTER", "ACME_RR_READ"), "YES", "SELECT", OWNER, "T4", "TABLE", "NO"),
    (_path("ACME_RR_OUTER", "ACME_RR_READ"), "YES", "SELECT", OWNER, "T5", "TABLE", "NO"),
    (_path("ACME_RR_OUTER", "ACME_RR_READ"), "YES", "EXECUTE", OWNER, "P1", "PROCEDURE", "NO"),
    (_path("ACME_RR_EXTRA"), "NO", "INSERT", OWNER, "T1", "TABLE", "NO"),
]

RR4_PUBLIC_OBJECTS = [
    (None, None, "SELECT", OWNER, "T6", "TABLE", "NO"),
    (_path("ACME_RR_PUB"), "YES", "SELECT", OWNER, "T7", "TABLE", "NO"),
]

RR4_ROLES = [
    ("ACME_RR_OUTER", "NO", "YES", "NONE"),
    ("ACME_RR_EXTRA", "NO", "NO", "NONE"),
    ("ACME_RR_DUP", "YES", "YES", "PASSWORD"),
]

RR4_SYSTEM = [
    (None, None, "CREATE SESSION", "NO"),
    (_path("ACME_RR_OUTER", "ACME_RR_READ"), "YES", "CREATE TABLE", "NO"),
]

RR4_COLUMNS = [(None, None, "UPDATE", OWNER, "T4", "N", "NO")]


def _answers(**overrides: Any) -> dict[tuple[str, str], Any]:
    answers: dict[tuple[str, str], Any] = {
        (ROLE_GRANTS_QUERY, APP): RR4_ROLES,
        (SYS_PRIVS_QUERY, APP): RR4_SYSTEM,
        (TAB_PRIVS_QUERY, APP): RR4_OBJECTS,
        (COL_PRIVS_QUERY, APP): RR4_COLUMNS,
    }
    for key, value in overrides.items():
        answers[_KEYS[key]] = value
    return answers


_KEYS = {
    "roles": (ROLE_GRANTS_QUERY, APP),
    "system": (SYS_PRIVS_QUERY, APP),
    "objects": (TAB_PRIVS_QUERY, APP),
    "columns": (COL_PRIVS_QUERY, APP),
}


def test_rr4_gives_one_object_row_per_path() -> None:
    answers = _answers()
    answers[(TAB_PRIVS_QUERY, "PUBLIC")] = RR4_PUBLIC_OBJECTS
    survey = survey_grants(_Cursor(answers), [APP], public=True)
    assert survey.objects is not None
    assert len(survey.objects) == 13
    distinct = {(row.privilege, row.owner, row.name) for row in survey.objects}
    assert len(distinct) == 9
    t2 = sorted(row.path for row in survey.objects if (row.privilege, row.name) == ("SELECT", "T2"))
    assert t2 == [(), ("ACME_RR_DUP",), ("ACME_RR_OUTER", "ACME_RR_DUP")]
    assert survey.unreadable == ()


def test_an_object_row_carries_every_field() -> None:
    survey = survey_grants(_Cursor(_answers()), [APP], public=False)
    assert survey.objects is not None
    by_key = {(row.privilege, row.name, row.path): row for row in survey.objects}
    assert by_key[("EXECUTE", "P1", ("ACME_RR_OUTER", "ACME_RR_READ"))] == GrantRow(
        grantee=APP,
        kind=OBJECT,
        privilege="EXECUTE",
        owner=OWNER,
        name="P1",
        object_type="PROCEDURE",
        column=None,
        path=("ACME_RR_OUTER", "ACME_RR_READ"),
        first_role_default=True,
        grantable=False,
    )
    direct = by_key[("SELECT", "T1", ())]
    assert direct.first_role_default is None
    assert direct.grantable is False
    assert by_key[("INSERT", "T1", ("ACME_RR_EXTRA",))].first_role_default is False


def test_grantable_comes_from_the_grant() -> None:
    answers = _answers(objects=[(None, None, "SELECT", OWNER, "T1", "TABLE", "YES")])
    survey = survey_grants(_Cursor(answers), [APP], public=False)
    assert survey.objects is not None
    assert survey.objects[0].grantable is True


def test_system_privileges_carry_their_path() -> None:
    survey = survey_grants(_Cursor(_answers()), [APP], public=False)
    assert survey.system == (
        GrantRow(APP, SYSTEM, "CREATE SESSION", None, None, None, None, (), None, False),
        GrantRow(
            APP,
            SYSTEM,
            "CREATE TABLE",
            None,
            None,
            None,
            None,
            ("ACME_RR_OUTER", "ACME_RR_READ"),
            True,
            False,
        ),
    )


def test_a_column_grant_comes_from_dba_col_privs() -> None:
    survey = survey_grants(_Cursor(_answers()), [APP], public=False)
    assert survey.columns == (
        GrantRow(APP, COLUMN, "UPDATE", OWNER, "T4", None, "N", (), None, False),
    )


def test_roles_carry_their_authentication() -> None:
    survey = survey_grants(_Cursor(_answers()), [APP], public=False)
    assert survey.roles == (
        RoleGrant(
            APP, "ACME_RR_DUP", admin_option=True, default_role=True, authentication="PASSWORD"
        ),
        RoleGrant(
            APP, "ACME_RR_EXTRA", admin_option=False, default_role=False, authentication="NONE"
        ),
        RoleGrant(
            APP, "ACME_RR_OUTER", admin_option=False, default_role=True, authentication="NONE"
        ),
    )


def test_a_refused_view_is_none_not_empty_and_names_the_grant() -> None:
    refused = _ora("ORA-00942", "table or view does not exist")
    cursor = _Cursor(_answers(objects=refused))
    survey = survey_grants(cursor, [APP, "ACME_WEB_USER"], public=False)
    assert survey.objects is None
    assert survey.system is not None
    assert survey.columns is not None
    (reason,) = survey.unreadable
    assert "SELECT ON SYS.DBA_TAB_PRIVS" in reason
    assert "ORA-00942" in reason
    # Once refused, the view is not asked again for the next account.
    tab = [sql for sql, _ in cursor.asked if sql in (TAB_PRIVS_QUERY, TAB_PRIVS_QUERY_LEGACY)]
    assert len(tab) == 1


def test_every_view_refused_gives_three_reasons() -> None:
    refused = _ora("ORA-00942", "table or view does not exist")
    survey = survey_grants(
        _Cursor(_answers(system=refused, objects=refused, columns=refused)), [APP], public=False
    )
    assert (survey.system, survey.objects, survey.columns) == (None, None, None)
    assert len(survey.unreadable) == 3
    assert survey.roles


def test_a_refused_role_view_raises_naming_the_grant() -> None:
    refused = _ora("ORA-00942", "table or view does not exist")
    with pytest.raises(DictionaryUnreadableError):
        survey_grants(_Cursor(_answers(roles=refused)), [APP], public=False)


def test_another_failure_is_raised_not_read_as_unreadable() -> None:
    with pytest.raises(DriverError) as raised:
        survey_grants(
            _Cursor(_answers(objects=_ora("ORA-03113", "end-of-file on communication channel"))),
            [APP],
            public=False,
        )
    assert not isinstance(raised.value, DictionaryUnreadableError)
    assert raised.value.code == "ORA-03113"


def test_public_false_sends_no_public_branch() -> None:
    cursor = _Cursor(_answers())
    survey_grants(cursor, [APP], public=False)
    assert {(parameters or {}).get("grantee") for _, parameters in cursor.asked} == {APP}


def test_public_true_reads_public_once() -> None:
    answers = _answers()
    answers[(ROLE_GRANTS_QUERY, "PUBLIC")] = [("ACME_RR_PUB", "NO", "YES", "NONE")]
    answers[(SYS_PRIVS_QUERY, "PUBLIC")] = [(_path("ACME_RR_PUB"), "YES", "CREATE SYNONYM", "NO")]
    cursor = _Cursor(answers)
    survey = survey_grants(cursor, [APP, "PUBLIC"], public=True)
    grantees = [(parameters or {}).get("grantee") for sql, parameters in cursor.asked]
    assert grantees.count("PUBLIC") == 4
    assert survey.system is not None
    public = [row for row in survey.system if row.grantee == "PUBLIC"]
    assert public == [
        GrantRow(
            "PUBLIC",
            SYSTEM,
            "CREATE SYNONYM",
            None,
            None,
            None,
            None,
            ("ACME_RR_PUB",),
            True,
            False,
        )
    ]


def test_a_release_without_type_or_authentication_type() -> None:
    no_column = _ora("ORA-00904", '"T"."TYPE": invalid identifier')
    answers = _answers(roles=_ora("ORA-00904", '"R"."AUTHENTICATION_TYPE": invalid identifier'))
    answers[(ROLE_GRANTS_QUERY_LEGACY, APP)] = [("ACME_RR_DUP", "NO", "YES", "YES")]
    answers[(TAB_PRIVS_QUERY, APP)] = no_column
    answers[(TAB_PRIVS_QUERY_LEGACY, APP)] = [(None, None, "SELECT", OWNER, "T1", None, "NO")]
    survey = survey_grants(_Cursor(answers), [APP], public=False)
    assert survey.objects is not None
    assert survey.objects[0].object_type is None
    # PASSWORD_REQUIRED YES is reported in the newer column's word.
    assert survey.roles[0].authentication == "PASSWORD"


def test_without_role_lookup_roles_are_read_without_dba_roles() -> None:
    """DBA_ROLES is optional (`PREDICATE_READS`), so its absence must not end
    the survey: the roles come from DBA_ROLE_PRIVS alone, with authentication
    UNKNOWN and a reason naming the grant."""
    answers = _answers()
    answers[(ROLE_GRANTS_QUERY_NO_ROLES, APP)] = [("ACME_RR_DUP", "NO", "YES", None)]
    cursor = _Cursor(answers)
    survey = survey_grants(cursor, [APP], public=False, role_lookup=False)
    assert survey.roles == (
        RoleGrant(APP, "ACME_RR_DUP", False, True, authentication=UNKNOWN_AUTHENTICATION),
    )
    assert survey.objects is not None
    (reason,) = survey.unreadable
    assert "GRANT SELECT ON SYS.DBA_ROLES" in reason
    assert ROLE_GRANTS_QUERY not in [sql for sql, _ in cursor.asked]


def test_an_empty_authentication_is_unknown_not_blank() -> None:
    answers = _answers(roles=[("ACME_RR_DUP", "NO", "YES", None)])
    survey = survey_grants(_Cursor(answers), [APP], public=False)
    assert survey.roles[0].authentication == UNKNOWN_AUTHENTICATION


def test_rows_from_two_grantors_are_one_row_and_grantable_if_either_is() -> None:
    answers = _answers(
        objects=[
            (None, None, "SELECT", OWNER, "T1", "TABLE", "NO"),
            (None, None, "SELECT", OWNER, "T1", "TABLE", "YES"),
            (None, None, "SELECT", OWNER, "T1", "TABLE", "NO"),
        ]
    )
    survey = survey_grants(_Cursor(answers), [APP], public=False)
    assert survey.objects is not None
    (row,) = survey.objects
    assert row.grantable is True


def test_a_narrower_shape_is_kept_for_the_next_grantee() -> None:
    """A release without DBA_TAB_PRIVS.TYPE refuses the wider query once, not
    once per account."""
    no_column = _ora("ORA-00904", '"T"."TYPE": invalid identifier')
    answers = _answers(objects=no_column)
    answers[(TAB_PRIVS_QUERY_LEGACY, APP)] = []
    answers[(TAB_PRIVS_QUERY, "ACME_WEB_USER")] = no_column
    cursor = _Cursor(answers)
    survey_grants(cursor, [APP, "ACME_WEB_USER"], public=False)
    asked = [sql for sql, _ in cursor.asked]
    assert asked.count(TAB_PRIVS_QUERY) == 1
    assert asked.count(TAB_PRIVS_QUERY_LEGACY) == 2


def test_every_statement_binds_only_the_grantee_and_reads_no_verifier() -> None:
    cursor = _Cursor(_answers())
    survey_grants(cursor, [APP], public=False)
    for sql, parameters in cursor.asked:
        assert set(parameters) == {"grantee"}
        lowered = sql.lower()
        assert "user$" not in lowered
        assert "spare4" not in lowered
        assert "password" not in lowered.replace("password_required", "")


def test_the_recursion_cannot_loop() -> None:
    for statement in (SYS_PRIVS_QUERY, TAB_PRIVS_QUERY, COL_PRIVS_QUERY):
        assert "cycle granted_role set" in statement.lower()


class _Connection:
    def __init__(self) -> None:
        self.cursor_ = _Cursor(_answers())

    def cursor(self) -> _Cursor:
        return self.cursor_


def test_the_session_method_reads_through_its_connection(session_module: Any) -> None:
    session = session_module.OracleSession(
        connection=_Connection(),
        target=ExpandedTarget(
            target=Target(name="orders", type="oracle", dsn="db.example.com:1521/orders"),
            index=0,
        ),
        correlation_id="00000000-0000-0000-0000-000000000000",
    )
    session._scope = Scope(type="pdb", capabilities=frozenset({ROLE_LOOKUP}))
    survey = session.survey_privileges([APP], public=False)
    assert isinstance(survey, GrantSurvey)
    assert survey.objects is not None
    assert len(survey.objects) == len(RR4_OBJECTS)
