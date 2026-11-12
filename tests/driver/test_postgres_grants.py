"""How the PostgreSQL privilege survey assembles what the catalogs answer (#1481).

Tier 0, with a cursor that answers each statement in turn. The SQL itself is
checked against a server in ``test_postgres_grants_live.py``.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sopuli.driver.grants import COLUMN, OBJECT, SCHEMA, SYSTEM, RoleGrant
from sopuli.driver.postgres.grants import (
    ATTRIBUTE,
    ATTRIBUTES_QUERY,
    HAS_PARAMETER_ACL,
    OTHER_DATABASES,
    PUBLIC,
    WALK_QUERY,
    privileges_query,
    survey_grants,
)

USER = "acme_rp_user"
NONE = (False, False, False, False, False)


def walk(
    *path: str,
    inherits: bool,
    sets: bool,
    reach: bool | None = None,
    admin: bool = False,
    predefined: bool = False,
) -> tuple[Any, ...]:
    """One walk row: account, path, inherits, sets, reach, admin, predefined.
    ``reach`` is ``sets`` unless given."""
    return (USER, list(path), inherits, sets, sets if reach is None else reach, admin, predefined)


class Answers:
    """A cursor that answers each statement with the next scripted result."""

    def __init__(self, *answers: Any) -> None:
        self.answers = list(answers)
        self.executed: list[tuple[str, Any]] = []
        self.last: Any = None

    def execute(self, statement: Any, parameters: Any = None, /) -> None:
        self.executed.append((statement, parameters))
        self.last = self.answers.pop(0)

    def fetchone(self) -> Any:
        return self.last

    def fetchall(self) -> Any:
        return self.last


def survey(
    walks: Sequence[tuple[Any, ...]] = (),
    attributes: Sequence[tuple[Any, ...]] = (),
    privileges: Sequence[tuple[Any, ...]] = (),
    others: Sequence[str] = (),
    *,
    parameters: bool = True,
    public: bool = False,
) -> tuple[Any, Answers]:
    cursor = Answers(
        list(walks),
        list(attributes),
        (parameters,),
        list(privileges),
        [(name,) for name in others],
    )
    return survey_grants(cursor, [USER], public=public), cursor


def table(grantee: str, privilege: str, name: str | None, **fields: Any) -> tuple[Any, ...]:
    """One privileges-query row: grantee, kind, level, owner, name, type, column,
    privilege, grantable."""
    values = {
        "kind": OBJECT,
        "level": None,
        "owner": "acme_rp",
        "object_type": "TABLE",
        "column": None,
        "grantable": False,
    }
    values.update(fields)
    return (
        grantee,
        values["kind"],
        values["level"],
        values["owner"],
        name,
        values["object_type"],
        values["column"],
        privilege,
        values["grantable"],
    )


def test_the_statements_and_their_parameters() -> None:
    _, cursor = survey(walks=[walk("acme_rp_app", inherits=True, sets=True)], public=True)
    statements = [statement for statement, _ in cursor.executed]
    assert statements == [
        WALK_QUERY,
        ATTRIBUTES_QUERY,
        HAS_PARAMETER_ACL,
        privileges_query(parameters=True),
        OTHER_DATABASES,
    ]
    assert cursor.executed[0][1] == ([USER],)
    # The privileges of every role the account reaches are read, and PUBLIC's
    # only when asked for.
    assert cursor.executed[3][1] == (["acme_rp_app", USER], True)


def test_a_server_without_parameter_acls_is_not_asked_for_them() -> None:
    _, cursor = survey(parameters=False)
    assert cursor.executed[3][0] == privileges_query(parameters=False)
    assert "pg_parameter_acl" not in privileges_query(parameters=False)
    assert "pg_parameter_acl" in privileges_query(parameters=True)


def test_a_direct_grant_has_no_path_and_an_inherited_one_is_active() -> None:
    result, _ = survey(
        walks=[walk("acme_rp_app", "acme_rp_read", inherits=True, sets=True)],
        privileges=[
            table(USER, "SELECT", "orders"),
            table("acme_rp_read", "SELECT", "orders"),
        ],
    )
    paths = {(row.path, row.first_role_default) for row in result.objects}
    assert paths == {((), None), (("acme_rp_app", "acme_rp_read"), True)}
    assert {row.grantee for row in result.objects} == {USER}


def test_a_path_without_inherit_is_reachable_only_by_set_role() -> None:
    result, _ = survey(
        walks=[walk("acme_rp_batch", inherits=False, sets=True)],
        privileges=[table("acme_rp_batch", "INSERT", "orders")],
    )
    (row,) = result.objects
    assert row.first_role_default is False


def test_set_role_then_inheriting_reaches_the_inherited_role() -> None:
    # user -[SET, no INHERIT]-> b -[INHERIT, no SET]-> c: after SET ROLE b, the
    # session holds c's privileges, though no grant chain both sets and inherits.
    result, _ = survey(
        walks=[
            walk("acme_rp_b", inherits=False, sets=True),
            walk("acme_rp_b", "acme_rp_c", inherits=False, sets=False, reach=True),
        ],
        attributes=[("acme_rp_c", False, True, False, False, False)],
        privileges=[table("acme_rp_c", "SELECT", "orders")],
    )
    (row,) = result.objects
    assert (row.path, row.first_role_default) == (("acme_rp_b", "acme_rp_c"), False)
    # c's attributes need SET ROLE to c itself, which the chain does not allow.
    assert result.system == ()


def test_a_predefined_role_is_listed_as_a_privilege_of_its_name() -> None:
    # What pg_read_all_data gives is in no ACL.
    result, _ = survey(
        walks=[walk("pg_read_all_data", inherits=True, sets=True, predefined=True)],
    )
    assert [
        (row.level, row.privilege, row.path, row.first_role_default) for row in result.system
    ] == [("predefined role", "pg_read_all_data", ("pg_read_all_data",), True)]


def test_a_path_with_neither_option_gives_nothing_but_the_membership() -> None:
    result, _ = survey(
        walks=[walk("acme_rp_watch", inherits=False, sets=False)],
        attributes=[("acme_rp_watch", True, False, False, False, False)],
        privileges=[table("acme_rp_watch", "SELECT", "orders")],
    )
    assert result.objects == ()
    assert result.system == ()
    assert result.roles == (
        RoleGrant(USER, "acme_rp_watch", False, False, "NONE", set_option=False),
    )


def test_an_attribute_reaches_a_member_only_by_set_role() -> None:
    result, _ = survey(
        walks=[
            walk("acme_rp_admin", inherits=True, sets=True),
            walk("acme_rp_dba", inherits=True, sets=False),
        ],
        attributes=[
            (USER, False, False, True, False, False),
            ("acme_rp_admin", False, True, False, False, False),
            ("acme_rp_dba", True, False, False, False, False),
        ],
    )
    found = {(row.privilege, row.path, row.first_role_default) for row in result.system}
    # CREATEDB is the account's own. CREATEROLE needs SET ROLE, even through a
    # grant that inherits, because an attribute is never inherited. The
    # SUPERUSER role cannot be SET to, so it gives nothing.
    assert found == {("CREATEDB", (), None), ("CREATEROLE", ("acme_rp_admin",), False)}
    assert {row.level for row in result.system} == {ATTRIBUTE}


def test_each_part_gets_its_own_rows_and_levels() -> None:
    result, _ = survey(
        privileges=[
            table(USER, "USAGE", None, kind=SCHEMA, level="schema", object_type="SCHEMA"),
            table(USER, "CONNECT", None, kind=SCHEMA, level="database", owner="acme_rp_db"),
            table(USER, "UPDATE", "items", kind=COLUMN, column="n"),
            table(USER, "SET", "work_mem", kind=SYSTEM, level="parameter", owner=None),
            table(USER, "SELECT", None, level="default for acme_rp_owner"),
        ]
    )
    assert [(row.level, row.privilege) for row in result.schemas] == [
        ("database", "CONNECT"),
        ("schema", "USAGE"),
    ]
    assert [(row.column, row.privilege) for row in result.columns] == [("n", "UPDATE")]
    assert [(row.level, row.name) for row in result.system] == [("parameter", "work_mem")]
    assert [row.level for row in result.objects] == ["default for acme_rp_owner"]


def test_public_is_its_own_grantee_and_only_when_asked() -> None:
    granted = table(PUBLIC, "EXECUTE", "post_order()", object_type="FUNCTION")
    asked, _ = survey(privileges=[granted], public=True)
    assert [(row.grantee, row.path) for row in asked.objects] == [(PUBLIC, ())]
    not_asked, cursor = survey(privileges=[granted], public=False)
    assert not_asked.objects == ()
    assert cursor.executed[3][1] == ([USER], False)


def test_a_membership_carries_its_options() -> None:
    result, _ = survey(walks=[walk("acme_rp_app", inherits=False, sets=True, admin=True)])
    assert result.roles == (RoleGrant(USER, "acme_rp_app", True, False, "NONE", set_option=True),)


def test_the_walk_merges_the_grants_of_every_grantor_first() -> None:
    # From 16, two grantors can each grant one role, with their own options.
    # One row per pair keeps the walk from growing with the grantors.
    assert "group by m.member, m.roleid" in WALK_QUERY
    assert "bool_or(" in WALK_QUERY


def test_the_other_databases_are_named_as_not_read() -> None:
    result, _ = survey(others=["acme_rp_other", "postgres"])
    (reason,) = result.unreadable
    assert "(acme_rp_other, postgres)" in reason
    assert "declare a target for each database" in reason
    alone, _ = survey()
    assert alone.unreadable == ()


def test_a_role_that_holds_nothing_reads_as_holding_nothing() -> None:
    result, _ = survey(attributes=[(USER, *NONE)])
    assert (result.roles, result.system, result.schemas, result.objects, result.columns) == (
        (),
        (),
        (),
        (),
        (),
    )
