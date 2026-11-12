"""The shared privilege survey of MySQL and MariaDB: rows per path (#1482). Tier 0."""

from __future__ import annotations

import pytest

from sopuli.driver.grants import COLUMN, OBJECT, SCHEMA, SYSTEM
from sopuli.driver.mysql_family.accounts import Principal
from sopuli.driver.mysql_family.privilege_survey import (
    MANDATORY_UNKNOWN,
    Activation,
    Edge,
    Held,
    survey,
)
from sopuli.report_privileges import collapse

APP = Principal("acme_app", "%")
MID = Principal("acme_mid", "%")
TOP = Principal("acme_top", "%")
MAND = Principal("acme_mand", "%")


def grant(holder: Principal, privilege: str = "SELECT", **fields: object) -> Held:
    values: dict[str, object] = {
        "kind": OBJECT,
        "level": "table",
        "owner": "acme",
        "name": "orders",
        "object_type": "TABLE",
    }
    values.update(fields)
    return Held(holder=holder, privilege=privilege, **values)  # type: ignore[arg-type]


def defaults(
    *pairs: tuple[Principal, Principal],
) -> frozenset[tuple[tuple[str, str], tuple[str, str]]]:
    return frozenset((member.key(), role.key()) for member, role in pairs)


NESTED = (Edge(APP, MID, admin_option=False), Edge(MID, TOP, admin_option=True))


def test_an_own_grant_is_a_row_with_no_path() -> None:
    found = survey(["acme_app@%"], [], [grant(APP)], Activation(defaults()))
    assert found.objects is not None
    (row,) = found.objects
    assert (row.grantee, row.privilege, row.path, row.first_role_default) == (
        "acme_app@%",
        "SELECT",
        (),
        None,
    )
    assert row.level == "table"
    assert found.unreadable == ()


def test_a_privilege_of_a_nested_role_has_its_whole_path() -> None:
    found = survey(["acme_app@%"], NESTED, [grant(TOP)], Activation(defaults((APP, MID))))
    assert found.objects is not None
    (row,) = found.objects
    assert row.path == ("acme_mid@%", "acme_top@%")
    # A role a default role holds is active: the first role says it.
    assert row.first_role_default is True


def test_a_privilege_held_two_ways_is_one_row_per_path_and_one_privilege() -> None:
    found = survey(
        ["acme_app@%"], NESTED, [grant(APP), grant(MID), grant(TOP)], Activation(defaults())
    )
    assert found.objects is not None
    assert sorted(row.path for row in found.objects) == [
        (),
        ("acme_mid@%",),
        ("acme_mid@%", "acme_top@%"),
    ]
    (privilege,) = collapse(found.objects)
    assert len(privilege.paths) == 3
    assert privilege.via_default_role is True


def test_a_role_that_is_not_a_default_is_not_active() -> None:
    found = survey(["acme_app@%"], NESTED, [grant(MID)], Activation(defaults()))
    assert found.objects is not None
    assert [row.first_role_default for row in found.objects] == [False]
    (role,) = found.roles
    assert (role.role, role.default_role, role.admin_option) == ("acme_mid@%", False, False)


def test_unread_default_roles_leave_activation_unknown() -> None:
    found = survey(
        ["acme_app@%"], NESTED, [grant(MID)], Activation(None), reasons=("no default roles",)
    )
    assert found.objects is not None
    assert [row.first_role_default for row in found.objects] == [None]
    assert (found.roles[0].default_role, found.roles[0].default_role_checked) == (False, False)
    assert found.unreadable == ("no default roles",)


def test_every_role_is_active_when_all_are_activated_at_login() -> None:
    found = survey(
        ["acme_app@%"],
        NESTED,
        [grant(TOP), grant(MAND)],
        Activation(None, all_active=True, mandatory=(MAND,)),
    )
    assert found.objects is not None
    assert {row.first_role_default for row in found.objects} == {True}
    assert found.unreadable == ()


def test_a_mandatory_role_is_held_by_every_account_and_its_activation_unknown() -> None:
    found = survey(
        ["acme_app@%", "acme_ops@localhost"],
        [],
        [grant(MAND)],
        Activation(defaults(), mandatory=(MAND,)),
    )
    assert found.objects is not None
    assert [(row.grantee, row.path, row.first_role_default) for row in found.objects] == [
        ("acme_app@%", ("acme_mand@%",), None),
        ("acme_ops@localhost", ("acme_mand@%",), None),
    ]
    assert found.unreadable == (MANDATORY_UNKNOWN,)


def test_a_mandatory_role_set_as_a_default_is_active() -> None:
    found = survey(
        ["acme_app@%"], [], [grant(MAND)], Activation(defaults((APP, MAND)), mandatory=(MAND,))
    )
    assert found.objects is not None
    assert [row.first_role_default for row in found.objects] == [True]
    assert found.roles[0].default_role is True
    assert found.unreadable == ()


def test_a_mandatory_role_also_granted_is_followed_as_granted() -> None:
    found = survey(
        ["acme_app@%"],
        [Edge(APP, MAND, admin_option=True)],
        [grant(MAND)],
        Activation(defaults(), mandatory=(MAND,)),
    )
    assert [(role.role, role.admin_option) for role in found.roles] == [("acme_mand@%", True)]
    assert found.objects is not None
    assert [row.first_role_default for row in found.objects] == [False]
    assert found.unreadable == ()


def test_a_circular_grant_ends() -> None:
    edges = (*NESTED, Edge(TOP, MID, admin_option=False))
    found = survey(["acme_app@%"], edges, [grant(TOP)], Activation(defaults()))
    assert found.objects is not None
    assert [row.path for row in found.objects] == [("acme_mid@%", "acme_top@%")]


def test_hosts_compare_without_ascii_case_and_the_survey_spelling_is_kept() -> None:
    upper = Principal("acme_app", "DB.EXAMPLE.COM")
    lower = Principal("acme_app", "db.example.com")
    found = survey(
        ["acme_app@DB.EXAMPLE.COM"],
        [Edge(lower, MID, admin_option=False)],
        [grant(MID)],
        Activation(defaults((lower, MID))),
    )
    assert found.objects is not None
    (row,) = found.objects
    assert (row.grantee, row.first_role_default) == ("acme_app@DB.EXAMPLE.COM", True)
    assert upper.key() == lower.key()


def test_each_kind_lands_in_its_part() -> None:
    held = [
        grant(APP, "CREATE USER", kind=SYSTEM, level="global static", owner=None, name=None,
              object_type=None),
        grant(APP, "INSERT", kind=SCHEMA, level="database", name=None, object_type=None),
        grant(APP, "UPDATE", kind=COLUMN, level="column", column="total"),
        grant(APP),
    ]  # fmt: skip
    found = survey(["acme_app@%"], [], held, Activation(defaults()))
    assert [row.privilege for row in found.system or ()] == ["CREATE USER"]
    assert [row.privilege for row in found.schemas or ()] == ["INSERT"]
    assert [row.privilege for row in found.columns or ()] == ["UPDATE"]
    assert [row.privilege for row in found.objects or ()] == ["SELECT"]


def test_an_unread_part_is_none_with_its_reason() -> None:
    found = survey(
        ["acme_app@%"],
        [],
        [grant(APP, kind=SYSTEM, level="global static")],
        Activation(defaults()),
        unread={SYSTEM: "partial revokes are on"},
    )
    assert found.system is None
    assert found.objects == ()
    assert found.unreadable == ("partial revokes are on",)


def test_an_account_with_nothing_has_empty_parts() -> None:
    found = survey(["acme_app@%"], [], [grant(MID)], Activation(defaults()))
    assert (found.system, found.schemas, found.objects, found.columns) == ((), (), (), ())
    assert found.roles == ()


def test_a_held_privilege_of_no_known_part_is_refused() -> None:
    with pytest.raises(ValueError, match="routine"):
        Held(holder=APP, kind="routine", level="routine", privilege="EXECUTE")


def test_all_roles_active_at_login_is_not_a_default_role() -> None:
    found = survey(["acme_app@%"], NESTED, [grant(MID)], Activation(None, all_active=True))
    assert found.objects is not None
    assert [row.first_role_default for row in found.objects] == [True]
    # The roles line says what was read: the role is not a default role.
    assert found.roles[0].default_role is False


def test_a_mysql_role_at_an_empty_host_keeps_its_at_sign() -> None:
    """MySQL can make a role at host '', and `r` alone would name `r@%` there,
    another role. The engine names a role `user@host` unless the driver
    passes its own naming, as MariaDB's does for its hostless roles."""
    empty = Principal("acme_bare", "")
    edges = [Edge(member=APP, role=empty, admin_option=False)]
    found = survey(["acme_app@%"], edges, [grant(empty)], Activation(defaults()))
    assert [role.role for role in found.roles] == ["acme_bare@"]
    assert found.objects is not None
    assert [row.path for row in found.objects] == [("acme_bare@",)]
