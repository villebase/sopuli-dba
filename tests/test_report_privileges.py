"""UC-5's privilege report: collapsing paths, counting, and the exit code. Tier 0.

The grant rows have the shape probe 19 v3 RR4 measured: one row per path, so a
privilege granted directly and through two roles arrives three times.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from sopuli.driver.grants import COLUMN, OBJECT, SCHEMA, SYSTEM, GrantRow, GrantSurvey, RoleGrant
from sopuli.report_accounts import REPORT_OK, AccountRow
from sopuli.report_privileges import collapse, counts, exit_code, per_account

APP = "ACME_RR_APP"


def grant(
    privilege: str,
    name: str | None = None,
    *,
    path: tuple[str, ...] = (),
    kind: str = OBJECT,
    default: bool | None = True,
    grantee: str = APP,
    object_type: str | None = "TABLE",
    column: str | None = None,
    grantable: bool = False,
) -> GrantRow:
    return GrantRow(
        grantee=grantee,
        kind=kind,
        privilege=privilege,
        owner="ACME_RR_OWNER" if name else None,
        name=name,
        object_type=object_type if kind != SYSTEM else None,
        column=column,
        path=path,
        first_role_default=None if not path else default,
        grantable=grantable,
    )


RR4 = (
    grant("EXECUTE", "P1", path=("ACME_RR_OUTER", "ACME_RR_READ"), object_type="PROCEDURE"),
    grant("INSERT", "T1", path=("ACME_RR_EXTRA",), default=False),
    grant("SELECT", "T1"),
    grant("SELECT", "T2", path=("ACME_RR_DUP",)),
    grant("SELECT", "T2", path=("ACME_RR_OUTER", "ACME_RR_DUP")),
    grant("SELECT", "T2"),
    grant("SELECT", "T3", path=("ACME_RR_DUP",)),
    grant("SELECT", "T3", path=("ACME_RR_OUTER", "ACME_RR_DUP")),
    grant("SELECT", "T3", path=("ACME_RR_OUTER", "ACME_RR_READ")),
    grant("SELECT", "T4", path=("ACME_RR_OUTER", "ACME_RR_READ")),
    grant("SELECT", "T5", path=("ACME_RR_OUTER", "ACME_RR_READ")),
)


def test_a_schema_is_an_exception_only_where_every_path_revokes_it() -> None:
    """Privileges add up: on 8.4.13, an account whose own SELECT ON *.* is
    revoked on acme_hr reads acme_hr through an active role that holds SELECT
    ON *.* without that revoke (#1502)."""
    own = GrantRow(
        grantee=APP,
        kind=SYSTEM,
        privilege="SELECT",
        owner=None,
        name=None,
        object_type=None,
        column=None,
        path=(),
        first_role_default=None,
        grantable=False,
        level="global static",
        except_schemas=("acme_hr", "acme_pay"),
    )
    via_role = replace(
        own, path=("acme_reader@%",), first_role_default=True, except_schemas=("acme_pay",)
    )
    (alone,) = collapse([own])
    (both,) = collapse([own, via_role])
    assert alone.except_schemas == ("acme_hr", "acme_pay")
    assert both.except_schemas == ("acme_pay",)


def test_a_role_not_active_at_login_gives_no_schema_back() -> None:
    """At login, a role that is not a default role grants nothing, so its
    unrevoked SELECT does not undo the account's own revoke (#1510). One not
    known to be active may: the report then shows the wider reach."""
    own = GrantRow(
        grantee=APP,
        kind=SYSTEM,
        privilege="SELECT",
        owner=None,
        name=None,
        object_type=None,
        column=None,
        path=(),
        first_role_default=None,
        grantable=False,
        level="global static",
        except_schemas=("acme_hr",),
    )
    role = replace(own, path=("acme_reader@%",), except_schemas=())
    (not_default,) = collapse([own, replace(role, first_role_default=False)])
    assert not_default.except_schemas == ("acme_hr",)
    (not_known,) = collapse([own, replace(role, first_role_default=None)])
    assert not_known.except_schemas == ()
    # Held only through roles not active: every path counts.
    first = replace(own, path=("acme_a@%",), first_role_default=False)
    second = replace(first, path=("acme_b@%",), except_schemas=())
    (only_roles,) = collapse([first, second])
    assert only_roles.except_schemas == ()


def test_one_privilege_at_two_levels_stays_two_privileges() -> None:
    # MySQL keeps a static and a dynamic global privilege in two places; a
    # privilege named the same at both levels is two grants, not two paths.
    static = GrantRow(
        APP, SYSTEM, "AUDIT_ADMIN", None, None, None, None, (), None, False, "global static"
    )
    dynamic = GrantRow(
        APP,
        SYSTEM,
        "AUDIT_ADMIN",
        None,
        None,
        None,
        None,
        ("ACME_ROLE",),
        True,
        False,
        "global dynamic",
    )
    collapsed = collapse([static, dynamic])
    assert [(p.level, p.paths) for p in collapsed] == [
        ("global dynamic", (("ACME_ROLE",),)),
        ("global static", ((),)),
    ]


def test_two_levels_of_one_privilege_and_type_are_counted_apart() -> None:
    # A default privilege is not a grant on a table that exists (#1481).
    granted = grant("SELECT", "T1")
    default = GrantRow(
        APP, OBJECT, "SELECT", "ACME_RR_OWNER", None, "TABLE", None, (), None, False, "default"
    )
    assert counts(collapse([granted, default])) == {
        ("", "SELECT", "TABLE"): (1, 0),
        ("default", "SELECT", "TABLE"): (1, 0),
    }


def test_oracle_rows_have_no_level() -> None:
    assert {p.level for p in collapse(RR4)} == {None}


def test_collapse_gives_one_privilege_per_object_with_every_path() -> None:
    collapsed = collapse(RR4)
    # 11 rows, 7 privileges: RR4's two PUBLIC grants are not in this fixture.
    assert len(collapsed) == 7
    t2 = next(p for p in collapsed if p.privilege == "SELECT" and p.name == "T2")
    assert set(t2.paths) == {(), ("ACME_RR_DUP",), ("ACME_RR_OUTER", "ACME_RR_DUP")}


def test_a_non_default_role_still_counts_and_is_marked() -> None:
    insert = next(p for p in collapse(RR4) if p.privilege == "INSERT")
    assert insert.via_default_role is False
    assert insert.active_at_login_checked is True


def test_a_path_whose_first_role_is_unknown_is_not_checked() -> None:
    # MySQL without SELECT on mysql.default_roles, or a mandatory role (#1482).
    (unknown,) = collapse((grant("SELECT", "T9", path=("R",), default=None),))
    assert (unknown.via_default_role, unknown.active_at_login_checked) == (False, False)
    (mixed,) = collapse(
        (
            grant("SELECT", "T9", path=("R",), default=None),
            grant("SELECT", "T9", path=("S",), default=False),
        )
    )
    assert (mixed.via_default_role, mixed.active_at_login_checked) == (False, False)
    # One active path is enough, whatever the others are.
    (active,) = collapse(
        (
            grant("SELECT", "T9", path=("R",), default=None),
            grant("SELECT", "T9", path=("S",), default=True),
        )
    )
    assert (active.via_default_role, active.active_at_login_checked) == (True, True)


def test_counts_split_direct_and_via_roles() -> None:
    by_kind = counts(collapse(RR4))
    assert by_kind[("", "SELECT", "TABLE")] == (2, 3)
    assert by_kind[("", "EXECUTE", "PROCEDURE")] == (0, 1)
    assert by_kind[("", "INSERT", "TABLE")] == (0, 1)


def test_grantable_if_any_path_is() -> None:
    rows = (grant("SELECT", "T9"), grant("SELECT", "T9", path=("R",), grantable=True))
    assert collapse(rows)[0].grantable is True


#: Probe 21's direct schema privilege: its schema is ``owner``.
SCHEMA_ROW = GrantRow(
    grantee=APP,
    kind=SCHEMA,
    privilege="SELECT ANY TABLE",
    owner="ACME_SP_OWNER",
    name=None,
    object_type=None,
    column=None,
    path=(),
    first_role_default=None,
    grantable=False,
)


def account_row(name: str, kind: str = "technical") -> AccountRow:
    return AccountRow("free-pdb", name, kind, "DEFAULT", "OPEN", (), REPORT_OK, 0)


def survey(**parts: Any) -> GrantSurvey:
    values: dict[str, Any] = {
        "roles": (RoleGrant(APP, "ACME_RR_OUTER", False, True, "NONE"),),
        "system": (grant("CREATE SESSION", kind=SYSTEM),),
        "objects": RR4,
        "columns": (grant("UPDATE", "T4", kind=COLUMN, column="N"),),
        "schemas": (SCHEMA_ROW,),
        "unreadable": (),
    }
    values.update(parts)
    return GrantSurvey(**values)


def test_per_account_splits_the_parts_and_keeps_kind() -> None:
    (one,) = per_account("free-pdb", [account_row(APP)], survey())
    assert one.kind == "technical"
    assert [role.role for role in one.roles] == ["ACME_RR_OUTER"]
    assert one.system is not None
    assert len(one.system) == 1
    assert one.objects is not None
    assert len(one.objects) == 7
    assert one.columns is not None
    assert one.columns[0].column == "N"
    assert one.schemas is not None
    assert [(p.privilege, p.owner) for p in one.schemas] == [("SELECT ANY TABLE", "ACME_SP_OWNER")]
    assert one.complete is True


def test_an_unreadable_part_is_none_not_empty() -> None:
    (one,) = per_account(
        "free-pdb", [account_row(APP)], survey(objects=None, unreadable=("DBA_TAB_PRIVS",))
    )
    assert one.objects is None
    assert one.system is not None


def test_unread_schema_privileges_leave_the_account_incomplete() -> None:
    (one,) = per_account("free-pdb", [account_row(APP)], survey(schemas=None))
    assert one.schemas is None
    assert one.complete is False


def test_a_release_without_schema_privileges_is_complete() -> None:
    (one,) = per_account("free-pdb", [account_row(APP)], survey(schemas=()))
    assert one.schemas == ()
    assert one.complete is True


def test_public_is_one_block_not_repeated() -> None:
    public_rows = (grant("SELECT", "T6", grantee="PUBLIC"),)
    found = per_account(
        "free-pdb",
        [account_row(APP), account_row("ACME_OTHER")],
        survey(objects=RR4 + public_rows),
        public=True,
    )
    names = [one.account for one in found]
    assert names.count("PUBLIC") == 1
    other = next(one for one in found if one.account == "ACME_OTHER")
    assert other.objects == ()


def test_public_asked_for_and_unreadable_is_listed_not_checked() -> None:
    found = per_account(
        "free-pdb",
        [account_row(APP)],
        survey(system=None, objects=None, columns=None, roles=()),
        public=True,
    )
    public = next(one for one in found if one.account == "PUBLIC")
    assert public.objects is None
    assert public.complete is False


def test_public_is_not_listed_unless_asked_for() -> None:
    public_rows = (grant("SELECT", "T6", grantee="PUBLIC"),)
    found = per_account("free-pdb", [account_row(APP)], survey(objects=RR4 + public_rows))
    assert [one.account for one in found] == [APP]


def test_names_that_differ_only_in_case_are_two_accounts() -> None:
    rows = (grant("SELECT", "T1", grantee="ACME"), grant("SELECT", "T2", grantee="acme"))
    found = per_account(
        "free-pdb", [account_row("ACME"), account_row("acme")], survey(objects=rows)
    )
    by_name = {one.account: one for one in found}
    assert [p.name for p in by_name["ACME"].objects or ()] == ["T1"]
    assert [p.name for p in by_name["acme"].objects or ()] == ["T2"]


def test_a_survey_that_could_not_read_something_exits_4() -> None:
    full = per_account("free-pdb", [account_row(APP)], survey())
    assert exit_code(full, unreachable=0, unsupported=0, targets=1, unreadable=True) == 4


def test_exit_codes() -> None:
    full = per_account("free-pdb", [account_row(APP)], survey())
    partial = per_account("free-pdb", [account_row(APP)], survey(columns=None))
    assert exit_code(full, unreachable=0, unsupported=0, targets=1) == 0
    assert exit_code(partial, unreachable=0, unsupported=0, targets=1) == 4
    assert exit_code(full, unreachable=1, unsupported=0, targets=2) == 1
    assert exit_code((), unreachable=0, unsupported=1, targets=1) == 5
    assert exit_code(full, unreachable=0, unsupported=1, targets=2) == 4
