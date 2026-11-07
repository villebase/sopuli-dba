"""UC-5's privilege report: collapsing paths, counting, and the exit code. Tier 0.

The grant rows have the shape probe 19 v3 RR4 measured: one row per path, so a
privilege granted directly and through two roles arrives three times.
"""

from __future__ import annotations

from typing import Any

from sopuli.driver.grants import COLUMN, OBJECT, SYSTEM, GrantRow, GrantSurvey, RoleGrant
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


def test_collapse_gives_one_privilege_per_object_with_every_path() -> None:
    collapsed = collapse(RR4)
    # 11 rows, 7 privileges: RR4's two PUBLIC grants are not in this fixture.
    assert len(collapsed) == 7
    t2 = next(p for p in collapsed if p.privilege == "SELECT" and p.name == "T2")
    assert set(t2.paths) == {(), ("ACME_RR_DUP",), ("ACME_RR_OUTER", "ACME_RR_DUP")}


def test_a_non_default_role_still_counts_and_is_marked() -> None:
    insert = next(p for p in collapse(RR4) if p.privilege == "INSERT")
    assert insert.via_default_role is False


def test_counts_split_direct_and_via_roles() -> None:
    by_kind = counts(collapse(RR4))
    assert by_kind[("SELECT", "TABLE")] == (2, 3)
    assert by_kind[("EXECUTE", "PROCEDURE")] == (0, 1)
    assert by_kind[("INSERT", "TABLE")] == (0, 1)


def test_grantable_if_any_path_is() -> None:
    rows = (grant("SELECT", "T9"), grant("SELECT", "T9", path=("R",), grantable=True))
    assert collapse(rows)[0].grantable is True


def account_row(name: str, kind: str = "technical") -> AccountRow:
    return AccountRow("free-pdb", name, kind, "DEFAULT", "OPEN", (), REPORT_OK, 0)


def survey(**parts: Any) -> GrantSurvey:
    values: dict[str, Any] = {
        "roles": (RoleGrant(APP, "ACME_RR_OUTER", False, True, "NONE"),),
        "system": (grant("CREATE SESSION", kind=SYSTEM),),
        "objects": RR4,
        "columns": (grant("UPDATE", "T4", kind=COLUMN, column="N"),),
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


def test_an_unreadable_part_is_none_not_empty() -> None:
    (one,) = per_account(
        "free-pdb", [account_row(APP)], survey(objects=None, unreadable=("DBA_TAB_PRIVS",))
    )
    assert one.objects is None
    assert one.system is not None


def test_public_is_one_block_not_repeated() -> None:
    public_rows = (grant("SELECT", "T6", grantee="PUBLIC"),)
    found = per_account(
        "free-pdb",
        [account_row(APP), account_row("ACME_OTHER")],
        survey(objects=RR4 + public_rows),
    )
    names = [one.account for one in found]
    assert names.count("PUBLIC") == 1
    other = next(one for one in found if one.account == "ACME_OTHER")
    assert other.objects == ()


def test_exit_codes() -> None:
    full = per_account("free-pdb", [account_row(APP)], survey())
    partial = per_account("free-pdb", [account_row(APP)], survey(columns=None))
    assert exit_code(full, unreachable=0, unsupported=0, targets=1) == 0
    assert exit_code(partial, unreachable=0, unsupported=0, targets=1) == 4
    assert exit_code(full, unreachable=1, unsupported=0, targets=2) == 1
    assert exit_code((), unreachable=0, unsupported=1, targets=1) == 5
    assert exit_code(full, unreachable=0, unsupported=1, targets=2) == 4
