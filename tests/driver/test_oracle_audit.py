"""Whether a reset is audited: `02-oracle-privileges.md` §5's rules. Tier 0.

The rules come from `sql/oracle/13_audit_coverage_probe.sql`'s measurements on
26ai 23.26.2.0.0. Each test here is one rule, given the rows the two policy views
returned for that shape in the probe. Tier 1, in
`test_oracle_service_account.py`, asks a real database the same questions.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Target
from sopuli.driver.oracle.audit import (
    ALL_USERS,
    BY_ROLE,
    BY_USER,
    COMMON_QUERY,
    ENABLED_QUERY,
    EXCEPT_USER,
    MODE_QUERY,
    OPTIONS_QUERY,
    STANDARD_ACTION,
    SYSTEM_PRIVILEGE,
    UNREADABLE,
    Enablement,
    Option,
    _is_common,
    classify,
    coverage_of,
)
from sopuli.driver.protocol import AuditCoverage

PERSON = "ACME_DEV_ALICE"
COMMON_PERSON = "C##ACME_DEV_CAROL"
DBA = "ACME_DBA1"


def enabled(
    policy: str, option: str = BY_USER, entity: str = ALL_USERS, *, success: bool = True
) -> Enablement:
    return Enablement(policy=policy, option=option, entity=entity, success=success)


def action(
    policy: str,
    name: str,
    *,
    kind: str = STANDARD_ACTION,
    condition: str | None = None,
    common: bool = False,
) -> Option:
    return Option(policy=policy, option=name, type=kind, condition=condition, common=common)


def both(policy: str, **kwargs: Any) -> list[Option]:
    """`ACTIONS ALTER USER, LOGON`, and the `XS ACTION` row Oracle adds to it."""
    return [
        action(policy, "ALTER USER", **kwargs),
        action(policy, "LOGON", **kwargs),
        action(policy, "UPDATE USER", kind="XS ACTION", **kwargs),
    ]


def answer(
    enablements: Sequence[Enablement], options: Sequence[Option], mode: str | None = "TRUE"
) -> AuditCoverage:
    return classify(mode, enablements, options, PERSON)


# ------------------------------------------------------------------ covers ---


def test_one_policy_for_every_user_covers_both() -> None:
    found = answer([enabled("P")], both("P"))

    assert found.audited is True
    assert found.detail == "LOGON by P; ALTER USER by P"


def test_actions_all_covers_both() -> None:
    """Measured: `ACTIONS ALL` records the `ALTER USER` and the logons."""
    assert answer([enabled("P")], [action("P", "ALL")]).audited is True


def test_the_alter_user_privilege_covers_alter_user() -> None:
    """Measured: `PRIVILEGES ALTER USER` records the DBA's `ALTER USER`."""
    found = answer(
        [enabled("PRIV"), enabled("LOG")],
        [action("PRIV", "ALTER USER", kind=SYSTEM_PRIVILEGE), action("LOG", "LOGON")],
    )

    assert found.audited is True
    assert found.detail == "LOGON by LOG; ALTER USER by PRIV"


def test_a_logon_policy_by_the_person_covers_their_logon() -> None:
    found = answer(
        [enabled("LOG", BY_USER, PERSON), enabled("ALT")],
        [action("LOG", "LOGON"), action("ALT", "ALTER USER")],
    )

    assert found.audited is True


def test_a_logon_policy_except_somebody_else_covers_the_person() -> None:
    found = answer(
        [enabled("LOG", EXCEPT_USER, DBA), enabled("ALT")],
        [action("LOG", "LOGON"), action("ALT", "ALTER USER")],
    )

    assert found.audited is True


def test_a_covering_policy_settles_an_action_whatever_the_others_say() -> None:
    found = answer(
        [enabled("P"), enabled("COND")],
        [*both("P"), *both("COND", condition="sys_context('userenv', 'ip_address') = 'x'")],
    )

    assert found.audited is True


def test_mixed_mode_does_not_stop_a_true() -> None:
    """Traditional auditing can only add records, so covered is covered."""
    assert answer([enabled("P")], both("P"), mode="FALSE").audited is True


# ---------------------------------------------------------- does not cover ---


def test_a_list_applies_to_whoever_issues_the_statement() -> None:
    """Measured: a policy `BY` the person records the proxy logon and not the
    DBA's `ALTER USER`. It covers `LOGON` and only might cover `ALTER USER`."""
    found = answer([enabled("P", BY_USER, PERSON)], both("P"))

    assert found.audited is None
    assert found.detail == (
        "LOGON by P; ALTER USER might be recorded: P records ALTER USER only for a list of users"
    )


def test_a_certain_gap_wins_over_a_doubt_about_the_other_action() -> None:
    """Nothing records `LOGON`, so the logon route is certainly unrecorded, and
    that is `false` whatever might record `ALTER USER`."""
    found = answer([enabled("ALT", BY_ROLE, "ACME_DBA_ROLE")], [action("ALT", "ALTER USER")])

    assert found.audited is False
    assert found.detail == f"no enabled policy records LOGON for {PERSON}"


def test_a_privilege_neither_route_uses_does_not_count() -> None:
    """`SELECT ANY TABLE` is used by neither a logon nor an `ALTER USER`, so a
    default policy that audits it does not make `false` unreachable."""
    found = answer(
        [enabled("SEL"), enabled("ALT")],
        [action("SEL", "SELECT ANY TABLE", kind=SYSTEM_PRIVILEGE), action("ALT", "ALTER USER")],
    )

    assert found.audited is False


def test_a_reason_for_both_actions_is_said_once_per_action() -> None:
    found = answer([enabled("C##P")], [action("C##P", "ALL", common=True)])

    assert found.audited is None
    assert found.detail.count("C##P is a common policy") == 2, "one per action, not repeated"
    assert found.detail.startswith("LOGON might be recorded: C##P is a common policy")


def test_a_logon_policy_by_somebody_else_does_not_cover_the_person() -> None:
    found = answer(
        [enabled("LOG", BY_USER, DBA), enabled("ALT")],
        [action("LOG", "LOGON"), action("ALT", "ALTER USER")],
    )

    assert found.audited is False
    assert found.detail == f"no enabled policy records LOGON for {PERSON}"


def test_a_list_is_read_whole() -> None:
    """`EXCEPT acme_dba1, acme_dev_alice` is two rows and one list, and it names
    the person. Read one row at a time, the first would look like it covers her."""
    found = answer(
        [enabled("LOG", EXCEPT_USER, DBA), enabled("LOG", EXCEPT_USER, PERSON), enabled("ALT")],
        [action("LOG", "LOGON"), action("ALT", "ALTER USER")],
    )

    assert found.audited is False


def test_a_policy_recording_only_failures_does_not_count() -> None:
    assert answer([enabled("P", success=False)], both("P")).audited is False


def test_the_install_scripts_policies_give_false() -> None:
    """`01_audit_policy.sql`: `sopuli_pol` for every user, and `sopuli_logon_pol`
    `BY` the service account `WHENEVER NOT SUCCESSFUL` (§5)."""
    found = answer(
        [
            enabled("SOPULI_POL"),
            enabled("SOPULI_LOGON_POL", BY_USER, "SOPULI_SVC", success=False),
        ],
        [
            action("SOPULI_POL", "ALTER USER"),
            action("SOPULI_POL", "CREATE USER"),
            action("SOPULI_POL", "DROP USER"),
            action("SOPULI_LOGON_POL", "LOGON"),
        ],
    )

    assert found.audited is False
    assert found.detail == f"no enabled policy records LOGON for {PERSON}"


def test_the_install_scripts_policies_with_the_person_listed_give_true() -> None:
    """`01_audit_policy.sql` run in the PDB with a list of personal accounts adds
    `sopuli_person_logon_pol` `BY` each of them `WHENEVER SUCCESSFUL` (§5)."""
    found = answer(
        [
            enabled("SOPULI_POL"),
            enabled("SOPULI_LOGON_POL", BY_USER, "SOPULI_SVC", success=False),
            enabled("SOPULI_PERSON_LOGON_POL", BY_USER, PERSON),
            enabled("SOPULI_PERSON_LOGON_POL", BY_USER, "ACME_DEV_BOB"),
        ],
        [
            action("SOPULI_POL", "ALTER USER"),
            action("SOPULI_POL", "CREATE USER"),
            action("SOPULI_POL", "DROP USER"),
            action("SOPULI_LOGON_POL", "LOGON"),
            action("SOPULI_PERSON_LOGON_POL", "LOGON"),
        ],
    )

    assert found.audited is True
    assert found.detail == "LOGON by SOPULI_PERSON_LOGON_POL; ALTER USER by SOPULI_POL"


def test_the_install_scripts_root_policies_alone_give_unknown() -> None:
    """Run in `CDB$ROOT`, the script creates common policies. From the PDB they
    might cover, because a common policy records nothing of local accounts."""
    found = answer(
        [
            enabled("SOPULI_CDB_POL"),
            enabled("SOPULI_CDB_LOGON_POL", BY_USER, "C##SOPULI_SVC", success=False),
            enabled("SOPULI_CDB_PERSON_LOGON_POL", BY_USER, PERSON),
        ],
        [
            action("SOPULI_CDB_POL", "ALTER USER", common=True),
            action("SOPULI_CDB_LOGON_POL", "LOGON", common=True),
            action("SOPULI_CDB_PERSON_LOGON_POL", "LOGON", common=True),
        ],
    )

    assert found.audited is None
    assert "SOPULI_CDB_POL is a common policy" in found.detail
    assert "SOPULI_CDB_PERSON_LOGON_POL is a common policy" in found.detail


def test_the_root_listing_the_person_and_the_pdb_not_gives_unknown() -> None:
    """A COMMON install run in both places, with the person in the root's list
    only. The PDB's `sopuli_pol` covers `ALTER USER`; the person's `LOGON` has
    only the common policy's doubt, so the answer is unknown, not false (§5)."""
    found = answer(
        [
            enabled("SOPULI_POL"),
            enabled("SOPULI_LOGON_POL", BY_USER, "C##SOPULI_SVC", success=False),
            enabled("SOPULI_CDB_POL"),
            enabled("SOPULI_CDB_PERSON_LOGON_POL", BY_USER, PERSON),
        ],
        [
            action("SOPULI_POL", "ALTER USER"),
            action("SOPULI_LOGON_POL", "LOGON"),
            action("SOPULI_CDB_POL", "ALTER USER", common=True),
            action("SOPULI_CDB_PERSON_LOGON_POL", "LOGON", common=True),
        ],
    )

    assert found.audited is None
    assert found.detail.startswith("LOGON might be recorded: SOPULI_CDB_PERSON_LOGON_POL")
    assert found.detail.endswith("ALTER USER by SOPULI_POL")


def test_nothing_enabled_names_both_actions() -> None:
    found = answer([], [])

    assert found.audited is False
    assert found.detail == f"no enabled policy records LOGON or ALTER USER for {PERSON}"


# --------------------------------------------------------------- might cover ---


def test_a_condition_is_not_evaluated() -> None:
    found = answer([enabled("P")], both("P", condition="sys_context('userenv', 'x') = 'y'"))

    assert found.audited is None
    assert "P has a condition, which is not evaluated" in found.detail


def test_a_common_policy_records_nothing_of_local_accounts() -> None:
    """Measured: it looks like an every-user policy from the PDB, and records
    nothing of a local account's route."""
    found = answer([enabled("C##P")], both("C##P", common=True))

    assert found.audited is None
    assert "C##P is a common policy" in found.detail


#: The install scripts' policies for a COMMON install run in the root with the
#: person in the list, and in the PDB with no list. #839's case.
ROOT_AND_PDB = (
    [
        enabled("SOPULI_POL"),
        enabled("SOPULI_CDB_POL"),
        enabled("SOPULI_CDB_PERSON_LOGON_POL", BY_USER, COMMON_PERSON),
    ],
    [
        action("SOPULI_POL", "ALTER USER"),
        action("SOPULI_CDB_POL", "ALTER USER", common=True),
        action("SOPULI_CDB_PERSON_LOGON_POL", "LOGON", common=True),
    ],
)


def test_a_common_policy_covers_a_common_persons_logon() -> None:
    """Measured (AC9): a common logon policy enabled `BY` a common person records
    their proxy logon in the root and in the PDB. With the PDB's every-user
    `ALTER USER` policy, the reset is audited (#839)."""
    enablements, options = ROOT_AND_PDB

    found = classify("TRUE", enablements, options, COMMON_PERSON, common=True)

    assert found.audited is True
    assert found.detail == "LOGON by SOPULI_CDB_PERSON_LOGON_POL; ALTER USER by SOPULI_POL"


def test_the_same_policies_for_a_local_person_stay_unknown() -> None:
    """AC6 and AC8: a common policy records nothing of a local account."""
    enablements, options = ROOT_AND_PDB
    listed = [
        enabled(one.policy, one.option, PERSON) if one.entity == COMMON_PERSON else one
        for one in enablements
    ]

    found = classify("TRUE", listed, options, PERSON, common=False)

    assert found.audited is None
    assert "SOPULI_CDB_PERSON_LOGON_POL is a common policy, which records nothing of local" in (
        found.detail
    )


def test_a_common_policy_never_covers_alter_user_even_for_a_common_person() -> None:
    """A DBA issues the `ALTER USER`, and the tool cannot know that the DBA is
    common. The detail says why, and does not call the person local."""
    found = classify(
        "TRUE",
        [enabled("C##P", BY_USER, COMMON_PERSON)],
        both("C##P", common=True),
        COMMON_PERSON,
        common=True,
    )

    assert found.audited is None
    assert found.detail.startswith("LOGON by C##P; ALTER USER might be recorded:")
    assert "records nothing of a local DBA's ALTER USER" in found.detail


@pytest.mark.parametrize(
    "enablement",
    [
        enabled("C##LOG"),
        enabled("C##LOG", EXCEPT_USER, DBA),
        enabled("C##LOG", BY_ROLE, "ACME_DEV_ROLE"),
    ],
    ids=["every user", "except a list", "a role"],
)
def test_a_common_policy_not_enabled_by_the_person_might_cover_their_logon(
    enablement: Enablement,
) -> None:
    """AC9a measured only a common policy enabled `BY` the person. Every other
    shape is unmeasured for a proxy logon, so it is not counted."""
    found = classify(
        "TRUE",
        [enablement, enabled("P")],
        [action("C##LOG", "LOGON", common=True), action("P", "ALTER USER")],
        COMMON_PERSON,
        common=True,
    )

    assert found.audited is None
    assert "C##LOG is a common policy not enabled BY the person" in found.detail


def test_a_role_is_not_resolved() -> None:
    found = answer([enabled("P", BY_ROLE, "ACME_DBA_ROLE")], both("P"))

    assert found.audited is None
    assert "P is enabled for a role" in found.detail


def test_an_unmeasured_kind_of_row_might_record_a_logon() -> None:
    """`PRIVILEGES CREATE SESSION` may record logons. Nobody has measured it, so
    it gives unknown, never a wrong false."""
    found = answer(
        [enabled("SESS"), enabled("ALT")],
        [action("SESS", "CREATE SESSION", kind=SYSTEM_PRIVILEGE), action("ALT", "ALTER USER")],
    )

    assert found.audited is None
    assert "SESS has SYSTEM PRIVILEGE CREATE SESSION" in found.detail


def test_an_unmeasured_row_for_somebody_else_does_not_reach_the_persons_logon() -> None:
    """Who the policy applies to comes first. `PRIVILEGES SELECT ANY TABLE` enabled
    `BY` a DBA records nothing the person issues, so it cannot record their logon."""
    found = answer(
        [enabled("SEL", BY_USER, DBA), enabled("ALT")],
        [action("SEL", "SELECT ANY TABLE", kind=SYSTEM_PRIVILEGE), action("ALT", "ALTER USER")],
    )

    assert found.audited is False
    assert found.detail == f"no enabled policy records LOGON for {PERSON}"


def test_an_enablement_nobody_has_seen_might_cover() -> None:
    """An `ENABLED_OPTION` outside the three the probe saw is never read as
    "does not cover", which on a unified-only database would be a wrong false."""
    found = answer([enabled("P", "SOMETHING NEW", PERSON)], both("P"))

    assert found.audited is None
    assert "P is enabled as SOMETHING NEW" in found.detail


def test_a_role_privilege_row_is_unmeasured() -> None:
    found = answer(
        [enabled("ROLES"), enabled("LOG")],
        [action("ROLES", "DBA", kind="ROLE PRIVILEGE"), action("LOG", "LOGON")],
    )

    assert found.audited is None


# ------------------------------------------------------------ the audit mode ---


def test_mixed_mode_turns_a_false_into_unknown() -> None:
    found = answer([], [], mode="FALSE")

    assert found.audited is None
    assert "mixed audit mode" in found.detail


def test_no_unified_auditing_is_unknown() -> None:
    found = answer([], [], mode=None)

    assert found.audited is None
    assert "no unified auditing" in found.detail


# ------------------------------------------------------------- the reading ---


class Cursor:
    """Answers each of the four queries from a table, or fails one of them.

    A query with no entry raises ``KeyError``, so a test cannot pass on a read it
    forgot to answer.
    """

    def __init__(self, answers: dict[str, Any], fail: dict[str, Exception] | None = None):
        self.answers = answers
        self.fail = fail or {}
        self.asked: list[tuple[str, Any]] = []
        self._last = ""

    def execute(self, statement: str, parameters: Any = None, /) -> None:
        self.asked.append((statement, parameters))
        if statement in self.fail:
            raise self.fail[statement]
        self._last = statement

    def fetchone(self) -> Any:
        return self.answers[self._last]

    def fetchall(self) -> Any:
        return self.answers[self._last]


def test_the_four_reads_are_classified() -> None:
    cursor = Cursor(
        {
            MODE_QUERY: ("TRUE",),
            COMMON_QUERY: ("NO",),
            ENABLED_QUERY: [("P", "BY USER", "ALL USERS", "YES")],
            OPTIONS_QUERY: [
                ("P", "LOGON", "STANDARD ACTION", "NONE", "NO"),
                ("P", "ALTER USER", "STANDARD ACTION", "NONE", "NO"),
            ],
        }
    )

    found = coverage_of(cursor, PERSON)

    assert found.audited is True
    assert [parameters for _, parameters in cursor.asked] == [None, {"name": PERSON}, None, None], (
        "only the person's name is bound"
    )


def test_the_persons_common_column_reaches_the_rules() -> None:
    """`DBA_USERS.COMMON` decides whether a common logon policy counts (#839)."""
    cursor = Cursor(
        {
            MODE_QUERY: ("TRUE",),
            COMMON_QUERY: ("YES",),
            ENABLED_QUERY: [
                ("C##P", "BY USER", COMMON_PERSON, "YES"),
                ("P", "BY USER", "ALL USERS", "YES"),
            ],
            OPTIONS_QUERY: [
                ("C##P", "LOGON", "STANDARD ACTION", "NONE", "YES"),
                ("P", "ALTER USER", "STANDARD ACTION", "NONE", "NO"),
            ],
        }
    )

    assert coverage_of(cursor, COMMON_PERSON).audited is True
    cursor.answers[COMMON_QUERY] = ("NO",)
    assert coverage_of(cursor, COMMON_PERSON).audited is None


@pytest.mark.parametrize(
    ("row", "common"),
    [(("yes",), True), (None, False), ((None,), False)],
    ids=["lower case", "no row", "null"],
)
def test_the_common_column_is_read_carefully(row: Any, common: bool) -> None:
    """No row or a `NULL` is a local person, the cautious reading."""
    cursor = Cursor({COMMON_QUERY: row})
    assert _is_common(cursor, COMMON_PERSON) is common


def test_an_unreadable_common_column_reads_the_person_as_local() -> None:
    """A failed `DBA_USERS` read must not cost the answer the check gave before
    it read the column: here, `false`, because nothing records the logon."""
    cursor = Cursor(
        {
            MODE_QUERY: ("TRUE",),
            ENABLED_QUERY: [("P", "BY USER", "ALL USERS", "YES")],
            OPTIONS_QUERY: [("P", "ALTER USER", "STANDARD ACTION", "NONE", "NO")],
        },
        fail={COMMON_QUERY: RuntimeError("ORA-00942: table or view does not exist")},
    )

    found = coverage_of(cursor, PERSON)

    assert found.audited is False
    assert found.detail == f"no enabled policy records LOGON for {PERSON}"


def test_an_unreadable_policy_view_names_the_grant() -> None:
    """Measured: the default install gets `ORA-00942` on both views."""
    cursor = Cursor(
        {MODE_QUERY: ("TRUE",)},
        fail={ENABLED_QUERY: RuntimeError("ORA-00942: table or view does not exist")},
    )

    found = coverage_of(cursor, PERSON)

    assert found.audited is None
    assert found.detail == UNREADABLE


def test_a_view_without_the_columns_read_says_so() -> None:
    """A release whose view has other columns answers `ORA-00904`. No grant fixes
    that, so the detail does not name one."""
    cursor = Cursor(
        {MODE_QUERY: ("TRUE",)},
        fail={ENABLED_QUERY: RuntimeError('ORA-00904: "ENABLED_OPTION": invalid identifier')},
    )

    found = coverage_of(cursor, PERSON)

    assert found.audited is None
    assert found.detail.startswith("the audit policy views on this database do not have")
    assert "GRANT" not in found.detail


def test_any_other_failure_is_unknown_with_the_servers_code() -> None:
    """Never raised: a reset records this and acts on nothing."""
    cursor = Cursor(
        {MODE_QUERY: ("TRUE",)},
        fail={ENABLED_QUERY: RuntimeError("ORA-00600: internal error code")},
    )

    found = coverage_of(cursor, PERSON)

    assert found.audited is None
    assert "ORA-00600" in found.detail


class _NoCursor:
    """A connection that dropped: it cannot open a cursor."""

    def cursor(self) -> Any:
        raise RuntimeError("DPI-1080: connection was closed by ORA-03113")


def test_a_connection_that_cannot_open_a_cursor_is_unknown_and_not_raised() -> None:
    """The protocol's promise covers the cursor too, not only the reads: an
    exception here would end the whole reset run rather than one row."""
    session_module = pytest.importorskip("sopuli.driver.oracle.session")
    session = session_module.OracleSession(
        connection=_NoCursor(),
        target=ExpandedTarget(
            target=Target(name="t", type="oracle", dsn="192.0.2.10:1521/ALPHA"), index=0
        ),
        correlation_id="9f1c4e02-77ab-4d51-9c6e-3b8a5d2f0e14",
    )

    found = session.audit_coverage(PERSON)

    assert found.audited is None
    assert "DPI-1080" in found.detail


def test_no_unified_auditing_row_asks_nothing_else() -> None:
    """11.2 has no `Unified Auditing` row, and no policy views to read."""
    cursor = Cursor({MODE_QUERY: None})

    found = coverage_of(cursor, PERSON)

    assert found.audited is None
    assert [statement for statement, _ in cursor.asked] == [MODE_QUERY]
