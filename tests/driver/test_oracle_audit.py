"""Whether a reset is audited: `02-oracle-privileges.md` §5's rules. Tier 0.

The rules come from `sql/oracle/13_audit_coverage_probe.sql`'s measurements on
26ai 23.26.2.0.0. Each test here is one rule, given the rows the two policy views
returned for that shape in the probe. Tier 1, in
`test_oracle_service_account.py`, asks a real database the same questions.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sopuli.driver.oracle.audit import (
    ALL_USERS,
    BY_ROLE,
    BY_USER,
    ENABLED_QUERY,
    EXCEPT_USER,
    MODE_QUERY,
    OPTIONS_QUERY,
    STANDARD_ACTION,
    SYSTEM_PRIVILEGE,
    UNREADABLE,
    Enablement,
    Option,
    classify,
    coverage_of,
)
from sopuli.driver.protocol import AuditCoverage

PERSON = "ACME_DEV_ALICE"
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


def test_a_policy_recording_only_successes_counts() -> None:
    """The routes succeed, so a policy that records successes records them."""
    assert answer([enabled("P")], both("P")).audited is True


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
    assert found.detail == "P records ALTER USER only for a list of users"


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
    """Answers each of the three queries from a table, or fails one of them."""

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


def test_the_three_reads_are_classified() -> None:
    cursor = Cursor(
        {
            MODE_QUERY: ("TRUE",),
            ENABLED_QUERY: [("P", "BY USER", "ALL USERS", "YES")],
            OPTIONS_QUERY: [
                ("P", "LOGON", "STANDARD ACTION", "NONE", "NO"),
                ("P", "ALTER USER", "STANDARD ACTION", "NONE", "NO"),
            ],
        }
    )

    found = coverage_of(cursor, PERSON)

    assert found.audited is True
    assert [parameters for _, parameters in cursor.asked] == [None, None, None], "nothing bound"


def test_an_unreadable_policy_view_names_the_grant() -> None:
    """Measured: the default install gets `ORA-00942` on both views."""
    cursor = Cursor(
        {MODE_QUERY: ("TRUE",)},
        fail={ENABLED_QUERY: RuntimeError("ORA-00942: table or view does not exist")},
    )

    found = coverage_of(cursor, PERSON)

    assert found.audited is None
    assert found.detail == UNREADABLE


def test_any_other_failure_is_unknown_with_the_servers_code() -> None:
    """Never raised: a reset records this and acts on nothing."""
    cursor = Cursor(
        {MODE_QUERY: ("TRUE",)},
        fail={ENABLED_QUERY: RuntimeError("ORA-00600: internal error code")},
    )

    found = coverage_of(cursor, PERSON)

    assert found.audited is None
    assert "ORA-00600" in found.detail


def test_no_unified_auditing_row_asks_nothing_else() -> None:
    """11.2 has no `Unified Auditing` row, and no policy views to read."""
    cursor = Cursor({MODE_QUERY: None})

    found = coverage_of(cursor, PERSON)

    assert found.audited is None
    assert [statement for statement, _ in cursor.asked] == [MODE_QUERY]
