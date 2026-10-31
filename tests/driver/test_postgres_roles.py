"""A PostgreSQL role as `UserState`, from scripted `pg_roles` rows. Tier 0.

Each guardrail's input is reached here by writing the row, and the guardrails
are run on the result, so this file shows what each fact refuses. The live
counterpart, against the tier-1 `postgres` service, is
`test_postgres_roles_live.py`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from sopuli.driver.guardrails import (
    OWN_ACCOUNT,
    PRIVILEGED_ROLE,
    RESERVED,
    SUPERUSER,
    VENDOR_MAINTAINED,
    review,
)
from sopuli.driver.postgres.roles import (
    COUNTING_GRANT,
    MEMBERS_QUERY,
    NO_CHANGE_DATE,
    RESERVED_ROLES,
    ROLE_NAME_QUERY,
    ROLE_QUERY,
    AmbiguousRoleError,
    describe,
    members_of,
    reserved_names,
    resolve_role,
    state_of,
)
from sopuli.exit_codes import ExitCode

WEB = "acme_web_user"
DECLARED = (WEB, "pg_read_all_data")


def _row(
    name: str = WEB,
    *,
    superuser: bool = False,
    can_login: bool = True,
    replication: bool = False,
    bypassrls: bool = False,
    createrole: bool = False,
    built_in: bool = False,
    session: bool = False,
    valid_until: datetime | None = None,
    expired: bool = False,
    member_of: tuple[str, ...] = (),
    counted_in: tuple[str, ...] | None = None,
    reserved_roles: str | None = None,
) -> tuple[Any, ...]:
    return (
        name,
        superuser,
        can_login,
        replication,
        bypassrls,
        createrole,
        built_in,
        session,
        valid_until,
        expired,
        list(member_of),
        list(member_of if counted_in is None else counted_in),
        reserved_roles,
    )


def _checks(**row: Any) -> set[str]:
    state = state_of(_row(**row))
    return {refusal.check for refusal in review(state, declared=DECLARED).refusals}


class _Cursor:
    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self.rows = rows
        self.executed: list[tuple[str, Any]] = []

    def execute(self, query: Any, params: Any = None, /) -> None:
        self.executed.append((query, params))

    def fetchall(self) -> Any:
        return self.rows


# ------------------------------------------------------------- the mapping ---


def test_an_ordinary_login_role_is_open_and_passes_every_guardrail() -> None:
    state = state_of(_row())

    assert state.name == WEB
    assert state.status == "OPEN"
    assert not state.locked
    assert not state.expired
    assert state.password_file_member is False, "PostgreSQL has no password file"
    assert state.password_changed_at is None
    assert state.password_changed_unknown == NO_CHANGE_DATE
    assert _checks() == set()


def test_nologin_is_reported_as_locked() -> None:
    state = state_of(_row(can_login=False))

    assert state.locked
    assert state.status == "NOLOGIN"


def test_a_past_valid_until_is_expired_and_keeps_its_date() -> None:
    when = datetime(2020, 1, 1, tzinfo=UTC)
    state = state_of(_row(valid_until=when, expired=True))

    assert state.expired
    assert state.status == "EXPIRED"
    assert state.password_expires_at == when


def test_nologin_outranks_an_expired_date_in_the_status() -> None:
    state = state_of(_row(can_login=False, expired=True))

    assert state.status == "NOLOGIN"
    assert state.locked
    assert state.expired


def test_memberships_are_upper_cased_as_the_protocol_says() -> None:
    state = state_of(_row(member_of=("acme_readers",)))

    assert state.roles == frozenset({"ACME_READERS"})
    assert state.admin_roles == frozenset()


def test_a_predicate_admits_by_counting_grants_only() -> None:
    """A role's creator holds it by an ADMIN-only grant, which a `role:`
    predicate does not count (#1201)."""
    state = state_of(_row(member_of=("acme_dev_team",), counted_in=()))

    assert state.roles == frozenset()


def test_check_four_walks_every_grant_whatever_its_options() -> None:
    """An ADMIN-only member of a guarded role can grant it on, so it is
    refused although a predicate would not count the grant."""
    assert _checks(member_of=("pg_read_all_data",), counted_in=()) == {PRIVILEGED_ROLE}


# ------------------------------------------------------- what each refuses ---


def test_a_superuser_is_check_six() -> None:
    assert SUPERUSER in _checks(superuser=True)


def test_a_built_in_role_is_vendor_maintained() -> None:
    assert _checks(name="pg_read_all_data", built_in=True, can_login=False) == {VENDOR_MAINTAINED}


@pytest.mark.parametrize("attribute", ["replication", "bypassrls", "createrole"])
def test_each_powerful_attribute_is_check_four(attribute: str) -> None:
    flags: dict[str, Any] = {attribute: True}
    state = state_of(_row(**flags))

    assert state.admin_roles == frozenset({attribute.upper()})
    assert _checks(**flags) == {PRIVILEGED_ROLE}


@pytest.mark.parametrize(
    "role",
    [
        "pg_execute_server_program",
        "pg_read_server_files",
        "pg_write_server_files",
        "pg_read_all_data",
        "pg_write_all_data",
        "pg_signal_backend",
    ],
)
def test_membership_in_a_guarded_built_in_role_is_check_four(role: str) -> None:
    assert _checks(member_of=(role,)) == {PRIVILEGED_ROLE}


@pytest.mark.parametrize("role", ["pg_monitor", "pg_read_all_stats"])
def test_a_monitoring_role_is_ordinary_for_an_application(role: str) -> None:
    """The tool account must not hold these (`02-postgres-privileges.md` §3);
    an application account may."""
    assert _checks(member_of=(role,)) == set()


def test_the_session_s_own_role_is_check_seven() -> None:
    assert _checks(session=True) == {OWN_ACCOUNT}


#: The local Supabase stack's value, measured with Supabase CLI 2.78.1 (#1111).
SUPABASE_RESERVED = (
    "supabase_admin, supabase_auth_admin, supabase_storage_admin, supabase_read_only_user, "
    "supabase_realtime_admin, supabase_replication_admin, supabase_etl_admin, dashboard_user, "
    "pgbouncer, service_role*, authenticator*, authenticated*, anon*"
)


@pytest.mark.parametrize("name", ["pgbouncer", "authenticator", "anon"])
def test_a_role_supautils_reserves_is_check_eight_and_force_does_not_waive_it(name: str) -> None:
    """`authenticator*` is reserved too: the `*` lets the privileged role change
    its settings, not its password."""
    state = state_of(_row(name, reserved_roles=SUPABASE_RESERVED))

    assert state.reserved_by == RESERVED_ROLES
    found = review(state, declared=(name,))
    assert [refusal.check for refusal in found.refusals] == [RESERVED]
    assert RESERVED_ROLES in found.refusals[0].reason
    forced = review(state, declared=(name,), force=True)
    assert not forced.permitted
    assert forced.overridden == ()


@pytest.mark.parametrize("setting", [None, "", SUPABASE_RESERVED])
def test_a_role_the_setting_does_not_name_is_not_reserved(setting: str | None) -> None:
    """`None` is a server without supautils, where `current_setting(…, true)`
    gives `NULL`."""
    state = state_of(_row(reserved_roles=setting))

    assert state.reserved_by is None
    assert _checks(reserved_roles=setting) == set()


def test_the_role_name_is_compared_exactly_with_the_name_the_list_gives() -> None:
    assert "authenticator*" not in reserved_names(SUPABASE_RESERVED)
    assert state_of(_row("ANON", reserved_roles="anon*")).reserved_by is None
    assert state_of(_row("ANON", reserved_roles='"ANON"')).reserved_by == RESERVED_ROLES


@pytest.mark.parametrize(
    ("setting", "names"),
    [
        ("pgbouncer, authenticator*, anon*", {"pgbouncer", "authenticator", "anon"}),
        # Unquoted names are lower-cased; quoted ones keep their case and `""`.
        ("ANON*, Acme_Web_User", {"anon", "acme_web_user"}),
        ('"Acme_Web_User", "a""b*"', {"Acme_Web_User", 'a"b'}),
        # One `*` goes, and not from a name that is only `*`.
        ("anon**, *", {"anon*", "*"}),
        ("  anon\t,\nacme_web_user  ", {"anon", "acme_web_user"}),
        # A syntax error stops the split, and the names before it are kept.
        ("anon, , acme_web_user", {"anon"}),
        (" , anon", set()),
        ("anon,", {"anon"}),
        ('anon, "acme_web_user', {"anon"}),
        ('"anon"x, acme_web_user', set()),
        # Only ASCII is lower-cased in UTF-8, and a name stops at 63 bytes.
        ("ÄNON", {"Änon"}),
        ("a" * 70, {"a" * 63}),
        (None, set()),
        ("", set()),
    ],
)
def test_the_list_is_split_as_postgres_splits_an_identifier_list(
    setting: str | None, names: set[str]
) -> None:
    """supautils reads the setting with `SplitIdentifierString`, then drops
    one trailing `*` from each name (`remove_ending_wildcard`)."""
    assert reserved_names(setting) == names


def test_the_query_reads_the_setting_without_failing_where_it_is_undefined() -> None:
    assert f"current_setting('{RESERVED_ROLES}', true)" in ROLE_QUERY


# ------------------------------------------------------------- the lookup ---


def test_a_missing_role_is_none() -> None:
    assert describe(_Cursor([]), WEB, target="pg-dev") is None


def test_the_name_is_bound_and_never_written_into_the_query() -> None:
    cursor = _Cursor([_row()])

    describe(cursor, WEB, target="pg-dev")

    ((query, params),) = cursor.executed
    assert query == ROLE_QUERY
    assert params == (WEB,)
    assert WEB not in ROLE_QUERY


def test_two_roles_that_differ_only_in_case_are_refused_as_config() -> None:
    cursor = _Cursor([_row("acme_web_user"), _row("ACME_WEB_USER")])

    with pytest.raises(AmbiguousRoleError) as refused:
        describe(cursor, WEB, target="pg-dev")

    assert '"ACME_WEB_USER", "acme_web_user"' in refused.value.message
    assert 'target "pg-dev"' in refused.value.message
    assert refused.value.category == "config"
    assert refused.value.exit_code == ExitCode.CONFIG_INVALID


def test_a_non_ascii_name_is_matched_by_python_s_upper() -> None:
    """The server's upper() follows LC_CTYPE, so under `C` it leaves `ä` alone.
    The query returns non-ASCII names whatever their case, and the match is
    made with the comparison the config uses."""
    cursor = _Cursor([_row("ACME_Ä_USER"), _row("acme_ö_user")])

    found = describe(cursor, "acme_ä_user", target="pg-dev")

    assert found is not None
    assert found.name == "ACME_Ä_USER"


def test_a_candidate_that_does_not_match_is_not_the_role() -> None:
    assert describe(_Cursor([_row("acme_ö_user")]), "acme_ä_user", target="pg-dev") is None


def test_the_memberships_walk_the_grants_that_exist() -> None:
    """Not `pg_has_role` over every role in the cluster, which costs the whole
    cluster per role and reports a superuser as a member of everything."""
    assert "pg_auth_members" in ROLE_QUERY
    assert "with recursive" in ROLE_QUERY
    assert "pg_has_role" not in ROLE_QUERY


# ------------------------------------------------ a `role:` predicate (#1201) ---


def test_a_role_is_resolved_to_the_spelling_pg_roles_gives() -> None:
    cursor = _Cursor([("acme_dev_team",)])

    assert resolve_role(cursor, "ACME_DEV_TEAM", target="pg-dev") == "acme_dev_team"
    ((query, params),) = cursor.executed
    assert query == ROLE_NAME_QUERY
    assert params == ("ACME_DEV_TEAM",)


def test_a_role_that_does_not_exist_resolves_to_none() -> None:
    assert resolve_role(_Cursor([("acme_ö_team",)]), "acme_ä_team", target="pg-dev") is None


def test_two_roles_that_differ_only_in_case_refuse_a_predicate() -> None:
    cursor = _Cursor([("acme_dev_team",), ("ACME_DEV_TEAM",)])

    with pytest.raises(AmbiguousRoleError) as refused:
        resolve_role(cursor, "acme_dev_team", target="pg-dev")

    assert '"ACME_DEV_TEAM", "acme_dev_team"' in refused.value.message
    assert refused.value.exit_code == ExitCode.CONFIG_INVALID


def test_the_members_are_every_role_below_the_named_one() -> None:
    cursor = _Cursor([("acme_dev_alice",), ("acme_dev_bob",), ("acme_dev_leads",)])

    assert members_of(cursor, "acme_dev_team") == (
        "acme_dev_alice",
        "acme_dev_bob",
        "acme_dev_leads",
    )
    ((query, params),) = cursor.executed
    assert query == MEMBERS_QUERY
    assert params == ("acme_dev_team",)


def test_the_members_walk_down_the_grants_a_predicate_counts() -> None:
    """ROLE_QUERY's counting walk, the other way: every step, the first too,
    keeps only a grant with INHERIT or SET (#1201)."""
    assert "with recursive" in MEMBERS_QUERY
    assert "m.roleid = members.oid" in MEMBERS_QUERY
    assert MEMBERS_QUERY.count(COUNTING_GRANT) == 2
    assert ROLE_QUERY.count(COUNTING_GRANT) == 2, "both steps of the second walk"
    assert "rolcanlogin" not in MEMBERS_QUERY, "a NOLOGIN member is still admitted"


def test_a_grant_counts_by_either_option_and_every_grant_counts_without_them() -> None:
    """``to_jsonb`` gives NULL for a column the server does not have, so a
    server without the options counts every grant, with no version read."""
    assert "'inherit_option'" in COUNTING_GRANT
    assert "'set_option'" in COUNTING_GRANT
    assert " or " in COUNTING_GRANT
    assert COUNTING_GRANT.startswith("coalesce(")
    assert COUNTING_GRANT.endswith(", true)")
