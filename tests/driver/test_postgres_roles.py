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
    NO_CHANGE_DATE,
    RESERVED_ROLES,
    ROLE_QUERY,
    AmbiguousRoleError,
    describe,
    reserved_names,
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


def test_reserved_names_are_compared_exactly_as_supautils_compares_them() -> None:
    assert reserved_names(SUPABASE_RESERVED) >= {"pgbouncer", "authenticator", "anon"}
    assert "authenticator*" not in reserved_names(SUPABASE_RESERVED)
    assert state_of(_row("ANON", reserved_roles="anon*")).reserved_by is None
    assert reserved_names(" , anon ,") == frozenset({"anon"})


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
