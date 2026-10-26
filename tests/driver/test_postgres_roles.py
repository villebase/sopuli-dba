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
    SUPERUSER,
    VENDOR_MAINTAINED,
    review,
)
from sopuli.driver.postgres.roles import (
    NO_CHANGE_DATE,
    ROLE_QUERY,
    AmbiguousRoleError,
    describe,
    state_of,
)

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


# ------------------------------------------------------------- the lookup ---


def test_a_missing_role_is_none() -> None:
    assert describe(_Cursor([]), WEB) is None


def test_the_name_is_bound_and_never_written_into_the_query() -> None:
    cursor = _Cursor([_row()])

    describe(cursor, WEB)

    ((query, params),) = cursor.executed
    assert query == ROLE_QUERY
    assert params == (WEB,)
    assert WEB not in ROLE_QUERY


def test_two_roles_that_differ_only_in_case_are_refused() -> None:
    cursor = _Cursor([_row("acme_web_user"), _row("ACME_WEB_USER")])

    with pytest.raises(AmbiguousRoleError) as refused:
        describe(cursor, WEB)

    assert '"ACME_WEB_USER", "acme_web_user"' in refused.value.message
    assert refused.value.category == "config"
