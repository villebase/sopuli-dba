"""`describe_user` and the guardrails against the tier-1 `postgres` service.

Tier 1. One role per guardrail, created by the stack's superuser and described
by a `CREATEROLE` tool account, which is how the tool connects
(`02-postgres-privileges.md` §2). What only a server can answer: that
`pg_roles` gives the facts this driver maps, that `pg_has_role(..., 'MEMBER')`
follows a chain of grants, and that a role with no grants of its own can read
all of it.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from contextlib import suppress
from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Runtime, Target, TargetPostgres
from sopuli.driver.guardrails import (
    OWN_ACCOUNT,
    PRIVILEGED_ROLE,
    SUPERUSER,
    VENDOR_MAINTAINED,
    review,
)
from sopuli.driver.protocol import Credential, DriverContext
from sopuli.secrets import Secret


def _superuser(live_postgres: Any) -> Any:
    import psycopg

    return psycopg.connect(
        host=live_postgres.host,
        port=live_postgres.port,
        user=live_postgres.user,
        password=live_postgres.password,
        dbname="postgres",
        sslmode="disable",
        autocommit=True,
    )


@pytest.fixture
def roles(live_postgres: Any) -> Iterator[dict[str, str]]:
    """The tool account and one role per case, all dropped afterwards."""
    import psycopg
    from psycopg import sql

    suffix = uuid.uuid4().hex[:8]
    names = {
        "tool": f"sopuli_tool_{suffix}",
        "ordinary": f"acme_{suffix}_web_user",
        "nologin": f"acme_{suffix}_nologin_user",
        "expired": f"acme_{suffix}_expired_user",
        "superuser": f"acme_{suffix}_super_user",
        "replication": f"acme_{suffix}_repl_user",
        "bypassrls": f"acme_{suffix}_rls_user",
        "createrole": f"acme_{suffix}_cr_user",
        "reader": f"acme_{suffix}_reader_user",
        "group": f"acme_{suffix}_readers",
    }
    password = uuid.uuid4().hex
    try:
        # Inside the `try`, so a failure part way still drops what was made.
        with _superuser(live_postgres) as admin:
            admin.execute(
                sql.SQL("create role {} login createrole password {}").format(
                    sql.Identifier(names["tool"]), sql.Literal(password)
                )
            )
            admin.execute(f'create role "{names["ordinary"]}" login')
            admin.execute(f'create role "{names["nologin"]}" nologin')
            admin.execute(f"create role \"{names['expired']}\" login valid until '2000-01-01'")
            admin.execute(f'create role "{names["superuser"]}" login superuser')
            admin.execute(f'create role "{names["replication"]}" login replication')
            admin.execute(f'create role "{names["bypassrls"]}" login bypassrls')
            admin.execute(f'create role "{names["createrole"]}" login createrole')
            # Membership through a chain: reader -> group -> pg_read_all_data.
            admin.execute(f'create role "{names["group"]}" nologin')
            admin.execute(f'grant pg_read_all_data to "{names["group"]}"')
            admin.execute(f'create role "{names["reader"]}" login in role "{names["group"]}"')
        yield {**names, "password": password}
    finally:
        with _superuser(live_postgres) as admin:
            for role in reversed(list(names.values())):
                with suppress(psycopg.Error):
                    admin.execute(f'drop role "{role}"')


@pytest.fixture
def session(live_postgres: Any, roles: dict[str, str]) -> Iterator[Any]:
    """A session as the tool account, built the way the CLI builds one."""
    from sopuli.driver.postgres.session import build_driver

    driver = build_driver(DriverContext(env=os.environ, correlation_id="roles", runtime=Runtime()))
    target = ExpandedTarget(
        target=Target(
            name="tier1-postgres",
            type="postgresql",
            dsn=live_postgres.dsn,
            postgres=TargetPostgres(sslmode="disable"),
        )
    )
    opened = driver.connect(
        target, Credential(username=roles["tool"], secret=Secret(roles["password"]))
    )
    try:
        yield opened
    finally:
        opened.close()


def _checks(session: Any, name: str) -> set[str]:
    state = session.describe_user(name)
    assert state is not None, name
    return {refusal.check for refusal in review(state, declared=[state.name]).refusals}


def test_an_ordinary_role_is_open_and_passes(session: Any, roles: dict[str, str]) -> None:
    state = session.describe_user(roles["ordinary"])

    assert state.name == roles["ordinary"]
    assert state.status == "OPEN"
    assert not state.locked
    assert not state.expired
    assert _checks(session, roles["ordinary"]) == set()


def test_the_name_is_matched_by_upper_and_spelled_as_pg_roles_spells_it(
    session: Any, roles: dict[str, str]
) -> None:
    assert session.describe_user(roles["ordinary"].upper()).name == roles["ordinary"]


def test_a_missing_role_is_none(session: Any) -> None:
    assert session.describe_user(f"acme_{uuid.uuid4().hex[:8]}_missing_user") is None


def test_nologin_is_locked(session: Any, roles: dict[str, str]) -> None:
    state = session.describe_user(roles["nologin"])

    assert state.locked
    assert state.status == "NOLOGIN"


def test_a_past_valid_until_is_expired(session: Any, roles: dict[str, str]) -> None:
    state = session.describe_user(roles["expired"])

    assert state.expired
    assert state.password_expires_at is not None
    assert state.password_expires_at.year == 2000


def test_a_superuser_is_refused_for_what_it_is_and_nothing_it_was_not_granted(
    session: Any, roles: dict[str, str]
) -> None:
    """The memberships come from the grants that exist, so a superuser is not
    reported as a member of every role in the cluster."""
    state = session.describe_user(roles["superuser"])

    assert state.roles == frozenset()
    assert _checks(session, roles["superuser"]) == {SUPERUSER}


@pytest.mark.parametrize("case", ["replication", "bypassrls", "createrole"])
def test_each_powerful_attribute_is_refused(session: Any, roles: dict[str, str], case: str) -> None:
    state = session.describe_user(roles[case])

    assert case.upper() in state.admin_roles
    assert _checks(session, roles[case]) == {PRIVILEGED_ROLE}


def test_a_guarded_built_in_role_held_through_a_chain_is_refused(
    session: Any, roles: dict[str, str]
) -> None:
    state = session.describe_user(roles["reader"])

    assert "PG_READ_ALL_DATA" in state.admin_roles
    assert _checks(session, roles["reader"]) == {PRIVILEGED_ROLE}


def test_a_built_in_role_is_vendor_maintained(session: Any) -> None:
    assert VENDOR_MAINTAINED in _checks(session, "pg_read_all_data")


def test_the_tool_s_own_role_is_check_seven(session: Any, roles: dict[str, str]) -> None:
    state = session.describe_user(roles["tool"])

    assert state.session_account
    # The tool account holds CREATEROLE, as `02-postgres-privileges.md` §2 says
    # it must, so check 4 objects as well.
    assert _checks(session, roles["tool"]) == {OWN_ACCOUNT, PRIVILEGED_ROLE}
