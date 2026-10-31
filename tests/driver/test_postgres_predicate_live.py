"""A `role:` predicate against the tier-1 `postgres` service (#1201).

Tier 1. What only a server can answer: that a `CREATEROLE` tool account with
no other grant can read every chain of `pg_auth_members` grants, that a grant
`WITH INHERIT FALSE` still counts by its `SET`, that a grant with neither does
not, nor does the `ADMIN OPTION` grant a role's creator holds, and that a
`NOLOGIN` member is listed. `describe_user` counts the same grants walking up,
so a listing and a mutating verb agree on who a predicate admits.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from contextlib import suppress
from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Runtime, Target, TargetPostgres
from sopuli.driver.protocol import Credential, DriverContext, UnsupportedCapabilityError
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
    """A team role, a chain below it, and roles outside it, all dropped afterwards.

    The tool account creates the team, so from PostgreSQL 16 it holds the team
    by an ``ADMIN OPTION`` grant with neither ``INHERIT`` nor ``SET``.
    ``alice`` holds the team directly. ``bob`` holds it through ``leads``,
    whose grant has ``INHERIT FALSE``. ``carol`` holds it and cannot log in.
    ``observer`` holds it by a grant with neither option. ``stranger`` holds
    nothing.
    """
    import psycopg
    from psycopg import sql

    suffix = uuid.uuid4().hex[:8]
    names = {
        "tool": f"sopuli_tool_{suffix}",
        "team": f"acme_{suffix}_dev_team",
        "leads": f"acme_{suffix}_dev_leads",
        "alice": f"acme_{suffix}_dev_alice",
        "bob": f"acme_{suffix}_dev_bob",
        "carol": f"acme_{suffix}_dev_carol",
        "observer": f"acme_{suffix}_dev_observer",
        "stranger": f"acme_{suffix}_dev_stranger",
    }
    with _superuser(live_postgres) as admin:
        options = admin.execute(
            "select count(*) from pg_attribute where attrelid = 'pg_auth_members'::regclass "
            "and attname in ('inherit_option', 'set_option')"
        ).fetchone()
    if options != (2,):
        pytest.skip("the server's grants have no INHERIT and SET options, which these cases need")
    password = uuid.uuid4().hex
    try:
        with _superuser(live_postgres) as admin:
            admin.execute(
                sql.SQL("create role {} login createrole password {}").format(
                    sql.Identifier(names["tool"]), sql.Literal(password)
                )
            )
        with psycopg.connect(
            host=live_postgres.host,
            port=live_postgres.port,
            user=names["tool"],
            password=password,
            dbname="postgres",
            sslmode="disable",
            autocommit=True,
        ) as tool:
            tool.execute(f'create role "{names["team"]}" nologin')
        with _superuser(live_postgres) as admin:
            admin.execute(f'create role "{names["leads"]}" nologin')
            admin.execute(f'grant "{names["team"]}" to "{names["leads"]}" with inherit false')
            admin.execute(f'create role "{names["alice"]}" login in role "{names["team"]}"')
            admin.execute(f'create role "{names["bob"]}" login in role "{names["leads"]}"')
            admin.execute(f'create role "{names["carol"]}" nologin in role "{names["team"]}"')
            admin.execute(f'create role "{names["observer"]}" login')
            admin.execute(
                f'grant "{names["team"]}" to "{names["observer"]}" with inherit false, set false'
            )
            admin.execute(f'create role "{names["stranger"]}" login')
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

    driver = build_driver(
        DriverContext(env=os.environ, correlation_id="predicate", runtime=Runtime())
    )
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


def test_a_role_resolves_by_upper_to_the_spelling_pg_roles_gives(
    session: Any, roles: dict[str, str]
) -> None:
    assert session.resolve_role(roles["team"].upper()) == roles["team"]
    assert session.resolve_role(f"{roles['team']}_missing") is None


def test_the_members_are_exactly_those_with_counting_grants(
    session: Any, roles: dict[str, str]
) -> None:
    """Through a grant WITH INHERIT FALSE, and a NOLOGIN member too; not the
    creator's ADMIN-only grant, nor a grant with neither option."""
    members = set(session.accounts_matching(role=roles["team"]))

    assert members == {roles["leads"], roles["alice"], roles["bob"], roles["carol"]}


def test_the_creator_s_grant_exists_and_is_not_counted(
    live_postgres: Any, session: Any, roles: dict[str, str]
) -> None:
    """The case the filter exists for: the tool account created the team, and
    PostgreSQL 16 made it a member with ADMIN OPTION."""
    with _superuser(live_postgres) as admin:
        grant = admin.execute(
            "select m.admin_option, m.inherit_option, m.set_option from pg_auth_members m "
            "where m.member = %s::regrole and m.roleid = %s::regrole",
            (roles["tool"], roles["team"]),
        ).fetchone()
    assert grant == (True, False, False)

    tool = session.describe_user(roles["tool"])

    assert tool is not None
    assert roles["team"].upper() not in tool.roles


def test_the_listing_agrees_with_what_describe_user_reports(
    session: Any, roles: dict[str, str]
) -> None:
    """A mutating verb admits by `describe_user`'s memberships, so every role
    the listing names must hold the team there, and the stranger must not."""
    team = roles["team"].upper()
    for name in session.accounts_matching(role=roles["team"]):
        state = session.describe_user(name)
        assert state is not None, name
        assert team in state.roles, name
    for outsider in ("observer", "stranger", "tool"):
        state = session.describe_user(roles[outsider])
        assert state is not None, outsider
        assert team not in state.roles, outsider


def test_a_role_nobody_holds_lists_nobody(session: Any, roles: dict[str, str]) -> None:
    assert session.accounts_matching(role=roles["stranger"]) == ()


def test_a_profile_predicate_is_refused_by_capability(session: Any) -> None:
    with pytest.raises(UnsupportedCapabilityError):
        session.resolve_profile("acme_dev_profile")
