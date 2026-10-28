"""The driver against the database a Supabase project runs (#1111).

Tier 1, on the `supabase` service of `test/compose.yaml`. What only that server
can answer: that the tool's reading of `supautils.reserved_roles` names the
roles supautils itself refuses to change, and that the setup
`docs/scenarios/supabase.md` gives works there. The tool account is created by
`postgres`, as on a Supabase project, where `postgres` is not a superuser.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from contextlib import suppress
from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Runtime, Target, TargetPostgres
from sopuli.driver.guardrails import OWN_ACCOUNT, PRIVILEGED_ROLE, RESERVED, review
from sopuli.driver.postgres.roles import RESERVED_ROLES, reserved_names
from sopuli.driver.protocol import PASS, Credential, DriverContext
from sopuli.secrets import Secret


def _owner(live_supabase: Any) -> Any:
    """A session as `postgres`, the account the project's owner holds."""
    import psycopg

    return psycopg.connect(
        host=live_supabase.host,
        port=live_supabase.port,
        user=live_supabase.user,
        password=live_supabase.password,
        dbname="postgres",
        sslmode="disable",
        autocommit=True,
    )


def _reserved_roles(live_supabase: Any) -> list[str]:
    """The roles the server reserves that exist, and are not superusers.

    A superuser is refused by check 6 as well, and supautils refuses a change to
    one with a message of its own, so it shows nothing about the reserved list.
    """
    with _owner(live_supabase) as owner:
        setting = owner.execute("select current_setting(%s, true)", (RESERVED_ROLES,)).fetchone()
        names = sorted(reserved_names(setting[0]))
        rows = owner.execute(
            "select rolname from pg_roles where rolname = any(%s) and not rolsuper", (names,)
        ).fetchall()
    return [row[0] for row in rows]


@pytest.fixture
def roles(live_supabase: Any) -> Iterator[dict[str, str]]:
    """The tool account and an application role it creates, dropped afterwards."""
    import psycopg
    from psycopg import sql

    suffix = uuid.uuid4().hex[:8]
    names = {"tool": f"sopuli_tool_{suffix}", "app": f"acme_{suffix}_web_user"}
    password = uuid.uuid4().hex
    try:
        with _owner(live_supabase) as owner:
            owner.execute(
                sql.SQL("create role {} login createrole password {}").format(
                    sql.Identifier(names["tool"]), sql.Literal(password)
                )
            )
        yield {**names, "password": password}
    finally:
        with _owner(live_supabase) as owner:
            for role in reversed(list(names.values())):
                with suppress(psycopg.Error):
                    owner.execute(f'drop role "{role}"')


@pytest.fixture
def session(live_supabase: Any, roles: dict[str, str]) -> Iterator[Any]:
    """A session as the tool account, built the way the CLI builds one."""
    from sopuli.driver.postgres.session import build_driver

    driver = build_driver(
        DriverContext(env=os.environ, correlation_id="supabase", runtime=Runtime())
    )
    target = ExpandedTarget(
        target=Target(
            name="tier1-supabase",
            type="postgresql",
            dsn=live_supabase.dsn,
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


def test_the_server_reserves_roles(live_supabase: Any) -> None:
    """Without this, the tests below would pass on a server with no supautils."""
    assert "authenticator" in _reserved_roles(live_supabase)


def test_every_role_the_server_reserves_is_check_eight(live_supabase: Any, session: Any) -> None:
    for name in _reserved_roles(live_supabase):
        state = session.describe_user(name)

        assert state is not None, name
        assert state.reserved_by == RESERVED_ROLES, name
        assert RESERVED in _checks(session, name), name


def test_supautils_refuses_every_role_check_eight_refuses(live_supabase: Any) -> None:
    """The tool's reading of the setting against the server's: `postgres`, which
    may change other roles here, is refused each one with supautils' message.
    Each change is rolled back, a change the server lets through included, so
    a failing run leaves no role changed."""
    import psycopg
    from psycopg import sql

    with _owner(live_supabase) as owner:
        for name in _reserved_roles(live_supabase):
            with (
                pytest.raises(psycopg.errors.InsufficientPrivilege) as refused,
                owner.transaction(force_rollback=True),
            ):
                owner.execute(
                    sql.SQL("alter role {} connection limit 5").format(sql.Identifier(name))
                )

            assert f'"{name}" is a reserved role' in str(refused.value)


def test_the_tool_account_sets_the_password_of_a_role_it_created(
    live_supabase: Any, session: Any, roles: dict[str, str]
) -> None:
    """The scenario's setup: on 16 and later, the creator gets ADMIN OPTION."""
    import psycopg

    with psycopg.connect(
        host=live_supabase.host,
        port=live_supabase.port,
        user=roles["tool"],
        password=roles["password"],
        dbname="postgres",
        sslmode="disable",
        autocommit=True,
    ) as tool:
        tool.execute(f'create role "{roles["app"]}" login')
    secret = Secret(f"Acme-{uuid.uuid4().hex}")

    assert _checks(session, roles["app"]) == set()
    assert session.set_password(roles["app"], secret).changed
    assert session.verify_password(roles["app"], secret).result == PASS


def test_the_tool_account_is_not_reserved(session: Any, roles: dict[str, str]) -> None:
    state = session.describe_user(roles["tool"])

    assert state.reserved_by is None
    assert _checks(session, roles["tool"]) == {OWN_ACCOUNT, PRIVILEGED_ROLE}
