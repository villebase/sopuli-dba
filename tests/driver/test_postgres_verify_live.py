"""`verify_password` against the tier-1 `postgres` service.

Tier 1. The login as a managed role, made the way `creds check` makes it: as the
role, over a `scram-sha-256` line of the image's `pg_hba.conf`, with
`require_auth=scram-sha-256`. What only a server can answer: that the right
password logs in through `require_auth`, that a wrong one reaches the client as
the text the driver reads as `28P01`, and that a `NOLOGIN` role's refusal reads
as `28000`.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from contextlib import suppress
from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Runtime, Target, TargetPostgres
from sopuli.driver.protocol import (
    FAIL,
    PASS,
    UNAVAILABLE,
    Credential,
    DriverContext,
    UnsupportedCapabilityError,
)
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
    """The tool account, a managed role with a password, and a `NOLOGIN` one
    with a password, all dropped afterwards."""
    import psycopg
    from psycopg import sql

    suffix = uuid.uuid4().hex[:8]
    names = {
        "tool": f"sopuli_tool_{suffix}",
        "managed": f"acme_{suffix}_app_user",
        "nologin": f"acme_{suffix}_nologin_user",
        "limited": f"acme_{suffix}_limited_user",
    }
    # Test passwords for throwaway roles, not credentials.
    password = uuid.uuid4().hex
    try:
        with _superuser(live_postgres) as admin:
            admin.execute("set password_encryption = 'scram-sha-256'")
            for key, kind in (
                ("tool", "login createrole"),
                ("managed", "login"),
                ("limited", "login connection limit 0"),
            ):
                admin.execute(
                    sql.SQL(f"create role {{}} {kind} password {{}}").format(
                        sql.Identifier(names[key]), sql.Literal(password)
                    )
                )
            admin.execute(
                sql.SQL("create role {} nologin password {}").format(
                    sql.Identifier(names["nologin"]), sql.Literal(password)
                )
            )
        yield {**names, "password": password}
    finally:
        with _superuser(live_postgres) as admin:
            for role in reversed(list(names.values())):
                with suppress(psycopg.Error):
                    admin.execute(f'drop role "{role}"')


@pytest.fixture
def session(live_postgres: Any, roles: dict[str, str]) -> Iterator[Any]:
    """A session as the tool account, built the way the CLI builds one.

    The managed role's login needs `require_auth`, so a psycopg that loaded an
    older libpq skips: the driver refuses that login by design.
    """
    from psycopg import pq

    from sopuli.driver.postgres.client import REQUIRE_AUTH_FROM, libpq_release
    from sopuli.driver.postgres.session import build_driver

    major, minor = libpq_release(pq.version())
    if major < REQUIRE_AUTH_FROM:
        pytest.skip(f"libpq {major}.{minor} has no require_auth; libpq {REQUIRE_AUTH_FROM}+ needed")

    driver = build_driver(DriverContext(env=os.environ, correlation_id="verify", runtime=Runtime()))
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


def test_the_right_password_passes(session: Any, roles: dict[str, str]) -> None:
    result = session.verify_password(roles["managed"], Secret(roles["password"]))

    assert result.result == PASS
    assert result.latency_ms is not None
    assert result.failed_logins is None


def test_a_wrong_password_fails(session: Any, roles: dict[str, str]) -> None:
    result = session.verify_password(roles["managed"], Secret("Not-The-Password-7x"))

    assert result.result == FAIL


def test_a_missing_role_is_unavailable(session: Any) -> None:
    result = session.verify_password(f"acme_{uuid.uuid4().hex[:8]}_missing_user", Secret("x"))

    assert result.result == UNAVAILABLE
    assert "there is no role" in str(result.detail)


def test_a_nologin_role_is_unavailable_and_not_tried(session: Any, roles: dict[str, str]) -> None:
    result = session.verify_password(roles["nologin"], Secret(roles["password"]))

    assert result.result == UNAVAILABLE
    assert "the role cannot log in (NOLOGIN)" in str(result.detail)


def test_a_role_at_its_connection_limit_has_its_password_accepted(
    session: Any, roles: dict[str, str]
) -> None:
    """The server says `too many connections` only after it accepted the password."""
    right = session.verify_password(roles["limited"], Secret(roles["password"]))
    wrong = session.verify_password(roles["limited"], Secret("Not-The-Password-7x"))

    assert right.result == PASS
    assert "too many connections for role" in str(right.detail)
    assert wrong.result == FAIL


def test_a_comparison_is_refused(session: Any, roles: dict[str, str]) -> None:
    with pytest.raises(UnsupportedCapabilityError) as refused:
        session.require_verifier(roles["managed"], Secret(roles["password"]))

    assert refused.value.capability == "offline_verify"
