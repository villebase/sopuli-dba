"""UC-2 against the tier-1 `postgres` service (#1201).

Tier 1. What only a server can answer: that a `CREATEROLE` tool account with
`ADMIN OPTION` on a role can send `ALTER ROLE … PASSWORD … VALID UNTIL
'infinity'`, that the role then logs in with the new password, and that a role
past its `VALID UNTIL` cannot log in before the reset and can after it. Also
that the same tool account can send `ALTER ROLE … NOLOGIN`, after which the
role cannot log in and the reset refuses it.
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
    ACCOUNT_UNLOCK,
    Credential,
    DriverContext,
    DriverError,
    UnsupportedCapabilityError,
)
from sopuli.secrets import Secret


def _connect(live_postgres: Any, user: str, password: str) -> Any:
    import psycopg

    return psycopg.connect(
        host=live_postgres.host,
        port=live_postgres.port,
        user=user,
        password=password,
        dbname="postgres",
        sslmode="disable",
        autocommit=True,
    )


@pytest.fixture
def roles(live_postgres: Any) -> Iterator[dict[str, str]]:
    """The tool account, and three roles it created and so administers: one
    open, one past its VALID UNTIL, and one NOLOGIN. All dropped afterwards."""
    import psycopg
    from psycopg import sql

    suffix = uuid.uuid4().hex[:8]
    names = {
        "tool": f"sopuli_tool_{suffix}",
        "open": f"acme_{suffix}_dev_alice",
        "lapsed": f"acme_{suffix}_dev_bob",
        "suspended": f"acme_{suffix}_dev_carol",
    }
    password = uuid.uuid4().hex
    old = uuid.uuid4().hex
    superuser = (live_postgres.user, live_postgres.password)
    try:
        with _connect(live_postgres, *superuser) as admin:
            admin.execute("set password_encryption = 'scram-sha-256'")
            admin.execute(
                sql.SQL("create role {} login createrole password {}").format(
                    sql.Identifier(names["tool"]), sql.Literal(password)
                )
            )
        with _connect(live_postgres, names["tool"], password) as tool:
            tool.execute("set password_encryption = 'scram-sha-256'")
            for key, attributes in (
                ("open", "login"),
                ("lapsed", "login valid until '2000-01-01'"),
                ("suspended", "nologin"),
            ):
                tool.execute(
                    sql.SQL(f"create role {{}} {attributes} password {{}}").format(
                        sql.Identifier(names[key]), sql.Literal(old)
                    )
                )
        yield {**names, "password": password, "old": old}
    finally:
        with _connect(live_postgres, *superuser) as admin:
            for role in reversed(list(names.values())):
                with suppress(psycopg.Error):
                    admin.execute(f'drop role "{role}"')


@pytest.fixture
def session(live_postgres: Any, roles: dict[str, str]) -> Iterator[Any]:
    """A session as the tool account, built the way the CLI builds one."""
    from sopuli.driver.postgres.session import build_driver

    driver = build_driver(DriverContext(env=os.environ, correlation_id="reset", runtime=Runtime()))
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


def _logs_in(live_postgres: Any, user: str, password: str) -> bool:
    import psycopg

    try:
        with _connect(live_postgres, user, password):
            return True
    except psycopg.OperationalError:
        return False


def test_an_unseen_reset_sets_a_password_the_role_logs_in_with(
    live_postgres: Any, session: Any, roles: dict[str, str]
) -> None:
    new = uuid.uuid4().hex

    changes = session.reset_password(roles["open"], Secret(new), expire=False)

    assert changes[0].changed is False
    assert _logs_in(live_postgres, roles["open"], new)
    assert not _logs_in(live_postgres, roles["open"], roles["old"])


def test_a_reset_clears_a_past_valid_until_with_the_password(
    live_postgres: Any, session: Any, roles: dict[str, str]
) -> None:
    assert not _logs_in(live_postgres, roles["lapsed"], roles["old"])
    new = uuid.uuid4().hex

    changes = session.reset_password(roles["lapsed"], Secret(new), expire=False)

    assert changes[0].action == ACCOUNT_UNLOCK
    assert changes[0].changed is True
    assert _logs_in(live_postgres, roles["lapsed"], new)
    state = session.describe_user(roles["lapsed"])
    assert state is not None
    assert not state.expired
    assert state.password_expires_at is None, "infinity reads as no date"


def test_a_nologin_role_is_refused_and_keeps_its_password(
    live_postgres: Any, session: Any, roles: dict[str, str]
) -> None:
    with pytest.raises(DriverError, match="NOLOGIN"):
        session.reset_password(roles["suspended"], Secret(uuid.uuid4().hex), expire=False)

    state = session.describe_user(roles["suspended"])
    assert state is not None
    assert state.deliberately_locked


def test_a_seen_reset_is_refused_by_capability(session: Any, roles: dict[str, str]) -> None:
    with pytest.raises(UnsupportedCapabilityError):
        session.reset_password(roles["open"], Secret(uuid.uuid4().hex), expire=True)


def test_suspend_sets_nologin_and_the_role_cannot_log_in(
    live_postgres: Any, session: Any, roles: dict[str, str]
) -> None:
    assert _logs_in(live_postgres, roles["open"], roles["old"])

    change = session.suspend_account(roles["open"])

    assert change.changed is True
    assert not _logs_in(live_postgres, roles["open"], roles["old"])
    state = session.describe_user(roles["open"])
    assert state is not None
    assert state.deliberately_locked

    again = session.suspend_account(roles["open"])
    assert again.changed is False, "invariant 9: the second run changes nothing"


def test_a_suspended_role_is_refused_by_the_reset(session: Any, roles: dict[str, str]) -> None:
    """H4: suspend, then reset, and the reset refuses."""
    session.suspend_account(roles["open"])

    with pytest.raises(DriverError, match="NOLOGIN"):
        session.reset_password(roles["open"], Secret(uuid.uuid4().hex), expire=False)


def test_expire_password_is_refused_by_capability(session: Any, roles: dict[str, str]) -> None:
    with pytest.raises(UnsupportedCapabilityError):
        session.expire_password(roles["open"])
