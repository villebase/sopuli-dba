"""Invariant 15 against the tier-1 `postgres` service: the password reaches
neither the server's log nor `pg_stat_statements`.

Tier 1. The service runs with the logging collector and `pg_stat_statements`
preloaded (`test/compose.yaml`), so a superuser can read the log back with
`pg_read_file()`. The tool account's own sessions log every statement
(`ALTER ROLE … SET log_statement = 'all'`), which touches no other session of
the shared stack. The test proves the log is working by finding the verifier
there, and then that the password is not.
"""

from __future__ import annotations

import os
import time
import uuid
from collections.abc import Iterator
from contextlib import suppress
from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Runtime, Target, TargetPostgres
from sopuli.driver.protocol import Credential, DriverContext
from sopuli.secrets import Secret

LOG_FILE = "log/postgresql.log"


def _superuser(live_postgres: Any, dbname: str = "postgres") -> Any:
    import psycopg

    return psycopg.connect(
        host=live_postgres.host,
        port=live_postgres.port,
        user=live_postgres.user,
        password=live_postgres.password,
        dbname=dbname,
        sslmode="disable",
        autocommit=True,
    )


def _log_size(admin: Any) -> int:
    return int(admin.execute("select size from pg_stat_file(%s)", (LOG_FILE,)).fetchone()[0])


def _log_since(admin: Any, offset: int) -> str:
    return str(
        admin.execute("select pg_read_file(%s, %s, 1048576)", (LOG_FILE, offset)).fetchone()[0]
    )


@pytest.fixture
def observed(live_postgres: Any) -> Iterator[dict[str, Any]]:
    """A tool account that logs every statement, a role for it to manage, and
    the log's position before the test. Skips where the server cannot show
    what it keeps."""
    import psycopg
    from psycopg import sql

    with _superuser(live_postgres) as admin:
        collector = admin.execute("show logging_collector").fetchone()[0]
        preload = admin.execute("show shared_preload_libraries").fetchone()[0]
    if collector != "on" or "pg_stat_statements" not in preload:
        pytest.skip(
            "the postgres service runs without the logging collector or "
            "pg_stat_statements; recreate it from test/compose.yaml"
        )

    suffix = uuid.uuid4().hex[:8]
    tool, managed = f"sopuli_tool_{suffix}", f"acme_{suffix}_web_user"
    tool_password = uuid.uuid4().hex
    try:
        with _superuser(live_postgres) as admin:
            admin.execute("create extension if not exists pg_stat_statements")
            admin.execute(
                sql.SQL("create role {} login createrole password {}").format(
                    sql.Identifier(tool), sql.Literal(tool_password)
                )
            )
            admin.execute(
                sql.SQL("alter role {} set log_statement = 'all'").format(sql.Identifier(tool))
            )
            admin.execute(sql.SQL("create role {} login").format(sql.Identifier(managed)))
            # From 16, CREATEROLE needs ADMIN OPTION on the role
            # (`02-postgres-privileges.md` §2.2). Before 16 the grant is not
            # needed, and the syntax with options does not exist.
            (options,) = admin.execute(
                "select exists (select 1 from pg_attribute "
                "where attrelid = 'pg_catalog.pg_auth_members'::regclass "
                "and attname = 'set_option')"
            ).fetchone()
            if options:
                admin.execute(
                    sql.SQL("grant {} to {} with admin option, inherit false, set false").format(
                        sql.Identifier(managed), sql.Identifier(tool)
                    )
                )
            offset = _log_size(admin)
        yield {"tool": tool, "tool_password": tool_password, "managed": managed, "offset": offset}
    finally:
        with _superuser(live_postgres) as admin:
            for role in (managed, tool):
                with suppress(psycopg.Error):
                    admin.execute(sql.SQL("drop role {}").format(sql.Identifier(role)))


def _session_as(live_postgres: Any, user: str, password: str) -> Any:
    from sopuli.driver.postgres.session import build_driver

    driver = build_driver(DriverContext(env=os.environ, correlation_id="inv15", runtime=Runtime()))
    target = ExpandedTarget(
        target=Target(
            name="tier1-postgres",
            type="postgresql",
            dsn=live_postgres.dsn,
            postgres=TargetPostgres(sslmode="disable"),
        )
    )
    return driver.connect(target, Credential(username=user, secret=Secret(password)))


def test_the_password_reaches_neither_the_log_nor_pg_stat_statements(
    live_postgres: Any, observed: dict[str, Any]
) -> None:
    import psycopg

    new_password = f"Inv15-{uuid.uuid4().hex}"
    session = _session_as(live_postgres, observed["tool"], observed["tool_password"])
    try:
        result = session.set_password(observed["managed"], Secret(new_password))
    finally:
        session.close()
    assert result.changed is True

    # The logging collector writes in its own process, so wait for the
    # statement to reach the file, with a deadline rather than a fixed sleep.
    # pg_stat_statements is read for the tool account's rows only: the new
    # role is unique, and nothing is reset for the other sessions of the stack.
    deadline = time.monotonic() + 30
    with _superuser(live_postgres) as admin:
        logged = _log_since(admin, observed["offset"])
        while "SCRAM-SHA-256$" not in logged and time.monotonic() < deadline:
            time.sleep(0.5)
            logged = _log_since(admin, observed["offset"])
        statements = [
            str(row[0])
            for row in admin.execute(
                "select s.query from pg_stat_statements s "
                "join pg_roles r on r.oid = s.userid where r.rolname = %s",
                (observed["tool"],),
            ).fetchall()
        ]

    assert "SCRAM-SHA-256$" in logged, "the log is working: it keeps the verifier"
    assert any("SCRAM-SHA-256$" in text for text in statements), (
        "pg_stat_statements is working: it keeps the verifier"
    )
    assert new_password not in logged
    assert not any(new_password in text for text in statements)

    # And the password works: the verifier libpq computed is the one the
    # server checks at login.
    with psycopg.connect(
        host=live_postgres.host,
        port=live_postgres.port,
        user=observed["managed"],
        password=new_password,
        dbname="postgres",
        sslmode="disable",
    ) as login:
        row = login.execute("select current_user").fetchone()
        assert row is not None
        assert row[0] == observed["managed"]
