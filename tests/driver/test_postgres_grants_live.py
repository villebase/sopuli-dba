"""`report privileges`' survey against the tier-1 `postgres` service (#1481).

Tier 1. What only a server can answer: that a `CREATEROLE` tool account with
no other grant reads every catalog's ACL; that a privilege through a chain of
roles comes with its path, one through a grant `WITH INHERIT FALSE` is marked
as needing `SET ROLE`, and one through a grant with neither option is not
listed; that an attribute reaches a member only by `SET ROLE`; that an
object nobody granted on still gives its owner and `PUBLIC` their default
privileges; and that the cluster's other databases are named as not read.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from contextlib import suppress
from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Runtime, Target, TargetPostgres
from sopuli.driver.grants import PrivilegeSurvey
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
    """An account, the roles it holds, and a schema of objects, all dropped afterwards.

    ``user`` holds ``app``, which holds ``read``, by grants that inherit;
    ``batch`` by one ``WITH INHERIT FALSE``; ``admin``, which is
    ``CREATEROLE``, the same way; and ``watch`` by one with neither option.
    ``owner`` owns the schema, two tables and a function, and has default
    privileges for ``read``. ``user`` owns a table nobody has granted on.
    """
    import psycopg

    suffix = uuid.uuid4().hex[:8]
    names = {
        "tool": f"sopuli_tool_{suffix}",
        "owner": f"acme_{suffix}_owner",
        "read": f"acme_{suffix}_read",
        "app": f"acme_{suffix}_app",
        "batch": f"acme_{suffix}_batch",
        "admin": f"acme_{suffix}_admin",
        "watch": f"acme_{suffix}_watch",
        "user": f"acme_{suffix}_user",
    }
    schema = f"acme_{suffix}"
    with _superuser(live_postgres) as admin:
        options = admin.execute(
            "select count(*) from pg_attribute where attrelid = 'pg_auth_members'::regclass "
            "and attname in ('inherit_option', 'set_option')"
        ).fetchone()
    if options != (2,):
        pytest.skip("the server's grants have no INHERIT and SET options, which these cases need")
    password = uuid.uuid4().hex
    n = {key: f'"{value}"' for key, value in names.items()}
    statements = [
        f"create role {n['tool']} login createrole password '{password}'",
        f"create role {n['owner']}",
        f"create schema {schema} authorization {n['owner']}",
        f"create table {schema}.orders (n int)",
        f"create table {schema}.items (n int)",
        f"create function {schema}.post_order() returns void language sql as 'select'",
        f"alter table {schema}.orders owner to {n['owner']}",
        f"alter table {schema}.items owner to {n['owner']}",
        f"alter function {schema}.post_order() owner to {n['owner']}",
        f"create role {n['read']}",
        f"create role {n['app']}",
        f"create role {n['batch']}",
        f"create role {n['admin']} createrole",
        f"create role {n['watch']}",
        f"create role {n['user']} login createdb",
        f"grant usage on schema {schema} to {n['read']}",
        f"grant select on {schema}.orders, {schema}.items to {n['read']}",
        f"grant insert on {schema}.orders to {n['batch']}",
        f"grant delete on {schema}.orders to {n['watch']}",
        f"grant {n['read']} to {n['app']}",
        f"grant {n['app']} to {n['user']}",
        f"grant {n['batch']} to {n['user']} with inherit false",
        f"grant {n['admin']} to {n['user']} with inherit false",
        f"grant {n['watch']} to {n['user']} with inherit false, set false",
        f"grant select on {schema}.orders to {n['user']}",
        f"grant update (n) on {schema}.items to {n['user']}",
        f"create table {schema}.notes (n int)",
        f"alter table {schema}.notes owner to {n['user']}",
        f"alter default privileges for role {n['owner']} in schema {schema} "
        f"grant select on tables to {n['read']}",
    ]
    try:
        with _superuser(live_postgres) as admin:
            for statement in statements:
                admin.execute(statement)
        yield {**names, "schema": schema, "password": password}
    finally:
        with _superuser(live_postgres) as admin:
            with suppress(psycopg.Error):
                admin.execute(f"drop schema {schema} cascade")
            for role in reversed(list(n.values())):
                with suppress(psycopg.Error):
                    admin.execute(f"drop owned by {role}")
                with suppress(psycopg.Error):
                    admin.execute(f"drop role {role}")


@pytest.fixture
def session(live_postgres: Any, roles: dict[str, str]) -> Iterator[Any]:
    """A session as the tool account, built the way the CLI builds one."""
    from sopuli.driver.postgres.session import build_driver

    driver = build_driver(DriverContext(env=os.environ, correlation_id="grants", runtime=Runtime()))
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


def _mine(rows: Any, schema: str) -> set[tuple[Any, ...]]:
    return {
        (row.privilege, row.name, row.column, row.path, row.first_role_default)
        for row in rows
        if row.owner == schema
    }


def test_the_session_is_a_privilege_survey(session: Any) -> None:
    assert isinstance(session, PrivilegeSurvey)


def test_paths_and_whether_each_is_active(session: Any, roles: dict[str, str]) -> None:
    survey = session.survey_privileges([roles["user"]], public=False)
    app, read, batch = roles["app"], roles["read"], roles["batch"]
    objects = _mine(survey.objects, roles["schema"])

    assert ("SELECT", "orders", None, (), None) in objects
    assert ("SELECT", "orders", None, (app, read), True) in objects
    assert ("SELECT", "items", None, (app, read), True) in objects
    assert ("INSERT", "orders", None, (batch,), False) in objects
    # The watch role's DELETE comes through a grant with neither option.
    assert not any(row[0] == "DELETE" and row[1] == "orders" for row in objects)
    # The table the account owns, with a NULL ACL, gives it every privilege.
    owned = {row[0] for row in objects if row[1] == "notes" and row[3] == ()}
    assert {"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE"} <= owned
    assert ("UPDATE", "items", "n", (), None) in _mine(survey.columns, roles["schema"])
    assert ("USAGE", None, None, (app, read), True) in {
        (row.privilege, row.name, row.column, row.path, row.first_role_default)
        for row in survey.schemas
        if row.level == "schema" and row.owner == roles["schema"]
    }


def test_default_privileges_name_whose_future_objects(session: Any, roles: dict[str, str]) -> None:
    survey = session.survey_privileges([roles["user"]], public=False)
    defaults = [row for row in survey.objects if (row.level or "").startswith("default for ")]
    assert [
        (row.level, row.privilege, row.owner, row.object_type, row.path) for row in defaults
    ] == [
        (
            f"default for {roles['owner']}",
            "SELECT",
            roles["schema"],
            "TABLE",
            (roles["app"], roles["read"]),
        )
    ]


def test_attributes_own_and_by_set_role(session: Any, roles: dict[str, str]) -> None:
    survey = session.survey_privileges([roles["user"]], public=False)
    found = {(row.privilege, row.path, row.first_role_default) for row in survey.system}
    assert ("CREATEDB", (), None) in found
    assert ("CREATEROLE", (roles["admin"],), False) in found


def test_the_memberships_and_their_options(session: Any, roles: dict[str, str]) -> None:
    survey = session.survey_privileges([roles["user"]], public=False)
    found = {(grant.role, grant.default_role, grant.set_option) for grant in survey.roles}
    assert found == {
        (roles["app"], True, True),
        (roles["batch"], False, True),
        (roles["admin"], False, True),
        (roles["watch"], False, False),
    }


def test_public_holds_execute_on_a_function_nobody_revoked(
    session: Any, roles: dict[str, str]
) -> None:
    asked = session.survey_privileges([roles["user"]], public=True)
    function = [
        row
        for row in asked.objects
        if row.grantee == "PUBLIC" and row.owner == roles["schema"] and row.name == "post_order()"
    ]
    assert [(row.privilege, row.object_type) for row in function] == [("EXECUTE", "FUNCTION")]
    not_asked = session.survey_privileges([roles["user"]], public=False)
    assert not any(row.grantee == "PUBLIC" for row in not_asked.objects)


def test_the_other_databases_are_named_as_not_read(live_postgres: Any, session: Any) -> None:
    with _superuser(live_postgres) as admin:
        others = [
            row[0]
            for row in admin.execute(
                "select datname from pg_database where datname <> 'postgres' "
                "and datallowconn and not datistemplate order by 1"
            ).fetchall()
        ]
    survey = session.survey_privileges([], public=False)
    if not others:
        assert survey.unreadable == ()
        return
    (reason,) = survey.unreadable
    assert f"({', '.join(others)})" in reason
