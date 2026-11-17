"""The server-level privileges of SQL Server logins, read from a live server
(#1555).

Tier 1. `sa` makes a login in a role nested in another, with a grant on each
step, and two readers of its own: one with the tool login's grant, `ALTER
ANY LOGIN`, and one with `VIEW ANY DEFINITION` as well
(`02-mssql-privileges.md` §2.2). The shared tool login is left as it is.
Every principal this file makes starts `w2_` and is dropped after.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

pyodbc = pytest.importorskip("pyodbc")

from sopuli.driver.mssql import server_grants  # noqa: E402
from sopuli.driver.mssql.server_grants import (  # noqa: E402
    FIXED_ROLE_LEVEL,
    NO_DEFINITIONS,
    PUBLIC_GRANTEE,
)

SUBJECT = "w2_acme_rp_user"
READER, FULL_READER = "w2_acme_rp_reader", "w2_acme_rp_full"
INNER, OUTER = "w2_acme_rp_inner", "w2_acme_rp_outer"
PASSWORD = "W2-reader-pw1"


def _sa(live_mssql: Any, *statements: str) -> None:
    connection = live_mssql.connect()
    try:
        cursor = connection.cursor()
        for statement in statements:
            cursor.execute(statement)
    finally:
        connection.close()


def _drop(live_mssql: Any) -> None:
    _sa(
        live_mssql,
        # sys.server_role_members, not IS_SRVROLEMEMBER, which takes a login
        # as its second argument and so does not answer for a role in a role.
        *(
            "IF EXISTS (SELECT 1 FROM sys.server_role_members "
            f"WHERE role_principal_id = SUSER_ID(N'{role}') "
            f"AND member_principal_id = SUSER_ID(N'{member}')) "
            f"ALTER SERVER ROLE [{role}] DROP MEMBER [{member}]"
            for role, member in ((INNER, SUBJECT), (OUTER, INNER), ("processadmin", SUBJECT))
        ),
        *(f"IF SUSER_ID(N'{name}') IS NOT NULL DROP LOGIN [{name}]" for name in (SUBJECT,)),
        *(
            f"IF SUSER_ID(N'{name}') IS NOT NULL DROP SERVER ROLE [{name}]"
            for name in (INNER, OUTER)
        ),
        *(
            f"IF SUSER_ID(N'{name}') IS NOT NULL DROP LOGIN [{name}]"
            for name in (READER, FULL_READER)
        ),
    )


@pytest.fixture
def made(live_mssql: Any) -> Iterator[Any]:
    _drop(live_mssql)
    try:
        _sa(
            live_mssql,
            f"CREATE LOGIN [{SUBJECT}] WITH PASSWORD = N'W2-subject-pw1', CHECK_POLICY = OFF",
            f"CREATE SERVER ROLE [{INNER}]",
            f"CREATE SERVER ROLE [{OUTER}]",
            f"ALTER SERVER ROLE [{INNER}] ADD MEMBER [{SUBJECT}]",
            f"ALTER SERVER ROLE [{OUTER}] ADD MEMBER [{INNER}]",
            f"ALTER SERVER ROLE [processadmin] ADD MEMBER [{SUBJECT}]",
            f"GRANT VIEW SERVER STATE TO [{INNER}]",
            f"GRANT ALTER TRACE TO [{OUTER}]",
            f"GRANT CONNECT ON ENDPOINT::[TSQL Default TCP] TO [{OUTER}]",
            f"CREATE LOGIN [{READER}] WITH PASSWORD = N'{PASSWORD}', CHECK_POLICY = OFF",
            f"GRANT ALTER ANY LOGIN TO [{READER}]",
            f"CREATE LOGIN [{FULL_READER}] WITH PASSWORD = N'{PASSWORD}', CHECK_POLICY = OFF",
            f"GRANT ALTER ANY LOGIN TO [{FULL_READER}]",
            f"GRANT VIEW ANY DEFINITION TO [{FULL_READER}]",
            f"GRANT IMPERSONATE ON LOGIN::[{READER}] TO [{SUBJECT}]",
        )
        yield live_mssql
    finally:
        _drop(live_mssql)


def _read(live_mssql: Any, reader: str, *, public: bool = False) -> Any:
    connection = live_mssql.connect_as(reader, PASSWORD)
    try:
        return server_grants.read(connection.cursor(), [SUBJECT], public=public)
    finally:
        connection.close()


def test_with_view_any_definition_every_path_is_read(made: Any) -> None:
    found = _read(made, FULL_READER, public=True)

    assert found.unread is None
    system = {
        (row.privilege, row.path, row.level) for row in found.system if row.grantee == SUBJECT
    }
    assert ("VIEW SERVER STATE", (INNER,), "server") in system
    assert ("ALTER TRACE", (INNER, OUTER), "server") in system
    assert ("processadmin", ("processadmin",), FIXED_ROLE_LEVEL) in system
    objects = {(row.privilege, row.object_type, row.name, row.path) for row in found.objects}
    assert ("IMPERSONATE", "LOGIN", READER, ()) in objects
    assert ("CONNECT", "ENDPOINT", "TSQL Default TCP", (INNER, OUTER)) in objects
    assert {role.role for role in found.roles} == {INNER, "processadmin"}
    assert any(row.grantee == PUBLIC_GRANTEE for row in found.system)


def test_with_alter_any_login_alone_the_paths_are_not_checked(made: Any) -> None:
    """PA2: a user-defined role's row is hidden, so its name is too."""
    found = _read(made, READER)

    assert found.unread == NO_DEFINITIONS
    assert found.system is None
    assert found.objects is None
    assert {role.role for role in found.roles} <= {INNER, "processadmin"}
    assert "processadmin" in {role.role for role in found.roles}
