"""Check 9's reads on the tier-1 `mariadb` service (11.8.9). Tier 1.

The reads run as `sopuli_admin`, which holds exactly the grants of
`02-mariadb-privileges.md` §2.1, as `test/mariadb-init/` creates it. Each test
creates its own accounts and roles, with random names, and drops them; one
grants to `PUBLIC` and revokes it. The port follows `SOPULI_TEST_MARIADB_PORT`,
as the compose file's does.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Any

import pytest

from conftest import _missing_environment
from sopuli.driver.mariadb.admin import global_privileges
from sopuli.driver.mysql_family.accounts import Principal

pymysql = pytest.importorskip("pymysql")

PORT = int(os.environ.get("SOPULI_TEST_MARIADB_PORT", "3307"))

#: What the PUBLIC test grants. Fixed, not random, so that the next run's
#: fixture removes what a killed run left.
PUBLIC_GRANT = "SHUTDOWN ON *.*"
PUBLIC_ROLE = "acme_public_role"


def connect(user: str, password: str) -> Any:
    return pymysql.connect(
        host="127.0.0.1",
        port=PORT,
        user=user,
        password=password,
        ssl_disabled=True,
        autocommit=True,
        connect_timeout=5,
    )


@dataclass
class Stage:
    """Root, for setup, and the tool account's cursor, for the reads."""

    root: Any
    tool: Any
    accounts: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    public: list[str] = field(default_factory=list)

    def account(self) -> Principal:
        name = f"acme_app_{uuid.uuid4().hex[:8]}"
        self.root.execute("CREATE USER %s@'%%' IDENTIFIED BY %s", (name, uuid.uuid4().hex))
        self.accounts.append(name)
        return Principal(name, "%")

    def role(self, name: str = "") -> str:
        name = name or f"acme_role_{uuid.uuid4().hex[:8]}"
        self.root.execute(f"CREATE ROLE {name}")
        self.roles.append(name)
        return name

    def grant_public(self, what: str) -> None:
        """``GRANT <what> TO PUBLIC``, revoked at the end."""
        self.root.execute(f"GRANT {what} TO PUBLIC")
        self.public.append(what)

    def held(self, account: Principal) -> frozenset[str]:
        return global_privileges(self.tool, account)


@pytest.fixture
def stage() -> Iterator[Stage]:
    try:
        root = connect("root", "sopuli-test")
        tool = connect("sopuli_admin", "sopuli-test-admin")
    except pymysql.err.MySQLError as error:
        _missing_environment(f"MariaDB not reachable at 127.0.0.1:{PORT}: {error}")
    with root, tool, root.cursor() as root_cursor, tool.cursor() as tool_cursor:
        # What an interrupted run may have left with PUBLIC, which every
        # account on the server would hold (RR3).
        for leftover in (f"REVOKE {PUBLIC_GRANT} FROM PUBLIC", f"DROP ROLE {PUBLIC_ROLE}"):
            with suppress(pymysql.Error):
                root_cursor.execute(leftover)
        staged = Stage(root=root_cursor, tool=tool_cursor)
        try:
            yield staged
        finally:
            for what in staged.public:
                # A role granted to PUBLIC is revoked by dropping the role.
                with suppress(pymysql.Error):
                    root_cursor.execute(f"REVOKE {what} FROM PUBLIC")
            for role in staged.roles:
                with suppress(pymysql.Error):
                    root_cursor.execute(f"DROP ROLE {role}")
            for name in staged.accounts:
                with suppress(pymysql.Error):
                    root_cursor.execute("DROP USER %s@'%%'", (name,))


def test_an_account_with_no_grant_holds_nothing(stage: Stage) -> None:
    assert stage.held(stage.account()) == frozenset()


def test_direct_grants_of_each_kind_are_read(stage: Stage) -> None:
    app = stage.account()
    for what in (
        "PROCESS ON *.*",
        "BINLOG MONITOR ON *.*",
        "INSERT ON mysql.*",
        "SELECT ON mysql.db",
        "SELECT (User) ON mysql.proxies_priv",
        "EXECUTE ON PROCEDURE mysql.AddGeometryColumn",
        "PROXY ON 'root'@'localhost'",
    ):
        stage.root.execute(f"GRANT {what} TO {app.sql()}")

    assert stage.held(app) == {
        "PROCESS ON *.*",
        "BINLOG MONITOR ON *.*",
        "INSERT ON mysql.*",
        "SELECT ON mysql.db",
        "SELECT (User) ON mysql.proxies_priv",
        "EXECUTE ON PROCEDURE mysql.AddGeometryColumn",
        "PROXY ON root@localhost",
    }


def test_a_grant_on_another_schema_is_not_read(stage: Stage) -> None:
    app = stage.account()
    stage.root.execute(f"GRANT SELECT ON acme.* TO {app.sql()}")

    assert stage.held(app) == frozenset()


def test_a_nested_role_s_privilege_is_read_whether_or_not_it_is_active(stage: Stage) -> None:
    app = stage.account()
    outer, inner = stage.role(), stage.role()
    stage.root.execute(f"GRANT SUPER ON *.* TO {inner}")
    stage.root.execute(f"GRANT {inner} TO {outer}")
    stage.root.execute(f"GRANT {outer} TO {app.sql()}")

    assert stage.held(app) == {f"SUPER ON *.* through {inner}"}


def test_what_public_and_its_roles_hold_every_account_holds(stage: Stage) -> None:
    app = stage.account()
    role = stage.role(PUBLIC_ROLE)
    stage.root.execute(f"GRANT SELECT ON mysql.proxies_priv TO {role}")
    stage.grant_public(PUBLIC_GRANT)
    stage.grant_public(role)

    assert stage.held(app) == {
        "SHUTDOWN ON *.* through PUBLIC",
        f"SELECT ON mysql.proxies_priv through {role}",
    }


def test_a_schema_pattern_that_matches_mysql_is_read_and_named(stage: Stage) -> None:
    app = stage.account()
    stage.root.execute(f"GRANT SELECT ON `mysq%`.* TO {app.sql()}")

    assert stage.held(app) == {"SELECT ON `mysq%`.*"}


def test_a_host_written_in_capitals_reads_the_stored_account(stage: Stage) -> None:
    """The server stores the host in lower case (ID3)."""
    name = f"acme_app_{uuid.uuid4().hex[:8]}"
    stage.root.execute("CREATE USER %s@'App.Example.COM' IDENTIFIED BY %s", (name, "x"))
    try:
        stage.root.execute("GRANT SUPER ON *.* TO %s@'app.example.com'", (name,))

        assert stage.held(Principal(name, "App.Example.COM")) == {"SUPER ON *.*"}
    finally:
        stage.root.execute("DROP USER %s@'app.example.com'", (name,))


def test_set_user_is_not_seen(stage: Stage) -> None:
    """The accepted gap of decision 4: SET USER sets no column of the view
    (`08_split_privileges_probe.py`, SP2), so check 9 cannot read it."""
    app = stage.account()
    stage.root.execute(f"GRANT SET USER ON *.* TO {app.sql()}")

    assert stage.held(app) == frozenset()
