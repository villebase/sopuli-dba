"""Reading MySQL accounts against the tier-1 `mysql` service (8.4.13). Tier 1.

The tool account holds the grants of `02-mysql-privileges.md` §2.1, so it reads
the columns of `mysql.user` the driver needs. Each test creates its own
accounts, with random names, and drops them.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Target, TargetMysql
from sopuli.driver.protocol import Credential
from sopuli.secrets import Secret

pymysql = pytest.importorskip("pymysql")
session_module = pytest.importorskip("sopuli.driver.mysql.session")
accounts_module = pytest.importorskip("sopuli.driver.mysql.accounts")

COLUMNS = (
    "User, Host, plugin, account_locked, password_expired, password_last_changed, password_lifetime"
)


@dataclass
class Stage:
    """A session as a tool account with §2.1's grants, and the accounts a test
    created, dropped afterwards."""

    live: Any
    tool: str
    session: Any
    created: list[tuple[str, str]] = field(default_factory=list)

    def admin(self, statement: str, args: tuple[Any, ...] = ()) -> None:
        with self.live.connect() as admin, admin.cursor() as cursor:
            cursor.execute(statement, args)

    def account(self, host: str, user: str | None = None, *, extra: str = "") -> str:
        """Create `user@host` with a password, and return the user name."""
        name = user or f"acme_app_{uuid.uuid4().hex[:8]}"
        self.created.append((name, host))
        self.admin(f"create user %s@%s identified {extra or 'by %s'}", (name, host, "Acme-pw1"))
        return name


@pytest.fixture
def stage(live_mysql: Any) -> Iterator[Stage]:
    tool, password = f"sopuli_tool_{uuid.uuid4().hex[:8]}", uuid.uuid4().hex
    with live_mysql.connect() as admin, admin.cursor() as cursor:
        cursor.execute("create user %s@'%%' identified by %s", (tool, password))
        cursor.execute("grant create user on *.* to %s@'%%'", (tool,))
        cursor.execute(f"grant select ({COLUMNS}) on mysql.user to %s@'%%'", (tool,))
    target = ExpandedTarget(
        target=Target(
            name="tier1-mysql",
            type="mysql",
            dsn=live_mysql.dsn,
            mysql=TargetMysql(ssl_mode="REQUIRED"),
        )
    )
    session = session_module.MysqlDriver(correlation_id="tier1").connect(
        target, Credential(username=tool, secret=Secret(password))
    )
    staged = Stage(live=live_mysql, tool=tool, session=session)
    try:
        yield staged
    finally:
        session.close()
        with live_mysql.connect() as admin, admin.cursor() as cursor:
            for user, host in [(tool, "%"), *staged.created]:
                with suppress(pymysql.Error):
                    cursor.execute("drop user %s@%s", (user, host))


def test_describe_reads_a_locked_account_at_its_host(stage: Stage) -> None:
    user = stage.account("10.%")
    stage.account("localhost", user)
    stage.admin("alter user %s@'10.%%' account lock", (user,))

    state = stage.session.describe_user(f"{user}@10.%")

    assert state is not None
    assert state.name == f"{user}@10.%"
    assert state.locked is True
    assert state.status == accounts_module.LOCKED
    assert state.password_changed_at is not None
    assert stage.session.describe_user(f"{user}@192.0.2.%") is None


def test_another_plugin_is_refused(stage: Stage) -> None:
    """8.4.13 ships sha256_password, deprecated; mysql_native_password is off."""
    user = stage.account("%", extra="with sha256_password by %s")

    with pytest.raises(accounts_module.OtherPluginError, match="uses sha256_password"):
        stage.session.describe_user(f"{user}@%")


def test_check_privileges_reports_the_declared_accounts(stage: Stage) -> None:
    user = stage.account("10.%")
    stage.account("localhost", user)

    audit = stage.session.privileges(accounts=(f"{user}@10.%", "acme_none@%"))

    assert audit.missing == ()
    assert audit.unreadable == ()
    assert any(
        f"{user}@localhost exists and the config does not declare it" in line
        for line in audit.remedies
    )
    assert any("acme_none@% does not exist on this server" in line for line in audit.remedies)


def test_without_the_column_grant_mysql_user_is_unreadable(stage: Stage) -> None:
    """A column privilege applies to the session's next statement. The server
    refuses the read, and the audit is partial rather than failed."""
    user = stage.account("%")
    stage.admin(f"revoke select ({COLUMNS}) on mysql.user from %s@'%%'", (stage.tool,))

    audit = stage.session.privileges(accounts=(f"{user}@%",))

    assert audit.unreadable == ("mysql.user",)
    assert "SELECT (plugin) ON mysql.user" in audit.missing
