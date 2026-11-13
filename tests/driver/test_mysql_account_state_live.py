"""The optional view `sopuli.account_state` on the tier-1 `mysql` service (#1502). Tier 1.

The install script `sql/mysql/account_state_view.sql` is run as root for a
tool account made per test, and the view is then read as that account, which
holds nothing but `SELECT` on the view, through
:func:`sopuli.driver.mysql.account_state.read`. Each test creates its own
accounts with random names. The view, its schema and its definer are dropped
afterwards, so the service is as it was.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterator
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest

pymysql = pytest.importorskip("pymysql")

from sopuli.driver.mysql.account_state import ABSENT, read  # noqa: E402

SCRIPT = Path(__file__).resolve().parents[2] / "sql" / "mysql" / "account_state_view.sql"


def _statements(tool: str) -> list[str]:
    """The script's statements, for ``tool`` at `%`."""
    text = SCRIPT.read_text(encoding="utf-8")
    text = text.replace("SET @tool_user = 'sopuli_admin';", f"SET @tool_user = '{tool}';")
    text = text.replace("SET @tool_host = '192.0.2.10';", "SET @tool_host = '%';")
    body = "\n".join(line for line in text.splitlines() if not line.startswith("--"))
    return [statement.strip() for statement in re.split(r";\s*\n", body) if statement.strip()]


class Stage:
    def __init__(self, live: Any) -> None:
        self.live = live
        self.tool = f"sopuli_tool_{uuid.uuid4().hex[:8]}"
        self.tool_password = uuid.uuid4().hex
        self.accounts: list[str] = [self.tool]
        self.root(f"CREATE USER '{self.tool}'@'%' IDENTIFIED BY '{self.tool_password}'")

    def root(self, *statements: str) -> None:
        with self.live.connect() as root, root.cursor() as cursor:
            for statement in statements:
                cursor.execute(statement)

    def install(self) -> None:
        self.root(*_statements(self.tool))

    def account(self, options: str = "") -> str:
        name = f"acme_dev_{uuid.uuid4().hex[:8]}"
        self.root(f"CREATE USER '{name}'@'%' IDENTIFIED BY '{uuid.uuid4().hex}' {options}")
        self.accounts.append(name)
        return name

    def read(self) -> Any:
        tool = self.live.connect_as(self.tool, self.tool_password)
        with tool, tool.cursor() as cursor:
            return read(cursor)


@pytest.fixture
def stage(live_mysql: Any) -> Iterator[Stage]:
    staged = Stage(live_mysql)
    try:
        yield staged
    finally:
        for name in staged.accounts:
            with suppress(pymysql.Error):
                staged.root(f"DROP USER '{name}'@'%'")
        for statement in (
            "DROP VIEW IF EXISTS sopuli.account_state",
            "DROP SCHEMA IF EXISTS sopuli",
            "DROP USER IF EXISTS 'sopuli_view_definer'@'localhost'",
        ):
            with suppress(pymysql.Error):
                staged.root(statement)


def test_without_the_view_the_reason_names_the_script(stage: Stage) -> None:
    states = stage.read()
    assert (states.rows, states.reason, states.broken) == (None, ABSENT, None)


def test_the_installed_view_gives_the_failed_login_limit(stage: Stage) -> None:
    three = stage.account("FAILED_LOGIN_ATTEMPTS 3 PASSWORD_LOCK_TIME 2")
    none = stage.account()
    zero = stage.account("FAILED_LOGIN_ATTEMPTS 4 PASSWORD_LOCK_TIME UNBOUNDED")
    # DV2: setting both to 0 removes the keys.
    stage.root(f"ALTER USER '{zero}'@'%' FAILED_LOGIN_ATTEMPTS 0 PASSWORD_LOCK_TIME 0")
    stage.install()
    # Twice: the script is safe to run again.
    stage.install()

    states = stage.read()

    assert states.broken is None
    assert states.limit(three, "%") == (3, None)
    assert states.limit(none, "%") == ("unlimited", None)
    assert states.limit(zero, "%") == ("unlimited", None)


def test_a_view_with_another_column_is_broken_and_not_read(stage: Stage) -> None:
    stage.install()
    stage.root(
        "CREATE OR REPLACE DEFINER = 'sopuli_view_definer'@'localhost' SQL SECURITY DEFINER "
        "VIEW sopuli.account_state AS SELECT User, Host, "
        "JSON_EXTRACT(User_attributes, '$.Password_locking.failed_login_attempts') "
        "AS failed_login_attempts, 'x' AS authentication_string FROM mysql.user"
    )
    states = stage.read()
    assert states.rows is None
    assert states.broken == "it has columns the tool does not expect (authentication_string)"


def test_a_view_whose_definer_is_gone_is_broken(stage: Stage) -> None:
    stage.install()
    stage.root("DROP USER 'sopuli_view_definer'@'localhost'")
    states = stage.read()
    assert states.rows is None
    assert states.broken == "its definer no longer exists (1045)"


def test_a_definer_without_select_is_broken(stage: Stage) -> None:
    stage.install()
    stage.root("REVOKE SELECT ON mysql.user FROM 'sopuli_view_definer'@'localhost'")
    states = stage.read()
    assert states.rows is None
    assert states.broken == "its definer cannot read mysql.user (1356)"
