"""The optional view `sopuli.account_state` on the tier-1 `mariadb` service (#1491). Tier 1.

The install script `sql/mariadb/account_state_view.sql` is run as root, for
the service's tool account `sopuli_admin@%`, and the view is then read as that
account through :func:`sopuli.driver.mariadb.account_state.read`. Each test
creates its own accounts with random names. The view, its schema and its
definer are dropped afterwards, so the service is as it was.
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

from sopuli.driver.mariadb.account_state import ABSENT, read  # noqa: E402

SCRIPT = Path(__file__).resolve().parents[2] / "sql" / "mariadb" / "account_state_view.sql"


def _statements() -> list[str]:
    """The script's statements, for the service's tool account at `%`."""
    text = SCRIPT.read_text(encoding="utf-8")
    text = text.replace("SET @tool_host = '192.0.2.10';", "SET @tool_host = '%';")
    body = "\n".join(line for line in text.splitlines() if not line.startswith("--"))
    return [statement.strip() for statement in re.split(r";\s*\n", body) if statement.strip()]


class Stage:
    def __init__(self, live: Any) -> None:
        self.live = live
        self.accounts: list[str] = []

    def root(self, *statements: str) -> None:
        with self.live.connect() as root, root.cursor() as cursor:
            for statement in statements:
                cursor.execute(statement)

    def install(self) -> None:
        self.root(*_statements())

    def account(self, options: str = "") -> str:
        name = f"acme_dev_{uuid.uuid4().hex[:8]}"
        self.root(f"CREATE USER '{name}'@'%' IDENTIFIED BY '{uuid.uuid4().hex}' {options}")
        self.accounts.append(name)
        return name

    def read(self) -> Any:
        tool = self.live.connect_as(self.live.tool_user, self.live.tool_password)
        with tool, tool.cursor() as cursor:
            return read(cursor)


@pytest.fixture
def stage(live_mariadb: Any) -> Iterator[Stage]:
    staged = Stage(live_mariadb)
    try:
        yield staged
    finally:
        for name in staged.accounts:
            with suppress(pymysql.Error):
                staged.root(f"DROP USER '{name}'@'%'")
        for statement in (
            # MariaDB keeps a table grant after DROP VIEW, and doctor's audit
            # on the same service would then see it.
            "REVOKE SELECT ON sopuli.account_state FROM 'sopuli_admin'@'%'",
            "DROP VIEW IF EXISTS sopuli.account_state",
            "DROP SCHEMA IF EXISTS sopuli",
            "DROP USER IF EXISTS 'sopuli_view_definer'@'localhost'",
        ):
            with suppress(pymysql.Error):
                staged.root(statement)


def test_without_the_view_the_reason_names_the_script(stage: Stage) -> None:
    states = stage.read()
    assert (states.rows, states.reason, states.broken) == (None, ABSENT, None)


def test_the_installed_view_gives_the_lock_lifetime_and_time(stage: Stage) -> None:
    locked = stage.account("ACCOUNT LOCK")
    ninety = stage.account("PASSWORD EXPIRE INTERVAL 90 DAY")
    never = stage.account("PASSWORD EXPIRE NEVER")
    expired = stage.account()
    stage.root(f"ALTER USER '{expired}'@'%' PASSWORD EXPIRE")
    stage.install()
    # Twice: the script is safe to run again.
    stage.install()

    states = stage.read()

    assert states.broken is None
    assert states.get(locked, "%").locked is True
    assert states.get(ninety, "%").locked is False
    assert states.get(ninety, "%").lifetime == 90
    assert states.get(never, "%").lifetime == "unlimited"
    assert states.get(ninety, "%").changed_at is not None
    # PASSWORD EXPIRE sets the time of the last change to 0 (#1479).
    assert states.get(expired, "%").changed_at is None


def test_a_view_with_another_column_is_broken_and_not_read(stage: Stage) -> None:
    stage.install()
    stage.root(
        "CREATE OR REPLACE DEFINER = 'sopuli_view_definer'@'localhost' SQL SECURITY DEFINER "
        "VIEW sopuli.account_state AS SELECT User, Host, "
        "JSON_VALUE(Priv, '$.account_locked') AS account_locked, "
        "JSON_VALUE(Priv, '$.password_lifetime') AS password_lifetime, "
        "JSON_VALUE(Priv, '$.password_last_changed') AS password_last_changed, "
        "0 AS rollover_open, 'x' AS authentication_string FROM mysql.global_priv"
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
