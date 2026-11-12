"""The optional view `sopuli.global_privileges` on the tier-1 `mariadb` service (#1483). Tier 1.

The install script `sql/mariadb/global_privileges_view.sql` is run as root,
for the service's tool account `sopuli_admin@%`, and the view is then read as
that account through :func:`sopuli.driver.mariadb.global_privileges.read`.
Each test makes its own accounts. The grant, the view, its definer and the
schema, where empty, are removed afterwards, the grant first: MariaDB keeps a
table grant after ``DROP VIEW``, and doctor's audit on the same service would
see it.
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

from sopuli.driver.mariadb.global_privileges import ABSENT, read  # noqa: E402

SCRIPT = Path(__file__).resolve().parents[2] / "sql" / "mariadb" / "global_privileges_view.sql"


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

    def account(self, *grants: str) -> str:
        name = f"acme_dev_{uuid.uuid4().hex[:8]}"
        # The service checks password strength (simple_password_check).
        self.root(f"CREATE USER '{name}'@'%' IDENTIFIED BY 'Acme-{uuid.uuid4().hex}'")
        self.root(*(f"GRANT {grant} ON *.* TO '{name}'@'%'" for grant in grants))
        self.accounts.append(name)
        return name

    def read(self) -> Any:
        tool = self.live.connect_as(self.live.tool_user, self.live.tool_password)
        with tool, tool.cursor() as cursor:
            return read(cursor, user=self.live.tool_user, host="%")


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
            "REVOKE SELECT ON sopuli.global_privileges FROM 'sopuli_admin'@'%'",
            "DROP VIEW IF EXISTS sopuli.global_privileges",
            "DROP USER IF EXISTS 'sopuli_grants_definer'@'localhost'",
        ):
            with suppress(pymysql.Error):
                staged.root(statement)


def test_without_the_view_the_reason_names_the_script(stage: Stage) -> None:
    found = stage.read()
    assert (found.rows, found.reason, found.broken) == (None, ABSENT, None)


def test_the_installed_view_gives_each_accounts_global_privileges(stage: Stage) -> None:
    ops = stage.account("PROCESS", "CONNECTION ADMIN")
    plain = stage.account()
    stage.install()
    stage.install()

    found = stage.read()

    assert found.broken is None
    assert found.of(ops, "%") == (("CONNECTION ADMIN", False), ("PROCESS", False))
    assert found.of(plain, "%") == ()


def test_a_definer_that_reads_less_than_mysql_is_broken(stage: Stage) -> None:
    stage.install()
    stage.root(
        "REVOKE SELECT ON mysql.* FROM 'sopuli_grants_definer'@'localhost'",
        "GRANT SELECT ON mysql.global_priv TO 'sopuli_grants_definer'@'localhost'",
    )
    found = stage.read()
    assert found.rows is None
    assert found.broken == (
        "the tool account's own row is missing, so its definer cannot read mysql.*"
    )
