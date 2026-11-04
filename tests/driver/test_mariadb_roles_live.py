"""MariaDB roles for a `role:` rule, on the tier-1 `mariadb` service
(11.8.9). Tier 1.

Read as `sopuli_admin`, which holds the grants of `02-mariadb-privileges.md`
§2.1. Each test creates its own accounts and roles, with random names, and
drops them. The PUBLIC test uses a fixed role name, which the fixture drops
first, so a killed run leaves nothing every account holds.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Any

import pytest

pymysql = pytest.importorskip("pymysql")

from sopuli.driver.mariadb.roles import PublicRoleError, members_of, resolve  # noqa: E402

PUBLIC_ROLE = "acme_public_role"


@dataclass
class Stage:
    live: Any
    accounts: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)

    def root(self, statement: str, args: tuple[Any, ...] = ()) -> None:
        with self.live.connect() as root, root.cursor() as cursor:
            cursor.execute(statement, args or None)

    def account(self, host: str = "%") -> str:
        name = f"acme_dev_{uuid.uuid4().hex[:8]}"
        self.root("CREATE USER %s@%s IDENTIFIED BY %s", (name, host, uuid.uuid4().hex))
        self.accounts.append(f"{name}@{host}")
        return f"{name}@{host}"

    def role(self, name: str = "") -> str:
        name = name or f"acme_role_{uuid.uuid4().hex[:8]}"
        self.root(f"CREATE ROLE {name}")
        self.roles.append(name)
        return name

    def grant(self, role: str, to: str) -> None:
        user, _, host = to.partition("@")
        target = f"'{user}'@'{host}'" if host else to
        self.root(f"GRANT {role} TO {target}")

    def read(self, reader: Any) -> Any:
        tool = self.live.connect_as(self.live.tool_user, self.live.tool_password)
        with tool, tool.cursor() as cursor:
            return reader(cursor)


@pytest.fixture
def stage(live_mariadb: Any) -> Iterator[Stage]:
    staged = Stage(live=live_mariadb)
    with suppress(pymysql.Error):
        staged.root(f"DROP ROLE {PUBLIC_ROLE}")
    try:
        yield staged
    finally:
        for role in staged.roles:
            with suppress(pymysql.Error):
                staged.root(f"DROP ROLE {role}")
        for account in staged.accounts:
            user, _, host = account.partition("@")
            with suppress(pymysql.Error):
                staged.root("DROP USER %s@%s", (user, host))


def test_a_role_resolves_to_its_name_and_a_missing_one_to_none(stage: Stage) -> None:
    role = stage.role()

    assert stage.read(lambda cursor: resolve(cursor, role, target="tier1")) == role
    assert stage.read(lambda cursor: resolve(cursor, "acme_no_such_role", target="tier1")) is None


def test_an_account_is_not_a_role(stage: Stage) -> None:
    user = stage.account().partition("@")[0]

    assert stage.read(lambda cursor: resolve(cursor, user, target="tier1")) is None


def test_members_are_the_accounts_that_hold_the_role_through_any_chain(stage: Stage) -> None:
    """A role in the chain is followed and not listed: it cannot log in."""
    outer, inner = stage.role(), stage.role()
    direct, nested, local, other = (
        stage.account(),
        stage.account(),
        stage.account("localhost"),
        stage.account(),
    )
    stage.grant(inner, outer)
    stage.grant(outer, direct)
    stage.grant(inner, nested)
    stage.grant(outer, local)

    members = stage.read(lambda cursor: members_of(cursor, inner))

    # `CREATE ROLE` grants the role to the account that created it, here root,
    # with ADMIN OPTION: root can `SET ROLE` to it, so it holds it.
    assert members == tuple(sorted((direct, nested, local, "root@%")))
    assert other not in members
    assert outer not in " ".join(members)


def test_a_role_public_reaches_is_refused(stage: Stage) -> None:
    outer = stage.role(PUBLIC_ROLE)
    inner = stage.role()
    stage.grant(inner, outer)
    stage.root(f"GRANT {outer} TO PUBLIC")

    for role, through in ((outer, outer), (inner, outer)):
        with pytest.raises(PublicRoleError) as refused:
            stage.read(lambda cursor, role=role: resolve(cursor, role, target="tier1"))
        assert refused.value.category == "config"
        assert "every account holds it" in str(refused.value)
        assert through in str(refused.value)
