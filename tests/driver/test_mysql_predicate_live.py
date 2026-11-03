"""A `role:` rule against the tier-1 `mysql` service (#1225).

Tier 1. What only a server can answer: that a tool account with the grants of
`02-mysql-privileges.md` §2.1 reads every chain of `mysql.role_edges` grants,
that a role granted to a role reaches that role's members, that the host of a
role compares without case, and that a mandatory role is refused. A role
granted but never activated counts. `describe_user` follows the same grants
the other way, so the listing and a verb agree on who the rule admits.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Target, TargetMysql
from sopuli.driver.protocol import Credential, UnsupportedCapabilityError
from sopuli.exit_codes import ExitCode
from sopuli.secrets import Secret

pymysql = pytest.importorskip("pymysql")
session_module = pytest.importorskip("sopuli.driver.mysql.session")
roles_module = pytest.importorskip("sopuli.driver.mysql.roles")


@dataclass
class Estate:
    """A team role, a role below it, and accounts in and out of it."""

    session: Any
    names: dict[str, str]
    live: Any
    created: list[str] = field(default_factory=list)

    def admin(self, statement: str) -> None:
        """One statement as root, with no bind values, so a `%` in it is
        literal."""
        with self.live.connect() as admin, admin.cursor() as cursor:
            cursor.execute(statement)


@pytest.fixture
def estate(live_mysql: Any) -> Iterator[Estate]:
    """``team@%`` is granted to ``leads@%`` and to ``alice@%``; ``leads@%`` to
    ``bob@localhost``. ``stranger@%`` holds nothing. No role is activated."""
    suffix = uuid.uuid4().hex[:8]
    names = {
        "tool": f"sopuli_tool_{suffix}",
        "team": f"acme_{suffix}_team",
        "leads": f"acme_{suffix}_leads",
        "alice": f"acme_{suffix}_alice",
        "bob": f"acme_{suffix}_bob",
        "stranger": f"acme_{suffix}_stranger",
    }
    accounts = [
        (names["team"], "%"),
        (names["leads"], "%"),
        (names["alice"], "%"),
        (names["bob"], "localhost"),
        (names["stranger"], "%"),
    ]
    password = uuid.uuid4().hex
    with live_mysql.connect() as admin, admin.cursor() as cursor:
        cursor.execute("create user %s@'%%' identified by %s", (names["tool"], password))
        cursor.execute("create role %s@'%%', %s@'%%'", (names["team"], names["leads"]))
        for user, host in accounts[2:]:
            cursor.execute("create user %s@%s identified by %s", (user, host, "Acme-pw1"))
        cursor.execute("grant %s@'%%' to %s@'%%'", (names["team"], names["leads"]))
        cursor.execute("grant %s@'%%' to %s@'%%'", (names["team"], names["alice"]))
        cursor.execute("grant %s@'%%' to %s@'localhost'", (names["leads"], names["bob"]))
    live_mysql.grant_section_2(names["tool"])
    target = ExpandedTarget(
        target=Target(
            name="tier1-mysql",
            type="mysql",
            dsn=live_mysql.dsn,
            mysql=TargetMysql(ssl_mode="REQUIRED"),
        )
    )
    session = session_module.MysqlDriver(correlation_id="tier1").connect(
        target, Credential(username=names["tool"], secret=Secret(password))
    )
    try:
        yield Estate(session=session, names=names, live=live_mysql)
    finally:
        session.close()
        with live_mysql.connect() as admin, admin.cursor() as cursor:
            for user, host in [(names["tool"], "%"), *accounts]:
                with suppress(pymysql.Error):
                    cursor.execute("drop user %s@%s", (user, host))


def test_the_members_are_every_account_below_the_role(estate: Estate) -> None:
    """Through the role in between, and with no role active."""
    names = estate.names
    team = f"{names['team']}@%"

    assert estate.session.resolve_role(team) == team
    assert estate.session.accounts_matching(role=team) == tuple(
        sorted([f"{names['alice']}@%", f"{names['bob']}@localhost", f"{names['leads']}@%"])
    )


def test_a_role_host_compares_without_case(estate: Estate) -> None:
    leads = estate.names["leads"]

    assert estate.session.resolve_role(f"{leads}@%") == f"{leads}@%"
    assert estate.session.accounts_matching(role=f"{leads}@%") == (
        f"{estate.names['bob']}@localhost",
    )


def test_a_role_whose_user_differs_by_case_does_not_exist(estate: Estate) -> None:
    assert estate.session.resolve_role(f"{estate.names['team'].upper()}@%") is None


def test_describe_user_reads_the_same_grants_upward(estate: Estate) -> None:
    """A verb admits by these, so it admits the accounts the listing shows."""
    names = estate.names
    bob = estate.session.describe_user(f"{names['bob']}@localhost")
    stranger = estate.session.describe_user(f"{names['stranger']}@%")

    assert bob is not None
    assert stranger is not None
    assert bob.roles == frozenset({f"{names['leads']}@%", f"{names['team']}@%"})
    assert stranger.roles == frozenset()


def test_a_mandatory_role_is_refused(estate: Estate) -> None:
    """Decision 5 of #1225: the rule would admit every account. A role the
    mandatory one holds is refused too."""
    names = estate.names
    estate.admin(f"set global mandatory_roles = '`{names['leads']}`@`%`'")
    try:
        for role, through in ((names["leads"], names["leads"]), (names["team"], names["leads"])):
            with pytest.raises(roles_module.MandatoryRoleError) as caught:
                estate.session.resolve_role(f"{role}@%")
            assert caught.value.exit_code == ExitCode.CONFIG_INVALID
            assert f"{through}@%" in str(caught.value)
        stranger = estate.session.describe_user(f"{names['stranger']}@%")
        assert stranger is not None
        assert stranger.roles == frozenset()
    finally:
        estate.admin("set global mandatory_roles = ''")


def test_a_profile_rule_is_refused_by_capability(estate: Estate) -> None:
    with pytest.raises(UnsupportedCapabilityError):
        estate.session.resolve_profile("default")
