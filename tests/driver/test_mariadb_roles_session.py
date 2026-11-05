"""Roles and `suspend_account` through the MariaDB session, on the tier-1
`mariadb` service, as the tool account (#1272).

Tier 1. A described account carries the roles it holds by name alone, a role is
listed with every account that holds it, a `profile:` rule is refused by
capability, and `suspend_account` sends ``ACCOUNT LOCK`` on every run
(#1267, decision 2).
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import suppress
from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Target, TargetMysql
from sopuli.driver.protocol import (
    ACCOUNT_LOCK,
    Credential,
    DriverError,
    Timeouts,
    UnsupportedCapabilityError,
)
from sopuli.secrets import Secret

pymysql = pytest.importorskip("pymysql")
session_module = pytest.importorskip("sopuli.driver.mariadb.session")


@pytest.fixture
def session(live_mariadb: Any) -> Iterator[Any]:
    target = ExpandedTarget(
        target=Target(
            name="tier1-mariadb",
            type="mariadb",
            dsn=live_mariadb.dsn,
            mariadb=TargetMysql(ssl_mode="REQUIRED"),
        )
    )
    driver = session_module.MariadbDriver(correlation_id="tier1-roles", timeouts=Timeouts())
    opened = driver.connect(
        target,
        Credential(username=live_mariadb.tool_user, secret=Secret(live_mariadb.tool_password)),
    )
    try:
        yield opened
    finally:
        opened.close()


@pytest.fixture
def names(live_mariadb: Any) -> Iterator[tuple[str, str, str]]:
    """A user, a role it is granted, and a role that role is granted."""
    tag = uuid.uuid4().hex[:8]
    user, role, nested = f"acme_{tag}", f"acme_dev_{tag}", f"acme_ro_{tag}"
    try:
        yield user, role, nested
    finally:
        with live_mariadb.connect() as admin, admin.cursor() as cursor:
            for statement, name in (
                ("drop user if exists %s@'%%'", user),
                ("drop role if exists %s", role),
                ("drop role if exists %s", nested),
            ):
                with suppress(pymysql.Error):
                    cursor.execute(statement, (name,))


def _root(live_mariadb: Any, *statements: tuple[str, tuple[Any, ...]]) -> None:
    with live_mariadb.connect() as admin, admin.cursor() as cursor:
        for statement, arguments in statements:
            cursor.execute(statement, arguments)


def test_a_described_account_carries_its_roles_by_name(
    live_mariadb: Any, session: Any, names: tuple[str, str, str]
) -> None:
    user, role, nested = names
    _root(
        live_mariadb,
        ("create user %s@'%%' identified by %s", (user, uuid.uuid4().hex)),
        (f"create role {role}", ()),
        (f"create role {nested}", ()),
        (f"grant {nested} to {role}", ()),
        (f"grant {role} to %s@'%%'", (user,)),
    )

    state = session.describe_user(f"{user}@%")

    assert state.roles == frozenset({role, nested})


def test_a_role_lists_every_account_that_holds_it(
    live_mariadb: Any, session: Any, names: tuple[str, str, str]
) -> None:
    """Through a nested role too. A role in the chain is followed, not
    listed: it cannot log in."""
    user, role, nested = names
    _root(
        live_mariadb,
        ("create user %s@'%%' identified by %s", (user, uuid.uuid4().hex)),
        (f"create role {role}", ()),
        (f"create role {nested}", ()),
        (f"grant {nested} to {role}", ()),
        (f"grant {role} to %s@'%%'", (user,)),
    )

    assert session.resolve_role(nested) == nested
    members = session.accounts_matching(role=nested)
    assert f"{user}@%" in members
    assert role not in {member.split("@")[0] for member in members}, "a role is not listed"
    assert session.resolve_role("acme_no_such_role") is None
    assert session.accounts_matching(role="acme_no_such_role") == ()


def test_a_profile_rule_is_refused_by_capability(session: Any) -> None:
    with pytest.raises(UnsupportedCapabilityError):
        session.accounts_matching(profile="ACME_DEFAULT")


def test_suspend_sends_account_lock_on_every_run(
    live_mariadb: Any, session: Any, names: tuple[str, str, str]
) -> None:
    user, _, _ = names
    password = f"Acme-{uuid.uuid4().hex[:12]}"
    _root(live_mariadb, ("create user %s@'%%' identified by %s", (user, password)))

    first = session.suspend_account(f"{user}@%")
    second = session.suspend_account(f"{user}@%")

    for change in (first, second):
        assert (change.action, change.changed, change.status) == (ACCOUNT_LOCK, True, "OPEN")
        assert "cannot be read" in (change.detail or "")
    with pytest.raises(pymysql.err.OperationalError) as caught:
        live_mariadb.connect_as(user, password)
    assert caught.value.args[0] == 4151


def test_suspend_refuses_a_missing_account(session: Any) -> None:
    with pytest.raises(DriverError) as caught:
        session.suspend_account("acme_nobody@%")

    assert "does not exist" in str(caught.value)
