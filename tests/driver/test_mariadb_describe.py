"""`describe_user` on the tier-1 `mariadb` service, as the tool account (#1270).

Tier 1. The session reads the account's plugin and expiry from the view, never
its lock, and the privileges guardrail 9 checks, through
:func:`~sopuli.driver.mariadb.admin.global_privileges`.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import suppress
from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Target, TargetMysql
from sopuli.driver.protocol import Credential, DriverError, Timeouts
from sopuli.secrets import Secret

pymysql = pytest.importorskip("pymysql")
session_module = pytest.importorskip("sopuli.driver.mariadb.session")
accounts_module = pytest.importorskip("sopuli.driver.mariadb.accounts")


def _connect(live_mariadb: Any, user: str, password: str) -> Any:
    target = ExpandedTarget(
        target=Target(
            name="tier1-mariadb",
            type="mariadb",
            dsn=live_mariadb.dsn,
            mariadb=TargetMysql(ssl_mode="REQUIRED"),
        )
    )
    driver = session_module.MariadbDriver(correlation_id="tier1-describe", timeouts=Timeouts())
    return driver.connect(target, Credential(username=user, secret=Secret(password)))


@pytest.fixture
def session(live_mariadb: Any) -> Iterator[Any]:
    opened = _connect(live_mariadb, live_mariadb.tool_user, live_mariadb.tool_password)
    try:
        yield opened
    finally:
        opened.close()


@pytest.fixture
def tool(live_mariadb: Any) -> Iterator[tuple[str, str]]:
    """A second tool account, holding only what each test grants it."""
    name = f"acme_tool_{uuid.uuid4().hex[:8]}"
    password = uuid.uuid4().hex
    _root(live_mariadb, ("create user %s@'%%' identified by %s", (name, password)))
    try:
        yield name, password
    finally:
        with live_mariadb.connect() as admin, admin.cursor() as cursor, suppress(pymysql.Error):
            cursor.execute("drop user if exists %s@'%%'", (name,))


@pytest.fixture
def user(live_mariadb: Any) -> Iterator[str]:
    name = f"acme_{uuid.uuid4().hex[:8]}"
    try:
        yield name
    finally:
        with live_mariadb.connect() as admin, admin.cursor() as cursor, suppress(pymysql.Error):
            cursor.execute("drop user if exists %s@'%%'", (name,))


def _root(live_mariadb: Any, *statements: tuple[str, tuple[Any, ...]]) -> None:
    with live_mariadb.connect() as admin, admin.cursor() as cursor:
        for statement, arguments in statements:
            cursor.execute(statement, arguments)


def test_an_account_reads_its_plugin_and_expiry_and_no_lock(
    live_mariadb: Any, session: Any, user: str
) -> None:
    _root(
        live_mariadb,
        ("create user %s@'%%' identified by %s", (user, uuid.uuid4().hex)),
        ("alter user %s@'%%' password expire", (user,)),
        ("alter user %s@'%%' account lock", (user,)),
    )

    state = session.describe_user(f"{user}@%")

    assert state.name == f"{user}@%"
    assert (state.status, state.expired) == ("EXPIRED", True)
    # Locked on the server; the tool never reads the lock (#1267, decision 2).
    assert state.locked is False
    assert state.global_privileges == frozenset()
    assert state.session_account is False


def test_a_global_privilege_is_read_for_guardrail_9(
    live_mariadb: Any, session: Any, user: str
) -> None:
    _root(
        live_mariadb,
        ("create user %s@'%%' identified by %s", (user, uuid.uuid4().hex)),
        ("grant process on *.* to %s@'%%'", (user,)),
    )

    state = session.describe_user(f"{user}@%")

    assert any(held.startswith("PROCESS") for held in state.global_privileges)


def test_an_account_on_another_plugin_is_refused(
    live_mariadb: Any, session: Any, user: str
) -> None:
    _root(live_mariadb, ("create user %s@'%%' identified via unix_socket", (user,)))

    with pytest.raises(accounts_module.OtherPluginError) as caught:
        session.describe_user(f"{user}@%")

    assert "uses unix_socket" in str(caught.value)


def test_a_missing_account_is_none_and_the_tool_account_is_its_own(
    live_mariadb: Any, session: Any
) -> None:
    assert session.describe_user("acme_nobody@%") is None
    own = session.describe_user(f"{live_mariadb.tool_user}@%")
    assert own.session_account is True


def test_the_server_s_own_account_is_vendor_maintained(session: Any) -> None:
    state = session.describe_user("mariadb.sys@localhost")

    assert state.vendor_maintained is True


def test_section_2_1_is_enough_to_describe_an_account(
    live_mariadb: Any, tool: tuple[str, str], user: str
) -> None:
    name, password = tool
    live_mariadb.grant_section_2(name)
    _root(
        live_mariadb,
        ("create user %s@'%%' identified by %s", (user, uuid.uuid4().hex)),
        ("grant process on *.* to %s@'%%'", (user,)),
    )
    opened = _connect(live_mariadb, name, password)
    try:
        state = opened.describe_user(f"{user}@%")
    finally:
        opened.close()

    assert state.status == "OPEN"
    assert any(held.startswith("PROCESS") for held in state.global_privileges)


def test_a_missing_grant_names_section_2_1(live_mariadb: Any, tool: tuple[str, str]) -> None:
    name, password = tool
    _root(live_mariadb, ("grant create user on *.* to %s@'%%'", (name,)))
    opened = _connect(live_mariadb, name, password)
    try:
        with pytest.raises(DriverError) as caught:
            opened.describe_user("acme_app@%")
    finally:
        opened.close()

    assert caught.value.code in {"1142", "1143"}
    assert caught.value.hint == session_module.MISSING_GRANT_HINT
