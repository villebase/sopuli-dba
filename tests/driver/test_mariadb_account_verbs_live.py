"""`reset_password` and `expire_password` through the MariaDB session, on the
tier-1 `mariadb` service, as the tool account (#1272). Tier 1.

Each test creates `acme_<random>@%` as root, acts on it as the tool account
with the grants of `02-mariadb-privileges.md` §2.1, and drops it.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Target, TargetMysql
from sopuli.driver.protocol import (
    EXPIRE_PASSWORD,
    PASSWORD_EXPIRE,
    PASSWORD_SET,
    Credential,
    DriverError,
    Timeouts,
)
from sopuli.secrets import Secret

pymysql = pytest.importorskip("pymysql")
session_module = pytest.importorskip("sopuli.driver.mariadb.session")

OLD = "Acme-Old-pw1"
NEW = "Acme-New-pw2"
#: A second method's password, joined by OR.
OTHER = "Acme-Other-pw3"

ACCESS_DENIED = 1045
MUST_CHANGE_PASSWORD = 1820
ACCOUNT_LOCKED = 4151


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
    driver = session_module.MariadbDriver(correlation_id="tier1-uc2", timeouts=Timeouts())
    opened = driver.connect(
        target,
        Credential(username=live_mariadb.tool_user, secret=Secret(live_mariadb.tool_password)),
    )
    try:
        yield opened
    finally:
        opened.close()


@pytest.fixture
def user(live_mariadb: Any) -> Iterator[str]:
    name = f"acme_{uuid.uuid4().hex[:8]}"
    _root(live_mariadb, "create user %s@'%%' identified by %s", (name, OLD))
    try:
        yield name
    finally:
        _root(live_mariadb, "drop user if exists %s@'%%'", (name,))


def _root(live_mariadb: Any, statement: str, arguments: tuple[Any, ...] = ()) -> None:
    with live_mariadb.connect() as admin, admin.cursor() as cursor:
        cursor.execute(statement, arguments or None)


def _expired(live_mariadb: Any, user: str) -> str:
    with live_mariadb.connect() as admin, admin.cursor() as cursor:
        cursor.execute("select password_expired from mysql.user where user = %s", (user,))
        return str(cursor.fetchone()[0])


def _login(live_mariadb: Any, user: str, password: str) -> int | None:
    """``None`` where the password logs in and a statement runs, or the
    server's number."""
    try:
        with live_mariadb.connect_as(user, password) as connection, connection.cursor() as cursor:
            cursor.execute("select 1")
    except pymysql.err.MySQLError as error:
        return int(error.args[0])
    return None


def test_the_scope_reports_expire_password(session: Any) -> None:
    assert EXPIRE_PASSWORD in session.scope().capabilities


def test_a_reset_sets_and_expires_by_one_statement(
    live_mariadb: Any, session: Any, user: str
) -> None:
    (change,) = session.reset_password(f"{user}@%", Secret(NEW), expire=True)

    assert change.action == PASSWORD_SET
    assert change.changed
    assert "password set, expired" in change.detail
    assert _expired(live_mariadb, user) == "Y"
    assert _login(live_mariadb, user, NEW) == MUST_CHANGE_PASSWORD
    assert _login(live_mariadb, user, OLD) == ACCESS_DENIED


def test_a_reset_ends_a_second_method(live_mariadb: Any, session: Any, user: str) -> None:
    """A method added with OR stops logging in: the reset names one."""
    _root(
        live_mariadb,
        "alter user %s@'%%' identified via mysql_native_password using password(%s) "
        "or mysql_native_password using password(%s)",
        (user, OLD, OTHER),
    )

    session.reset_password(f"{user}@%", Secret(NEW), expire=False)

    assert _login(live_mariadb, user, NEW) is None
    assert _login(live_mariadb, user, OTHER) == ACCESS_DENIED


def test_a_reset_leaves_a_lock_in_place(live_mariadb: Any, session: Any, user: str) -> None:
    """The lock is not read, so a suspension stays (#1272, decision 1)."""
    _root(live_mariadb, "alter user %s@'%%' account lock", (user,))

    (change,) = session.reset_password(f"{user}@%", Secret(NEW), expire=False)

    assert "a reset does not unlock it" in change.detail
    assert _login(live_mariadb, user, NEW) == ACCOUNT_LOCKED


def test_an_expiry_converges(live_mariadb: Any, session: Any, user: str) -> None:
    (first,) = session.expire_password(f"{user}@%")
    (second,) = session.expire_password(f"{user}@%")

    assert (first.action, first.changed) == (PASSWORD_EXPIRE, True)
    assert (second.action, second.changed) == (PASSWORD_EXPIRE, False)
    assert _expired(live_mariadb, user) == "Y"
    assert _login(live_mariadb, user, OLD) == MUST_CHANGE_PASSWORD


def test_an_expiry_leaves_a_second_method_expired_and_working(
    live_mariadb: Any, session: Any, user: str
) -> None:
    """`PASSWORD EXPIRE` does not end an OR (`11_rollover_expiry_probe.py`):
    both passwords log in, expired. UC-2 documents it (#1272, decision 2)."""
    _root(
        live_mariadb,
        "alter user %s@'%%' identified via mysql_native_password using password(%s) "
        "or mysql_native_password using password(%s)",
        (user, OLD, OTHER),
    )

    session.expire_password(f"{user}@%")

    assert _login(live_mariadb, user, OLD) == MUST_CHANGE_PASSWORD
    assert _login(live_mariadb, user, OTHER) == MUST_CHANGE_PASSWORD


def test_an_account_that_does_not_exist_is_refused(session: Any) -> None:
    missing = f"acme_missing_{uuid.uuid4().hex[:8]}@%"

    with pytest.raises(DriverError, match="does not exist"):
        session.reset_password(missing, Secret(NEW), expire=True)
    with pytest.raises(DriverError, match="does not exist"):
        session.expire_password(missing)
