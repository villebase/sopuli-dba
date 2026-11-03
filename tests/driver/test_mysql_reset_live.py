"""`reset_password` against the tier-1 `mysql` service (#1225).

Tier 1. What only a server can answer, as the tool account with the grants of
`02-mysql-privileges.md` §2.1: that a reset ends a block after failed logins
it cannot read, that the seen path leaves the new password expired, and that
no old password logs in afterwards, a retained one included. Probe 04's LE6
and LE7 measured the same statements with the mysql client.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import suppress
from dataclasses import dataclass
from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Target, TargetMysql
from sopuli.driver.protocol import ACCOUNT_UNLOCK, PASSWORD_SET, ROLLOVER_FINISH, Credential
from sopuli.secrets import Secret

pymysql = pytest.importorskip("pymysql")
session_module = pytest.importorskip("sopuli.driver.mysql.session")

#: Test passwords, not credentials.
OLD, KEPT, NEW = "Acme-Old-pw1", "Acme-Kept-pw2", "Acme-New-pw3"
#: The server's answers to a login.
REFUSED, BLOCKED, MUST_CHANGE = 1045, 3955, 1862


@dataclass
class Reset:
    """A blocked account with a retained password, and the tool's session."""

    session: Any
    account: str
    user: str
    live: Any

    def login(self, password: str) -> int | str:
        """``ok``, or the server's error number. PyMySQL does not say it can
        handle an expired password, so the server refuses one with ``1862``
        after it has checked the password."""
        try:
            self.live.connect_as(self.user, password).close()
        except pymysql.err.MySQLError as error:
            return int(error.args[0])
        return "ok"

    def admin(self, statement: str) -> None:
        """One statement as root, with no bind values."""
        with self.live.connect() as admin, admin.cursor() as cursor:
            cursor.execute(statement)

    def expired(self) -> str:
        with self.live.connect() as admin, admin.cursor() as cursor:
            cursor.execute(
                "select password_expired from mysql.user where User = %s and Host = '%%'",
                (self.user,),
            )
            (value,) = cursor.fetchone()
        return str(value)


@pytest.fixture
def blocked(live_mysql: Any) -> Iterator[Reset]:
    """``acme_<id>_alice@%`` with ``KEPT`` current and ``OLD`` retained,
    blocked by one wrong login under ``FAILED_LOGIN_ATTEMPTS 1``."""
    suffix = uuid.uuid4().hex[:8]
    tool, user = f"sopuli_tool_{suffix}", f"acme_{suffix}_alice"
    password = uuid.uuid4().hex
    with live_mysql.connect() as admin, admin.cursor() as cursor:
        cursor.execute("create user %s@'%%' identified by %s", (tool, password))
        cursor.execute(
            "create user %s@'%%' identified by %s FAILED_LOGIN_ATTEMPTS 1 PASSWORD_LOCK_TIME 1",
            (user, OLD),
        )
        cursor.execute("alter user %s@'%%' identified by %s retain current password", (user, KEPT))
    live_mysql.grant_section_2(tool)
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
    state = Reset(session=session, account=f"{user}@%", user=user, live=live_mysql)
    assert state.login("Acme-Wrong-pw9") == BLOCKED
    assert state.login(KEPT) == BLOCKED
    try:
        yield state
    finally:
        session.close()
        with live_mysql.connect() as admin, admin.cursor() as cursor:
            for name in (tool, user):
                with suppress(pymysql.Error):
                    cursor.execute("drop user %s@'%%'", (name,))


def test_a_seen_reset_ends_the_block_and_leaves_only_the_new_password_expired(
    blocked: Reset,
) -> None:
    rows = blocked.session.reset_password(blocked.account, Secret(NEW), expire=True)

    assert [row.action for row in rows] == [ACCOUNT_UNLOCK, PASSWORD_SET, ROLLOVER_FINISH]
    assert blocked.expired() == "Y"
    # Checked, and expired: the block is gone, or the answer would be 3955.
    assert blocked.login(NEW) == MUST_CHANGE
    # That refusal counts as a failed login and blocks the account again, so
    # the limit goes before the old passwords are tried.
    blocked.admin(f"alter user `{blocked.user}`@`%` failed_login_attempts 0 account unlock")
    assert blocked.login(OLD) == REFUSED
    assert blocked.login(KEPT) == REFUSED
    assert blocked.login(NEW) == MUST_CHANGE


@pytest.mark.parametrize("old_password", ["discard", "retain"])
def test_a_set_ends_an_expiry_so_creds_apply_may_change_an_expired_account(
    blocked: Reset, old_password: str
) -> None:
    """Why the scope reports `expire_password` (LE7, LE8): UC-1 changes an
    expired account because the new password ends the expiry, on a rollover
    too."""
    blocked.admin(f"alter user `{blocked.user}`@`%` account unlock password expire")

    blocked.session.set_password(blocked.account, Secret(NEW), old_password=old_password)

    assert blocked.expired() == "N"
    assert blocked.login(NEW) == "ok"


def test_an_unseen_reset_ends_the_block_and_the_new_password_logs_in(blocked: Reset) -> None:
    blocked.session.reset_password(blocked.account, Secret(NEW), expire=False)

    assert blocked.expired() == "N"
    assert blocked.login(NEW) == "ok"
    # A wrong login blocks the account again: each password is tried once,
    # the right one first.
    assert blocked.login(OLD) == BLOCKED
