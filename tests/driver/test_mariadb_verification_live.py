"""A login as a managed account on the tier-1 `mariadb` service (11.8.9),
through the driver's own connection arguments. Tier 1.

Each test creates `acme_vfy_<random>@%` with a password, changes it as root,
and drops it. The accounts the login can reach are read as the tool account,
with the grants of `02-mariadb-privileges.md` §2.1.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Target, TargetMysql
from sopuli.driver.protocol import FAIL, PASS, UNAVAILABLE, Timeouts, VerifyResult
from sopuli.secrets import Secret

pymysql = pytest.importorskip("pymysql")

from sopuli.driver.mariadb import accounts  # noqa: E402
from sopuli.driver.mariadb.verification import competitor, login  # noqa: E402

PASSWORD = "Acme-Vfy-pw1"


@dataclass
class Stage:
    live: Any
    user: str = field(default_factory=lambda: f"acme_vfy_{uuid.uuid4().hex[:8]}")
    hosts: list[str] = field(default_factory=list)

    def root(self, statement: str, args: tuple[Any, ...] = ()) -> None:
        with self.live.connect() as root, root.cursor() as cursor:
            cursor.execute(statement, args or None)

    def create(self, host: str, password: str = PASSWORD) -> None:
        self.root("CREATE USER %s@%s IDENTIFIED BY %s", (self.user, host, password))
        self.hosts.append(host)

    def verify(self, host: str, password: str, ssl_mode: str = "REQUIRED") -> VerifyResult:
        """As the driver will: read the user's accounts as the tool account,
        decide the competitor, and log in."""
        with (
            self.live.connect_as(self.live.tool_user, self.live.tool_password) as tool,
            tool.cursor() as cursor,
        ):
            found = accounts.read(cursor, [self.user, ""])
        declared = accounts.find(found[self.user], host)
        assert declared is not None
        target = ExpandedTarget(
            target=Target(
                name="tier1-mariadb",
                type="mariadb",
                dsn=self.live.dsn,
                mariadb=TargetMysql(ssl_mode=ssl_mode),
            )
        )
        return login(
            target,
            declared,
            Secret(password),
            competing=competitor(declared, found[self.user], found[""]),
            correlation_id="tier1",
            timeouts=Timeouts(),
        )


@pytest.fixture
def stage(live_mariadb: Any) -> Iterator[Stage]:
    staged = Stage(live=live_mariadb)
    try:
        yield staged
    finally:
        for host in staged.hosts:
            staged.root("DROP USER IF EXISTS %s@%s", (staged.user, host))


def test_the_right_password_passes_and_a_wrong_one_fails(stage: Stage) -> None:
    stage.create("%")

    right = stage.verify("%", PASSWORD)
    wrong = stage.verify("%", "Not-the-pw9")

    assert right.result == PASS
    assert right.latency_ms is not None
    assert "lockout guard is unavailable" in str(right.detail)
    assert wrong.result == FAIL
    assert "(1045)" in str(wrong.detail)


def test_a_password_that_is_not_ascii_passes(stage: Stage) -> None:
    stage.create("%", "Acme-pässwörd-€")

    assert stage.verify("%", "Acme-pässwörd-€").result == PASS


def test_an_expired_account_s_right_password_passes(stage: Stage) -> None:
    """The session opens, and `1820` answers `SELECT CURRENT_USER()`."""
    stage.create("%")
    stage.root("ALTER USER %s@'%%' PASSWORD EXPIRE", (stage.user,))

    result = stage.verify("%", PASSWORD)

    assert result.result == PASS
    assert "(1820)" in str(result.detail)
    assert stage.verify("%", "Not-the-pw9").result == FAIL


def test_an_expired_account_refused_at_connect_passes(stage: Stage) -> None:
    """With `disconnect_on_expired_password = ON` the right password gets
    `1862` at connect, and a wrong one `1045`."""
    stage.create("%")
    stage.root("ALTER USER %s@'%%' PASSWORD EXPIRE", (stage.user,))
    stage.root("SET GLOBAL disconnect_on_expired_password = ON")
    try:
        right = stage.verify("%", PASSWORD)
        wrong = stage.verify("%", "Not-the-pw9")
    finally:
        stage.root("SET GLOBAL disconnect_on_expired_password = OFF")

    assert right.result == PASS
    assert "(1862)" in str(right.detail)
    assert wrong.result == FAIL


def test_a_refusal_without_tls_says_nothing(stage: Stage) -> None:
    """An account that requires TLS answers its right password with `1045`
    over a session without it, so a target whose mode does not require TLS
    cannot read `1045` as a wrong password."""
    stage.create("%")
    stage.root("ALTER USER %s@'%%' REQUIRE SSL", (stage.user,))

    plain = stage.verify("%", PASSWORD, ssl_mode="DISABLED")
    over_tls = stage.verify("%", PASSWORD)

    assert plain.result == UNAVAILABLE
    assert "does not require TLS" in str(plain.detail)
    assert over_tls.result == PASS


def test_a_locked_account_s_right_password_passes(stage: Stage) -> None:
    stage.create("%")
    stage.root("ALTER USER %s@'%%' ACCOUNT LOCK", (stage.user,))

    result = stage.verify("%", PASSWORD)

    assert result.result == PASS
    assert "(4151)" in str(result.detail)
    assert stage.verify("%", "Not-the-pw9").result == FAIL


def test_a_blocked_account_says_nothing(stage: Stage) -> None:
    stage.create("%")
    stage.root("SET GLOBAL max_password_errors = 1")
    try:
        stage.verify("%", "Not-the-pw9")
        result = stage.verify("%", PASSWORD)
    finally:
        stage.root("SET GLOBAL max_password_errors = DEFAULT")

    assert result.result == UNAVAILABLE
    assert "(4150)" in str(result.detail)


def test_a_login_that_reaches_another_account_says_nothing(stage: Stage) -> None:
    """Declared at `localhost`, the login from the tool's host reaches `%`:
    with the same password it logs in there, and with its own it is refused."""
    stage.create("%")
    stage.create("localhost")

    reached = stage.verify("localhost", PASSWORD)
    stage.root("ALTER USER %s@'localhost' IDENTIFIED BY %s", (stage.user, "Acme-Local-pw2"))
    refused = stage.verify("localhost", "Acme-Local-pw2")

    assert reached.result == UNAVAILABLE
    assert f"reached {stage.user}@%" in str(reached.detail)
    assert refused.result == UNAVAILABLE
    assert "nothing certain" in str(refused.detail)
