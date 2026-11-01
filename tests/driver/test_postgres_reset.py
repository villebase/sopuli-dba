"""UC-2 on PostgreSQL in tier 0: what `reset_password` and `suspend_account`
send, what they refuse before sending anything, and the refusal of
`expire_password` (#1201).

A scripted connection returns the verifier, as in `test_postgres_password.py`.
The live test (`test_postgres_reset_live.py`) has libpq compute it and logs in
with the new password.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Target
from sopuli.driver.protocol import (
    ACCOUNT_LOCK,
    ACCOUNT_UNLOCK,
    PASSWORD_SET,
    ROLLOVER_FINISH,
    DriverError,
    Scope,
    Timeouts,
    UnsupportedCapabilityError,
)
from sopuli.exit_codes import ExitCode
from sopuli.secrets import Secret

session_module = pytest.importorskip("sopuli.driver.postgres.session")
roles = pytest.importorskip("sopuli.driver.postgres.roles")

ROLE = "acme_dev_alice"
PASSWORD = "Correct-Horse-Battery-9"
VERIFIER = "SCRAM-SHA-256$4096:c2FsdA==$c3RvcmVk:c2VydmVy"


class _PGconn:
    def encrypt_password(self, passwd: bytes, user: bytes, algorithm: bytes | None = None) -> bytes:
        return VERIFIER.encode("ascii")


class _Cursor:
    def __init__(self, connection: _Connection) -> None:
        self.connection = connection

    def execute(self, query: Any, params: Any = None, /) -> None:
        if query == roles.ROLE_QUERY:
            return
        self.connection.sent.append(query)

    def fetchall(self) -> Any:
        return self.connection.role_rows


class _Connection:
    def __init__(self, *, can_login: bool = True, expired: bool = False) -> None:
        self.pgconn = _PGconn()
        self.sent: list[Any] = []
        self.role_rows: list[tuple[Any, ...]] = [
            (ROLE, False, can_login, False, False, False, False, False, None, expired, [], [], None)
        ]

    @contextmanager
    def cursor(self) -> Iterator[_Cursor]:
        yield _Cursor(self)


def _session(*, can_login: bool = True, expired: bool = False, read_write: bool = True) -> Any:
    target = ExpandedTarget(
        target=Target(name="pg-dev", type="postgresql", dsn="pg-dev.example.com:5432")
    )
    built = session_module.PostgresSession(
        connection=_Connection(can_login=can_login, expired=expired),
        target=target,
        correlation_id="run-id",
        timeouts=Timeouts(),
    )
    built._scope = Scope(
        type="cluster",
        open_mode="READ WRITE" if read_write else "READ ONLY",
        read_write=read_write,
        db_version="16.15",
    )
    return built


def test_an_unseen_reset_sends_one_statement_with_the_verifier() -> None:
    session = _session()

    changes = session.reset_password(ROLE, Secret(PASSWORD), expire=False)

    (statement,) = session.connection.sent
    text = repr(statement)
    assert VERIFIER in text
    assert PASSWORD not in text
    assert "VALID UNTIL" not in text
    assert [(one.action, one.changed) for one in changes] == [
        (ACCOUNT_UNLOCK, False),
        (PASSWORD_SET, True),
        (ROLLOVER_FINISH, False),
    ]


def test_a_past_valid_until_is_cleared_in_the_same_statement() -> None:
    """Decision 3 on #1201: the date and the password change together."""
    session = _session(expired=True)

    changes = session.reset_password(ROLE, Secret(PASSWORD), expire=False)

    (statement,) = session.connection.sent
    assert "VALID UNTIL 'infinity'" in repr(statement)
    assert changes[0].action == ACCOUNT_UNLOCK
    assert changes[0].changed is True
    assert "VALID UNTIL had passed" in str(changes[0].detail)


def test_keep_rollover_changes_nothing_on_a_cluster() -> None:
    session = _session()

    changes = session.reset_password(ROLE, Secret(PASSWORD), expire=False, keep_rollover=True)

    assert changes[2].action == ROLLOVER_FINISH
    assert changes[2].changed is False
    assert len(session.connection.sent) == 1


def test_a_seen_reset_is_refused_by_capability_before_anything_is_sent() -> None:
    session = _session()

    with pytest.raises(UnsupportedCapabilityError) as refused:
        session.reset_password(ROLE, Secret(PASSWORD), expire=True)

    assert refused.value.exit_code == ExitCode.UNSUPPORTED_CAPABILITY
    assert "expire_password" in refused.value.message
    assert session.connection.sent == []


def test_a_nologin_role_is_refused_as_deliberately_suspended() -> None:
    session = _session(can_login=False)

    with pytest.raises(DriverError) as refused:
        session.reset_password(ROLE, Secret(PASSWORD), expire=False)

    assert "NOLOGIN" in refused.value.message
    assert "H4" in str(refused.value.hint)
    assert session.connection.sent == []
    assert refused.value.password_sent is False


def test_a_missing_role_is_refused_before_anything_is_sent() -> None:
    session = _session()
    session.connection.role_rows = []

    with pytest.raises(DriverError, match="does not exist"):
        session.reset_password(ROLE, Secret(PASSWORD), expire=False)
    assert session.connection.sent == []


def test_a_read_only_cluster_is_refused_before_anything_is_sent() -> None:
    session = _session(read_write=False)

    with pytest.raises(DriverError):
        session.reset_password(ROLE, Secret(PASSWORD), expire=False)
    assert session.connection.sent == []


def test_a_nologin_role_reads_as_deliberately_locked() -> None:
    """So `reset.decide` skips it before a password is drawn, as it skips
    Oracle's `LOCKED`."""
    state = roles.state_of(
        (ROLE, False, False, False, False, False, False, False, None, False, [], [], None)
    )

    assert state.locked is True
    assert state.deliberately_locked is True


# ----------------------------------------------------------------- suspend --


def test_suspend_sends_alter_role_nologin() -> None:
    session = _session()

    change = session.suspend_account(ROLE)

    (statement,) = session.connection.sent
    assert statement.as_string(None) == f'ALTER ROLE "{ROLE}" NOLOGIN'
    assert change.action == ACCOUNT_LOCK
    assert change.changed is True
    assert change.status == roles.OPEN
    assert change.detail == "role was open; set NOLOGIN"


def test_suspend_of_a_nologin_role_sends_nothing() -> None:
    """Invariant 9: a second NOLOGIN is accepted silently (probe 03, CR8), so
    the driver reads the state and issues nothing."""
    session = _session(can_login=False)

    change = session.suspend_account(ROLE)

    assert session.connection.sent == []
    assert change.changed is False
    assert change.status == roles.NOLOGIN


def test_suspend_of_a_role_past_its_valid_until_still_sets_nologin() -> None:
    """A past VALID UNTIL stops only a password; NOLOGIN stops every method."""
    session = _session(expired=True)

    change = session.suspend_account(ROLE)

    assert len(session.connection.sent) == 1
    assert change.changed is True
    assert change.detail == "role was expired; set NOLOGIN"


def test_suspend_of_a_missing_role_is_refused() -> None:
    session = _session()
    session.connection.role_rows = []

    with pytest.raises(DriverError, match="does not exist"):
        session.suspend_account(ROLE)
    assert session.connection.sent == []


def test_suspend_on_a_read_only_cluster_is_refused_before_anything_is_sent() -> None:
    session = _session(read_write=False)

    with pytest.raises(DriverError):
        session.suspend_account(ROLE)
    assert session.connection.sent == []


# ---------------------------------------------------------- expire-password --


def test_expire_password_is_refused_by_capability() -> None:
    session = _session()

    with pytest.raises(UnsupportedCapabilityError) as refused:
        session.expire_password(ROLE)

    assert refused.value.exit_code == ExitCode.UNSUPPORTED_CAPABILITY
    assert "expire_password" in refused.value.message
    assert "account suspend" in str(refused.value.hint)
    assert session.connection.sent == []
