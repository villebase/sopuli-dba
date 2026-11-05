"""`reset_password` and `expire_password` on a MariaDB session, with the
reads and the statement replaced (#1272). Tier 0.

What the server then does is `test_mariadb_account_verbs_live.py`'s. Here:
what is refused before anything is sent, `password_sent` on a failed reset,
and an expiry that has nothing to do.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Target
from sopuli.driver.protocol import (
    ENCRYPTION_TLS,
    PASSWORD_EXPIRE,
    DriverError,
    Encryption,
    Scope,
    Timeouts,
)
from sopuli.secrets import Secret

session_module = pytest.importorskip("sopuli.driver.mariadb.session")
from sopuli.driver.mariadb.accounts import Account  # noqa: E402

NEW = "Acme-New-pw2"


class Recorder:
    """Stands in for the session's reads: the account it finds, and every
    statement it was handed."""

    def __init__(self, found: Account | None, *, fails: bool = False) -> None:
        self.found = found
        self.fails = fails
        self.sent: list[Any] = []

    def read_grants(self, reader: Any) -> Account | None:
        return self.found

    def read(self, reader: Any, **_: Any) -> None:
        self.sent.append(reader)
        if self.fails:
            raise DriverError("the server refused the statement", code="1396")


def _session(
    monkeypatch: pytest.MonkeyPatch, recorder: Recorder, *, read_write: bool = True
) -> Any:
    session = session_module.MariadbSession(
        connection=None,
        target=ExpandedTarget(
            target=Target(name="mariadb-dev", type="mariadb", dsn="mariadb-dev.example.com:3306")
        ),
        correlation_id="tier0",
        timeouts=Timeouts(),
    )
    scope = Scope(
        type="server",
        read_write=read_write,
        capabilities=session_module.CAPABILITIES,
        encryption=Encryption(method=ENCRYPTION_TLS),
    )
    monkeypatch.setattr(session, "scope", lambda: scope)
    monkeypatch.setattr(session, "_read_grants", recorder.read_grants)
    monkeypatch.setattr(session, "_read", recorder.read)
    return session


ACCOUNT = Account(user="acme_dev_alice", host="%", plugin="mysql_native_password")


def test_a_read_only_session_is_refused_before_anything_is_sent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = Recorder(ACCOUNT)
    session = _session(monkeypatch, recorder, read_write=False)

    with pytest.raises(DriverError):
        session.reset_password("acme_dev_alice@%", Secret(NEW), expire=True)
    with pytest.raises(DriverError):
        session.expire_password("acme_dev_alice@%")

    assert recorder.sent == []


def test_a_missing_account_is_refused_before_anything_is_sent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = Recorder(None)
    session = _session(monkeypatch, recorder)

    with pytest.raises(DriverError, match="does not exist") as caught:
        session.reset_password("acme_dev_alice@%", Secret(NEW), expire=True)

    assert not caught.value.password_sent
    assert recorder.sent == []


def test_a_failed_reset_says_the_value_was_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    """What crossed is the value, which still allows an offline guess."""
    recorder = Recorder(ACCOUNT, fails=True)
    session = _session(monkeypatch, recorder)

    with pytest.raises(DriverError) as caught:
        session.reset_password("acme_dev_alice@%", Secret(NEW), expire=True)

    assert caught.value.password_sent
    assert len(recorder.sent) == 1


def test_audit_coverage_answers_unknown_and_never_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unseen reset asks it, so it must not refuse as an unwritten method."""
    recorder = Recorder(ACCOUNT)
    session = _session(monkeypatch, recorder)

    coverage = session.audit_coverage("acme_dev_alice@%")

    assert coverage.audited is None
    assert recorder.sent == []


def test_an_expired_password_is_left_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    """Invariant 9: nothing is sent, and the row says no change."""
    recorder = Recorder(
        Account(user="acme_dev_alice", host="%", plugin="mysql_native_password", expired=True)
    )
    session = _session(monkeypatch, recorder)

    (change,) = session.expire_password("acme_dev_alice@%")

    assert (change.action, change.changed) == (PASSWORD_EXPIRE, False)
    assert recorder.sent == []
