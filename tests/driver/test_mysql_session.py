"""The MySQL session on a scripted connection. Tier 0, with PyMySQL installed.

What this build does past connecting is refuse, so the refusals are the
behaviour: ``SOPULI-20006`` for an operation not written yet, an absent
capability named, a session without TLS refused where the mode requires it,
and PyMySQL's own failure of a plain login reported as what it is.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Runtime, Target, TargetMysql
from sopuli.driver.protocol import (
    PASSWORD_ROLLOVER,
    AccountAttributes,
    Credential,
    Driver,
    DriverContext,
    DriverError,
    Session,
    UnsupportedCapabilityError,
)
from sopuli.driver.registry import DRIVER_NOT_IMPLEMENTED
from sopuli.exit_codes import ExitCode
from sopuli.secrets import Secret

session_module = pytest.importorskip("sopuli.driver.mysql.session")
scope_module = pytest.importorskip("sopuli.driver.mysql.scope")


class _Cursor:
    def __init__(self, tls: str) -> None:
        self._rows = {
            scope_module.VERSION: ("8.4.13",),
            scope_module.READ_ONLY_SETTINGS: (0, 0, 0),
            scope_module.TLS_VERSION: ("Ssl_version", tls),
        }
        self._last = ""

    def execute(self, query: str, args: Any = None, /) -> None:
        self._last = query

    def fetchone(self) -> Any:
        return self._rows[self._last]


class _Connection:
    def __init__(self, tls: str = "TLSv1.3") -> None:
        self.tls = tls
        self.closed = 0

    @contextmanager
    def cursor(self) -> Iterator[_Cursor]:
        yield _Cursor(self.tls)

    def close(self) -> None:
        self.closed += 1


def _target(mode: str = "VERIFY_IDENTITY") -> ExpandedTarget:
    return ExpandedTarget(
        target=Target(
            name="mysql-dev",
            type="mysql",
            dsn="mysql-dev.example.com:3306",
            mysql=TargetMysql(ssl_mode=mode),
        )
    )


def _session(tls: str = "TLSv1.3") -> Any:
    return session_module.MysqlSession(connection=_Connection(tls), target=_target())


def test_the_session_and_the_driver_satisfy_the_protocol() -> None:
    driver = session_module.build_driver(
        DriverContext(env={}, correlation_id="run", runtime=Runtime())
    )

    assert isinstance(driver, Driver)
    assert isinstance(_session(), Session)


def test_the_scope_is_read_once_and_cached() -> None:
    session = _session()

    first = session.scope()

    assert first.type == "server"
    assert session.scope() is first


@pytest.mark.parametrize(
    "call",
    [
        lambda s: s.describe_user("acme_app@%"),
        lambda s: s.byte_limit(),
        lambda s: s.set_password("acme_app@%", Secret("x")),
        lambda s: s.suspend_account("acme_app@%"),
        lambda s: s.reset_password("acme_app@%", Secret("x"), expire=True),
        lambda s: s.expire_password("acme_app@%"),
        lambda s: s.apply_attributes("acme_app@%", AccountAttributes()),
        lambda s: s.resolve_profile("default"),
        lambda s: s.resolve_role("acme_role"),
        lambda s: s.accounts_matching(role="acme_role"),
        lambda s: s.verify_password("acme_app@%", Secret("x")),
        lambda s: s.require_verifier("acme_app@%", Secret("x")),
        lambda s: s.finish_rollover("acme_app@%"),
    ],
)
def test_what_is_not_written_refuses_with_20006(call: Any) -> None:
    with pytest.raises(DriverError) as caught:
        call(_session())

    assert caught.value.code == DRIVER_NOT_IMPLEMENTED
    assert caught.value.exit_code == ExitCode.CONFIG_INVALID
    assert 'target "mysql-dev" is a MySQL server' in str(caught.value)


def test_a_rollover_is_refused_by_capability_until_it_is_written() -> None:
    with pytest.raises(UnsupportedCapabilityError, match=PASSWORD_ROLLOVER):
        _session().require_rollover("acme_app@%")


def test_audit_coverage_never_raises() -> None:
    assert _session().audit_coverage("acme_app@%").audited is None


def test_the_privilege_audit_says_nothing_was_looked_at() -> None:
    """`doctor --check-privileges` reports and never fails, so an audit not
    written yet is a caveat, not a refusal."""
    audit = _session().privileges()

    assert audit.unaudited == ("every grant of the tool account",)
    assert audit.over_granted == ()
    assert "does not audit" in audit.remedies[0]


def test_close_is_safe_twice() -> None:
    session = _session()
    connection = session.connection

    session.close()
    session.close()

    assert connection.closed == 1


def _scope(method: str) -> Any:
    from sopuli.driver.protocol import Encryption, Scope

    return Scope(type="server", encryption=Encryption(method=method, hint="the hint"))


@pytest.mark.parametrize("mode", ["REQUIRED", "VERIFY_CA", "VERIFY_IDENTITY"])
def test_a_mode_that_requires_tls_refuses_a_session_without_it(mode: str) -> None:
    """Read from the session's scope, so the rule does not rest on PyMySQL alone."""
    with pytest.raises(session_module.UnencryptedSessionError) as caught:
        session_module.require_tls(_scope("none"), _target(mode))

    assert caught.value.category == "connectivity"
    assert caught.value.code == "2026"
    assert f"without TLS under `ssl_mode: {mode}`" in str(caught.value)


def test_a_session_not_known_to_be_tls_is_refused_in_its_own_words() -> None:
    with pytest.raises(session_module.UnencryptedSessionError) as caught:
        session_module.require_tls(_scope("unknown"), _target("REQUIRED"))

    assert "could not confirm TLS" in str(caught.value)
    assert caught.value.hint == "the hint"


@pytest.mark.parametrize("mode", ["DISABLED", "PREFERRED"])
def test_a_mode_that_does_not_require_tls_accepts_any_session(mode: str) -> None:
    session_module.require_tls(_scope("none"), _target(mode))


def test_a_session_with_tls_passes_the_check() -> None:
    session_module.require_tls(_scope("tls"), _target("REQUIRED"))


def test_connect_closes_a_session_it_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    """The scope is read once, at connect, and a refused session is closed."""
    connection = _Connection(tls="")
    monkeypatch.setattr(session_module.pymysql, "connect", lambda **arguments: connection)
    driver = session_module.MysqlDriver(correlation_id="run")

    with pytest.raises(session_module.UnencryptedSessionError):
        driver.connect(_target("REQUIRED"), _credential())

    assert connection.closed == 1


def test_connect_reads_the_scope_once_and_keeps_it(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = _Connection(tls="TLSv1.3")
    monkeypatch.setattr(session_module.pymysql, "connect", lambda **arguments: connection)
    session = session_module.MysqlDriver(correlation_id="run").connect(
        _target("REQUIRED"), _credential()
    )

    assert session._scope is not None
    assert session.scope() is session._scope


def _credential() -> Credential:
    return Credential(username="sopuli_svc", secret=Secret("Tr0ub4dor-and-3"))


def test_pymysqls_failure_of_a_plain_login_is_reported_as_what_it_is(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Measured on 8.4.13: a login the server has not cached fails inside
    PyMySQL 1.2.3 with an AttributeError over a plain connection."""

    def fail(**arguments: Any) -> Any:
        raise AttributeError("'NoneType' object has no attribute 'is_auth_switch_request'")

    monkeypatch.setattr(session_module.pymysql, "connect", fail)
    driver = session_module.MysqlDriver(correlation_id="run")

    with pytest.raises(session_module.PlainLoginError) as caught:
        driver.connect(_target("DISABLED"), _credential())

    assert caught.value.category == "connectivity"
    assert caught.value.code == "2061"
    assert "REQUIRED" in str(caught.value.hint)


@pytest.mark.parametrize("mode", ["DISABLED", "PREFERRED"])
def test_any_other_attribute_error_is_not_hidden(
    monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    """Only PyMySQL's measured failure, by its exact text, is reported as a
    plain-login failure. Anything else is a fault, and surfaces as one."""

    def fail(**arguments: Any) -> Any:
        raise AttributeError("something else")

    monkeypatch.setattr(session_module.pymysql, "connect", fail)
    driver = session_module.MysqlDriver(correlation_id="run")

    with pytest.raises(AttributeError, match="something else"):
        driver.connect(_target(mode), _credential())


def test_a_failed_connect_is_classified_as_a_connect(monkeypatch: pytest.MonkeyPatch) -> None:
    import pymysql

    def fail(**arguments: Any) -> Any:
        raise pymysql.err.OperationalError(1045, "Access denied for user 'sopuli_svc'@'%'")

    monkeypatch.setattr(session_module.pymysql, "connect", fail)
    driver = session_module.MysqlDriver(correlation_id="run")

    with pytest.raises(DriverError) as caught:
        driver.connect(_target(), _credential())

    assert caught.value.code == "1045"
    assert caught.value.exit_code == ExitCode.AUTH_FAILURE
