"""The PostgreSQL session on a scripted connection. Tier 0, with psycopg installed.

Past the scope, the privilege audit and the login that verifies a password,
what this build does is refuse, so the refusals are the behaviour:
``SOPULI-20006`` for an operation not written yet, and an absent capability
named. The audit itself is in ``test_postgres_privileges.py``, and what each
failed login means in ``test_postgres_verification.py``.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Runtime, Target
from sopuli.driver.protocol import (
    PASSWORD_ROLLOVER,
    AccountAttributes,
    Credential,
    Driver,
    DriverContext,
    DriverError,
    Session,
    UnsupportedCapabilityError,
    UserState,
)
from sopuli.driver.registry import DRIVER_NOT_IMPLEMENTED
from sopuli.exit_codes import ExitCode
from sopuli.secrets import Secret

session_module = pytest.importorskip("sopuli.driver.postgres.session")
scope_module = pytest.importorskip("sopuli.driver.postgres.scope")


class _Cursor:
    def __init__(self, recovery: bool) -> None:
        self._rows = {
            scope_module.SESSION_FACTS: ("16.15", recovery, "off", "sopuli_admin", False, None),
            scope_module.SSL_ROW: (False,),
            scope_module.SYSTEM_IDENTIFIER: (7426912345678901234,),
        }
        self._last = ""

    def execute(self, query: str, params: Any = None, /) -> None:
        self._last = query

    def fetchone(self) -> Any:
        return self._rows[self._last]


class _Connection:
    def __init__(self, recovery: bool = False) -> None:
        self.recovery = recovery
        self.closed = 0

    @contextmanager
    def cursor(self) -> Iterator[_Cursor]:
        yield _Cursor(self.recovery)

    def close(self) -> None:
        self.closed += 1


def _session(recovery: bool = False) -> Any:
    target = ExpandedTarget(
        target=Target(name="pg-dev", type="postgresql", dsn="pg-dev.example.com:5432")
    )
    return session_module.PostgresSession(
        connection=_Connection(recovery), target=target, correlation_id="run"
    )


def test_the_session_and_the_driver_satisfy_the_protocol() -> None:
    driver = session_module.build_driver(
        DriverContext(env={}, correlation_id="run", runtime=Runtime())
    )

    assert isinstance(driver, Driver)
    assert isinstance(_session(), Session)


@pytest.mark.parametrize(
    "call",
    [
        lambda s: s.byte_limit(),
        lambda s: s.set_password("acme_app_user", Secret("x")),
        lambda s: s.apply_attributes("acme_app_user", AccountAttributes()),
    ],
)
def test_an_operation_not_written_yet_is_sopuli_20006(call: Any) -> None:
    with pytest.raises(session_module.NotWrittenError) as refused:
        call(_session())

    assert refused.value.code == DRIVER_NOT_IMPLEMENTED
    assert refused.value.exit_code == ExitCode.CONFIG_INVALID
    assert refused.value.category == "config"
    assert 'target "pg-dev" is a PostgreSQL cluster' in refused.value.message
    assert "pip" not in str(refused.value)


def test_a_write_refuses_without_reading_the_scope() -> None:
    """Not written yet is the answer on a standby too, so no round trip."""
    session = _session(recovery=True)

    with pytest.raises(session_module.NotWrittenError):
        session.set_password("acme_app_user", Secret("x"))

    assert session._scope is None


def test_rollover_is_an_absent_capability() -> None:
    with pytest.raises(UnsupportedCapabilityError) as refused:
        _session().require_rollover("acme_app_user")

    assert refused.value.capability == PASSWORD_ROLLOVER
    assert refused.value.exit_code == ExitCode.UNSUPPORTED_CAPABILITY


def test_audit_coverage_answers_unknown_and_never_raises() -> None:
    assert _session().audit_coverage("acme_app_user").audited is None


def test_the_scope_is_probed_once() -> None:
    session = _session()

    assert session.scope() is session.scope()


class _Failing(_Connection):
    """A connection whose first statement raises ``error``."""

    def __init__(self, error: Exception) -> None:
        super().__init__()
        self.error = error

    @contextmanager
    def cursor(self) -> Iterator[_Cursor]:
        raise self.error
        yield _Cursor(False)  # pragma: no cover - makes this a generator


def _failing_session(error: Exception) -> Any:
    session = _session()
    session.connection = _Failing(error)
    return session


@pytest.mark.parametrize(
    ("raised", "code"),
    [
        ("OperationalError", "08006"),
        ("InsufficientPrivilege", "42501"),
    ],
)
@pytest.mark.parametrize("read", [lambda s: s.scope(), lambda s: s.privileges()])
def test_a_failed_read_is_mapped(raised: str, code: str, read: Any) -> None:
    """A lost connection has no SQLSTATE; a server error has its own."""
    import psycopg

    error = getattr(psycopg.errors, raised)("the server's message")

    with pytest.raises(DriverError) as caught:
        read(_failing_session(error))

    assert caught.value.code == code
    assert caught.value.message == f"{code}: the server's message"


def test_a_client_side_error_is_not_read_as_a_lost_connection() -> None:
    """psycopg raised it before sending anything, so it is this tool's fault."""
    import psycopg

    error = psycopg.ProgrammingError("the query has 1 placeholder but 0 parameters were passed")

    with pytest.raises(psycopg.ProgrammingError):
        _failing_session(error).scope()


@pytest.mark.parametrize("read", [lambda s: s.scope(), lambda s: s.privileges()])
def test_a_closed_session_refuses_with_a_message(read: Any) -> None:
    session = _session()
    session.close()

    with pytest.raises(DriverError, match="is closed"):
        read(session)


def test_the_cluster_identity_is_the_system_identifier_as_text() -> None:
    session = _session()

    assert session.cluster_identity() == "7426912345678901234"
    assert session.identity_caveat is None


def test_an_identity_the_site_revoked_is_a_caveat_and_not_an_error() -> None:
    import psycopg

    error = psycopg.errors.InsufficientPrivilege("permission denied for function pg_control_system")
    session = _failing_session(error)

    assert session.cluster_identity() is None
    assert session.identity_caveat == (
        "cannot read system_identifier, so the tool cannot tell whether another target "
        "is the same cluster: 42501: permission denied for function pg_control_system"
    )


def test_any_other_failure_to_read_the_identity_is_raised() -> None:
    import psycopg

    with pytest.raises(DriverError) as caught:
        _failing_session(
            psycopg.OperationalError("server closed the connection")
        ).cluster_identity()

    assert caught.value.code == "08006"


def test_close_is_safe_twice() -> None:
    session = _session()
    connection = session.connection

    session.close()
    session.close()

    assert connection.closed == 1


def test_the_client_report_names_the_libpq_this_process_loaded() -> None:
    import psycopg

    report = session_module.client_report(env={}, runtime=Runtime())

    assert report["psycopg"] == psycopg.__version__
    assert set(report) == {"psycopg", "libpq", "require_auth"}


# --------------------------------------------- verifying a password by login ---


class _Logins:
    """``psycopg.connect`` for the managed role's login: records the arguments,
    and connects or raises what the test says."""

    def __init__(self, raises: Exception | None = None) -> None:
        self.raises = raises
        self.calls: list[dict[str, Any]] = []
        self.closed = 0

    def __call__(self, **arguments: Any) -> Any:
        self.calls.append(arguments)
        if self.raises is not None:
            raise self.raises
        return self

    def close(self) -> None:
        self.closed += 1


@pytest.fixture
def logins(monkeypatch: pytest.MonkeyPatch) -> Any:
    """The login, and a `describe_user` that finds every role but
    `acme_missing_user`, spelled as `pg_roles` would."""

    def described(self: Any, account: str) -> UserState | None:
        if account == "acme_missing_user":
            return None
        return UserState(
            name=account.lower(),
            status="NOLOGIN" if "nologin" in account else "OPEN",
            password_file_member=False,
            vendor_maintained=False,
            locked="nologin" in account,
            expired="expired" in account,
        )

    def install(raises: Exception | None = None, libpq: int = 180004) -> _Logins:
        fake = _Logins(raises)
        monkeypatch.setattr(session_module.psycopg, "connect", fake)
        monkeypatch.setattr(session_module.pq, "version", lambda: libpq)
        monkeypatch.setattr(session_module.PostgresSession, "describe_user", described)
        return fake

    return install


def _failed(message: str) -> Exception:
    import psycopg

    return psycopg.OperationalError(message)


def test_a_password_that_logs_in_passes(logins: Any) -> None:
    fake = logins()
    session = _session()
    session.correlation_id = "run-42"

    result = session.verify_password("acme_app_user", Secret("Correct-Horse-9x"))

    assert (result.method, result.result) == ("login", "pass")
    assert result.failed_logins is None
    assert result.lockout_margin_hit is False
    assert result.detail is None
    assert fake.closed == 1
    (arguments,) = fake.calls
    assert arguments["user"] == "acme_app_user"
    assert arguments["password"] == "Correct-Horse-9x"
    assert arguments["require_auth"] == "scram-sha-256"
    assert arguments["sslmode"] == "verify-full"
    assert arguments["application_name"].endswith("run-42")
    assert "autocommit" not in arguments


def test_a_wrong_password_fails(logins: Any) -> None:
    logins(_failed('FATAL:  password authentication failed for user "acme_app_user"'))

    result = _session().verify_password("acme_app_user", Secret("x"))

    assert result.result == "fail"
    assert "stored verifier is md5" in str(result.detail)


def test_a_missing_role_is_unavailable_and_not_tried(logins: Any) -> None:
    """The server would answer its login as a wrong password, which is drift."""
    fake = logins()

    result = _session().verify_password("acme_missing_user", Secret("x"))

    assert result.result == "unavailable"
    assert 'there is no role "acme_missing_user"' in str(result.detail)
    assert fake.calls == []


@pytest.mark.parametrize(
    ("account", "said"),
    [
        ("acme_nologin_user", "the role cannot log in (NOLOGIN)"),
        ("acme_expired_user", "VALID UNTIL has passed"),
    ],
)
def test_a_role_that_cannot_log_in_is_not_tried(logins: Any, account: str, said: str) -> None:
    """The server answers an expired role's right password as a wrong one
    (measured on 16.15), and NOLOGIN as 28000: neither is worth a login."""
    fake = logins()

    result = _session().verify_password(account, Secret("x"))

    assert result.result == "unavailable"
    assert said in str(result.detail)
    assert fake.calls == []


def test_a_refusal_after_the_password_was_accepted_is_a_pass(logins: Any) -> None:
    logins(
        _failed(
            'FATAL:  permission denied for database "postgres"\n'
            "DETAIL:  User does not have CONNECT privilege."
        )
    )

    result = _session().verify_password("acme_app_user", Secret("x"))

    assert result.result == "pass"
    assert "accepted the password, and then refused the session: 42501" in str(result.detail)


def test_the_login_uses_the_spelling_pg_roles_gives(logins: Any) -> None:
    fake = logins()

    _session().verify_password("ACME_APP_USER", Secret("x"))

    assert fake.calls[0]["user"] == "acme_app_user"


def test_an_unknown_method_is_refused_and_nothing_logs_in(logins: Any) -> None:
    fake = logins()

    with pytest.raises(UnsupportedCapabilityError) as refused:
        _session().verify_password("acme_app_user", Secret("x"), method="bogus")

    assert "verification method 'bogus'" in refused.value.message
    assert fake.calls == []


def test_a_failed_close_after_a_login_still_passes(
    logins: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = logins()

    def close() -> None:
        raise _failed("server closed the connection unexpectedly")

    monkeypatch.setattr(fake, "close", close)

    assert _session().verify_password("acme_app_user", Secret("x")).result == "pass"


def test_no_pg_hba_line_is_unavailable_with_the_hint(logins: Any) -> None:
    logins(_failed('FATAL:  no pg_hba.conf entry for host "192.0.2.10", user "acme_app_user"'))

    result = _session().verify_password("acme_app_user", Secret("x"))

    assert result.result == "unavailable"
    assert "pg_hba.conf line for this role" in str(result.detail)


def test_a_failure_that_is_not_about_the_password_is_raised(logins: Any) -> None:
    logins(_failed("connection timeout expired"))

    with pytest.raises(DriverError) as raised:
        _session().verify_password("acme_app_user", Secret("x"))

    assert raised.value.code == "08001"


def test_a_libpq_that_cannot_require_scram_sends_nothing(logins: Any) -> None:
    fake = logins(libpq=150000)

    with pytest.raises(DriverError) as refused:
        _session().verify_password("acme_app_user", Secret("x"))

    assert "libpq 15.0 cannot require SCRAM" in refused.value.message
    assert fake.calls == []


@pytest.mark.parametrize("method", ["hash", "both"])
def test_a_comparison_is_an_absent_capability(logins: Any, method: str) -> None:
    fake = logins()

    with pytest.raises(UnsupportedCapabilityError) as refused:
        _session().verify_password("acme_app_user", Secret("x"), method=method)

    assert refused.value.capability == "offline_verify"
    assert refused.value.exit_code == ExitCode.UNSUPPORTED_CAPABILITY
    assert "pg_authid" in str(refused.value.hint)
    assert fake.calls == []


def test_require_verifier_refuses_at_plan_time() -> None:
    with pytest.raises(UnsupportedCapabilityError) as refused:
        _session().require_verifier("acme_app_user", Secret("x"))

    assert refused.value.capability == "offline_verify"
    assert 'target "pg-dev"' in refused.value.message


def test_the_driver_gives_its_session_the_runs_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """The managed role's login carries the run's correlation id and timeouts."""
    from sopuli.driver.protocol import Timeouts

    monkeypatch.setattr(session_module.psycopg, "connect", lambda **_: _Connection())
    driver = session_module.PostgresDriver(correlation_id="run-7", timeouts=Timeouts(connect_s=3))

    opened = driver.connect(
        _session().target, Credential(username="sopuli_admin", secret=Secret("x"))
    )

    assert (opened.correlation_id, opened.timeouts.connect_s) == ("run-7", 3)
