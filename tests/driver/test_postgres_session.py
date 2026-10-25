"""The PostgreSQL session on a scripted connection. Tier 0, with psycopg installed.

Past the scope and the privilege audit, what this build does is refuse, so the
refusals are the behaviour: ``SOPULI-20006`` for an operation not written yet,
and an absent capability named. The audit itself is in
``test_postgres_privileges.py``.
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
    Driver,
    DriverContext,
    DriverError,
    Session,
    UnsupportedCapabilityError,
)
from sopuli.driver.registry import DRIVER_NOT_IMPLEMENTED
from sopuli.exit_codes import ExitCode
from sopuli.secrets import Secret

session_module = pytest.importorskip("sopuli.driver.postgres.session")
scope_module = pytest.importorskip("sopuli.driver.postgres.scope")


class _Cursor:
    def __init__(self, recovery: bool) -> None:
        self._rows = {
            scope_module.SESSION_FACTS: ("16.15", recovery, "off", "sopuli_admin", False),
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
    return session_module.PostgresSession(connection=_Connection(recovery), target=target)


def test_the_session_and_the_driver_satisfy_the_protocol() -> None:
    driver = session_module.build_driver(
        DriverContext(env={}, correlation_id="run", runtime=Runtime())
    )

    assert isinstance(driver, Driver)
    assert isinstance(_session(), Session)


@pytest.mark.parametrize(
    "call",
    [
        lambda s: s.describe_user("acme_app_user"),
        lambda s: s.byte_limit(),
        lambda s: s.verify_password("acme_app_user", Secret("x")),
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
