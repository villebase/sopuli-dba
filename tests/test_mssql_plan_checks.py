"""The plan-time checks `creds apply` and `creds rotate` make on a SQL Server
target (#1551, invariant 4). Tier 0: the session is a fake, and the helpers
are the command's own."""

from __future__ import annotations

from typing import Any

import pytest

from sopuli import cli
from sopuli.config.model import ExpandedTarget, Target, TargetMssql
from sopuli.driver.protocol import DriverError, UnsupportedCapabilityError
from sopuli.exit_codes import ExitCode

#: The command's helpers, typed loosely: the fakes below stand in for its types.
connection: Any = cli._require_connection
versions: Any = cli._value_versions
plan_scope: Any = cli._plan_scope

SCOPE = object()
RESET = UnsupportedCapabilityError("strict_encryption", target="mssql-dev", hint="reset")


def target(name: str = "mssql-dev", kind: str = "mssql", encrypt: str = "strict") -> ExpandedTarget:
    return ExpandedTarget(
        target=Target(
            name=name,
            type=kind,
            dsn="127.0.0.1:1433",
            mssql=TargetMssql(encrypt=encrypt) if kind == "mssql" else None,
        )
    )


class Session:
    def __init__(self, answer: int | Exception = 0x0300) -> None:
        self.answer = answer
        self.closed = False

    def scope(self) -> object:
        return SCOPE

    def hash_version(self) -> int:
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer

    def close(self) -> None:
        self.closed = True


def opening(monkeypatch: pytest.MonkeyPatch, result: Session | Exception) -> list[str]:
    """``_open_session`` gives ``result``, and the names it was asked for."""
    asked: list[str] = []

    def open_session(expanded: ExpandedTarget, run: Any, config: Any) -> Session:
        asked.append(expanded.name)
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(cli, "_open_session", open_session)
    return asked


def test_a_reset_strict_connection_refuses_the_run(monkeypatch: pytest.MonkeyPatch) -> None:
    """Invariant 4: before any target is changed, not on the target's rows."""
    opening(monkeypatch, RESET)
    with pytest.raises(UnsupportedCapabilityError) as caught:
        connection([target()], None, None, scopes={})
    assert caught.value.capability == "strict_encryption"
    assert caught.value.exit_code == ExitCode.UNSUPPORTED_CAPABILITY


def test_every_plan_check_refuses_a_reset_whatever_its_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`_plan_scope` is what the other checks open a target with."""
    opening(monkeypatch, RESET)
    with pytest.raises(UnsupportedCapabilityError, match="strict_encryption"):
        plan_scope(target(), None, None, {})


def test_the_connection_shares_the_login(monkeypatch: pytest.MonkeyPatch) -> None:
    asked = opening(monkeypatch, Session())
    scopes: dict[str, Any] = {"mssql-dev": SCOPE}
    connection([target()], None, None, scopes=scopes)
    assert asked == []


def test_an_unreachable_target_is_left_to_the_run(monkeypatch: pytest.MonkeyPatch) -> None:
    opening(monkeypatch, DriverError("no listener"))
    scopes: dict[str, Any] = {}
    connection([target()], None, None, scopes=scopes)
    assert scopes == {"mssql-dev": None}


def test_only_a_strict_target_is_opened_for_the_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asked = opening(monkeypatch, Session())
    connection([target(encrypt="mandatory"), target("pg-dev", "postgres")], None, None, scopes={})
    assert asked == []


def test_another_product_gets_no_value_check(monkeypatch: pytest.MonkeyPatch) -> None:
    asked = opening(monkeypatch, Session())
    assert versions([target("pg-dev", "postgres")], None, None) == []
    assert asked == []


def test_the_sql_server_session_answers_the_value_check() -> None:
    """A rename of `hash_version` would silently drop every note."""
    session = pytest.importorskip("sopuli.driver.mssql.session")
    assert issubclass(session.MssqlSession, cli._ValueChecked)


def test_the_dry_run_names_the_value(monkeypatch: pytest.MonkeyPatch) -> None:
    session = Session(0x0200)
    opening(monkeypatch, session)
    (named,) = versions([target()], None, None)
    assert (named.level, named.target) == ("info", "mssql-dev")
    assert named.message == (
        'target "mssql-dev" takes a 0x0200 password value (SHA-512), which a change sends'
    )
    assert session.closed


def test_a_value_the_check_refuses_refuses_the_dry_run(monkeypatch: pytest.MonkeyPatch) -> None:
    session = Session(UnsupportedCapabilityError("password_value", target="mssql-dev"))
    opening(monkeypatch, session)
    with pytest.raises(UnsupportedCapabilityError, match="password_value"):
        versions([target()], None, None)
    assert session.closed


@pytest.mark.parametrize("opens", [True, False])
def test_a_check_that_fails_another_way_says_so(
    monkeypatch: pytest.MonkeyPatch, opens: bool
) -> None:
    """Such as a missing grant, or no listener: a dry run has no rows to say it."""
    failure = DriverError("permission denied")
    session = Session(failure)
    opening(monkeypatch, session if opens else failure)
    (named,) = versions([target()], None, None)
    assert named.level == "info"
    assert named.message.startswith(
        'target "mssql-dev" did not say which password value it takes, and a change '
        "would stop there: permission denied"
    )
    assert session.closed is opens
