"""The plan-time checks `creds apply` and `creds rotate` make on a SQL Server
target before any password is drawn (#1551, invariant 4). Tier 0: the session
is a fake, and the helper is the command's own."""

from __future__ import annotations

from typing import Any

import pytest

from sopuli import cli
from sopuli.config.model import ExpandedTarget, Target, TargetMssql
from sopuli.driver.protocol import DriverError, UnsupportedCapabilityError
from sopuli.exit_codes import ExitCode

#: The command's helper, typed loosely: the fakes below stand in for its types.
check: Any = cli._require_value_check

SCOPE = object()


def target(name: str = "mssql-dev", kind: str = "mssql") -> ExpandedTarget:
    return ExpandedTarget(
        target=Target(
            name=name,
            type=kind,
            dsn="127.0.0.1:1433",
            mssql=TargetMssql(encrypt="strict") if kind == "mssql" else None,
        )
    )


class Session:
    def __init__(self, answer: int | Exception) -> None:
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
    opening(
        monkeypatch,
        UnsupportedCapabilityError("strict_encryption", target="mssql-dev", hint="reset"),
    )
    with pytest.raises(UnsupportedCapabilityError) as caught:
        check([target()], None, None, scopes={})
    assert caught.value.capability == "strict_encryption"
    assert caught.value.exit_code == ExitCode.UNSUPPORTED_CAPABILITY


def test_a_value_the_check_refuses_refuses_the_run(monkeypatch: pytest.MonkeyPatch) -> None:
    session = Session(UnsupportedCapabilityError("password_value", target="mssql-dev"))
    opening(monkeypatch, session)
    with pytest.raises(UnsupportedCapabilityError, match="password_value"):
        check([target()], None, None, scopes={})
    assert session.closed


def test_the_plan_names_the_value(monkeypatch: pytest.MonkeyPatch) -> None:
    session = Session(0x0300)
    opening(monkeypatch, session)
    scopes: dict[str, Any] = {}
    (named,) = check([target()], None, None, scopes=scopes)
    assert named.level == "info"
    assert named.target == "mssql-dev"
    assert named.message == (
        'target "mssql-dev" takes a 0x0300 password value (PBKDF2-HMAC-SHA512), '
        "which a change sends"
    )
    # The checks after it share the login.
    assert scopes == {"mssql-dev": SCOPE}
    assert session.closed


def test_an_unreachable_target_is_left_to_the_run(monkeypatch: pytest.MonkeyPatch) -> None:
    opening(monkeypatch, DriverError("no listener"))
    scopes: dict[str, Any] = {}
    assert check([target()], None, None, scopes=scopes) == []
    assert scopes == {"mssql-dev": None}


def test_a_check_that_fails_another_way_is_left_to_the_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Such as a missing grant: the run's row names it."""
    session = Session(DriverError("permission denied"))
    opening(monkeypatch, session)
    assert check([target()], None, None, scopes={}) == []
    assert session.closed


def test_another_product_is_not_opened(monkeypatch: pytest.MonkeyPatch) -> None:
    asked = opening(monkeypatch, Session(0x0200))
    assert check([target("pg-dev", "postgres")], None, None, scopes={}) == []
    assert asked == []
