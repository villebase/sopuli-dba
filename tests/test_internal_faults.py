"""Errors that are a fault in sopuli report category `internal` and exit 1
(#1640, #1644). Tier 0.

A correct build reaches none of these. Each is what a run says when a check
that should have come first did not, so the category and the exit code must
not send the operator to the config, the store or the database.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from sopuli import cli
from sopuli.config.model import ExpandedTarget, Target
from sopuli.driver.protocol import InternalFaultError, Timeouts
from sopuli.exit_codes import ExitCode


def _is_internal(error: InternalFaultError) -> None:
    assert error.category == "internal"
    assert error.exit_code == ExitCode.FAILURE
    assert "fault in sopuli" in (error.hint or "")


def _target(kind: str) -> ExpandedTarget:
    return ExpandedTarget(target=Target(name=f"{kind}-dev", type=kind, dsn="127.0.0.1:1"))


def _use(session: Any) -> None:
    """One read on ``session``. PostgreSQL's sessions read through
    ``_cursor``, the others through ``_read``."""
    if hasattr(session, "_read"):
        session._read(lambda cursor: None)
        return
    with session._cursor():
        pass


@pytest.mark.parametrize(
    ("kind", "module", "cls"),
    [
        ("postgresql", "sopuli.driver.postgres.session", "PostgresSession"),
        ("mysql", "sopuli.driver.mysql.session", "MysqlSession"),
        ("mariadb", "sopuli.driver.mariadb.session", "MariadbSession"),
        ("mssql", "sopuli.driver.mssql.session", "MssqlSession"),
    ],
)
def test_a_closed_session_used_again_is_an_internal_fault(kind: str, module: str, cls: str) -> None:
    session_module = pytest.importorskip(module)
    session = getattr(session_module, cls)(
        connection=None, target=_target(kind), correlation_id="tier0", timeouts=Timeouts()
    )

    with pytest.raises(InternalFaultError) as caught:
        _use(session)

    _is_internal(caught.value)
    assert f'the session to target "{kind}-dev" is closed' in caught.value.message


def test_a_mariadb_finish_with_no_current_is_an_internal_fault() -> None:
    session_module = pytest.importorskip("sopuli.driver.mariadb.session")
    session = session_module.MariadbSession(
        connection=None, target=_target("mariadb"), correlation_id="tier0", timeouts=Timeouts()
    )

    with pytest.raises(InternalFaultError) as caught:
        session.finish_rollover("acme_app@%", current=None)

    _is_internal(caught.value)
    assert "no current password was passed" in caught.value.message


def test_a_session_that_keeps_flags_without_the_reset_methods_is_an_internal_fault() -> None:
    with pytest.raises(InternalFaultError) as caught:
        cli._flag_keeper(SimpleNamespace(keeps_policy_flags=True))

    _is_internal(caught.value)


def test_a_reset_that_keeps_flags_with_no_record_store_is_an_internal_fault(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli, "_reset_journal", lambda run, config: None)
    keeper: Any = SimpleNamespace(
        reset_policy_flags=lambda account: SimpleNamespace(check_policy=True)
    )

    with pytest.raises(InternalFaultError) as caught:
        cli._flags_for_reset(
            keeper,
            "acme_app",
            run=SimpleNamespace(),  # type: ignore[arg-type]
            config=SimpleNamespace(),  # type: ignore[arg-type]
            target="mssql-dev",
            record_at="sopuli/resets/acme_app",
        )

    _is_internal(caught.value)


def test_a_change_that_keeps_flags_with_no_vault_is_an_internal_fault() -> None:
    binding: Any = SimpleNamespace(target="mssql-dev", secret=None)
    session = SimpleNamespace(policy_flags=lambda account: None)

    with pytest.raises(InternalFaultError) as caught:
        cli._keep_flags(binding, session, "acme_app", None)

    _is_internal(caught.value)


def test_a_onepassword_share_with_no_resolved_token_is_an_internal_fault() -> None:
    run: Any = SimpleNamespace(dry_run=False)
    delivery: Any = SimpleNamespace(is_seen=False, onepassword_share=object())

    with pytest.raises(InternalFaultError) as caught:
        cli._delivery_backends(
            run,
            SimpleNamespace(),  # type: ignore[arg-type]
            delivery,
            [],
            account="acme_dev_alice",
            onepassword_token=None,
        )

    _is_internal(caught.value)
