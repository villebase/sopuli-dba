"""The reports' use of MariaDB's optional view `sopuli.account_state` (#1491). Tier 0.

The view's own reads are `tests/driver/test_mariadb_account_state.py`'s. Here:
that a broken view is warned about once, as `SOPULI-W073`, and that `report
history` takes MariaDB's date from the view and never from `describe_user`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from sopuli.cli import _database_date, _warn_if_view_broken
from sopuli.config.codes import ACCOUNT_STATE_VIEW_BROKEN
from sopuli.driver.mariadb.account_state import ABSENT, AccountStates
from sopuli.driver.protocol import UserState
from sopuli.output.document import Diagnostic
from sopuli.report_history import AccountHistory

WHEN = datetime(2026, 11, 12, 9, 30, tzinfo=UTC)


class _Document:
    """The part of the run document the warning uses."""

    def __init__(self) -> None:
        self.diagnostics: list[Diagnostic] = []

    def warn_in_text(self, warning: Diagnostic) -> None:
        self.diagnostics.append(warning)


def _run() -> Any:
    return SimpleNamespace(document=_Document())


def _target() -> Any:
    return SimpleNamespace(name="mariadb-dev")


class ViewSession:
    def __init__(self, states: AccountStates, changed: tuple[datetime | None, str | None]):
        self.states = states
        self.changed = changed
        self.asked: list[str] = []

    def view_broken(self) -> str | None:
        return self.states.broken

    def describe_user(self, account: str) -> UserState:
        return UserState(name="acme_app@%", status="OPEN", password_changed_unknown="no date")

    def report_changed_at(self, user: UserState) -> tuple[datetime | None, str | None]:
        self.asked.append(user.name)
        return self.changed


def test_the_mariadb_session_is_a_state_view() -> None:
    from sopuli.driver.mariadb.session import MariadbSession
    from sopuli.driver.survey import StateView

    def typed(session: MariadbSession) -> StateView:
        # mypy checks the signatures here; isinstance only the names.
        return session

    assert typed is not None
    assert issubclass(MariadbSession, StateView)


def test_a_broken_view_is_warned_about() -> None:
    run = _run()
    states = AccountStates(rows=None, reason="x", broken="its definer no longer exists (1045)")
    _warn_if_view_broken(run, _target(), ViewSession(states, (None, None)))
    (warning,) = run.document.diagnostics
    assert warning.code == ACCOUNT_STATE_VIEW_BROKEN
    assert warning.target == "mariadb-dev"
    assert "its definer no longer exists (1045)" in warning.message


def test_an_absent_view_and_another_product_are_not_warned_about() -> None:
    run = _run()
    _warn_if_view_broken(
        run, _target(), ViewSession(AccountStates(rows=None, reason=ABSENT), (None, None))
    )
    _warn_if_view_broken(run, _target(), object())
    assert run.document.diagnostics == []


def test_history_takes_mariadbs_date_from_the_view() -> None:
    session = ViewSession(AccountStates(rows={}), (WHEN, None))
    one = AccountHistory("mariadb-dev", "acme_app@%", "application")
    found = _database_date(one, session)  # type: ignore[arg-type]  # a stub session
    assert (found.db_changed_at, found.db_unknown) == (WHEN, None)
    assert session.asked == ["acme_app@%"]


def test_history_says_why_there_is_no_date() -> None:
    session = ViewSession(AccountStates(rows=None, reason=ABSENT), (None, ABSENT))
    one = AccountHistory("mariadb-dev", "acme_app@%", "application")
    found = _database_date(one, session)  # type: ignore[arg-type]  # a stub session
    assert (found.db_changed_at, found.db_unknown) == (None, ABSENT)
