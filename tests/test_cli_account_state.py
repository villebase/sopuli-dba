"""The reports' use of MariaDB's optional view `sopuli.account_state` (#1491). Tier 0.

The view's own reads are `tests/driver/test_mariadb_account_state.py`'s. Here:
that a broken view is warned about once, as `SOPULI-W073`, that `report
history` takes MariaDB's date from the view and never from `describe_user`, and
that `account list` takes the lock and the date from it (#1500).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from click.testing import CliRunner

from sopuli.cli import _database_date, _warn_if_view_broken, _with_view_state, cli
from sopuli.config.codes import ACCOUNT_STATE_VIEW_BROKEN
from sopuli.diagnostics import FAILED_LOGIN_BLOCK_UNREAD
from sopuli.driver.mariadb.account_state import ABSENT, NO_ROW, AccountStates, State
from sopuli.driver.protocol import UserState
from sopuli.exit_codes import ExitCode
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


def _target(product: str = "mariadb") -> Any:
    return SimpleNamespace(name=f"{product}-dev", target=SimpleNamespace(type=product))


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

    def report_lock(self, user: UserState) -> UserState:
        return user


def _mariadb(states: AccountStates) -> Any:
    """A MariaDB session with no connection, whose view already gave ``states``."""
    from sopuli.config.model import ExpandedTarget, Target
    from sopuli.driver.mariadb.session import MariadbSession
    from sopuli.driver.protocol import Timeouts

    session = MariadbSession(
        connection=None,
        target=ExpandedTarget(
            target=Target(name="mariadb-dev", type="mariadb", dsn="mariadb-dev.example.com:3306")
        ),
        correlation_id="tier0",
        timeouts=Timeouts(),
    )
    session._account_states = states
    return session


def _state(*, locked: bool) -> State:
    return State(locked=locked, lifetime="unlimited", changed_at=WHEN)


@pytest.mark.parametrize(("expired", "status"), [(False, "LOCKED"), (True, "EXPIRED & LOCKED")])
def test_account_list_shows_the_lock_the_view_gives(expired: bool, status: str) -> None:
    """`describe_user` never reads the lock on MariaDB, so it says `OPEN` or
    `EXPIRED`; `account list` takes the lock from the view (#1491)."""
    session = _mariadb(AccountStates(rows={("acme_dev", "%"): _state(locked=True)}))
    read = UserState(name="acme_dev@%", status="EXPIRED" if expired else "OPEN", expired=expired)
    shown = _with_view_state(session, read)
    assert shown is not None
    # ACCOUNT LOCK's flag, never a failed-login block, which the view does not
    # hold (#1479).
    assert (shown.status, shown.locked, shown.deliberately_locked) == (status, True, True)


MARIADB_CONFIG = """version: 1
targets:
  - name: mariadb-dev
    type: mariadb
    environment: dev
    dsn: mariadb-dev.example.com:3306
    admin: { username: "sopuli_admin@%", auth: { method: env } }
personal_accounts:
  - accounts: ["acme_dev_alice@%", "acme_dev_bob@localhost"]
"""


class ListSession:
    """A MariaDB server for `account list`, whose view gave ``states``. The
    lock and the date are applied by the real
    :meth:`~sopuli.driver.mariadb.session.MariadbSession.report_lock` and
    :meth:`~sopuli.driver.mariadb.session.MariadbSession.report_changed_at`."""

    def __init__(self, states: AccountStates) -> None:
        self.states = states

    def account_states(self) -> AccountStates:
        return self.states

    def view_broken(self) -> str | None:
        return self.states.broken

    def report_changed_at(self, user: UserState) -> tuple[datetime | None, str | None]:
        from sopuli.driver.mariadb.session import MariadbSession

        return MariadbSession.report_changed_at(self, user)  # type: ignore[arg-type]  # a stub

    def report_lock(self, user: UserState) -> UserState:
        from sopuli.driver.mariadb.session import MariadbSession

        return MariadbSession.report_lock(self, user)  # type: ignore[arg-type]  # a stub

    def describe_user(self, account: str) -> UserState:
        return UserState(name=account, status="OPEN")

    def close(self) -> None:
        return None


def _listed(
    write_config: Any, monkeypatch: pytest.MonkeyPatch, states: AccountStates
) -> dict[str, Any]:
    monkeypatch.setattr("sopuli.cli._open_session", lambda target, run, config: ListSession(states))
    monkeypatch.setenv("SOPULI_DB_ADMIN_PASSWORD", "unused")
    config = write_config(MARIADB_CONFIG)
    result = CliRunner().invoke(
        cli, ["--config", str(config), "--output", "json", "account", "list"]
    )
    assert result.exit_code == ExitCode.SUCCESS, result.output
    return dict(json.loads(result.output))


def test_account_list_shows_a_locked_mariadb_account_locked(
    write_config: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    states = AccountStates(rows={("acme_dev_bob", "localhost"): _state(locked=True)})
    document = _listed(write_config, monkeypatch, states)
    shown = {row["account"]: row["account_status"] for row in document["results"]}
    assert shown == {"acme_dev_alice@%": "OPEN", "acme_dev_bob@localhost": "LOCKED"}
    codes = [one["code"] for one in document["diagnostics"]]
    assert ACCOUNT_STATE_VIEW_BROKEN not in codes


def test_account_list_warns_once_that_a_block_after_failed_logins_is_unread(
    write_config: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The view holds `ACCOUNT LOCK`, never a `max_password_errors` block, so
    an `OPEN` account may be blocked: `SOPULI-W063` once for the target, as
    on MySQL (#1500)."""
    states = AccountStates(rows={("acme_dev_bob", "localhost"): _state(locked=True)})
    document = _listed(write_config, monkeypatch, states)
    (block,) = [one for one in document["diagnostics"] if one["code"] == FAILED_LOGIN_BLOCK_UNREAD]
    assert block["target"] == "mariadb-dev"
    assert "MariaDB" in block["message"]
    assert "4150" in block["message"]
    assert "PASSWORD_LOCK_TIME" not in block["message"]


def test_account_list_does_not_warn_of_a_block_where_every_account_is_locked(
    write_config: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    states = AccountStates(
        rows={
            ("acme_dev_alice", "%"): _state(locked=True),
            ("acme_dev_bob", "localhost"): _state(locked=True),
        }
    )
    document = _listed(write_config, monkeypatch, states)
    codes = [one["code"] for one in document["diagnostics"]]
    assert FAILED_LOGIN_BLOCK_UNREAD not in codes


def test_account_list_shows_the_date_the_view_gives(
    write_config: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`DB_PW_CHANGED` comes from the view, as `report history`'s date does,
    so the two commands agree about one account (#1500). An account with no
    row says why."""
    states = AccountStates(rows={("acme_dev_bob", "localhost"): _state(locked=False)})
    document = _listed(write_config, monkeypatch, states)
    unknown = {
        row["account"]: [one["message"] for one in row.get("warnings", [])]
        for row in document["results"]
    }
    assert unknown == {"acme_dev_alice@%": [NO_ROW], "acme_dev_bob@localhost": []}

    text = CliRunner().invoke(
        cli, ["--config", str(write_config(MARIADB_CONFIG)), "account", "list"]
    )
    assert text.exit_code == ExitCode.SUCCESS, text.output
    (bob,) = [line for line in text.output.splitlines() if line.startswith("acme_dev_bob")]
    assert "2026-11-12" in bob


def test_account_list_warns_once_about_a_broken_view(
    write_config: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    states = AccountStates(rows=None, reason="x", broken="its definer no longer exists (1045)")
    document = _listed(write_config, monkeypatch, states)
    shown = {row["account_status"] for row in document["results"]}
    assert shown == {"OPEN"}
    broken = [one for one in document["diagnostics"] if one["code"] == ACCOUNT_STATE_VIEW_BROKEN]
    assert len(broken) == 1
    assert broken[0]["target"] == "mariadb-dev"


@pytest.mark.parametrize(
    "states",
    [
        AccountStates(rows={("acme_dev", "%"): _state(locked=False)}),
        AccountStates(rows={}),
        AccountStates(rows=None, reason=ABSENT),
        AccountStates(rows=None, reason="x", broken="its definer no longer exists (1045)"),
    ],
    ids=["not-locked", "no-row", "absent", "broken"],
)
def test_account_list_keeps_the_status_as_read_where_the_view_does_not_say_locked(
    states: AccountStates,
) -> None:
    read = UserState(name="acme_dev@%", status="OPEN")
    shown = _with_view_state(_mariadb(states), read)
    assert shown is not None
    assert (shown.status, shown.locked, shown.deliberately_locked) == ("OPEN", False, False)


@pytest.mark.parametrize(
    ("states", "date", "why"),
    [
        (AccountStates(rows={("acme_dev", "%"): _state(locked=False)}), WHEN, None),
        (AccountStates(rows={}), None, NO_ROW),
        (AccountStates(rows=None, reason=ABSENT), None, ABSENT),
    ],
    ids=["row", "no-row", "absent"],
)
def test_account_list_takes_the_date_from_the_view(
    states: AccountStates, date: datetime | None, why: str | None
) -> None:
    """Where the view has no time, the reason replaces `describe_user`'s,
    which named no view (#1500)."""
    read = UserState(name="acme_dev@%", status="OPEN", password_changed_unknown="no date")
    shown = _with_view_state(_mariadb(states), read)
    assert shown is not None
    assert (shown.password_changed_at, shown.password_changed_unknown) == (date, why)


def test_account_list_reads_no_view_on_another_product() -> None:
    read = UserState(name="ACME_DEV", status="OPEN")
    assert _with_view_state(object(), read) is read
    assert _with_view_state(object(), None) is None


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


def test_a_broken_mysql_view_is_warned_about_only_once_the_survey_read_it() -> None:
    """MySQL reads the view only in `report accounts`' survey (#1502): before
    that, `report history` and `account list` hear nothing of it."""
    from sopuli.driver.mysql import account_state as mysql_view
    from sopuli.driver.mysql.session import MysqlSession

    session = MysqlSession.__new__(MysqlSession)
    session._account_states = None
    run = _run()
    _warn_if_view_broken(run, _target("mysql"), session)
    assert run.document.diagnostics == []

    session._account_states = mysql_view.AccountStates(
        rows=None, reason="x", broken="its definer cannot read mysql.user (1356)"
    )
    _warn_if_view_broken(run, _target("mysql"), session)
    (warning,) = run.document.diagnostics
    assert warning.code == ACCOUNT_STATE_VIEW_BROKEN
    assert warning.message == (
        "mysql-dev: the optional view sopuli.account_state is not used: its definer cannot "
        "read mysql.user (1356). The failed-login limit and, with @@partial_revokes on, the "
        "global privileges are not checked here. Recreate it "
        "with sql/mysql/account_state_view.sql, which makes it with only the expected "
        "columns, owned by a locked definer that can read mysql.user"
    )


def test_a_product_without_the_view_gets_the_warning_without_the_fix() -> None:
    from sopuli.diagnostics import account_state_view_broken

    warning = account_state_view_broken("pg-dev", "it is broken", product="postgresql")
    assert warning.message == (
        "pg-dev: the optional view sopuli.account_state is not used: it is broken"
    )


def test_the_mysql_session_is_an_optional_view() -> None:
    from sopuli.driver.mysql.session import MysqlSession
    from sopuli.driver.survey import OptionalView, StateView

    def typed(session: MysqlSession) -> OptionalView:
        # mypy checks the signatures here; isinstance only the names.
        return session

    assert typed is not None
    assert issubclass(MysqlSession, OptionalView)
    assert not issubclass(MysqlSession, StateView)


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
