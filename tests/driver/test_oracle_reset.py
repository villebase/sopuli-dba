"""Resetting a personal account's password against a real Oracle (#441). Tier 1.

The statement text is tier 0 (`test_oracle_statements.py`) and so is the
component-wise status parse (`test_oracle_accounts.py`). What only a server can
answer is what the three statements UC-2 §4.1 issues actually *do* to an account,
and the four facts this file exists for are all ones the design turned on:

* an **unseen** reset leaves the account `OPEN` and the old password dead;
* a **seen** reset leaves it `EXPIRED`, and the new password still authenticates
  -- through Oracle's change-at-logon flow rather than by being refused, which is
  the difference between an expired password and a wrong one (§5, `ORA-28001`);
* `LOCKED(TIMED)` is cleared on the way past and a deliberate `LOCKED` is
  refused, which is H4 (#455) and the one place this verb and `account suspend`
  have to agree about what a status means;
* the **rollover window is closed by default**, so the old password stops
  working -- and kept where the caller asks, where it does not. §4.3 decided the
  default the opposite way to UC-1 and this is where that claim meets a database.

The fifth is a refusal rather than a behaviour: an expiring reset of an account
on a rollover profile is refused before any DDL, because #455's Q7 measured that
`PASSWORD EXPIRE` does *not* end the window -- the old password answers
`ORA-28001` rather than `ORA-01017`, so it still authenticates and is itself a
way to set the new one.
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import Iterator
from typing import Any

import pytest

from oracle_harness import Environment
from sopuli.config.model import AdminAuth, AdminCredential, ExpandedTarget, Target
from sopuli.driver.protocol import (
    ACCOUNT_UNLOCK,
    PASSWORD_SET,
    ROLLOVER_FINISH,
    Credential,
    DriverError,
)
from sopuli.secrets import Secret

USER = os.environ.get("SOPULI_TEST_ORACLE_USER", "system")
PASSWORD = os.environ.get("SOPULI_TEST_ORACLE_PASSWORD", "sopuli-test")

CORRELATION_ID = "9c41f0d2-6ab8-4e17-8c53-2f7ab1d0e4c9"

ACCOUNT = "acme_reset_user"

#: `test/oracle-init/01_test_profiles.sql` creates both: a failed-login limit low
#: enough to reach by trying, and a one-hour `PASSWORD_ROLLOVER_TIME`.
LOCKOUT_PROFILE = "sopuli_lockout"
ROLLOVER_PROFILE = "sopuli_rollover"

#: Distinct enough that a logon proving one of them is unambiguous about which.
OLD = "Re5et-Old-Pa55word1"
NEW = Secret("Re5et-New-Pa55word2")


@pytest.fixture
def session_module() -> Any:
    return pytest.importorskip("sopuli.driver.oracle.session")


@pytest.fixture
def session(live_oracle: Environment, session_module: Any) -> Iterator[Any]:
    driver = session_module.OracleDriver(env=os.environ, correlation_id=CORRELATION_ID)
    opened = driver.connect(
        ExpandedTarget(
            target=Target(
                name="tier1-oracle",
                type="oracle",
                dsn=live_oracle.dsn,
                admin=AdminCredential(username=USER, auth=AdminAuth(method="env")),
            ),
            index=0,
        ),
        Credential(username=USER, secret=Secret(PASSWORD)),
    )
    try:
        yield opened
    finally:
        opened.close()


def _run(session: Any, *statements: str) -> None:
    with session.connection.cursor() as cursor:
        for statement in statements:
            cursor.execute(statement)


def _drop(session: Any) -> None:
    with contextlib.suppress(Exception):
        _run(session, f"drop user {ACCOUNT} cascade")


def _create(session: Any, *, profile: str | None = None) -> None:
    _drop(session)
    clause = f" profile {profile}" if profile is not None else ""
    _run(
        session,
        f'create user {ACCOUNT} identified by "{OLD}"{clause}',
        f"grant create session to {ACCOUNT}",
    )


@pytest.fixture
def account(session: Any) -> Iterator[Any]:
    """An ordinary account on `DEFAULT`, which grants no rollover window."""
    _create(session)
    try:
        yield session
    finally:
        _drop(session)


@pytest.fixture
def rollover_account(session: Any) -> Iterator[Any]:
    """An account whose profile grants a one-hour window.

    Skips rather than fails where the release has no such feature: the profile's
    creation is guarded in the init script for 18c and 11g, so an absent profile
    here is the environment rather than a defect (`04-testing.md` §3).
    """
    try:
        _create(session, profile=ROLLOVER_PROFILE)
    except Exception as error:  # noqa: BLE001 -- the skip reason is the message
        pytest.skip(f"{ROLLOVER_PROFILE} is unavailable on this release: {error}")
    try:
        yield session
    finally:
        _drop(session)


def _status(session: Any) -> str:
    state = session.describe_user(ACCOUNT)
    assert state is not None
    return str(state.status)


def _logon(live_oracle: Environment, password: str) -> str:
    """What the server says to a logon with ``password``: ``ok`` or its ORA- code.

    The codes are the answer rather than a pass/fail, because three of them are
    meaningfully different here and only one is a failure: ``ORA-01017`` is a
    dead password, ``ORA-28001`` is a live one whose account is expired -- which
    is Oracle's change flow rather than a refusal (§5) -- and ``ORA-28000`` is a
    lock.
    """
    oracledb = pytest.importorskip("oracledb")
    try:
        oracledb.connect(user=ACCOUNT, password=password, dsn=live_oracle.dsn).close()
    except Exception as error:  # noqa: BLE001 -- the code is what is being asserted
        return str(error).split(":")[0].strip()
    return "ok"


def _by_action(changes: tuple[Any, ...]) -> dict[str, Any]:
    return {change.action: change for change in changes}


# ------------------------------------------------------------- the unseen path ---


def test_an_unseen_reset_sets_the_password_and_leaves_the_account_open(
    account: Any, live_oracle: Environment
) -> None:
    """The default path. Nothing is expired, because nobody but the owner is
    meant to know the value (§1)."""
    changes = account.reset_password(ACCOUNT, NEW, expire=False)

    assert [change.action for change in changes] == [ACCOUNT_UNLOCK, PASSWORD_SET, ROLLOVER_FINISH]
    assert _by_action(changes)[PASSWORD_SET].changed is True
    assert _status(account) == "OPEN"
    assert _logon(live_oracle, NEW.reveal()) == "ok"
    assert _logon(live_oracle, OLD) == "ORA-01017"


def test_every_statement_is_reported_even_where_it_was_not_issued(account: Any) -> None:
    """`apply_attributes`' rule read for a verb: a row per statement the
    operation considered, so an account that was not locked says so rather than
    being absent from the answer."""
    changes = _by_action(account.reset_password(ACCOUNT, NEW, expire=False))

    assert changes[ACCOUNT_UNLOCK].changed is False
    assert "not locked" in (changes[ACCOUNT_UNLOCK].detail or "")
    assert changes[ROLLOVER_FINISH].changed is False
    assert "grants no rollover window" in (changes[ROLLOVER_FINISH].detail or "")


def test_the_status_reported_is_the_one_read_before_anything_was_issued(account: Any) -> None:
    """`AccountChange.status` is the state it found, as it is for `suspend`. A
    row carrying the state afterwards could not say what the reset walked into."""
    changes = account.reset_password(ACCOUNT, NEW, expire=False)

    assert {change.status for change in changes} == {"OPEN"}


# --------------------------------------------------------------- the seen path ---


def test_a_seen_reset_expires_the_account(account: Any, live_oracle: Environment) -> None:
    """§4.1's seen statement, and the thing it buys: the DBA's exposure ends at
    the owner's first logon, because the owner must change it then.

    The new password still **authenticates** -- `ORA-28001` is Oracle's
    change-at-logon flow, not a refusal, which is why §5 says an expired account
    is fixed by the password while a locked one needs the unlock.
    """
    changes = _by_action(account.reset_password(ACCOUNT, NEW, expire=True))

    assert changes[PASSWORD_SET].changed is True
    assert "expired for first logon" in (changes[PASSWORD_SET].detail or "")
    assert _status(account) == "EXPIRED"
    assert _logon(live_oracle, NEW.reveal()) == "ORA-28001"
    assert _logon(live_oracle, OLD) == "ORA-01017"


# ------------------------------------------------------------------ the locks ---


def test_a_timed_lock_is_cleared_on_the_way_past(account: Any, live_oracle: Environment) -> None:
    """H4 (#455): a reset unlocks `LOCKED(TIMED)` by default.

    The account is locked the way an estate reaches it -- by getting the password
    wrong -- and the reset is the whole fix: `IDENTIFIED BY` alone leaves the lock
    exactly as it found it (§4.1), so without statement 1 the owner would have a
    password that works and an account that refuses it.
    """
    _create(account, profile=LOCKOUT_PROFILE)
    for _ in range(3):
        assert _logon(live_oracle, "not-the-password") == "ORA-01017"
    assert _status(account) == "LOCKED(TIMED)"

    changes = _by_action(account.reset_password(ACCOUNT, NEW, expire=False))

    assert changes[ACCOUNT_UNLOCK].changed is True
    assert "locked(timed)" in (changes[ACCOUNT_UNLOCK].detail or "").lower()
    assert _status(account) == "OPEN"
    assert _logon(live_oracle, NEW.reveal()) == "ok"


def test_a_deliberate_lock_is_refused_and_nothing_is_issued(
    account: Any, live_oracle: Environment
) -> None:
    """The other half of H4, and the reason the two verbs share
    `deliberately_locked`: handing a working password to somebody who has been
    offboarded would undo the offboarding silently.

    **Proving that nothing was issued takes an unlock**, and the reason is worth
    keeping: a locked account answers `ORA-28000` to *any* password, so asserting
    that the new one fails while the lock is on would pass whether or not
    statement 2 had run. The account is unlocked afterwards and the **old**
    password is what is asked -- it still working is the only thing that says the
    refusal came before the reset rather than after it.
    """
    _run(account, f"alter user {ACCOUNT} account lock")

    with pytest.raises(DriverError) as caught:
        account.reset_password(ACCOUNT, NEW, expire=False)

    assert "does not unlock it" in str(caught.value)
    assert _status(account) == "LOCKED"

    _run(account, f"alter user {ACCOUNT} account unlock")
    assert _logon(live_oracle, OLD) == "ok", "the password was changed by a refused reset"
    assert _logon(live_oracle, NEW.reveal()) == "ORA-01017"


# -------------------------------------------------------------- the rollover ---


def test_the_rollover_window_is_closed_by_default(
    rollover_account: Any, live_oracle: Environment
) -> None:
    """§4.3's decision, measured: *a reset means the new password is the only one
    that works*.

    Without statement 3 the old password keeps authenticating for the length of
    the window -- an hour, on this profile -- which is the exposure the default
    exists to remove.
    """
    changes = _by_action(rollover_account.reset_password(ACCOUNT, NEW, expire=False))

    assert changes[ROLLOVER_FINISH].changed is True
    assert _status(rollover_account) == "OPEN"
    assert _logon(live_oracle, NEW.reveal()) == "ok"
    assert _logon(live_oracle, OLD) == "ORA-01017"


def test_keeping_the_window_leaves_the_old_password_working(
    rollover_account: Any, live_oracle: Environment
) -> None:
    """The flag §4.3 asks for, and the measurement that makes it meaningful: with
    the window open, **both** passwords authenticate.

    This is the reset for somebody who does still know their old password. §4.3
    states the asymmetry rather than leaving it to be discovered -- a reset after
    a suspected disclosure is exactly the case that must not use it.
    """
    changes = _by_action(
        rollover_account.reset_password(ACCOUNT, NEW, expire=False, keep_rollover=True)
    )

    assert changes[ROLLOVER_FINISH].changed is False
    assert "kept, as asked" in (changes[ROLLOVER_FINISH].detail or "")
    assert "IN ROLLOVER" in _status(rollover_account)
    assert _logon(live_oracle, NEW.reveal()) == "ok"
    assert _logon(live_oracle, OLD) == "ok"


def test_an_expiring_reset_is_refused_on_a_rollover_profile(
    rollover_account: Any, live_oracle: Environment
) -> None:
    """#455's Q7, as a refusal. Expiring does **not** end the window, so the seen
    path would leave a second live password behind it.

    Both entry points refuse, and both are asserted: the plan-time call a verb
    makes before drawing a password, and the reset itself, which asks again
    because that is the last point at which refusing costs nothing.
    """
    with pytest.raises(DriverError) as planned:
        rollover_account.require_no_rollover_window(ACCOUNT)

    with pytest.raises(DriverError) as issued:
        rollover_account.reset_password(ACCOUNT, NEW, expire=True)

    for caught in (planned, issued):
        assert "rollover window" in str(caught.value)
        assert ROLLOVER_PROFILE.upper() in str(caught.value)
    assert _logon(live_oracle, OLD) == "ok", "nothing was issued"


def test_the_plan_time_call_says_nothing_where_no_window_is_granted(account: Any) -> None:
    """The other answer, and the one every ordinary account gets. A refusal that
    fired on `DEFAULT` would make the seen path unreachable everywhere."""
    assert account.require_no_rollover_window(ACCOUNT) is None


# ------------------------------------------------------------------- the rest ---


def test_resetting_an_account_that_does_not_exist_is_an_error(session: Any) -> None:
    """The tool creates nothing (Q8), so a name it cannot find is worth stopping
    for -- and stopping before a password has been delivered anywhere."""
    with pytest.raises(DriverError) as caught:
        session.reset_password("acme_no_such_user", NEW, expire=False)

    assert "does not exist" in str(caught.value)
