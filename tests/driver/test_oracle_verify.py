"""Verifying a password against a real Oracle. Tier 1.

The arithmetic is tier 0 (`test_verification.py`). What only a server can answer
is whether the codes mean what this code believes, and whether the guard actually
holds — which is **release gate 4**:

    a profile with FAILED_LOGIN_ATTEMPTS 3, check a deliberately drifted account
    five times, and the account never locks.

`04-testing.md` §5 makes that a gate because a tool that locks production
accounts while checking them is worse than no tool. It is the one test in this
repository whose failure means "do not ship", so it is written to fail loudly
rather than skip quietly: the profile comes from the container init script, and
so does the `SELECT ON SYS.USER$` grant the guard needs.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest

from oracle_harness import Environment
from sopuli.config.model import ExpandedTarget, Target
from sopuli.driver.protocol import (
    FAIL,
    OFFLINE_VERIFY,
    PASS,
    PASSWORD_ROLLOVER,
    SKIPPED,
    UNAVAILABLE,
    DriverError,
    Session,
    UnsupportedCapabilityError,
)
from sopuli.secrets import Secret

CORRELATION_ID = "2f6c8a90-1b47-4e35-8d92-6a0f3c5b7e21"

ACCOUNT = "acme_check_user"
LOCKOUT_PROFILE = "sopuli_lockout"
ROLLOVER_PROFILE = "sopuli_rollover"

CORRECT = "Corr3ct-Pa55-word"
WRONG = "Wr0ng-Pa55-word"


def _run(session: Any, *statements: str) -> None:
    with session.connection.cursor() as cursor:
        for statement in statements:
            cursor.execute(statement)


def _status(session: Any) -> str:
    state = session.describe_user(ACCOUNT)
    assert state is not None
    return str(state.status)


def _drop(session: Any) -> None:
    with contextlib.suppress(Exception):
        _run(session, f"drop user {ACCOUNT} cascade")


@pytest.fixture
def account(session: Any) -> Iterator[Any]:
    """An account on the DEFAULT profile — no lockout to trip over."""
    _drop(session)
    _run(
        session,
        f'create user {ACCOUNT} identified by "{CORRECT}"',
        f"grant create session to {ACCOUNT}",
    )
    try:
        yield session
    finally:
        _drop(session)


@pytest.fixture
def guarded_account(session: Any) -> Iterator[Any]:
    """An account on `SOPULI_LOCKOUT`, which the init script creates with
    `FAILED_LOGIN_ATTEMPTS 3`."""
    _drop(session)
    _run(
        session,
        f'create user {ACCOUNT} identified by "{CORRECT}" profile {LOCKOUT_PROFILE}',
        f"grant create session to {ACCOUNT}",
    )
    try:
        yield session
    finally:
        _drop(session)


# ------------------------------------------------------------- the outcomes ---


def test_the_session_is_a_driver_session(session: Any) -> None:
    """The protocol is structural, so a session is a driver session by having
    every method rather than by declaring anything — and it is worth asserting,
    because a signature drifting out of shape would otherwise be invisible until
    a command was written against the protocol."""
    assert isinstance(session, Session)


def test_the_right_password_passes(account: Any) -> None:
    result = account.verify_password(ACCOUNT, Secret(CORRECT))

    assert result.result == PASS
    assert result.method == "login"


def test_the_wrong_password_is_drift_and_not_an_exception(account: Any) -> None:
    """Exit 3 rather than a crash is what makes `check` schedulable — a wrong
    password is a finding, not a failure of the tool."""
    result = account.verify_password(ACCOUNT, Secret(WRONG))

    assert result.result == FAIL


def test_a_locked_account_is_unverifiable_rather_than_drifted(account: Any) -> None:
    """Measured: a locked account answers `ORA-28000` whether the password is
    right or wrong, so nothing was learned about the password. Calling it drift
    would start a rotation for an account whose password is fine."""
    _run(account, f"alter user {ACCOUNT} account lock")

    result = account.verify_password(ACCOUNT, Secret(CORRECT))

    assert result.result == UNAVAILABLE
    assert result.detail is not None
    assert "locked" in result.detail
    assert "LOCKED" in _status(account), "and the status is reported either way"


def test_an_expired_password_still_passes(account: Any) -> None:
    """The one that reads backwards, against the real server.

    `ORA-28001` comes back only when the password is **correct**; a wrong one
    against the same expired account still answers `ORA-01017`. Both halves are
    asserted, because it is the pair that makes the point.
    """
    _run(account, f"alter user {ACCOUNT} password expire")

    assert account.verify_password(ACCOUNT, Secret(CORRECT)).result == PASS
    assert account.verify_password(ACCOUNT, Secret(WRONG)).result == FAIL


def test_a_missing_account_is_unavailable(session: Any) -> None:
    _drop(session)

    result = session.verify_password(ACCOUNT, Secret(CORRECT))

    assert result.result == UNAVAILABLE
    assert result.detail is not None
    assert "no account" in result.detail


# --------------------------------------------------------- method="hash" ---
#
# Compare with the stored 12C verifier instead of logging in (UC-1 §7).
# Every test here asserts on the *account* as well as on the result, because the
# claim being tested is that nothing happened to it.
#
# Whether the account *has* a 12C verifier is read from the account, never from
# the release (invariant 3): 11g's accounts are `10G 11G`, and a 12.1+ server can
# hold one without `12C` too. The comparison tests skip where it is absent, and
# the refusal test is the one that runs there instead.


def _needs_12c(session: Any) -> None:
    state = session.describe_user(ACCOUNT)
    assert state is not None
    if "12C" not in state.password_versions:
        pytest.skip(
            f"{ACCOUNT} has no 12C verifier here (PASSWORD_VERSIONS "
            f"{' '.join(state.password_versions)}); the refusal test runs instead"
        )


@pytest.mark.requires_capability(OFFLINE_VERIFY)
def test_hash_passes_on_the_right_password_without_a_login(account: Any) -> None:
    _needs_12c(account)
    result = account.verify_password(ACCOUNT, Secret(CORRECT), method="hash")

    assert result.method == "hash"
    assert result.result == PASS
    assert result.detail is not None
    assert "current 12C verifier" in result.detail
    assert "no login attempted" in result.detail


@pytest.mark.requires_capability(OFFLINE_VERIFY)
def test_hash_fails_on_the_wrong_password(account: Any) -> None:
    _needs_12c(account)
    result = account.verify_password(ACCOUNT, Secret(WRONG), method="hash")

    assert result.result == FAIL


@pytest.mark.requires_capability(OFFLINE_VERIFY)
def test_hash_spends_nothing_against_the_lockout_counter(guarded_account: Any) -> None:
    """Release gate 4's scenario, through the method that makes it moot.

    Five wrong comparisons against `FAILED_LOGIN_ATTEMPTS 3`: under `login` the
    second to fifth are refused by the guard; under `hash` all five are answered,
    because none of them costs anything, and `LCOUNT` stays at zero.
    """
    _needs_12c(guarded_account)
    results = [
        guarded_account.verify_password(ACCOUNT, Secret(WRONG), method="hash") for _ in range(5)
    ]

    assert all(r.result == FAIL for r in results), "every one answered, none skipped"
    assert not any(r.lockout_margin_hit for r in results)
    assert results[-1].failed_logins == 0, "no attempt was made, so nothing was counted"
    assert "LOCKED" not in _status(guarded_account)


@pytest.mark.requires_capability(OFFLINE_VERIFY)
def test_hash_compares_a_locked_account(account: Any) -> None:
    """The thing a login cannot do: a locked account answers `ORA-28000` to the
    right password and the wrong one alike. Its lock is still `check`'s to report,
    from the status; the comparison only says whether the vault has its password."""
    _needs_12c(account)
    _run(account, f"alter user {ACCOUNT} account lock")

    assert account.verify_password(ACCOUNT, Secret(CORRECT), method="hash").result == PASS
    assert account.verify_password(ACCOUNT, Secret(WRONG), method="hash").result == FAIL


@pytest.mark.requires_capability(OFFLINE_VERIFY)
def test_hash_on_a_missing_account_is_unavailable(session: Any) -> None:
    _drop(session)

    result = session.verify_password(ACCOUNT, Secret(CORRECT), method="hash")

    assert result.result == UNAVAILABLE


@pytest.mark.requires_capability(OFFLINE_VERIFY)
@pytest.mark.requires_capability(PASSWORD_ROLLOVER)
def test_hash_tells_the_two_passwords_of_a_rollover_window_apart(session: Any) -> None:
    """Both authenticate during a window, so a login cannot say which the vault
    holds. `T:` is the previous password and `t:` the current."""
    _drop(session)
    _run(
        session,
        f'create user {ACCOUNT} identified by "{WRONG}" profile {ROLLOVER_PROFILE}',
        f'alter user {ACCOUNT} identified by "{CORRECT}"',
    )
    try:
        current = session.verify_password(ACCOUNT, Secret(CORRECT), method="hash")
        previous = session.verify_password(ACCOUNT, Secret(WRONG), method="hash")
        neither = session.verify_password(ACCOUNT, Secret("N31ther-Pa55-word"), method="hash")
    finally:
        _drop(session)

    assert current.result == PASS
    assert "current" in (current.detail or "")
    assert previous.result == PASS, "it authenticates until the window closes"
    assert "previous" in (previous.detail or "")
    assert neither.result == FAIL


@pytest.mark.requires_capability(OFFLINE_VERIFY)
def test_hash_refuses_an_account_with_no_12c_verifier(account: Any) -> None:
    """11g, or any account whose PASSWORD_VERSIONS lacks 12C: nothing to compare,
    and `S:` or 10G are never a fallback because both are weaker than a login.
    A refusal naming the target, which is invariant 4's shape."""
    state = account.describe_user(ACCOUNT)
    assert state is not None
    if "12C" in state.password_versions:
        pytest.skip(f"{ACCOUNT} has a 12C verifier here; the comparison tests cover it")

    with pytest.raises(UnsupportedCapabilityError) as refused:
        account.verify_password(ACCOUNT, Secret(CORRECT), method="hash")

    assert refused.value.capability == "verifier_12c", "a name a consumer branches on"
    assert refused.value.target == "tier1-oracle"
    assert ACCOUNT.upper() in (refused.value.hint or ""), "the account is in the hint"


class _Cursor:
    """Answers `CLOUD_SERVICE` and nothing else, which is all a refusal reads."""

    def __init__(self, cloud_service: str | None) -> None:
        self.cloud_service = cloud_service
        self.executed: list[str] = []

    def __enter__(self) -> Any:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def execute(self, statement: str, binds: Any = None) -> None:
        self.executed.append(statement)

    def fetchone(self) -> Any:
        return (self.cloud_service,)


class _Connection:
    def __init__(self, cloud_service: str | None = None) -> None:
        self.opened = _Cursor(cloud_service)

    def cursor(self) -> _Cursor:
        return self.opened


def _offline_session(
    session_module: Any,
    capabilities: frozenset[str],
    *,
    cloud_service: str | None = None,
    scope_type: str = "pdb",
) -> Any:
    """A session with a scope and no server behind it. The refusals below happen
    before anything but `CLOUD_SERVICE` would be asked."""
    from sopuli.driver.protocol import Scope

    offline = session_module.OracleSession(
        connection=_Connection(cloud_service),
        target=ExpandedTarget(
            target=Target(name="orders-pdb", type="oracle", dsn="db.example.com:1521/orders"),
            index=0,
        ),
        correlation_id=CORRELATION_ID,
    )
    offline._scope = Scope(type=scope_type, capabilities=capabilities)
    return offline


@pytest.mark.parametrize("method", ["hash", "both"])
def test_hash_without_the_sys_user_grant_is_refused_naming_the_target(
    session_module: Any, method: str
) -> None:
    """The branch every live test above skips: without `SELECT ON SYS.USER$`
    there is no verifier to read, and `login` is not substituted for it --
    `both` included, which would otherwise have a login half to fall back on."""
    offline = _offline_session(session_module, frozenset())

    with pytest.raises(UnsupportedCapabilityError) as refused:
        offline.verify_password(ACCOUNT, Secret(CORRECT), method=method)

    assert refused.value.capability == OFFLINE_VERIFY
    assert refused.value.target == "orders-pdb"
    assert "GRANT SELECT ON SYS.USER$" in (refused.value.hint or "")


def test_on_autonomous_database_the_refusal_does_not_advise_a_grant(
    session_module: Any,
) -> None:
    """UC-1 §7: on ADB no account can read `SYS.USER$`, `ADMIN`
    included, so "grant it" is advice nobody there can follow.
    `CLOUD_SERVICE` read `OLTP` on ADB serverless 23.26.3.3.0, and it is what tells
    the two apart: the capability probe gets `ORA-00942` from both."""
    offline = _offline_session(session_module, frozenset(), cloud_service="OLTP")

    with pytest.raises(UnsupportedCapabilityError) as refused:
        offline.require_verifier(ACCOUNT, Secret(CORRECT))

    hint = refused.value.hint or ""
    assert refused.value.target == "orders-pdb"
    assert "Autonomous Database (OLTP)" in hint
    assert "GRANT" not in hint
    assert "cloud_service" in offline.connection.opened.executed[0]


def test_hash_of_a_password_the_character_set_cannot_hold_is_refused(
    session_module: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The WE8DEC case at the session: a refusal naming the target and the
    set, rather than a `fail` that would report drift on a password that logs in.
    No live database in the stack has a non-Unicode set but 12.2's, which is
    maintainer-only, so the dictionary reads are stubbed."""
    from sopuli.driver.protocol import UserState
    from sopuli.passwords import ByteLimit

    offline = _offline_session(session_module, frozenset({OFFLINE_VERIFY}))
    offline._limit = ByteLimit(max_bytes=30, encoding="ascii", charset="WE8DEC")

    monkeypatch.setattr(
        session_module,
        "login_state",
        lambda _cursor, _account: UserState(name="ACME_CHECK_USER", status="OPEN"),
    )
    monkeypatch.setattr(session_module, "failed_logins", lambda _cursor, _name: 0)
    spare4 = "S:" + "0" * 60 + ";T:" + "A" * 160
    monkeypatch.setattr(session_module, "stored_verifiers", lambda _cursor, _name: spare4)

    with pytest.raises(UnsupportedCapabilityError) as refused:
        offline.verify_password(ACCOUNT, Secret("Corr3ct-Pa55-wΩrd"), method="hash")

    assert refused.value.capability == "verifier_charset"
    assert refused.value.target == "orders-pdb"
    assert "WE8DEC" in (refused.value.hint or "")
    assert "Ω" not in str(refused.value) + (refused.value.hint or "")


COMMON_ACCOUNT = "C##ACME_CHECK_USER"
IN_ROOT = (
    f"{COMMON_ACCOUNT} is a common account, and its failed logins are counted in "
    "CDB$ROOT, which this session cannot read"
)
UNGUARDED_IN_ROOT = f"the lockout guard is unavailable: {IN_ROOT}"


@dataclass
class _Dictionary:
    """What the stubbed dictionary was asked."""

    lcount: list[str] = field(default_factory=list)
    common: list[str] = field(default_factory=list)


def _stub_account(
    session_module: Any,
    offline: Any,
    monkeypatch: pytest.MonkeyPatch,
    *,
    name: str = COMMON_ACCOUNT,
    common: bool = True,
    status: str = "OPEN",
) -> _Dictionary:
    """An account with a limit of 3, `DBA_USERS.COMMON` as given, a login that
    passes, and a record of every read. The tier-1 stack holds no common
    account for the service account to check, so the dictionary is stubbed."""
    from sopuli.driver.protocol import UserState

    asked = _Dictionary()

    def counted(_cursor: Any, account: str) -> int:
        asked.lcount.append(account)
        return 0

    def is_common(_cursor: Any, account: str) -> bool:
        asked.common.append(account)
        return common

    monkeypatch.setattr(
        session_module,
        "login_state",
        lambda _cursor, _account: UserState(
            name=name, status=status, locked="LOCKED" in status, failed_login_limit="3"
        ),
    )
    monkeypatch.setattr(session_module, "failed_logins", counted)
    monkeypatch.setattr(session_module, "is_common", is_common)
    monkeypatch.setattr(offline, "_attempt", lambda _name, _secret: (PASS, None, None))
    return asked


def test_a_common_account_in_a_pdb_has_no_lockout_guard(
    session_module: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#1122: a common account's failed logins are counted in `CDB$ROOT`, and it
    locks on the limit of its profile there. In a PDB, `LCOUNT` reads 0 and the
    profile may not be the one that applies (`17_common_lcount_probe.sql`). So
    neither is read or reported, and the row says why, even where the grant is
    held."""
    offline = _offline_session(session_module, frozenset({OFFLINE_VERIFY}))
    asked = _stub_account(session_module, offline, monkeypatch)

    result = offline.verify_password(COMMON_ACCOUNT, Secret(CORRECT), method="login")

    assert result.result == PASS, "the login still runs"
    assert asked.lcount == [], "LCOUNT is not read in the wrong container"
    assert asked.common == [COMMON_ACCOUNT], "DBA_USERS.COMMON decides, not the name"
    assert result.failed_logins is None
    assert result.failed_login_limit is None
    assert result.detail == UNGUARDED_IN_ROOT


def test_the_dictionary_decides_for_a_name_without_the_prefix(
    session_module: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`COMMON_USER_PREFIX` can be changed, so a common account need not be
    spelled `C##`. `DBA_USERS.COMMON` says it is one."""
    offline = _offline_session(session_module, frozenset({OFFLINE_VERIFY}))
    asked = _stub_account(session_module, offline, monkeypatch, name="ACME_SHARED_USER")

    result = offline.verify_password("acme_shared_user", Secret(CORRECT), method="login")

    assert asked.lcount == []
    assert result.detail == (
        "the lockout guard is unavailable: ACME_SHARED_USER is a common account, "
        "and its failed logins are counted in CDB$ROOT, which this session cannot read"
    )


def test_a_local_account_in_a_pdb_keeps_its_guard(
    session_module: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    offline = _offline_session(session_module, frozenset({OFFLINE_VERIFY}))
    asked = _stub_account(
        session_module, offline, monkeypatch, name="ACME_CHECK_USER", common=False
    )

    result = offline.verify_password(ACCOUNT, Secret(CORRECT), method="login")

    assert asked.lcount == ["ACME_CHECK_USER"]
    assert result.failed_logins == 0
    assert result.failed_login_limit == "3"
    assert result.detail is None


@pytest.mark.parametrize("scope_type", ["app_pdb", "app_root"])
def test_an_application_common_account_has_no_lockout_guard(
    session_module: Any, monkeypatch: pytest.MonkeyPatch, scope_type: str
) -> None:
    """Where an application container counts a common account's failed logins
    was not measured, so the guard does not claim to read the right count."""
    offline = _offline_session(session_module, frozenset({OFFLINE_VERIFY}), scope_type=scope_type)
    asked = _stub_account(session_module, offline, monkeypatch, name="ACME_APP_USER")

    result = offline.verify_password("acme_app_user", Secret(CORRECT), method="login")

    assert asked.lcount == []
    assert result.failed_logins is None
    assert result.detail == (
        "the lockout guard is unavailable: ACME_APP_USER is a common account, and "
        "where an application container counts its failed logins has not been measured"
    )


def test_in_an_unknown_scope_the_prefix_decides_and_the_row_says_so(
    session_module: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unresolved scope may be a release with no `COMMON` column, so it is
    not asked. The row does not claim the session is outside the root."""
    offline = _offline_session(session_module, frozenset({OFFLINE_VERIFY}), scope_type="unknown")
    asked = _stub_account(session_module, offline, monkeypatch)

    result = offline.verify_password(COMMON_ACCOUNT, Secret(CORRECT), method="login")

    assert asked.common == []
    assert asked.lcount == []
    assert result.detail == (
        f"the lockout guard is unavailable: {COMMON_ACCOUNT} is a common account, and "
        "this session's container was not resolved, so its failed logins may be counted "
        "in CDB$ROOT"
    )


@pytest.mark.parametrize("scope_type", ["cdb_root", "non_cdb"])
def test_in_the_root_or_a_non_cdb_the_guard_runs(
    session_module: Any, monkeypatch: pytest.MonkeyPatch, scope_type: str
) -> None:
    """In `CDB$ROOT` the count and the profile are the account's own, and a
    non-CDB has one container. Neither asks `DBA_USERS.COMMON`."""
    offline = _offline_session(session_module, frozenset({OFFLINE_VERIFY}), scope_type=scope_type)
    asked = _stub_account(session_module, offline, monkeypatch)

    result = offline.verify_password(COMMON_ACCOUNT, Secret(CORRECT), method="login")

    assert asked.common == []
    assert asked.lcount == [COMMON_ACCOUNT]
    assert result.failed_logins == 0
    assert result.failed_login_limit == "3"
    assert result.detail is None


def test_an_unread_common_column_is_a_gap_and_not_a_local_account(
    session_module: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A read of `DBA_USERS.COMMON` that does not answer must not give the
    account a guard that counts the wrong container."""
    offline = _offline_session(session_module, frozenset({OFFLINE_VERIFY}))
    asked = _stub_account(session_module, offline, monkeypatch)
    monkeypatch.setattr(session_module, "is_common", lambda _cursor, _name: None)

    result = offline.verify_password(COMMON_ACCOUNT, Secret(CORRECT), method="login")

    assert asked.lcount == []
    assert result.failed_logins is None
    assert result.detail == (
        f"the lockout guard is unavailable: whether {COMMON_ACCOUNT} is a common account "
        "could not be read from DBA_USERS, so its failed logins may be counted in CDB$ROOT"
    )


class _CommonCursor:
    """Answers `COMMON_QUERY` with one row, no row, or an error."""

    def __init__(self, answer: Any) -> None:
        self.answer = answer
        self.asked: list[tuple[str, Any]] = []

    def execute(self, statement: str, binds: Any = None) -> None:
        self.asked.append((statement, binds))
        if isinstance(self.answer, Exception):
            raise self.answer

    def fetchone(self) -> Any:
        return self.answer

    def fetchall(self) -> list[Any]:
        return [] if self.answer is None else [self.answer]


@pytest.mark.parametrize(
    ("answer", "expected"),
    [
        (("YES",), True),
        (("NO",), False),
        ((None,), False),
        (None, None),
        (RuntimeError("ORA-00942: table or view does not exist"), None),
        (RuntimeError("ORA-00904: invalid identifier"), None),
    ],
    ids=["yes", "no", "null", "no-row", "ORA-00942", "ORA-00904"],
)
def test_is_common_reads_the_column_and_fails_closed(answer: Any, expected: bool | None) -> None:
    """The real read, which every test above stubs. No row and any error are
    `None`, which the guard reports as a gap, never `False`."""
    from sopuli.driver.oracle.accounts import COMMON_QUERY, is_common

    cursor = _CommonCursor(answer)

    assert is_common(cursor, COMMON_ACCOUNT) is expected
    assert cursor.asked == [(COMMON_QUERY, {"name": COMMON_ACCOUNT})], "the name is bound unchanged"


def test_the_scope_sets_name_only_real_scopes(session_module: Any) -> None:
    """A misspelt scope would never match, and the account would fall to the
    PDB branch without a sign."""
    from sopuli.driver.protocol import SCOPE_TYPES

    assert session_module.OWN_COUNT_SCOPES.issubset(SCOPE_TYPES)
    assert session_module.APPLICATION_SCOPES.issubset(SCOPE_TYPES)


def test_a_common_account_without_the_grant_is_told_the_container_reason(
    session_module: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Granting `SELECT ON SYS.USER$` would not give a common account its guard
    in a PDB, so the row gives the container as the reason, not the grant."""
    offline = _offline_session(session_module, frozenset())
    _stub_account(session_module, offline, monkeypatch)

    result = offline.verify_password(COMMON_ACCOUNT, Secret(CORRECT), method="login")

    assert result.detail == UNGUARDED_IN_ROOT


def test_a_locked_common_account_says_why_its_counter_is_missing(
    session_module: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A lock made in the PDB shows there. The row's null counter then needs
    its reason as much as a login's does."""
    offline = _offline_session(session_module, frozenset({OFFLINE_VERIFY}))
    _stub_account(session_module, offline, monkeypatch, status="LOCKED")

    result = offline.verify_password(COMMON_ACCOUNT, Secret(CORRECT), method="login")

    assert result.result == UNAVAILABLE
    assert result.detail == (
        f"the account is locked (LOCKED); no login was attempted; {UNGUARDED_IN_ROOT}"
    )


def _stub_comparison(
    session_module: Any, offline: Any, monkeypatch: pytest.MonkeyPatch, answer: str
) -> None:
    from sopuli.passwords import ByteLimit

    offline._limit = ByteLimit(max_bytes=128, encoding="utf-8", charset="AL32UTF8")
    monkeypatch.setattr(session_module, "stored_verifiers", lambda _cursor, _name: "T:")
    monkeypatch.setattr(session_module, "compare", lambda *_a, **_k: answer)


@pytest.mark.parametrize("method", ["hash", "both"])
def test_hash_refuses_a_common_account_in_a_pdb_naming_the_container(
    session_module: Any, monkeypatch: pytest.MonkeyPatch, method: str
) -> None:
    """#1126: in a PDB a common account's `SPARE4` is `S:` and `T:` followed by
    blanks, and its verifiers are held in `CDB$ROOT`
    (`18_common_spare4_probe.sql`). The refusal names the container, not the
    format, and nothing is read or compared."""
    offline = _offline_session(session_module, frozenset({OFFLINE_VERIFY}))
    asked = _stub_account(session_module, offline, monkeypatch)
    read: list[str] = []
    monkeypatch.setattr(session_module, "stored_verifiers", lambda _cursor, name: read.append(name))

    with pytest.raises(UnsupportedCapabilityError) as refused:
        offline.verify_password(COMMON_ACCOUNT, Secret(CORRECT), method=method)

    assert refused.value.capability == session_module.VERIFIER_CONTAINER
    assert refused.value.target == "orders-pdb"
    assert refused.value.hint == (
        f"{COMMON_ACCOUNT} is a common account, and its verifiers are held in "
        "CDB$ROOT; this container holds a blank placeholder in their place; check "
        "the account on a target that connects to CDB$ROOT, or verify by `login`, "
        "which has no lockout guard for this account here"
    )
    assert asked.common == [COMMON_ACCOUNT], "DBA_USERS.COMMON decides, not the name"
    assert read == []
    assert asked.lcount == []


def test_the_plan_time_check_makes_the_same_refusal(
    session_module: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`require_verifier` is what `creds check` asks every target before it
    checks any account (invariant 4)."""
    offline = _offline_session(session_module, frozenset({OFFLINE_VERIFY}))
    _stub_account(session_module, offline, monkeypatch)

    with pytest.raises(UnsupportedCapabilityError) as refused:
        offline.require_verifier(COMMON_ACCOUNT, Secret(CORRECT))

    assert refused.value.capability == session_module.VERIFIER_CONTAINER


UNGUARDED_LOGIN = "verify by `login`, which has no lockout guard for this account here"
IN_ROOT_REMEDY = f"check the account on a target that connects to CDB$ROOT, or {UNGUARDED_LOGIN}"


@pytest.mark.parametrize(
    ("scope_type", "common", "reason", "remedy"),
    [
        (
            "app_pdb",
            True,
            f"{COMMON_ACCOUNT} is a common account, and where an application container "
            "holds its verifiers has not been measured",
            UNGUARDED_LOGIN,
        ),
        (
            "pdb",
            None,
            f"whether {COMMON_ACCOUNT} is a common account could not be read from "
            "DBA_USERS, so its verifiers may be held in CDB$ROOT",
            UNGUARDED_LOGIN,
        ),
    ],
)
def test_hash_refuses_where_the_container_cannot_be_shown_to_hold_the_verifiers(
    session_module: Any,
    monkeypatch: pytest.MonkeyPatch,
    scope_type: str,
    common: bool | None,
    reason: str,
    remedy: str,
) -> None:
    """An application container was not measured, and a `COMMON` read that does
    not answer is never *not common*: the same rules as the lockout guard's.
    Neither offers `CDB$ROOT`, which may not be where the verifiers are."""
    offline = _offline_session(session_module, frozenset({OFFLINE_VERIFY}), scope_type=scope_type)
    _stub_account(session_module, offline, monkeypatch)
    monkeypatch.setattr(session_module, "is_common", lambda _cursor, _name: common)

    with pytest.raises(UnsupportedCapabilityError) as refused:
        offline.verify_password(COMMON_ACCOUNT, Secret(CORRECT), method="hash")

    assert refused.value.capability == session_module.VERIFIER_CONTAINER
    assert refused.value.hint == f"{reason}; {remedy}"


def test_hash_refuses_a_common_name_where_the_container_is_unresolved(
    session_module: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unresolved scope is not assumed to be the root, and the `C##` prefix
    decides, because the dictionary there may have no `COMMON` column."""
    offline = _offline_session(session_module, frozenset({OFFLINE_VERIFY}), scope_type="unknown")
    asked = _stub_account(session_module, offline, monkeypatch)

    with pytest.raises(UnsupportedCapabilityError) as refused:
        offline.verify_password(COMMON_ACCOUNT, Secret(CORRECT), method="hash")

    assert refused.value.capability == session_module.VERIFIER_CONTAINER
    assert refused.value.hint == (
        f"{COMMON_ACCOUNT} is a common account, and this session's container was "
        f"not resolved, so its verifiers may be held in CDB$ROOT; {IN_ROOT_REMEDY}"
    )
    assert asked.common == []


@pytest.mark.parametrize("method", ["hash", "both"])
@pytest.mark.parametrize(
    ("scope_type", "name", "common"),
    [
        ("cdb_root", COMMON_ACCOUNT, True),
        ("non_cdb", COMMON_ACCOUNT, True),
        ("pdb", COMMON_ACCOUNT, False),
        ("app_pdb", COMMON_ACCOUNT, False),
        ("unknown", "ACME_CHECK_USER", False),
    ],
)
def test_hash_compares_where_the_container_holds_the_verifiers(
    session_module: Any,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    scope_type: str,
    name: str,
    common: bool,
) -> None:
    """In `CDB$ROOT` and a non-CDB every account's row is its own, and so is a
    local account's in a PDB or an application PDB, and a name without the
    `C##` prefix where the container is unresolved. The comparison runs, and
    the guard's figures are the account's."""
    offline = _offline_session(session_module, frozenset({OFFLINE_VERIFY}), scope_type=scope_type)
    asked = _stub_account(session_module, offline, monkeypatch, name=name, common=common)
    _stub_comparison(session_module, offline, monkeypatch, session_module.NO_MATCH)

    result = offline.verify_password(name, Secret(CORRECT), method=method)

    assert result.method == method
    assert result.result == FAIL
    assert asked.lcount == [name]
    assert result.failed_logins == 0
    assert result.failed_login_limit == "3"


@pytest.mark.requires_capability(OFFLINE_VERIFY)
def test_both_compares_and_then_logs_in(guarded_account: Any) -> None:
    """The strongest answer: the verifier matches, and the account can log in."""
    _needs_12c(guarded_account)

    result = guarded_account.verify_password(ACCOUNT, Secret(CORRECT), method="both")

    assert result.method == "both"
    assert result.result == PASS
    assert "matches the account's 12C verifier" in (result.detail or "")


@pytest.mark.requires_capability(OFFLINE_VERIFY)
def test_both_does_not_spend_a_login_the_comparison_already_answered(
    guarded_account: Any,
) -> None:
    """UC-1 §7: a mismatch is `fail` from the comparison alone.
    Five of them against `FAILED_LOGIN_ATTEMPTS 3` leave the counter at zero,
    which a login half would not."""
    _needs_12c(guarded_account)

    results = [
        guarded_account.verify_password(ACCOUNT, Secret(WRONG), method="both") for _ in range(5)
    ]

    assert all(r.result == FAIL for r in results)
    assert all(r.method == "both" for r in results)
    assert "the login half was not spent" in (results[-1].detail or "")
    assert results[-1].failed_logins == 0
    assert "LOCKED" not in _status(guarded_account)


@pytest.mark.requires_capability(OFFLINE_VERIFY)
def test_require_verifier_says_nothing_where_the_comparison_can_run(account: Any) -> None:
    """The plan-time half. Silent here, and raising on 11g, where the refusal
    test above runs instead."""
    _needs_12c(account)

    assert account.require_verifier(ACCOUNT, Secret(WRONG)) is None


def test_require_verifier_passes_over_a_missing_account(session: Any) -> None:
    """`ACCOUNT_MISSING` is a per-account state the run reports; refusing the
    whole estate over one would turn the finding into a failure."""
    _drop(session)

    if OFFLINE_VERIFY not in session.scope().capabilities:
        pytest.skip("no SYS.USER$ read here, so the capability refusal comes first")
    assert session.require_verifier(ACCOUNT, Secret(CORRECT)) is None


# ---------------------------------------------------------- release gate 4 ---


def test_release_gate_4_checking_a_drifted_account_never_locks_it(
    guarded_account: Any, oracle_target: Environment
) -> None:
    """**The gate.** `04-testing.md` §5, and §6's rule that a gate does not skip.

    `FAILED_LOGIN_ATTEMPTS 3`, a password that is wrong, and five checks. Without
    the guard the account locks on the third; with it, exactly one attempt is
    spent and the remaining four are refused before they reach the server.

    The assertion is on the *account*, not on the tool: whatever the results say,
    `ACCOUNT_STATUS` must never contain `LOCKED`. That is the property that
    matters at 03:00 on a production estate.

    **No `requires_capability` marker, deliberately.** §6 opens with "not tests
    that can be skipped", and routing this through the generic capability gate
    would mean a missing `SELECT ON SYS.USER$` grant reports a tidy skip while
    the safety property goes unverified — a broken setup looking green, which is
    the one outcome a release gate must not have. So the guard's absence fails
    here, with a message saying what to grant.
    """
    if OFFLINE_VERIFY not in oracle_target.capabilities:
        pytest.fail(
            "release gate 4 cannot run without the LCOUNT guard, and a gate does not skip "
            "(04-testing.md §6). Grant SELECT ON SYS.USER$ to the test account -- "
            "test/oracle-init/01_test_profiles.sql does it, and it needs CONTAINER=ALL "
            "because the init script runs in CDB$ROOT while the suite connects to a PDB"
        )

    results = [guarded_account.verify_password(ACCOUNT, Secret(WRONG)) for _ in range(5)]

    assert "LOCKED" not in _status(guarded_account), (
        "the guard failed and the account is locked — this is the release gate"
    )

    assert results[0].result == FAIL, "the first attempt is spent, and it is drift"
    assert all(r.result == SKIPPED for r in results[1:]), "the rest are refused, not attempted"
    assert all(r.lockout_margin_hit for r in results[1:])
    assert results[1].detail is not None
    assert "margin" in results[1].detail


@pytest.mark.requires_capability(OFFLINE_VERIFY)
def test_the_guard_does_not_make_an_exception_for_a_password_it_cannot_know_is_right(
    guarded_account: Any,
) -> None:
    """The guard is **sticky**, and that is a real operational property.

    Once the margin is breached, *every* further attempt is refused — including
    one carrying the correct password. It has to be: the guard cannot know the
    password is right without spending an attempt to find out, and spending the
    last of the margin on a guess is exactly what it exists to prevent.

    The consequence, on a profile as tight as this one (`FAILED_LOGIN_ATTEMPTS
    3`, default margin 2), is that a single drift makes the account
    unverifiable by this tool until something *else* clears `LCOUNT` — the
    application logging in successfully, or an operator widening the margin
    deliberately. `check` reports `skipped` with the reason rather than a
    verdict, which is the honest answer and not a failure.

    Written down here because it surfaced as a failing test that looked like a
    bug and is not one.
    """
    assert guarded_account.verify_password(ACCOUNT, Secret(WRONG)).result == FAIL

    blocked = guarded_account.verify_password(ACCOUNT, Secret(CORRECT))

    assert blocked.result == SKIPPED, "the right password is refused too"
    assert blocked.lockout_margin_hit


@pytest.mark.requires_capability(OFFLINE_VERIFY)
def test_a_successful_check_clears_the_counter(guarded_account: Any) -> None:
    """Mitigation 3, and it is the database's doing rather than ours.

    Reaching the success at all needs the margin widened, which is the test
    above's finding turned into a fixture: `lockout_margin=0` spends the
    remaining budget deliberately, the login succeeds, and Oracle puts `LCOUNT`
    back to zero — after which an ordinary check is allowed again with no
    special pleading.
    """
    assert guarded_account.verify_password(ACCOUNT, Secret(WRONG)).result == FAIL
    assert guarded_account.verify_password(ACCOUNT, Secret(WRONG)).result == SKIPPED

    recovered = guarded_account.verify_password(ACCOUNT, Secret(CORRECT), lockout_margin=0)
    assert recovered.result == PASS

    again = guarded_account.verify_password(ACCOUNT, Secret(WRONG))
    assert again.result == FAIL, "the counter was reset, so there is budget again"


@pytest.mark.requires_capability(OFFLINE_VERIFY)
def test_the_counter_is_reported_with_the_result(guarded_account: Any) -> None:
    """`failed_logins` and `failed_login_limit` travel with the answer, so a
    report can show how close the account is without a second query."""
    guarded_account.verify_password(ACCOUNT, Secret(WRONG))
    result = guarded_account.verify_password(ACCOUNT, Secret(WRONG))

    assert result.failed_logins == 1
    assert result.failed_login_limit == "3"


# ------------------------------------------- the client, but no server ------


def test_an_unreachable_target_raises_rather_than_reporting_a_finding(
    account: Any, session_module: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A target nobody can reach is not an account whose password failed.

    Driven by making the *verification* connection fail while the admin session
    stays up, which is the shape that matters: `_attempt` opens its own
    connection, and a listener that has gone away between the two is exactly how
    this arises in an estate.
    """
    import oracledb

    def unreachable(**_: Any) -> Any:
        raise oracledb.DatabaseError("ORA-12541: TNS:no listener")

    monkeypatch.setattr(session_module.oracledb, "connect", unreachable)

    with pytest.raises(DriverError) as raised:
        account.verify_password(ACCOUNT, Secret(CORRECT))

    assert raised.value.category == "connectivity"
