"""`account reset-password` on the unseen path, for a session that keeps its
login's policy flags: SQL Server (#1554, decision 1). Tier 0, with a fake
session and an in-memory reset journal.

The unseen reset turns the login's policy off to send its value, so the
command records ``CHECK_POLICY`` and ``CHECK_EXPIRATION`` in the reset record
before the change, sets them back after it, and drops them from the record
(``02-mssql-privileges.md`` §6.3). Flags a stopped reset left in the record
are the ones set back. The fake's product is Oracle: the flow keys on the
session's ``keeps_policy_flags``, not on the product, as `creds apply`'s does.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner, Result

from conftest import WriteConfig
from sopuli.cli import _JournalFailures, _reset_at, cli
from sopuli.config.loading import load_config
from sopuli.delivery import Receipt
from sopuli.driver.protocol import (
    ACCOUNT_UNLOCK,
    ENCRYPTION_TLS,
    PASSWORD_SET,
    ROLLOVER_FINISH,
    AccountChange,
    AuditCoverage,
    DriverError,
    Encryption,
    Scope,
    UserState,
)
from sopuli.exit_codes import ExitCode
from sopuli.policy_flags import PolicyFlags
from sopuli.secrets import Secret
from sopuli.store import MemoryStore

ACCOUNT = "acme_dev_alice"
TARGET = "tier1-oracle"

CONFIG = f"""version: 1

defaults:
  policy: personal-standard
  vault: vault-dev

targets:
  - name: {TARGET}
    type: oracle
    environment: dev
    dsn: "192.0.2.10:1521/ALPHA"
    admin: {{ username: SOPULI_SVC, auth: {{ method: env }} }}

vaults:
  vault-dev:
    type: hashicorp
    addr: https://vault.example.com:8200
    mount: secret
    kv_version: 2
    auth:
      method: token

policies:
  personal-standard:
    password:
      length: 20
      charset: alnum_safe

personal_accounts:
  - accounts: [{ACCOUNT}]
    policy: personal-standard

delivery:
  method: vault_wrapped
  vault_wrapped:
    ttl: 15m
"""

JOURNALLED = CONFIG + "\nreset_records:\n  vault: vault-dev\n  prefix: sopuli/personal-resets\n"


class FlagSession:
    """A login whose flags read as ``flags``, on a session that keeps them.

    ``events`` holds what happened, in order, with the reset record as it
    stood when the value was sent. ``restore_fails`` makes setting the flags
    back fail.
    """

    keeps_policy_flags = True

    def __init__(self, flags: PolicyFlags, journal: MemoryStore) -> None:
        self.flags = flags
        self.journal = journal
        self.events: list[Any] = []
        self.restored_names: list[str] = []
        self.restore_fails = False

    def describe_user(self, account: str) -> UserState:
        return UserState(name=account.upper(), status="OPEN", password_file_member=False)

    def scope(self) -> Scope:
        return Scope(encryption=Encryption(method=ENCRYPTION_TLS, protocol="tcps"))

    def audit_coverage(self, account: str) -> AuditCoverage:
        return AuditCoverage(audited=True, detail="audited")

    def byte_limit(self) -> None:
        return None

    def reset_policy_flags(self, account: str) -> PolicyFlags:
        self.events.append("read flags")
        return self.flags

    def reset_password(self, account: str, secret: Secret, **_: Any) -> tuple[AccountChange, ...]:
        self.events.append(("sent", records(self.journal)))
        return (
            AccountChange(ACCOUNT_UNLOCK, changed=False, status="OPEN", detail="not locked"),
            AccountChange(PASSWORD_SET, changed=True, status="OPEN", detail="value set"),
            AccountChange(ROLLOVER_FINISH, changed=False, status="OPEN", detail="no window"),
        )

    def restore_policy(self, account: str, flags: PolicyFlags) -> bool:
        self.events.append(("restore", flags))
        self.restored_names.append(account)
        if self.restore_fails:
            raise DriverError("the connection was lost")
        return True

    def close(self) -> None:
        return None


class FakeBackend:
    stored_name = False

    def preflight(self, *, account: str, target: str) -> None:
        return None

    def deliver(self, secret: Secret, *, account: str, target: str) -> Receipt:
        return Receipt(
            method="vault_wrapped",
            token=Secret("hvs.CAESIFAKEWRAPPINGTOKEN0000"),
            accessor="accessor-0001",
            expires_at=datetime(2026, 9, 26, 12, 15, tzinfo=UTC),
        )


@pytest.fixture
def journal(monkeypatch: pytest.MonkeyPatch) -> MemoryStore:
    store = MemoryStore()
    monkeypatch.setattr("sopuli.cli._reset_journal", lambda run, config: store)
    monkeypatch.setattr(
        "sopuli.cli._delivery_backends",
        lambda run, config, delivery, reached, account, **_: {TARGET: FakeBackend()},
    )
    monkeypatch.setattr("sopuli.cli._notify", lambda *_, **__: None)
    return store


def opened(monkeypatch: pytest.MonkeyPatch, session: FlagSession) -> FlagSession:
    monkeypatch.setattr("sopuli.cli._open_session", lambda target, run, config: session)
    return session


def run(write_config: WriteConfig, text: str, *args: str) -> Result:
    path: Path = write_config(text)
    return CliRunner().invoke(
        cli,
        [
            "--config", str(path), "--output", "json", "account", "reset-password",
            "--account", ACCOUNT, *args,
        ],
    )  # fmt: skip


def records(journal: MemoryStore) -> list[dict[str, Any]]:
    """Every reset record in the journal, leaving the lock records out."""
    found = []
    for path in record_paths(journal):
        stored = journal.read(path)
        if stored is not None:
            found.append(stored.data)
    return found


def record_paths(journal: MemoryStore) -> list[str]:
    """The journal's paths, leaving the lock records out."""
    return sorted(path for path in journal.paths if "/locks/" not in f"/{path}")


ON = PolicyFlags(check_policy=True, check_expiration=True)
OFF = PolicyFlags(check_policy=False, check_expiration=False)


def test_the_flags_are_recorded_before_the_change_and_set_back_after(
    write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch, journal: MemoryStore
) -> None:
    session = opened(monkeypatch, FlagSession(ON, journal))

    result = run(write_config, JOURNALLED)

    assert result.exit_code == ExitCode.SUCCESS, result.output
    read, (sent, at_send), restored = session.events
    assert read == "read flags"
    assert sent == "sent"
    assert [one.get("policy_flags") for one in at_send] == [ON.to_record()]
    assert restored == ("restore", ON)
    [record] = records(journal)
    assert "policy_flags" not in record, "the flags are back, so the record drops them"
    assert record["account"] == ACCOUNT


def test_flags_both_off_need_no_record_and_nothing_set_back(
    write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch, journal: MemoryStore
) -> None:
    session = opened(monkeypatch, FlagSession(OFF, journal))

    result = run(write_config, JOURNALLED)

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert session.events == ["read flags", ("sent", [])]


def test_flags_a_stopped_reset_recorded_are_the_ones_set_back(
    write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch, journal: MemoryStore
) -> None:
    """The stopped run left the policy off, so the login reads off now; the
    record holds what it was before."""
    first = opened(monkeypatch, FlagSession(ON, journal))
    run(write_config, JOURNALLED)
    [path] = record_paths(journal)
    stored = journal.read(path)
    assert stored is not None
    journal.write(path, {**stored.data, "policy_flags": ON.to_record()}, cas=None)
    assert first.events[-1] == ("restore", ON)

    session = opened(monkeypatch, FlagSession(OFF, journal))
    result = run(write_config, JOURNALLED)

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert session.events[-1] == ("restore", ON)
    [record] = records(journal)
    assert "policy_flags" not in record


def test_flags_are_set_back_on_the_name_the_server_stores_and_the_action_says_so(
    write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch, journal: MemoryStore
) -> None:
    """The fake stores the name in upper case, as a case-sensitive collation
    could; step 2 changed that login, so step 4 sets it back."""
    session = opened(monkeypatch, FlagSession(ON, journal))

    result = run(write_config, JOURNALLED)

    assert session.events[-1] == ("restore", ON)
    assert session.restored_names == [ACCOUNT.upper()]
    [row] = json.loads(result.stdout)["results"]
    [password_set] = [one for one in row["actions"] if one["kind"] == PASSWORD_SET]
    assert "set back" in password_set["detail"]


def test_a_record_left_by_a_run_that_stopped_before_its_change_is_not_set_back(
    write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch, journal: MemoryStore
) -> None:
    """A run that stopped after its change leaves CHECK_POLICY off. This login
    reads it on, so the record is stale, from a run that stopped before its
    change, perhaps before a DBA changed the login: what the login reads now
    is recorded and set back."""
    opened(monkeypatch, FlagSession(ON, journal))
    run(write_config, JOURNALLED)
    [path] = record_paths(journal)
    stored = journal.read(path)
    assert stored is not None
    journal.write(path, {**stored.data, "policy_flags": ON.to_record()}, cas=None)

    now = PolicyFlags(check_policy=True, check_expiration=False)
    session = opened(monkeypatch, FlagSession(now, journal))
    result = run(write_config, JOURNALLED)

    assert result.exit_code == ExitCode.SUCCESS, result.output
    sent = next(one for one in session.events if isinstance(one, tuple) and one[0] == "sent")
    assert [one.get("policy_flags") for one in sent[1]] == [now.to_record()]
    assert session.events[-1] == ("restore", now)


def test_flags_not_set_back_stay_in_the_record_and_the_row_says_so(
    write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch, journal: MemoryStore
) -> None:
    session = FlagSession(ON, journal)
    session.restore_fails = True
    opened(monkeypatch, session)

    result = run(write_config, JOURNALLED)

    assert result.exit_code == ExitCode.PARTIAL, result.output
    [row] = json.loads(result.stdout)["results"]
    assert row["state"] == "ERROR"
    assert row["changed"] is True
    assert row["error"]["message"] == "the connection was lost"
    [record] = records(journal)
    assert record["policy_flags"] == ON.to_record()
    assert "reset_at" in record, "the reset's own record, keeping the flags"

    text = CliRunner().invoke(
        cli,
        [
            "--config", str(write_config(JOURNALLED)), "account", "reset-password",
            "--account", ACCOUNT,
        ],
    )  # fmt: skip
    assert "were not set back" in text.output


def test_a_record_whose_flags_cannot_be_read_stops_the_reset(
    write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch, journal: MemoryStore
) -> None:
    """It may be the only copy of the login's flags, so nothing is written
    over it, and nothing is sent."""
    opened(monkeypatch, FlagSession(ON, journal))
    run(write_config, JOURNALLED)
    [path] = record_paths(journal)
    journal.write(path, {"account": ACCOUNT, "policy_flags": "yes"}, cas=None)

    session = opened(monkeypatch, FlagSession(ON, journal))
    result = run(write_config, JOURNALLED)

    assert result.exit_code != ExitCode.SUCCESS, result.output
    assert not any(isinstance(one, tuple) and one[0] == "sent" for one in session.events)
    stored = journal.read(path)
    assert stored is not None
    assert stored.data["policy_flags"] == "yes"


def test_no_reset_records_and_the_policy_on_is_refused_before_anything_is_sent(
    write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch, journal: MemoryStore
) -> None:
    """Nothing could hold the flags (#1554, Q7). Plan time refuses it too,
    once the command is registered for SQL Server; this is the run's own
    guard."""
    session = opened(monkeypatch, FlagSession(ON, journal))

    result = run(write_config, CONFIG)

    assert result.exit_code != ExitCode.SUCCESS, result.output
    assert "reset_records" in result.output
    assert session.events == ["read flags"]


def test_a_preview_reads_the_flags_and_writes_nothing(
    write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch, journal: MemoryStore
) -> None:
    session = opened(monkeypatch, FlagSession(ON, journal))

    result = run(write_config, JOURNALLED, "--dry-run")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert session.events == ["read flags"]
    assert records(journal) == []


class LostError(DriverError):
    category = "connectivity"


def failing(session: FlagSession, error: DriverError) -> FlagSession:
    """``session``, whose value statement raises ``error``."""

    def fails(account: str, secret: Secret, **_: Any) -> tuple[AccountChange, ...]:
        session.events.append(("sent", records(session.journal)))
        raise error

    session.reset_password = fails  # type: ignore[method-assign]
    return session


def test_a_change_the_server_refused_takes_its_flags_out_of_the_record(
    write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch, journal: MemoryStore
) -> None:
    """The statement is atomic, so the login's policy never went off. The
    flags written for it are taken out, so a later reset does not set back
    flags a DBA may have changed since. On a first reset that leaves the
    account and the target alone, which `account list` reads as no reset,
    not as a journal it cannot read (`SOPULI-W054`)."""
    refused = DriverError("the server refused it")
    refused.password_sent = True
    session = opened(monkeypatch, failing(FlagSession(ON, journal), refused))

    result = run(write_config, JOURNALLED)

    assert result.exit_code != ExitCode.SUCCESS, result.output
    sent = next(one for one in session.events if isinstance(one, tuple))
    assert [one.get("policy_flags") for one in sent[1]] == [ON.to_record()]
    [record] = records(journal)
    assert record == {"account": ACCOUNT, "target": TARGET}

    config = load_config(write_config(JOURNALLED))
    [target] = config.expanded_targets
    unread = _JournalFailures()
    assert _reset_at(journal, config, target, ACCOUNT, unread=unread) is None
    assert unread.first is None


def test_a_connection_lost_after_the_change_went_out_keeps_the_flags(
    write_config: WriteConfig, monkeypatch: pytest.MonkeyPatch, journal: MemoryStore
) -> None:
    """It may have committed with the policy off, so the record keeps the
    flags for the next reset, and the row says so."""
    lost = LostError("the connection was lost")
    lost.password_sent = True
    opened(monkeypatch, failing(FlagSession(ON, journal), lost))

    result = CliRunner().invoke(
        cli,
        [
            "--config", str(write_config(JOURNALLED)), "account", "reset-password",
            "--account", ACCOUNT,
        ],
    )  # fmt: skip

    assert result.exit_code != ExitCode.SUCCESS, result.output
    [record] = records(journal)
    assert record["policy_flags"] == ON.to_record()
    assert "may have been set with the login's policy off" in result.output
