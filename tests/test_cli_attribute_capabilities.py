"""An account attribute a target cannot enforce is refused at plan time (#1072).

A policy's ``account.unlock_if_locked`` needs ``account_lock_state`` and its
``account.profile`` needs ``profile_management``. A target that reports neither,
such as a PostgreSQL cluster, is refused before any password is drawn or any
database is changed: exit 5, naming the capability, the target and the key
(invariant 4). The question is the capability's, so these fakes say nothing
about a product.

Every case asserts on what the fake session recorded, because a refusal the
command then ignored would look like one that worked in the output.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner, Result

from sopuli.admin import Resolved
from sopuli.apply import settled_before_acting
from sopuli.cli import cli
from sopuli.config.model import Vault
from sopuli.config.targets import EXTERNAL
from sopuli.driver.protocol import (
    ACCOUNT_LOCK_STATE,
    ENCRYPTION_TLS,
    PASS,
    PROFILE_MANAGEMENT,
    ChangeResult,
    Credential,
    Encryption,
    PrivilegeAudit,
    Scope,
    UserState,
    VerifyResult,
)
from sopuli.exit_codes import ExitCode
from sopuli.secrets import Secret
from sopuli.store import MemoryStore, SecretStore

LIVE = "Correct-Horse-Battery-9"
STAGED = "Vertical-Anchor-Marble-4"

CONFIG = """\
version: 1
defaults:
  policy: app-standard
policies:
  app-standard:
    password: { length: 24, charset: alnum, first_char: alpha }
ACCOUNT
vaults:
  vault-prod:
    type: hashicorp
    addr: https://vault-prod.example.com:8200
targets:
  - name: appdb-alpha
    type: oracle
    dsn: db-prod.example.com:1521/alpha.pdb.example.com
    environment: prod
    vault: vault-prod
applications:
  - name: acme
    accounts: [acme_web_user]
    secret_template: "apps/acme/db#DB_CREDENTIALS/{account}"
"""

UNLOCK = CONFIG.replace("ACCOUNT\n", "    account: { unlock_if_locked: true }\n")
PROFILE = CONFIG.replace("ACCOUNT\n", "    account: { profile: ACME_APP_PROF }\n")
NEITHER = CONFIG.replace("ACCOUNT\n", "")


class FakeSession:
    def __init__(self, capabilities: frozenset[str]) -> None:
        self.capabilities = capabilities
        self.changed: list[str] = []
        self.described = False

    def scope(self) -> Scope:
        return Scope(
            type="pdb",
            container="ALPHA",
            read_write=True,
            capabilities=self.capabilities,
            encryption=Encryption(method=ENCRYPTION_TLS, protocol="tcps"),
        )

    def privileges(self, *, accounts: tuple[str, ...] = ()) -> PrivilegeAudit:
        return PrivilegeAudit()

    def describe_user(self, account: str) -> UserState | None:
        self.described = True
        return UserState(
            name=account.upper(), status="OPEN", password_file_member=False, vendor_maintained=False
        )

    def resolve_profile(self, profile: str) -> str | None:
        return profile

    def verify_password(self, account: str, secret: Secret, **_: Any) -> VerifyResult:
        held = STAGED if self.changed else LIVE
        return VerifyResult("login", PASS if secret.reveal() == held else "fail", latency_ms=9)

    def set_password(self, account: str, secret: Secret) -> ChangeResult:
        self.changed.append(account.upper())
        return ChangeResult(changed=True)

    def apply_attributes(self, account: str, attributes: Any) -> tuple[Any, ...]:
        return ()

    def close(self) -> None:
        return None


Harness = Callable[..., dict[str, Any]]


@pytest.fixture
def estate(monkeypatch: pytest.MonkeyPatch) -> Harness:
    """A vault with `pending` staged, and a fake driver whose sessions report
    ``capabilities``."""

    def install(capabilities: frozenset[str], *, refuse_first: bool = False) -> dict[str, Any]:
        store = MemoryStore()
        store.write(
            "apps/acme/db",
            {"DB_CREDENTIALS": {"acme_web_user": LIVE}, "pending": {"acme_web_user": STAGED}},
            cas=0,
        )
        sessions: list[FakeSession] = []
        attempts: list[str] = []

        def fake_connect(
            vault: Vault, *, env: Mapping[str, str], token_file: Path | None = None
        ) -> SecretStore:
            return store

        class FakeDriver:
            def __init__(self, context: Any) -> None:
                pass

            def connect(self, target: Any, credential: Any) -> FakeSession:
                attempts.append(target.name)
                if refuse_first and len(attempts) == 1:
                    raise ConnectionError("the listener did not answer")
                opened = FakeSession(capabilities)
                sessions.append(opened)
                return opened

        monkeypatch.setattr("sopuli.cli.connect", fake_connect)
        monkeypatch.setattr("sopuli.cli.driver_for", lambda target, context: FakeDriver(context))
        monkeypatch.setattr(
            "sopuli.cli.admin_resolve",
            lambda target, **_: Resolved(
                credential=Credential(external=True), method=EXTERNAL, source="an external store"
            ),
        )
        return {"store": store, "sessions": sessions}

    return install


def invoke(runner: CliRunner, config: Path, *args: str) -> Result:
    return runner.invoke(cli, [*args[:2], "--config", str(config), *args[2:], "--output", "json"])


def exit_of(result: Result) -> int:
    """The process's exit code. `CliRunner` calls `cli` without `main()`'s
    boundary, so a refusal arrives as the exception that carries it."""
    code = getattr(result.exception, "exit_code", None)
    return int(code) if code is not None else result.exit_code


def changed(harness: dict[str, Any]) -> list[str]:
    return [name for session in harness["sessions"] for name in session.changed]


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.mark.parametrize(
    ("config", "capability", "key"),
    [
        (UNLOCK, ACCOUNT_LOCK_STATE, "policies.app-standard.account.unlock_if_locked"),
        (PROFILE, PROFILE_MANAGEMENT, "policies.app-standard.account.profile"),
    ],
    ids=["unlock", "profile"],
)
@pytest.mark.parametrize(
    "command",
    [("creds", "apply"), ("creds", "apply", "--dry-run"), ("creds", "rotate", "--confirm")],
    ids=["apply", "apply dry run", "rotate"],
)
def test_an_attribute_the_target_cannot_enforce_is_refused_before_anything_changes(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    config: str,
    capability: str,
    key: str,
    command: tuple[str, ...],
) -> None:
    harness = estate(frozenset())
    result = invoke(runner, write_config(config), *command)

    assert exit_of(result) == ExitCode.UNSUPPORTED_CAPABILITY, result.output
    error = json.loads(result.output)["error"]
    assert error["target_capability"] == capability
    assert f'target "appdb-alpha" does not support {capability}' in error["message"]
    assert error["hint"].startswith(f"`{key}` asks for it")
    assert changed(harness) == []
    # Only the scope was read: no account, before the lock.
    assert not any(session.described for session in harness["sessions"])
    assert harness["store"].list("locks/") == ()


@pytest.mark.parametrize(
    ("config", "capability"),
    [(UNLOCK, ACCOUNT_LOCK_STATE), (PROFILE, PROFILE_MANAGEMENT)],
    ids=["unlock", "profile"],
)
def test_a_target_that_reports_the_capability_is_applied(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    config: str,
    capability: str,
) -> None:
    harness = estate(frozenset({capability}))
    result = invoke(runner, write_config(config), "creds", "apply")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert changed(harness) == ["ACME_WEB_USER"]


def test_the_profile_hint_names_the_grant_before_dropping_the_key(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """On Oracle the capability is probed from DBA_PROFILES, so a missing grant
    is the usual cause, and dropping `profile:` would stop enforcing it."""
    estate(frozenset())
    result = invoke(runner, write_config(PROFILE), "creds", "apply")

    hint = json.loads(result.output)["error"]["hint"]
    assert "SELECT on DBA_PROFILES" in hint
    assert hint.index("grant") < hint.index("policy without that key")


def test_encryption_and_an_attribute_share_one_login_per_target(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The two plan-time checks read one scope: one login for both, then the run's."""
    harness = estate(frozenset({ACCOUNT_LOCK_STATE}))
    config = UNLOCK.replace(
        "  policy: app-standard\n",
        "  policy: app-standard\n  safety: { require_encryption: true }\n",
    )
    result = invoke(runner, write_config(config), "creds", "apply")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert [session.described for session in harness["sessions"]] == [False, True]


def test_a_target_the_plan_could_not_read_is_refused_on_its_row(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The plan-time read cannot reach the target, so the run asks the
    connection that would enforce the attribute, and refuses there. Nothing is
    unlocked and no password is set."""
    harness = estate(frozenset(), refuse_first=True)
    result = invoke(runner, write_config(UNLOCK), "creds", "apply")

    [row] = json.loads(result.output)["results"]
    assert row["state"] == "ERROR"
    assert "does not support account_lock_state" in row["error"]["message"]
    assert changed(harness) == []


def test_no_attribute_asks_nothing_and_opens_no_extra_connection(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """A config that declares no attribute costs nothing: one connection, the run's."""
    harness = estate(frozenset())
    result = invoke(runner, write_config(NEITHER), "creds", "apply")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert len(harness["sessions"]) == 1


# ---------------------------------------------- a locked account's advice ---

LOCKED = UserState(
    name="ACME_WEB_USER",
    status="NOLOGIN",
    password_file_member=False,
    vendor_maintained=False,
    locked=True,
)


def test_a_locked_account_is_told_to_declare_the_unlock_where_it_exists() -> None:
    outcome = settled_before_acting(LOCKED, object(), unlockable=True)  # type: ignore[arg-type]

    assert outcome is not None
    assert "declare `account: { unlock_if_locked: true }`" in outcome.detail


def test_a_locked_account_is_not_told_to_declare_what_the_target_refuses() -> None:
    """The advice would be refused at plan time where `account_lock_state` is absent."""
    outcome = settled_before_acting(LOCKED, object(), unlockable=False)  # type: ignore[arg-type]

    assert outcome is not None
    assert outcome.state == "LOCKED"
    assert "unlock_if_locked" not in outcome.detail
    assert "the tool does not change whether it can log in" in outcome.detail
