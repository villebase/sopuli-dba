"""`safety.require_encryption` (#857), asked by the commands that send a password.

With the setting on, a target whose connection is not encrypted, or whose
encryption could not be read, is refused before any password is drawn or any
database is changed: exit 5, naming the target and the key that required it
(invariant 4). With it off, nothing changes, and the notice #697 added stays.

Every case asserts on the statements the fake session recorded, because a
refusal the command then ignored would look like one that worked in the output.
The live case, against the tier-1 stack's unencrypted connection, is in
`test_cli_reset_password.py`.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner, Result

from sopuli.admin import Resolved
from sopuli.cli import cli
from sopuli.config.model import Vault
from sopuli.config.targets import EXTERNAL
from sopuli.driver.protocol import (
    ENCRYPTION_NATIVE,
    ENCRYPTION_NONE,
    PASS,
    UNKNOWN,
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

#: Two targets, so a group can require encryption of one of them only.
CONFIG = """\
version: 1
defaults:
  policy: app-standard
policies:
  app-standard:
    password: { length: 24, charset: alnum, first_char: alpha }
vaults:
  vault-prod:
    type: hashicorp
    addr: https://vault-prod.example.com:8200
targets:
  - name: appdb-alpha
    type: oracle
    dsn: db-prod.example.com:1521/alpha.pdb.example.com
    environment: prod
    labels: { env: prod, tenant: alpha }
    vault: vault-prod
  - name: appdb-beta
    type: oracle
    dsn: db-prod.example.com:1521/beta.pdb.example.com
    environment: prod
    labels: { env: prod, tenant: beta }
    vault: vault-prod
applications:
  - name: acme
    accounts: [acme_web_user]
    secret_template: "apps/acme/db#DB_CREDENTIALS/{account}"
"""

#: The setting under `defaults`, for every target.
REQUIRED = CONFIG.replace(
    "  policy: app-standard\n", "  policy: app-standard\n  safety: { require_encryption: true }\n"
)

#: The setting on a group that matches `appdb-beta` only.
BETA_ONLY = CONFIG + (
    "groups:\n  beta:\n    match: { tenant: beta }\n    safety: { require_encryption: true }\n"
)

NATIVE = Encryption(method=ENCRYPTION_NATIVE, algorithm="AES256", protocol="tcp")
CLEAR = Encryption(method=ENCRYPTION_NONE, protocol="tcp", hint="require NNE or TLS")
UNREAD = Encryption(method=UNKNOWN, protocol="tcp", hint="V$SESSION_CONNECT_INFO is not readable")


class FakeSession:
    def __init__(self, encryption: Encryption) -> None:
        self.encryption = encryption
        self.changed: list[str] = []

    def scope(self) -> Scope:
        return Scope(
            type="pdb",
            container="ALPHA",
            read_write=True,
            capabilities=frozenset(),
            encryption=self.encryption,
        )

    def privileges(self) -> PrivilegeAudit:
        return PrivilegeAudit()

    def describe_user(self, account: str) -> UserState | None:
        return UserState(
            name=account.upper(), status="OPEN", password_file_member=False, vendor_maintained=False
        )

    def verify_password(self, account: str, secret: Secret, **_: Any) -> VerifyResult:
        held = STAGED if account.upper() in self.changed else LIVE
        return VerifyResult("login", PASS if secret.reveal() == held else "fail", latency_ms=9)

    def set_password(self, account: str, secret: Secret) -> ChangeResult:
        self.changed.append(account.upper())
        return ChangeResult(changed=True)

    def close(self) -> None:
        return None


Harness = Callable[..., dict[str, Any]]


@pytest.fixture
def estate(monkeypatch: pytest.MonkeyPatch) -> Harness:
    """A vault with `pending` staged and a fake driver.

    ``encryption`` is each target's connection. ``refuse_first`` makes the first
    connection to a target fail, which is the plan-time read in these runs: the
    check at the point of sending must then still refuse.
    """

    def install(
        encryption: Mapping[str, Encryption],
        *,
        refuse_first: frozenset[str] = frozenset(),
    ) -> dict[str, Any]:
        store = MemoryStore()
        store.write(
            "apps/acme/db",
            {"DB_CREDENTIALS": {"acme_web_user": LIVE}, "pending": {"acme_web_user": STAGED}},
            cas=0,
        )
        sessions: list[FakeSession] = []
        attempts: dict[str, int] = {}

        def fake_connect(
            vault: Vault, *, env: Mapping[str, str], token_file: Path | None = None
        ) -> SecretStore:
            return store

        class FakeDriver:
            def __init__(self, **_: Any) -> None:
                pass

            def connect(self, target: Any, credential: Any) -> FakeSession:
                attempts[target.name] = attempts.get(target.name, 0) + 1
                if target.name in refuse_first and attempts[target.name] == 1:
                    raise ConnectionError("the listener did not answer")
                opened = FakeSession(encryption[target.name])
                sessions.append(opened)
                return opened

        class FakeModule:
            OracleDriver = FakeDriver

        monkeypatch.setattr("sopuli.cli.connect", fake_connect)
        monkeypatch.setattr("sopuli.cli.resolve_driver", lambda target: FakeModule)
        monkeypatch.setattr(
            "sopuli.cli.admin_resolve",
            lambda target, **_: Resolved(
                credential=Credential(external=True), method=EXTERNAL, source="an external store"
            ),
        )
        return {"store": store, "sessions": sessions}

    return install


def apply(runner: CliRunner, config: Path, *args: str) -> Result:
    return runner.invoke(cli, ["creds", "apply", "--config", str(config), *args])


def changed(harness: dict[str, Any]) -> list[str]:
    return [name for session in harness["sessions"] for name in session.changed]


def exit_of(result: Result) -> int:
    """The process's exit code. `CliRunner` calls `cli` without `main()`'s
    boundary, so a refusal arrives as the exception that carries it."""
    code = getattr(result.exception, "exit_code", None)
    return int(code) if code is not None else result.exit_code


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def test_an_unencrypted_target_is_refused_before_anything_changes(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    harness = estate({"appdb-alpha": NATIVE, "appdb-beta": CLEAR})
    result = apply(runner, write_config(REQUIRED), "--output", "json")

    assert exit_of(result) == ExitCode.UNSUPPORTED_CAPABILITY
    assert changed(harness) == []
    error = json.loads(result.output)["error"]
    assert error["category"] == "capability"
    assert error["target_capability"] == "encrypted_connection"
    assert 'target "appdb-beta" does not support encrypted_connection' in error["message"]
    assert error["hint"].startswith(
        "`defaults.safety.require_encryption` requires it, and this connection's encryption is none"
    )


def test_encryption_that_could_not_be_read_counts_as_unencrypted(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    harness = estate({"appdb-alpha": UNREAD, "appdb-beta": NATIVE})
    result = apply(runner, write_config(REQUIRED))

    assert exit_of(result) == ExitCode.UNSUPPORTED_CAPABILITY
    assert changed(harness) == []


def test_encrypted_targets_are_applied_as_usual(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    harness = estate({"appdb-alpha": NATIVE, "appdb-beta": NATIVE})
    result = apply(runner, write_config(REQUIRED))

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert changed(harness) == ["ACME_WEB_USER", "ACME_WEB_USER"]


def test_with_the_setting_off_an_unencrypted_target_is_applied(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The decided behaviour of #697: a notice, and the run goes on."""
    harness = estate({"appdb-alpha": CLEAR, "appdb-beta": CLEAR})
    result = apply(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert changed(harness) == ["ACME_WEB_USER", "ACME_WEB_USER"]


def test_a_group_requires_it_of_its_own_targets_only(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Per target, unlike `readonly`: `appdb-alpha` is outside the group, so its
    unencrypted connection does not refuse the run."""
    harness = estate({"appdb-alpha": CLEAR, "appdb-beta": NATIVE})
    result = apply(runner, write_config(BETA_ONLY))

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert changed(harness) == ["ACME_WEB_USER", "ACME_WEB_USER"]


def test_the_group_names_its_own_key(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    estate({"appdb-alpha": CLEAR, "appdb-beta": CLEAR})
    result = apply(runner, write_config(BETA_ONLY), "--output", "json")

    assert exit_of(result) == ExitCode.UNSUPPORTED_CAPABILITY
    hint = json.loads(result.output)["error"]["hint"]
    assert hint.startswith("`groups.beta.safety.require_encryption` requires it")


def test_the_connection_that_sends_is_checked_too(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The plan-time read cannot reach `appdb-beta`, so it is left to the run.
    The run reads the connection it would send over, finds it in clear, and
    refuses that row. The password does not cross it, and `current` stays."""
    harness = estate(
        {"appdb-alpha": NATIVE, "appdb-beta": CLEAR}, refuse_first=frozenset({"appdb-beta"})
    )
    result = apply(runner, write_config(REQUIRED), "--output", "json")

    rows = {one["target"]: one for one in json.loads(result.output)["results"]}
    assert rows["appdb-beta"]["state"] == "ERROR"
    assert "does not support encrypted_connection" in rows["appdb-beta"]["error"]["message"]
    assert changed(harness) == ["ACME_WEB_USER"]
    held = harness["store"].read("apps/acme/db")
    assert held is not None
    assert held.data["DB_CREDENTIALS"]["acme_web_user"] == LIVE
    assert result.exit_code == ExitCode.PARTIAL


def test_a_dry_run_is_refused_too(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """The preview would otherwise describe a run the tool will not do."""
    estate({"appdb-alpha": CLEAR, "appdb-beta": NATIVE})
    result = apply(runner, write_config(REQUIRED), "--dry-run")

    assert exit_of(result) == ExitCode.UNSUPPORTED_CAPABILITY


def test_rotate_is_refused_before_it_draws_a_password(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Harness
) -> None:
    """Step 4 writes `pending`. A refusal after it would leave a staged password
    that no database can be given."""
    harness = estate({"appdb-alpha": NATIVE, "appdb-beta": CLEAR})
    harness["store"].write("apps/acme/db", {"DB_CREDENTIALS": {"acme_web_user": LIVE}}, cas=1)
    result = runner.invoke(
        cli, ["creds", "rotate", "--config", str(write_config(REQUIRED)), "--confirm"]
    )

    assert exit_of(result) == ExitCode.UNSUPPORTED_CAPABILITY, result.output
    held = harness["store"].read("apps/acme/db")
    assert held is not None
    assert "pending" not in held.data
    assert changed(harness) == []


def test_a_later_config_file_cannot_turn_it_off(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    estate: Harness,
    tmp_path: Path,
) -> None:
    """Invariant 10 between files (#855): `false` in a later file loses."""
    estate({"appdb-alpha": CLEAR, "appdb-beta": CLEAR})
    later = tmp_path / "local.yaml"
    later.write_text("version: 1\ndefaults:\n  safety: { require_encryption: false }\n")
    if hasattr(later, "chmod"):
        later.chmod(0o600)
    result = runner.invoke(
        cli,
        ["creds", "apply", "--config", str(write_config(REQUIRED)), "--config", str(later)],
    )

    assert exit_of(result) == ExitCode.UNSUPPORTED_CAPABILITY
