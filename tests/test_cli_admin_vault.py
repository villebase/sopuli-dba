"""`auth: { method: vault }` reaches a store, from the CLI (#483). Tier 0.

The third instance of one bug. `admin.resolve` takes its sources as suppliers --
`env` a mapping, `prompt` a callable, `read_ref` a callable over a ref -- and the
CLI passed **none** of the callables. #476 fixed `prompt`; this is `read_ref`,
and until it landed `_read_ref`'s "no store was available here" was the only
reachable branch, with a hint reading *this is a caller that supplied no reader*.

So `method: vault` failed on every run of every verb, in the source P2 ranks
highest of the three that need something from this machine: `env` is flagged
low-assurance (#477) and `prompt` needs a human, which left no working unattended
source at all.

`tests/test_admin.py` covers `resolve` with an injected reader and passed
throughout. That is the same blind spot #476 had, and this file is the same
answer: run the real commands and assert on what reached the far side.

Two things are asserted that a unit test cannot see:

* the reader is **lazy** -- a target authenticating some other way must open no
  store, which is what makes `admin.resolve`'s "a run that authenticates by
  wallet never builds a store client" true, and ADR-006's "base opens no
  sockets" one layer down;
* it opens **one client per store per run**, however many targets share it.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner, Result

from sopuli.admin import store_name
from sopuli.cli import cli
from sopuli.config.loading import load_layers
from sopuli.config.model import Config
from sopuli.config.secret_refs import parse_secret_ref
from sopuli.driver.protocol import Credential, PrivilegeAudit, Scope
from sopuli.exit_codes import ExitCode
from sopuli.store import MemoryStore, SecretStore

WriteConfig = Callable[[str], Path]

STORED = "Correct-Horse-Battery-9"

VAULTS = """version: 1
vaults:
  vault-dev:
    type: hashicorp
    addr: https://vault-dev.example.com:8200
  vault-other:
    type: hashicorp
    addr: https://vault-other.example.com:8200
"""

#: The target from the issue: a ref with no prefix, resolved through the
#: target's own `vault:`.
VAULT_ADMIN = (
    VAULTS
    + """targets:
  - name: orders-pdb
    type: oracle
    dsn: "db.example.com:1521/orders"
    vault: vault-dev
    admin:
      username: C##SOPULI_SVC
      auth: { method: vault, secret: "ops/dba#password" }
"""
)

#: Two targets, one store. One client, not two.
TWO_TARGETS = (
    VAULT_ADMIN
    + """  - name: billing-pdb
    type: oracle
    dsn: "db.example.com:1521/billing"
    vault: vault-dev
    admin:
      username: C##SOPULI_SVC
      auth: { method: vault, secret: "ops/dba#password" }
"""
)

#: Authenticates from a wallet, and so must never reach a store.
WALLET_ADMIN = (
    VAULTS
    + """targets:
  - name: orders-pdb
    type: oracle
    dsn: ORDERS_DEV
    vault: vault-dev
    admin: { auth: external }
"""
)

#: `method: vault` and nowhere to read from: no prefix, no `vault:` on the
#: target, no `defaults.vault`.
NO_STORE = """version: 1
targets:
  - name: orders-pdb
    type: oracle
    dsn: "db.example.com:1521/orders"
    admin:
      username: C##SOPULI_SVC
      auth: { method: vault, secret: "ops/dba#password" }
"""


class FakeSession:
    def scope(self) -> Scope:
        return Scope(type="pdb", container="ORDERS", read_write=True, capabilities=frozenset())

    def privileges(self) -> PrivilegeAudit:
        return PrivilegeAudit()

    def close(self) -> None:
        return None


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def estate(monkeypatch: pytest.MonkeyPatch) -> Callable[..., dict[str, Any]]:
    """A driver, and a `connect` that records every store this run opened.

    `opened` is the list the laziness and one-client-per-store assertions turn
    on: what matters is not only that a credential arrived but how many times a
    vault was authenticated to get it.
    """

    def install(*, document: Any = None) -> dict[str, Any]:
        opened: list[str] = []
        seen: list[Credential] = []
        store = MemoryStore()
        store.write(
            "ops/dba",
            {"password": STORED} if document is None else document,
            cas=0,
        )

        def fake_connect(vault: Any, **_: Any) -> SecretStore:
            opened.append(vault.name)
            return store

        class FakeDriver:
            def __init__(self, **_: Any) -> None:
                pass

            def connect(self, target: Any, credential: Credential) -> FakeSession:
                seen.append(credential)
                return FakeSession()

        class FakeModule:
            OracleDriver = FakeDriver

        monkeypatch.setattr("sopuli.cli.connect", fake_connect)
        monkeypatch.setattr("sopuli.cli.resolve_driver", lambda target: FakeModule)
        # `doctor`'s `vaults` section surveys every declared store over the real
        # client, which needs a token this tier has not got -- and an unreachable
        # store is exit 1, which would mask the target result under test. That
        # section is #216's and has its own tests; nothing here is about it.
        monkeypatch.setattr("sopuli.cli.vault_survey", lambda *_, **__: ())
        return {"opened": opened, "seen": seen, "store": store}

    return install


def _doctor(runner: CliRunner, config: Path, *args: str) -> Result:
    return runner.invoke(cli, ["--config", str(config), *args, "doctor"])


# ----------------------------------------------------------- the store name ---


def _config(text: str, tmp_path: Path) -> Config:
    path = tmp_path / "sopuli.yaml"
    path.write_text(text, encoding="utf-8")
    return load_layers((path,), profile=None, env={})[1]


def test_the_refs_own_prefix_wins(tmp_path: Path) -> None:
    """§7 calls `vault-other:` an *explicit* vault, so nothing outranks it."""
    config = _config(VAULT_ADMIN, tmp_path)
    target = config.expanded_targets[0]

    found = store_name(
        target, parse_secret_ref("vault-other:ops/dba#password"), config=config, env={}
    )

    assert found == "vault-other"


def test_the_targets_vault_comes_next(tmp_path: Path) -> None:
    config = _config(VAULT_ADMIN, tmp_path)
    target = config.expanded_targets[0]

    found = store_name(target, parse_secret_ref("ops/dba#password"), config=config, env={})

    assert found == "vault-dev"


def test_the_run_layers_fill_a_hole(tmp_path: Path) -> None:
    """`SOPULI_VAULT` supplies a store where the file named none."""
    config = _config(NO_STORE, tmp_path)
    target = config.expanded_targets[0]
    ref = parse_secret_ref("ops/dba#password")

    assert store_name(target, ref, config=config, env={}) is None
    assert store_name(target, ref, config=config, env={"SOPULI_VAULT": "vault-dev"}) == "vault-dev"


def test_the_run_layers_never_repoint_an_arrow(tmp_path: Path) -> None:
    """The half that would be a security bug if it were precedence-ordered.

    A target naming its own store is a statement about *that database*. An
    exported `SOPULI_VAULT` -- a property of whichever shell the run started in
    -- must not silently send the credential that reaches production to a
    different vault. `binding_stores` makes the same choice for the same reason.
    """
    config = _config(VAULT_ADMIN, tmp_path)
    target = config.expanded_targets[0]

    found = store_name(
        target,
        parse_secret_ref("ops/dba#password"),
        config=config,
        env={"SOPULI_VAULT": "vault-other"},
    )

    assert found == "vault-dev"


# ------------------------------------------------------------- and the wiring ---


def test_the_stored_password_reaches_the_driver(
    runner: CliRunner, write_config: WriteConfig, estate: Callable[..., dict[str, Any]]
) -> None:
    """#483's repro: before this, every vault admin source was refused."""
    harness = estate()
    config = write_config(VAULT_ADMIN)

    result = _doctor(runner, config, "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert [one.secret.reveal() for one in harness["seen"] if one.secret] == [STORED]
    assert [one.username for one in harness["seen"]] == ["C##SOPULI_SVC"]
    assert json.loads(result.output)["targets"][0]["reachable"] is True


def test_a_wallet_target_opens_no_store(
    runner: CliRunner, write_config: WriteConfig, estate: Callable[..., dict[str, Any]]
) -> None:
    """The laziness, which is a property of the *shape* rather than a nicety.

    `admin.resolve` only calls `read_ref` on the vault branch, so a reader that
    resolved a store name or opened a client when it was built would authenticate
    to a vault on behalf of a run that never needed one -- and would fail a
    wallet estate whose `vaults:` block happens to be unreachable.
    """
    harness = estate()
    config = write_config(WALLET_ADMIN)

    _doctor(runner, config, "--output", "json")

    assert harness["opened"] == []


def test_two_targets_sharing_a_store_authenticate_once(
    runner: CliRunner, write_config: WriteConfig, estate: Callable[..., dict[str, Any]]
) -> None:
    """One client per store per run, which is `_stores_for`'s stated rule.

    Thirty-four targets in one vault would otherwise be thirty-four
    authentications, and thirty-four entries in that vault's audit log for one
    scheduled run.
    """
    harness = estate()
    config = write_config(TWO_TARGETS)

    result = _doctor(runner, config, "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert len(harness["seen"]) == 2
    assert harness["opened"] == ["vault-dev"]


def test_nothing_says_which_store(
    runner: CliRunner, write_config: WriteConfig, estate: Callable[..., dict[str, Any]]
) -> None:
    harness = estate()
    config = write_config(NO_STORE)

    result = _doctor(runner, config, "--output", "json")
    entry = json.loads(result.output)["targets"][0]

    assert entry["reachable"] is False
    assert "nothing says which one" in entry["error"]["message"]
    assert harness["opened"] == []


def test_an_empty_path_says_the_store_answered(
    runner: CliRunner, write_config: WriteConfig, estate: Callable[..., dict[str, Any]]
) -> None:
    """Distinct from a store that could not be reached, and worded to say so.

    `read_secret` returns `None` for every way of finding nothing (#183) -- no
    document, no field, no key. They have one remedy here, which is to go and
    look at the path, so they get one message.
    """
    harness = estate(document={"something-else": STORED})
    config = write_config(VAULT_ADMIN)

    result = _doctor(runner, config, "--output", "json")
    entry = json.loads(result.output)["targets"][0]

    assert entry["reachable"] is False
    assert "there is nothing at" in entry["error"]["message"]
    assert "ops/dba#password" in entry["error"]["message"]
    # It got as far as opening the store, which is what distinguishes this from
    # the refusal above.
    assert harness["opened"] == ["vault-dev"]
