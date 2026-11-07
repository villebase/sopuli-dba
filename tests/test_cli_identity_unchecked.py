"""`SOPULI-W068`: a skipped identity check is reported by every command (#1363).

Tier 0: the store is a :class:`~sopuli.store.MemoryStore` and the driver a
fake session that can name its cluster, patched where ``sopuli.cli`` imported
them, as ``tests/test_cli_creds_check.py`` does. The live runs are a
PostgreSQL role that may not run ``pg_control_system()`` and a desynced Galera
node (``02-mariadb-privileges.md`` §2.3).
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from click.testing import CliRunner, Result
from jsonschema import Draft202012Validator

from sopuli.admin import Resolved
from sopuli.cli import _claim, cli
from sopuli.config.model import Vault
from sopuli.config.targets import EXTERNAL
from sopuli.diagnostics import IDENTITY_UNCHECKED
from sopuli.driver.clusters import ClusterIdentity
from sopuli.driver.protocol import PASS, VERIFY_LOGIN, Credential, Scope, UserState, VerifyResult
from sopuli.exit_codes import ExitCode
from sopuli.output.document import SCHEMA_VERSION, RunDocument
from sopuli.output.emit import EVENT_SCHEMA_VERSION
from sopuli.secrets import Secret
from sopuli.store import MemoryStore, SecretStore

RUN_SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "schemas"
    / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
)
EVENT_SCHEMA = RUN_SCHEMA.with_name(f"sopuli-event-{EVENT_SCHEMA_VERSION}.schema.json")

CONFIG = """\
version: 1
vaults:
  vault-dev:
    type: hashicorp
    addr: https://vault-dev.example.com:8200
targets:
  - name: appdb-alpha
    type: oracle
    dsn: db-dev.example.com:1521/alpha.pdb.example.com
    environment: dev
    vault: vault-dev
  - name: appdb-beta
    type: oracle
    dsn: db-dev.example.com:1521/beta.pdb.example.com
    environment: dev
    vault: vault-dev
applications:
  - name: acme
    accounts: [acme_web_user]
    secret_template: "apps/acme/{target}#password"
"""

STORED = "Correct-Horse-Battery-9"

#: The words a desynced Galera node gives, as `MariaDBSession.shared_identity`
#: sets them.
CAVEAT = (
    "this Galera node is Donor/Desynced, not Synced, so it is known by its server "
    "alone: another target on a node of its cluster is not refused"
)


class ClusterSession:
    """A session that names its cluster, with a caveat on the targets given."""

    identity_kind = "Galera cluster"
    identity_key = "wsrep_cluster_state_uuid"
    identity_hint = "declare one target per cluster"

    def __init__(self, identity: str, caveat: str | None) -> None:
        self.identity = identity
        self.identity_caveat = caveat

    def cluster_identity(self) -> str | None:
        return self.identity

    def scope(self) -> Scope:
        return Scope(type="server", container=None, read_write=True)

    def describe_user(self, account: str) -> UserState:
        return UserState(name=account.upper(), status="OPEN")

    def verify_password(self, account: str, secret: Secret, **_: Any) -> VerifyResult:
        return VerifyResult(VERIFY_LOGIN, PASS, latency_ms=7)

    def close(self) -> None:
        return None


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def estate(monkeypatch: pytest.MonkeyPatch) -> Callable[[Mapping[str, str]], None]:
    """Patch the store and the driver. Each target is its own server, and the
    targets in ``caveats`` claim less than they could, for the reason given."""

    def install(caveats: Mapping[str, str]) -> None:
        store = MemoryStore()
        for target in ("appdb-alpha", "appdb-beta"):
            store.write(f"apps/acme/{target}", {"password": STORED}, cas=0)

        def fake_connect(
            vault: Vault, *, env: Mapping[str, str], token_file: Path | None = None
        ) -> SecretStore:
            return store

        class FakeDriver:
            def __init__(self, context: Any) -> None:
                pass

            def connect(self, target: Any, credential: Any) -> ClusterSession:
                return ClusterSession(f"uid-{target.name}", caveats.get(target.name))

        monkeypatch.setattr("sopuli.cli.connect", fake_connect)
        monkeypatch.setattr("sopuli.cli.driver_for", lambda target, context: FakeDriver(context))
        monkeypatch.setattr(
            "sopuli.cli.admin_resolve",
            lambda target, **_: Resolved(
                credential=Credential(external=True), method=EXTERNAL, source="external"
            ),
        )

    return install


def check(runner: CliRunner, config: Path, *args: str) -> Result:
    return runner.invoke(cli, ["creds", "check", "--config", str(config), *args])


def unchecked(document: dict[str, Any]) -> list[dict[str, Any]]:
    found = document.get("diagnostics", [])
    return [one for one in found if one.get("code") == IDENTITY_UNCHECKED]


def test_the_fake_session_is_one_the_check_asks() -> None:
    """Otherwise every test below would pass by claiming nothing."""
    assert isinstance(ClusterSession("uid", None), ClusterIdentity)


def test_a_skipped_identity_check_is_a_warning_on_its_target(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Any
) -> None:
    """One entry for the target that claimed less, none for the one that did
    not, and the run's outcome is unchanged: a warning, not a refusal."""
    estate({"appdb-alpha": CAVEAT})
    result = check(runner, write_config(CONFIG), "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    document = json.loads(result.output)
    Draft202012Validator(json.loads(RUN_SCHEMA.read_text(encoding="utf-8"))).validate(document)
    assert unchecked(document) == [
        {
            "level": "warning",
            "code": IDENTITY_UNCHECKED,
            "target": "appdb-alpha",
            "message": f"appdb-alpha: {CAVEAT}",
        }
    ]


def test_the_text_view_prints_it(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Any
) -> None:
    estate({"appdb-alpha": CAVEAT})
    result = check(runner, write_config(CONFIG))

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert result.output.count(f"appdb-alpha: {CAVEAT}") == 1


def test_a_session_that_claims_all_it_can_says_nothing(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Any
) -> None:
    estate({})
    result = check(runner, write_config(CONFIG), "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert unchecked(json.loads(result.output)) == []


def test_a_target_opened_twice_is_warned_of_once() -> None:
    """A run's pre-flight and the run itself open one target twice."""
    run: Any = SimpleNamespace(document=RunDocument.start("creds.apply"), clusters={})
    alpha: Any = ClusterSession("uid-alpha", CAVEAT)
    beta: Any = ClusterSession("uid-beta", CAVEAT)
    for _ in range(2):
        _claim(alpha, "appdb-alpha", run, in_text=True)
    _claim(beta, "appdb-beta", run, in_text=True)

    assert [one.target for one in run.document.diagnostics] == ["appdb-alpha", "appdb-beta"]
    assert len(run.document.warnings_text) == 2


def test_the_stream_carries_it_as_a_diagnostic_event(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Any
) -> None:
    """The event schema was bumped for this code, so its event is checked too."""
    estate({"appdb-alpha": CAVEAT})
    result = check(runner, write_config(CONFIG), "--output", "jsonl")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    events = [json.loads(line) for line in result.output.splitlines() if line.strip()]
    validator = Draft202012Validator(json.loads(EVENT_SCHEMA.read_text(encoding="utf-8")))
    for event in events:
        validator.validate(event)
    found = [
        event
        for event in events
        if event["event"] == "diagnostic"
        and (event.get("data") or {}).get("code") == IDENTITY_UNCHECKED
    ]
    assert [(event["target"], event["message"]) for event in found] == [
        ("appdb-alpha", f"appdb-alpha: {CAVEAT}")
    ]


def test_doctor_puts_it_in_diagnostics_and_prints_it_once(
    runner: CliRunner, write_config: Callable[[str], Path], estate: Any
) -> None:
    """`doctor` prints the caveat as a note on its target, so its warnings
    must not print it a second time."""
    estate({"appdb-alpha": CAVEAT})
    config = write_config(CONFIG)

    text = runner.invoke(cli, ["--config", str(config), "doctor"])
    assert text.output.count(CAVEAT) == 1, text.output

    result = runner.invoke(cli, ["--config", str(config), "doctor", "--output", "json"])
    assert [one["target"] for one in unchecked(json.loads(result.output))] == ["appdb-alpha"]
