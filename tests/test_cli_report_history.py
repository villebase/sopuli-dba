"""`sopuli report history` on a memory store and fake sessions (UC-5 §6). Tier 0.

The history rules are tested in `tests/test_report_history.py`. Here: what the
command reads, its text, its JSON and its exit codes.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import click
import pytest
from click.testing import CliRunner, Result
from jsonschema import Draft202012Validator

from conftest import WriteConfig
from native_estate import OCI_VAULT, seed, staging_store
from sopuli import cli as cli_module
from sopuli.admin import Resolved
from sopuli.cli import cli
from sopuli.config.model import Vault
from sopuli.config.targets import EXTERNAL
from sopuli.driver.protocol import Credential, Scope, UserState
from sopuli.exit_codes import ExitCode
from sopuli.output.document import SCHEMA_VERSION
from sopuli.store import MemoryStore, SecretStore
from sopuli.store.native_view import LayoutChangedError

RUN_SCHEMA = json.loads(
    (
        Path(__file__).resolve().parents[1]
        / "docs"
        / "schemas"
        / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
    ).read_text(encoding="utf-8")
)

CONFIG = """\
version: 1
vaults:
  vault-dev:
    type: hashicorp
    addr: https://vault-dev.example.com:8200
targets:
  - name: appdb-dev-alpha
    type: oracle
    dsn: db-dev.example.com:1521/alpha.pdb.example.com
    vault: vault-dev
applications:
  - name: acme
    accounts: [acme_web_user, acme_batch_user]
    secret_template: "apps/acme/db#DB_CREDENTIALS/{account}"
personal_accounts:
  - accounts: [jdoe, asmith]
reset_records:
  vault: vault-dev
  prefix: sopuli/personal-resets
"""

PG_CONFIG = """\
version: 1
targets:
  - name: pg-dev
    type: postgresql
    dsn: db-dev.example.com:5432
    postgres: { database: acme }
    admin: { username: sopuli_svc, auth: { method: env } }
"""

SECRET = "Correct-Horse-Battery-9"
CHANGED = datetime(2026, 11, 7, 3, 0, 5, tzinfo=UTC)
CREDENTIAL = Resolved(
    credential=Credential(external=True), method=EXTERNAL, source="an external password store"
)


def stamp(day: int) -> str:
    return f"2026-11-{day:02d}T03:00:00Z"


def app_document(web: str | None, batch: str | None) -> dict[str, Any]:
    rotated = {"acme_web_user": web, "acme_batch_user": batch}
    return {
        "DB_CREDENTIALS": {"acme_web_user": SECRET, "acme_batch_user": SECRET},
        "rotated_at": {k: v for k, v in rotated.items() if v},
        "rotated_by": {k: "ville" for k, v in rotated.items() if v},
    }


def reset_record(day: int, account: str = "JDOE") -> dict[str, Any]:
    return {
        "account": account,
        "target": "appdb-dev-alpha",
        "reset_at": stamp(day),
        "seen": False,
        "expired": True,
        "delivery": {"method": "vault_wrapped"},
        "by": {"host": "laptop", "pid": 7, "os_user": "ville"},
    }


class FakeSession:
    def __init__(self, users: Mapping[str, UserState]) -> None:
        self.users = users
        self.described: list[str] = []

    def scope(self) -> Scope:
        return Scope(type="pdb", db_version="23.0.0.0.0", capabilities=frozenset())

    def describe_user(self, account: str) -> UserState | None:
        self.described.append(account)
        return self.users.get(account.upper())

    def verify_password(self, *args: Any, **kwargs: Any) -> Any:
        raise AssertionError("report history must never attempt a login")

    def close(self) -> None:
        return None


Harness = Callable[..., MemoryStore]

#: The targets a test's driver connected to, so a test can say none was.
connected: list[Any] = []


@pytest.fixture
def estate(monkeypatch: pytest.MonkeyPatch) -> Harness:
    def install(
        *, connect_error: Exception | None = None, store: MemoryStore | None = None
    ) -> MemoryStore:
        connected.clear()
        if store is None:
            store = MemoryStore()
            # v1: both seeded; v2: web rotated; v3: batch rotated.
            store.write("apps/acme/db", app_document(stamp(1), stamp(1)), cas=0)
            store.write("apps/acme/db", app_document(stamp(2), stamp(1)), cas=1)
            store.write("apps/acme/db", app_document(stamp(2), stamp(3)), cas=2)
            record = "sopuli/personal-resets/appdb-dev-alpha/jdoe"
            store.write(record, reset_record(4), cas=0)
            store.write(record, reset_record(6), cas=1)
            store.write(
                "sopuli/personal-resets/appdb-dev-alpha/kroe", reset_record(5, "KROE"), cas=0
            )

        users = {
            "ACME_WEB_USER": UserState(
                name="ACME_WEB_USER", status="OPEN", password_changed_at=CHANGED
            ),
            "ACME_BATCH_USER": UserState(
                name="ACME_BATCH_USER",
                status="OPEN",
                password_changed_unknown="needs SELECT ON SYS.USER$",
            ),
            "JDOE": UserState(name="JDOE", status="OPEN", password_changed_at=CHANGED),
            "ACME_STRAY_USER": UserState(
                name="ACME_STRAY_USER", status="OPEN", password_changed_at=CHANGED
            ),
        }

        def fake_connect(
            vault: Vault, *, env: Mapping[str, str], token_file: Path | None = None
        ) -> SecretStore:
            assert store is not None
            return store

        class FakeDriver:
            def __init__(self, context: Any) -> None:
                pass

            def connect(self, target: Any, credential: Any) -> FakeSession:
                connected.append(target)
                if connect_error is not None:
                    raise connect_error
                return FakeSession(users)

        monkeypatch.setattr("sopuli.cli.connect", fake_connect)
        monkeypatch.setattr("sopuli.cli.driver_for", lambda target, context: FakeDriver(context))
        monkeypatch.setattr("sopuli.cli.admin_resolve", lambda target, **_: CREDENTIAL)
        return store

    return install


def report(write_config: WriteConfig, *args: str, config: str = CONFIG) -> Result:
    path = write_config(config)
    return CliRunner().invoke(cli, ["--config", str(path), "report", "history", *args])


def json_report(write_config: WriteConfig, *args: str) -> dict[str, Any]:
    path = write_config(CONFIG)
    result = CliRunner().invoke(
        cli, ["--config", str(path), "--output", "json", "report", "history", *args]
    )
    document: dict[str, Any] = json.loads(result.output)
    Draft202012Validator(RUN_SCHEMA).validate(document)
    return document


def flat(result: Result) -> str:
    """The text with its table padding collapsed, so a row reads as one line."""
    return " ".join(click.unstyle(result.output).split())


def test_each_account_gets_its_own_rotations(write_config: WriteConfig, estate: Harness) -> None:
    estate()
    result = report(write_config)
    text = flat(result)

    assert result.exit_code == ExitCode.SUCCESS, result.output
    web, batch = text.split("acme_batch_user (application)")
    assert "2026-11-02T03:00:00Z rotation v2 ville" in web
    assert "2026-11-01T03:00:00Z rotation v1 ville" in web
    assert "2026-11-03" not in web
    assert "2026-11-03T03:00:00Z rotation v3 ville" in batch
    assert "history from v1" in text
    assert "database changed: 2026-11-07T03:00:05Z" in web
    assert "database changed: unknown, needs SELECT ON SYS.USER$" in batch
    assert SECRET not in result.output


def test_a_personal_accounts_resets_come_from_its_record(
    write_config: WriteConfig, estate: Harness
) -> None:
    estate()
    text = flat(report(write_config, "--account", "jdoe"))

    assert "JDOE (personal)" in text
    assert "2026-11-06T03:00:00Z reset (not seen) v2 ville@laptop" in text
    assert "acme_web_user" not in text


def test_a_named_personal_account_with_no_record_has_nothing_recorded(
    write_config: WriteConfig, estate: Harness
) -> None:
    estate()
    text = click.unstyle(report(write_config, "--account", "asmith").output)

    assert "asmith  (personal)" in text
    assert "nothing recorded" in text


def test_the_json_validates(write_config: WriteConfig, estate: Harness) -> None:
    estate()
    document = json_report(write_config)

    assert document["command"] == "report.history"
    web = next(one for one in document["results"] if one["account"] == "acme_web_user")
    assert web["state"] == "REPORT_OK"
    assert [e["version"] for e in web["history"]["events"]] == [2, 1]
    assert web["history"]["db_changed_at"] == "2026-11-07T03:00:05Z"
    assert SECRET not in json.dumps(document)


def test_a_gap_exits_4(write_config: WriteConfig, estate: Harness) -> None:
    store = estate()
    original = store.read

    def unreadable_v2(path: str, *, version: int | None = None) -> Any:
        if path == "apps/acme/db" and version == 2:
            return None
        return original(path, version=version)

    store.read = unreadable_v2  # type: ignore[method-assign]
    result = report(write_config)

    assert result.exit_code == ExitCode.PARTIAL, result.output
    assert "not checked: version 2 could not be read" in click.unstyle(result.output)


def test_an_unreachable_target_still_shows_the_store_history_and_exits_1(
    write_config: WriteConfig, estate: Harness
) -> None:
    estate(connect_error=ConnectionError("listener down"))
    result = report(write_config)
    text = flat(result)

    assert result.exit_code == ExitCode.FAILURE
    assert "could not connect" in text
    assert "2026-11-02T03:00:00Z rotation v2" in text


def test_another_product_is_refused_and_exits_5(write_config: WriteConfig) -> None:
    result = report(write_config, config=PG_CONFIG)

    assert result.exit_code == ExitCode.UNSUPPORTED_CAPABILITY, result.output
    assert "not supported" in click.unstyle(result.output)


def test_account_names_one_nobody_manages(write_config: WriteConfig, estate: Harness) -> None:
    estate()
    text = click.unstyle(report(write_config, "--account", "acme_typo_user").output)

    # Not managed, and the database has no such account either.
    assert "no managed account acme_typo_user on this target" in text


def test_an_unmanaged_account_shows_only_its_database_date(
    write_config: WriteConfig, estate: Harness
) -> None:
    """UC-5 §6: for an account the tool does not manage, only the database's date."""
    estate()
    result = report(write_config, "--account", "acme_stray_user")
    text = flat(result)

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert "acme_stray_user (undeclared)" in text
    assert "database changed: 2026-11-07T03:00:05Z" in text
    assert "does not manage this account's password" in text


def test_a_target_with_nothing_to_describe_is_not_connected_to(
    write_config: WriteConfig, estate: Harness
) -> None:
    estate()
    nothing = CONFIG.split("applications:")[0]
    result = report(write_config, config=nothing)

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert "no account here has a password the tool manages" in flat(result)
    assert connected == []


# ------------------------------------------------- what #1401's review found ---

NO_RECORDS_CONFIG = CONFIG.split("reset_records:")[0]
RECORDS_ONLY_CONFIG = CONFIG.replace("personal_accounts:\n  - accounts: [jdoe, asmith]\n", "")


def test_a_records_listing_that_fails_is_said_even_with_no_named_account(
    write_config: WriteConfig, estate: Harness
) -> None:
    store = estate()

    def refused(prefix: str) -> tuple[str, ...]:
        raise ConnectionError("vault sealed")

    store.list = refused  # type: ignore[method-assign]
    result = report(write_config, config=RECORDS_ONLY_CONFIG)

    assert result.exit_code == ExitCode.FAILURE, result.output
    assert "reset records (personal)" in flat(result)
    assert "the store gave no answer" in flat(result)


def test_without_reset_records_a_named_account_shows_its_database_date(
    write_config: WriteConfig, estate: Harness
) -> None:
    """UC-5 §6: a reset with no records store writes no record, so only the
    database's date is shown, said in a note."""
    estate()
    result = report(write_config, "--account", "jdoe", config=NO_RECORDS_CONFIG)
    text = flat(result)

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert "database changed: 2026-11-07T03:00:05Z" in text
    assert "note: no `reset_records:` store is declared" in text


def test_account_naming_an_application_account_does_not_ask_the_records(
    write_config: WriteConfig, estate: Harness
) -> None:
    store = estate()

    def refused(prefix: str) -> tuple[str, ...]:
        raise ConnectionError("vault sealed")

    store.list = refused  # type: ignore[method-assign]
    result = report(write_config, "--account", "acme_web_user", config=RECORDS_ONLY_CONFIG)

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert "reset records" not in flat(result)


def test_every_version_read_failing_is_a_store_with_no_answer(
    write_config: WriteConfig, estate: Harness
) -> None:
    store = estate()
    original = store.read

    def forbidden(path: str, *, version: int | None = None) -> Any:
        if path == "apps/acme/db" and version is not None:
            raise PermissionError("403 permission denied on data/")
        return original(path, version=version)

    store.read = forbidden  # type: ignore[method-assign]
    result = report(write_config, "--account", "acme_web_user")

    assert result.exit_code == ExitCode.FAILURE, result.output
    assert "403 permission denied" in flat(result)


def test_a_version_whose_read_fails_is_a_gap_not_a_failure(
    write_config: WriteConfig, estate: Harness
) -> None:
    store = estate()
    original = store.read

    def failing_v2(path: str, *, version: int | None = None) -> Any:
        if path == "apps/acme/db" and version == 2:
            raise ConnectionError("one read failed")
        return original(path, version=version)

    store.read = failing_v2  # type: ignore[method-assign]
    result = report(write_config)

    assert result.exit_code == ExitCode.PARTIAL, result.output
    assert "version 2 could not be read" in flat(result)


def test_only_the_stamps_are_kept_from_a_version() -> None:
    document = {**app_document(stamp(1), stamp(1)), "previous": {"acme_web_user": "old"}}

    kept = cli_module._history_fields(document)

    assert kept is not None
    assert set(kept) == {"rotated_at", "rotated_by"}
    assert SECRET not in json.dumps(kept)


def test_account_reads_only_the_record_it_names(write_config: WriteConfig, estate: Harness) -> None:
    store = estate()
    asked: list[str] = []
    original = store.read

    def watched(path: str, *, version: int | None = None) -> Any:
        asked.append(path)
        return original(path, version=version)

    store.read = watched  # type: ignore[method-assign]
    report(write_config, "--account", "jdoe")

    assert not any(path.endswith("/kroe") for path in asked)


def test_a_layout_the_adapter_refuses_is_not_checked_not_unanswered(
    write_config: WriteConfig, estate: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    estate()

    def refuse(store: Any, path: str) -> Any:
        raise LayoutChangedError("the secret's layout changed")

    monkeypatch.setattr("sopuli.cli._secret_versions", refuse)
    result = report(write_config, "--account", "acme_web_user")

    assert result.exit_code == ExitCode.PARTIAL, result.output
    assert "not checked: the secret's layout changed" in flat(result)


NATIVE_CONFIG = (
    CONFIG.replace(
        "vaults:\n  vault-dev:\n    type: hashicorp\n"
        "    addr: https://vault-dev.example.com:8200\n",
        OCI_VAULT,
    )
    .replace("vault: vault-dev", "vault: vault-oci")
    .replace("[acme_web_user, acme_batch_user]", "[acme_web_user]")
    .replace('"apps/acme/db#DB_CREDENTIALS/{account}"', '"acme-db#password"')
    .split("personal_accounts:")[0]
)


def test_a_native_secret_lists_its_versions_by_generation(
    write_config: WriteConfig, estate: Harness
) -> None:
    store = staging_store()
    seed(store, "acme-db", {"password": "first"}, {"password": "second", "previous": "first"})
    estate(store=store)
    path = write_config(NATIVE_CONFIG)
    result = CliRunner().invoke(
        cli, ["--config", str(path), "--output", "json", "report", "history"]
    )

    document = json.loads(result.output)
    Draft202012Validator(RUN_SCHEMA).validate(document)
    entry = document["results"][0]
    assert entry["history"]["note"].startswith("the store keeps the promotion time")
    assert {e["kind"] for e in entry["history"]["events"]} >= {"generated"}
    assert "first" not in result.output
    assert "second" not in result.output
