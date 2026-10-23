"""``sopuli vault orphans`` -- records no binding declares (#999).

Tier 0: in-process through ``CliRunner``, with ``sopuli.cli.connect`` patched to
hand back :class:`~sopuli.store.MemoryStore` instances, as
``test_cli_lock_status.py`` does.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner, Result
from jsonschema import Draft202012Validator

from sopuli.cli import cli
from sopuli.config.model import Vault
from sopuli.diagnostics import UNADDRESSABLE_LOCK_PATH, UNLISTABLE_STORE
from sopuli.exit_codes import ExitCode
from sopuli.lock.record import Holder, LockRecord
from sopuli.orphans import delete_command, is_sopuli_document
from sopuli.output.document import SCHEMA_VERSION
from sopuli.store import CAS, MemoryStore, SecretStore

RUN_SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "schemas"
    / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
)

#: Two stores. Only `vault-dev` is bound, so `vault-old` is a store the config
#: stopped using.
CONFIG = """\
version: 1
vaults:
  vault-dev:
    type: hashicorp
    addr: https://vault-dev.example.com:8200
    mount: kv
  vault-old:
    type: hashicorp
    addr: https://vault-old.example.com:8200
targets:
  - name: appdb-alpha
    type: oracle
    dsn: db-dev.example.com:1521/alpha.pdb.example.com
    environment: dev
    vault: vault-dev
applications:
  - name: acme
    accounts: [acme_web_user]
    secret_template: "acme/db/alpha#DB_CREDENTIALS/{account}"
"""

RESETS = (
    CONFIG
    + """\
reset_records:
  vault: vault-dev
  prefix: sopuli/personal-resets
"""
)

#: What `creds generate` leaves, and what a promotion leaves.
STAGED = {"pending": {"acme_web_user": "x"}, "origin": {"acme_web_user": "generated"}}
PROMOTED = {"DB_CREDENTIALS": {"acme_web_user": "x"}, "rotated_at": {"acme_web_user": "t"}}

HOLDER = Holder(host="ci-runner-3", pid=8821, os_user="svc_sopuli")


def held(*, now: datetime | None = None) -> dict[str, Any]:
    moment = now if now is not None else datetime.now(UTC)
    return LockRecord.acquired(
        correlation_id="01JTHEIRS", command="creds rotate", holder=HOLDER, now=moment
    ).to_dict()


def released() -> dict[str, Any]:
    return (
        LockRecord.acquired(
            correlation_id="01JTHEIRS", command="creds rotate", holder=HOLDER, now=datetime.now(UTC)
        )
        .released()
        .to_dict()
    )


Records = Callable[..., Mapping[str, SecretStore]]


def _install(monkeypatch: pytest.MonkeyPatch, capabilities: frozenset[str] | None) -> Records:
    def install(*records: tuple[str, str, dict[str, Any]]) -> Mapping[str, SecretStore]:
        stores: dict[str, SecretStore] = {}

        def store(name: str) -> SecretStore:
            if name not in stores:
                stores[name] = (
                    MemoryStore()
                    if capabilities is None
                    else MemoryStore(capabilities=capabilities)
                )
            return stores[name]

        for name, path, data in records:
            store(name).write(path, data, cas=None)

        def fake_connect(
            vault: Vault, *, env: Mapping[str, str], token_file: Path | None = None
        ) -> SecretStore:
            return store(vault.name)

        monkeypatch.setattr("sopuli.cli.connect", fake_connect)
        return stores

    return install


@pytest.fixture
def with_records(monkeypatch: pytest.MonkeyPatch) -> Records:
    """Patch the store the command opens, holding the records a test names."""
    return _install(monkeypatch, None)


@pytest.fixture
def validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(RUN_SCHEMA.read_text(encoding="utf-8")))


def run(config: Path, *args: str) -> Result:
    return CliRunner().invoke(cli, ["vault", "orphans", "--config", str(config), *args])


def found(result: Result) -> list[dict[str, Any]]:
    return list(json.loads(result.output)["orphans"]["found"])


def test_a_moved_secret_and_its_lock_are_reported(
    write_config: Callable[[str], Path], with_records: Records, validator: Draft202012Validator
) -> None:
    with_records(
        ("vault-dev", "acme/alpha/db", PROMOTED),
        ("vault-dev", "locks/acme/alpha/db", released()),
    )
    result = run(write_config(CONFIG), "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS
    document = json.loads(result.output)
    validator.validate(document)
    assert document["command"] == "vault.orphans"
    assert [(entry["path"], entry["kind"]) for entry in found(result)] == [
        ("acme/alpha/db", "secret"),
        ("locks/acme/alpha/db", "lock"),
    ]
    assert found(result)[0]["delete_command"] == "vault kv metadata delete -mount=kv acme/alpha/db"
    assert found(result)[1]["lock"] == {"state": "released", "held": False, "expired": False}
    assert document["summary"]["total"] == 2


def test_the_text_view_prints_a_delete_command_per_record(
    write_config: Callable[[str], Path], with_records: Records
) -> None:
    with_records(
        ("vault-dev", "acme/alpha/db", STAGED),
        ("vault-dev", "locks/acme/alpha/db", released()),
    )
    result = run(write_config(CONFIG))

    assert result.exit_code == ExitCode.SUCCESS
    assert "2 orphans in 2 vaults (vault-dev, vault-old)" in result.output
    assert "  vault kv metadata delete -mount=kv acme/alpha/db" in result.output
    assert "  vault kv metadata delete -mount=kv locks/acme/alpha/db" in result.output


def test_declared_records_are_not_reported(
    write_config: Callable[[str], Path], with_records: Records
) -> None:
    with_records(
        ("vault-dev", "acme/db/alpha", PROMOTED),
        ("vault-dev", "locks/acme/db/alpha", released()),
    )
    result = run(write_config(CONFIG), "--output", "json")

    assert found(result) == []


def test_a_document_this_tool_did_not_write_is_not_reported(
    write_config: Callable[[str], Path], with_records: Records
) -> None:
    """A mount is often shared. A document with no marker is somebody else's."""
    with_records(("vault-dev", "other/team/db", {"password": "x", "pending": "y"}))
    result = run(write_config(CONFIG), "--output", "json")

    assert found(result) == []


def test_a_store_no_binding_names_is_surveyed(
    write_config: Callable[[str], Path], with_records: Records
) -> None:
    with_records(("vault-old", "acme/alpha/db", PROMOTED))
    result = run(write_config(CONFIG), "--output", "json")

    [entry] = found(result)
    assert entry["vault"] == "vault-old"
    assert entry["delete_command"] == "vault kv metadata delete -mount=secret acme/alpha/db"


def test_reset_records_and_their_locks_are_this_estates(
    write_config: Callable[[str], Path], with_records: Records
) -> None:
    with_records(
        ("vault-dev", "sopuli/personal-resets/appdb-alpha/acme_dev_alice", {"rotated_at": "t"}),
        ("vault-dev", "locks/sopuli/personal-resets/appdb-alpha/acme_dev_alice", released()),
    )
    result = run(write_config(RESETS), "--output", "json")

    assert found(result) == []


def test_a_live_lock_withholds_both_delete_commands(
    write_config: Callable[[str], Path], with_records: Records, validator: Draft202012Validator
) -> None:
    """Somebody may be rotating the path, from a config that still declares it."""
    with_records(
        ("vault-dev", "acme/alpha/db", PROMOTED),
        ("vault-dev", "locks/acme/alpha/db", held()),
    )
    config = write_config(CONFIG)
    result = run(config, "--output", "json")

    validator.validate(json.loads(result.output))
    assert [entry["delete_command"] for entry in found(result)] == [None, None]
    assert found(result)[1]["lock"]["held"] is True

    text = run(config)
    assert "metadata delete" not in text.output
    assert "a live lock stands on acme/alpha/db" in text.output


def test_an_expired_lock_does_not_withhold_them(
    write_config: Callable[[str], Path], with_records: Records
) -> None:
    with_records(
        ("vault-dev", "acme/alpha/db", PROMOTED),
        ("vault-dev", "locks/acme/alpha/db", held(now=datetime.now(UTC) - timedelta(days=2))),
    )
    result = run(write_config(CONFIG), "--output", "json")

    assert all(entry["delete_command"] is not None for entry in found(result))
    assert found(result)[1]["lock"]["expired"] is True


def test_a_clean_estate_emits_an_empty_section(
    write_config: Callable[[str], Path], with_records: Records, validator: Draft202012Validator
) -> None:
    with_records()
    config = write_config(CONFIG)
    result = run(config, "--output", "json")

    validator.validate(json.loads(result.output))
    assert found(result) == []
    assert "no orphans in 2 vaults (vault-dev, vault-old)" in run(config).output


def test_it_writes_nothing(write_config: Callable[[str], Path], with_records: Records) -> None:
    stores = with_records(
        ("vault-dev", "acme/alpha/db", PROMOTED),
        ("vault-dev", "locks/acme/alpha/db", released()),
    )
    before = {path: stores["vault-dev"].read(path) for path in stores["vault-dev"].list("")}
    run(write_config(CONFIG))

    after = {path: stores["vault-dev"].read(path) for path in stores["vault-dev"].list("")}
    assert after == before


def test_a_store_that_cannot_be_listed_warns(
    write_config: Callable[[str], Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    _install(monkeypatch, frozenset({CAS}))()
    result = run(write_config(CONFIG), "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS
    [warning] = json.loads(result.output)["diagnostics"]
    assert warning["code"] == UNLISTABLE_STORE
    assert "no orphan in them would appear" in warning["message"]


def test_a_secret_path_the_tool_refuses_is_named_in_a_warning(
    write_config: Callable[[str], Path], with_records: Records
) -> None:
    with_records(("vault-dev", "acme/bad%3Fkey", PROMOTED))
    result = run(write_config(CONFIG), "--output", "json")

    [warning] = json.loads(result.output)["diagnostics"]
    assert warning["code"] == UNADDRESSABLE_LOCK_PATH
    assert "skipped the record at 'acme/bad%3Fkey'" in warning["message"]
    assert found(result) == []


@pytest.mark.parametrize(
    ("vault", "expected"),
    [
        (Vault(name="v", type="hashicorp", mount="kv"), "vault kv metadata delete -mount=kv a/b"),
        (Vault(name="v", type="hashicorp", kv_version=1), "vault kv delete -mount=secret a/b"),
        (
            Vault(name="v", type="hashicorp", mount="kv", namespace="team-a"),
            "vault kv metadata delete -namespace=team-a -mount=kv a/b",
        ),
        (Vault(name="v", type="file"), None),
    ],
)
def test_the_delete_command_follows_the_store(vault: Vault, expected: str | None) -> None:
    assert delete_command(vault, "a/b") == expected


def test_a_path_with_a_space_is_quoted() -> None:
    vault = Vault(name="v", type="hashicorp", mount="kv")
    assert delete_command(vault, "a b/c") == "vault kv metadata delete -mount=kv 'a b/c'"


@pytest.mark.parametrize(
    ("data", "expected"),
    [(STAGED, True), (PROMOTED, True), ({"password": "x"}, False), ("text", False), (None, False)],
)
def test_the_shape_test(data: Any, expected: bool) -> None:
    assert is_sopuli_document(data) is expected
