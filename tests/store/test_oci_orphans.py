"""``vault orphans`` on an OCI store names each record as OCI does (#1186).

Tier 0: ``sopuli.cli.connect`` hands back an :class:`OciStore` over
``tests/store/oci_fake.py``.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner, Result
from jsonschema import Draft202012Validator
from oci_fake import COMPARTMENT_ID, KEY_ID, VAULT_ID, FakeOci

from sopuli.cli import cli
from sopuli.config.model import Vault
from sopuli.exit_codes import ExitCode
from sopuli.lock.keys import LockKey
from sopuli.lock.record import Holder, LockRecord
from sopuli.orphans import SECRET, Orphan, Survey
from sopuli.output.document import SCHEMA_VERSION
from sopuli.output.orphans_view import render
from sopuli.store.oci import Clients, OciStore, open_store
from sopuli.store.oci._names import CAS_KEY, RECORD_KEY
from sopuli.store.protocol import SecretStore

RUN_SCHEMA = (
    Path(__file__).resolve().parents[2]
    / "docs"
    / "schemas"
    / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
)

#: An OCI store whose one application is at `acme-new`, so `acme-old` and its
#: lock are what a moved application left behind.
CONFIG = f"""\
version: 1
vaults:
  vault-oci:
    type: oci
    vault_id: {VAULT_ID}
    compartment_id: {COMPARTMENT_ID}
    key_id: {KEY_ID}
targets:
  - name: appdb-alpha
    type: oracle
    dsn: db-dev.example.com:1521/alpha.pdb.example.com
    environment: dev
    vault: vault-oci
applications:
  - name: acme
    accounts: [acme_web_user]
    secret_template: "acme-new#password"
"""

HOLDER = Holder(host="ci-runner-3", pid=8821, os_user="svc_sopuli")

#: The start of every delete command for a record in `vault-oci`.
DELETE = "oci vault secret schedule-secret-deletion --secret-id"


def _lock(*, held: bool) -> dict[str, Any]:
    record = LockRecord.acquired(
        correlation_id="01JTHEIRS", command="creds rotate", holder=HOLDER, now=datetime.now(UTC)
    )
    return (record if held else record.released()).to_dict()


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeOci:
    """The OCI the command reaches, holding a moved application's records."""
    fake = FakeOci()
    fake.put("acme-old", {"password": "x", "origin": "generated"}, metadata={CAS_KEY: "1"})

    def fake_connect(
        vault: Vault, *, env: Mapping[str, str], token_file: Path | None = None
    ) -> SecretStore:
        return OciStore(
            vault, vaults=fake, secrets=fake, kms=fake, sleep=lambda _: None, monotonic=lambda: 0.0
        )

    monkeypatch.setattr("sopuli.cli.connect", fake_connect)
    return fake


def lock_at(fake: FakeOci, name: str, *, held: bool = False) -> None:
    fake.put(
        f"sopuli-locks.{name}",
        {},
        metadata={CAS_KEY: "2", RECORD_KEY: json.dumps(_lock(held=held))},
    )


def run(config: Path, *args: str) -> Result:
    return CliRunner().invoke(cli, ["vault", "orphans", "--config", str(config), *args])


def found(result: Result) -> list[dict[str, Any]]:
    return list(json.loads(result.output)["orphans"]["found"])


def test_a_record_is_named_as_oci_names_it(
    write_config: Callable[[str], Path], fake: FakeOci
) -> None:
    lock_at(fake, "acme-old")
    result = run(write_config(CONFIG), "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS
    document = json.loads(result.output)
    Draft202012Validator(json.loads(RUN_SCHEMA.read_text(encoding="utf-8"))).validate(document)
    assert [(entry["path"], entry["name"], entry["kind"]) for entry in found(result)] == [
        ("acme-old", "acme-old", "secret"),
        ("locks/acme-old", "sopuli-locks.acme-old", "lock"),
    ]


def test_each_record_gets_the_delete_command_for_its_ocid(
    write_config: Callable[[str], Path], fake: FakeOci
) -> None:
    lock_at(fake, "acme-old")
    result = run(write_config(CONFIG), "--output", "json")

    assert [entry["delete_command"] for entry in found(result)] == [
        f"{DELETE} {fake.secrets['acme-old'].id}",
        f"{DELETE} {fake.secrets['sopuli-locks.acme-old'].id}",
    ]


def test_the_text_view_shows_the_oci_names_and_the_commands(
    write_config: Callable[[str], Path], fake: FakeOci
) -> None:
    lock_at(fake, "acme-old")
    result = run(write_config(CONFIG))

    assert result.exit_code == ExitCode.SUCCESS
    assert "sopuli-locks.acme-old" in result.output
    assert "locks/acme-old" not in result.output
    assert f"  {DELETE} {fake.secrets['sopuli-locks.acme-old'].id}" in result.output


def test_a_live_lock_names_the_record_as_oci_does(
    write_config: Callable[[str], Path], fake: FakeOci
) -> None:
    lock_at(fake, "acme-old", held=True)
    result = run(write_config(CONFIG))

    assert "(none for vault-oci:sopuli-locks.acme-old: a live lock stands on acme-old;" in (
        result.output
    )
    assert DELETE not in result.output


def store_over(fake: FakeOci, *, cli_options: tuple[str, ...] = ()) -> OciStore:
    entry = Vault(
        name="vault-oci",
        type="oci",
        vault_id=VAULT_ID,
        compartment_id=COMPARTMENT_ID,
        key_id=KEY_ID,
    )
    return OciStore(entry, vaults=fake, secrets=fake, kms=fake, cli_options=cli_options)


def test_the_command_names_how_the_clients_reach_the_store() -> None:
    fake = FakeOci()
    fake.put("acme-old", {"origin": "generated"})
    store = store_over(fake, cli_options=("--profile", "ACME", "--region", "eu-stockholm-1"))
    store.list("")

    assert store.delete_command("acme-old") == (
        f"{DELETE} {fake.secrets['acme-old'].id} --profile ACME --region eu-stockholm-1"
    )


def test_open_store_hands_the_clients_cli_options_to_the_store() -> None:
    fake = FakeOci()
    fake.put("acme-old", {"origin": "generated"})
    entry = Vault(
        name="vault-oci",
        type="oci",
        vault_id=VAULT_ID,
        compartment_id=COMPARTMENT_ID,
        key_id=KEY_ID,
    )
    store = open_store(
        entry, Clients(vaults=fake, secrets=fake, kms=fake, cli_options=("--profile", "ACME"))
    )
    store.list("")

    assert store.delete_command("acme-old") == (
        f"{DELETE} {fake.secrets['acme-old'].id} --profile ACME"
    )


def test_no_command_for_a_secret_no_listing_held() -> None:
    fake = FakeOci()
    fake.put("acme-old", {"origin": "generated"})

    assert store_over(fake).delete_command("acme-old") is None


def test_every_listing_keeps_its_ids() -> None:
    """Under --prefix the survey lists twice, and the second keeps the first's."""
    fake = FakeOci()
    fake.put("acme-old", {"origin": "generated"})
    fake.put("sopuli-locks.acme-old", {})
    store = store_over(fake)
    store.list("")
    store.list("locks")

    assert store.delete_command("acme-old") is not None
    assert store.delete_command("locks/acme-old") is not None


def test_a_record_with_no_command_says_the_listing_gave_no_id() -> None:
    survey = Survey(
        orphans=(
            Orphan(
                key=LockKey(store="vault-oci", path="acme-old"),
                path="acme-old",
                kind=SECRET,
                native_name="acme-old",
            ),
        ),
        listed=("vault-oci",),
        seen=1,
    )
    text = render([Path("sopuli.yaml")], survey, [None])

    assert "(none for vault-oci:acme-old: the store's listing gave no id for it)" in text
