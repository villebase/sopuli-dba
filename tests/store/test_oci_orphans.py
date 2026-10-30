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
from sopuli.config.model import Vault, VaultAuth
from sopuli.exit_codes import ExitCode
from sopuli.lock.record import Holder, LockRecord
from sopuli.orphans import delete_command
from sopuli.output.document import SCHEMA_VERSION
from sopuli.store.oci import OciStore
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


SECRET_ID = "ocid1.vaultsecret.oc1..exampleuniqueid"


def oci_vault(**settings: Any) -> Vault:
    return Vault(
        name="v",
        type="oci",
        vault_id=VAULT_ID,
        compartment_id=COMPARTMENT_ID,
        key_id=KEY_ID,
        **settings,
    )


@pytest.mark.parametrize(
    ("vault", "expected"),
    [
        (oci_vault(), f"{DELETE} {SECRET_ID}"),
        (oci_vault(region="eu-frankfurt-1"), f"{DELETE} {SECRET_ID} --region eu-frankfurt-1"),
        (
            oci_vault(auth=VaultAuth(method="config_file", profile="SOPULI")),
            f"{DELETE} {SECRET_ID} --profile SOPULI",
        ),
        (
            oci_vault(auth=VaultAuth(method="session_token", profile="SOPULI_SESSION")),
            f"{DELETE} {SECRET_ID} --profile SOPULI_SESSION --auth security_token",
        ),
        (
            oci_vault(auth=VaultAuth(method="session_token")),
            f"{DELETE} {SECRET_ID} --auth security_token",
        ),
        (
            oci_vault(auth=VaultAuth(method="instance_principal")),
            f"{DELETE} {SECRET_ID} --auth instance_principal",
        ),
        (
            oci_vault(auth=VaultAuth(method="resource_principal")),
            f"{DELETE} {SECRET_ID} --auth resource_principal",
        ),
    ],
)
def test_the_oci_delete_command_follows_the_store(vault: Vault, expected: str) -> None:
    assert delete_command(vault, "a", native_id=SECRET_ID) == expected


def test_no_oci_delete_command_without_an_id() -> None:
    assert delete_command(oci_vault(), "a") is None
