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
from sopuli.config import ArgumentError
from sopuli.config.model import Vault
from sopuli.diagnostics import ORPHANS_UNREAD, UNADDRESSABLE_LOCK_PATH, UNLISTABLE_STORE
from sopuli.exit_codes import ExitCode
from sopuli.lock.record import Holder, LockRecord
from sopuli.orphans import delete_command, is_sopuli_document
from sopuli.output.document import SCHEMA_VERSION
from sopuli.store import CAS, MemoryStore, SecretStore, StoreError
from sopuli.store.protocol import LIST, Stored

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

#: `CONFIG` plus an application on a target that names no store. Legal: a
#: profile's `vault:` or SOPULI_VAULT completes it at run time (C15).
UNFIXED = CONFIG.replace(
    "applications:\n",
    """  - name: appdb-gamma
    type: oracle
    dsn: db-dev.example.com:1521/gamma.pdb.example.com
    environment: dev
applications:
""",
).replace(
    '    secret_template: "acme/db/alpha#DB_CREDENTIALS/{account}"\n',
    """    targets: [appdb-alpha]
    secret_template: "acme/db/alpha#DB_CREDENTIALS/{account}"
  - name: beta
    accounts: [acme_beta_user]
    targets: [appdb-gamma]
    secret_template: "acme/beta/db#DB_CREDENTIALS/{account}"
""",
)

#: The start of every delete command for a record in `vault-dev`.
DELETE_DEV = "vault kv metadata delete -address=https://vault-dev.example.com:8200 -mount=kv"

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
    assert found(result)[0]["delete_command"] == f"{DELETE_DEV} acme/alpha/db"
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
    assert f"  {DELETE_DEV} acme/alpha/db" in result.output
    assert f"  {DELETE_DEV} locks/acme/alpha/db" in result.output


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
    assert entry["delete_command"] == (
        "vault kv metadata delete -address=https://vault-old.example.com:8200 "
        "-mount=secret acme/alpha/db"
    )


def test_a_binding_whose_store_is_chosen_at_run_time_is_declared_in_every_store(
    write_config: Callable[[str], Path],
    with_records: Records,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Its store comes from SOPULI_VAULT or a profile, which a rotation job may
    set to either store. Its live document must not be offered for deletion."""
    monkeypatch.delenv("SOPULI_VAULT", raising=False)
    with_records(
        ("vault-dev", "acme/beta/db", PROMOTED),
        ("vault-old", "acme/beta/db", PROMOTED),
        ("vault-old", "locks/acme/beta/db", released()),
    )
    result = run(write_config(UNFIXED), "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert found(result) == []


def test_a_document_the_store_will_not_let_it_read_is_a_warning(
    write_config: Callable[[str], Path],
    with_records: Records,
    monkeypatch: pytest.MonkeyPatch,
    validator: Draft202012Validator,
) -> None:
    """On a shared mount another team's path may be listable and not readable.
    That must not end the survey."""
    stores = with_records(
        ("vault-dev", "acme/alpha/db", PROMOTED),
        ("vault-dev", "other/team/db", {"password": "x"}),
    )
    store = stores["vault-dev"]
    read = store.read

    def refuse(path: str, *, version: int | None = None) -> Stored | None:
        if path == "other/team/db":
            raise RefusedError("permission denied")
        return read(path, version=version)

    monkeypatch.setattr(store, "read", refuse)
    result = run(write_config(CONFIG), "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS
    document = json.loads(result.output)
    validator.validate(document)
    assert [entry["path"] for entry in found(result)] == ["acme/alpha/db"]
    [warning] = document["diagnostics"]
    assert warning["code"] == ORPHANS_UNREAD
    assert "'other/team/db': permission denied" in warning["message"]


class RefusedError(StoreError):
    """A 403, as the HashiCorp backend reports one."""

    category = "authorization"


def test_a_store_that_stops_answering_is_not_read_to_the_end(
    write_config: Callable[[str], Path],
    with_records: Records,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A seal or a timeout is the store's, and every later read would wait it out."""
    stores = with_records(
        ("vault-dev", "a/first", PROMOTED),
        ("vault-dev", "b/second", PROMOTED),
    )
    store = stores["vault-dev"]
    reads: list[str] = []

    def sealed(path: str, *, version: int | None = None) -> Stored | None:
        reads.append(path)
        raise StoreError("Vault is sealed")

    monkeypatch.setattr(store, "read", sealed)
    result = run(write_config(CONFIG), "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS
    assert reads == ["a/first"]
    [warning] = json.loads(result.output)["diagnostics"]
    assert warning["code"] == ORPHANS_UNREAD
    assert "stopped reading store 'vault-dev'" in warning["message"]
    assert "Vault is sealed" in warning["message"]


def test_a_listing_the_store_refuses_is_a_warning(
    write_config: Callable[[str], Path],
    with_records: Records,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stores = with_records(
        ("vault-dev", "acme/alpha/db", PROMOTED),
        ("vault-old", "acme/alpha/db", PROMOTED),
    )
    _refuse_listing(stores["vault-dev"], monkeypatch)
    result = run(write_config(CONFIG), "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS
    assert [entry["vault"] for entry in found(result)] == ["vault-old"]
    [warning] = json.loads(result.output)["diagnostics"]
    assert "stopped reading store 'vault-dev'" in warning["message"]


def _refuse_listing(store: SecretStore, monkeypatch: pytest.MonkeyPatch) -> None:
    def refused(prefix: str) -> tuple[str, ...]:
        raise RefusedError("permission denied")

    monkeypatch.setattr(store, "list", refused)


def test_no_store_listed_is_a_failure(
    write_config: Callable[[str], Path],
    with_records: Records,
    monkeypatch: pytest.MonkeyPatch,
    validator: Draft202012Validator,
) -> None:
    """An empty report from a run that looked nowhere would read as a clean estate (#1018)."""
    stores = with_records(("vault-dev", "acme/alpha/db", PROMOTED), ("vault-old", "x", PROMOTED))
    for store in stores.values():
        _refuse_listing(store, monkeypatch)
    config = write_config(CONFIG)
    result = run(config, "--output", "json")

    assert result.exit_code == ExitCode.FAILURE
    document = json.loads(result.output)
    validator.validate(document)
    assert document["exit_code"] == ExitCode.FAILURE
    assert document["error"]["category"] == "vault"
    assert "vault-dev, vault-old" in document["error"]["message"]
    assert document["orphans"] == {"listed": [], "found": []}
    assert [entry["code"] for entry in document["diagnostics"]] == [ORPHANS_UNREAD] * 2

    text = run(config)
    assert text.exit_code == ExitCode.FAILURE
    assert "no vault could be listed" in text.output


def test_one_store_listed_is_not_a_failure(
    write_config: Callable[[str], Path],
    with_records: Records,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stores = with_records(("vault-dev", "acme/alpha/db", PROMOTED), ("vault-old", "x", PROMOTED))
    _refuse_listing(stores["vault-old"], monkeypatch)
    result = run(write_config(CONFIG), "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS
    assert "error" not in json.loads(result.output)


def test_a_failed_listing_beside_an_unlistable_store_is_a_failure(
    write_config: Callable[[str], Path],
    with_records: Records,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exit 1, not 5: one store could list, and it failed."""
    stores = with_records(("vault-dev", "acme/alpha/db", PROMOTED))
    stores["vault-old"] = MemoryStore(capabilities=frozenset({CAS}))  # type: ignore[index]
    _refuse_listing(stores["vault-dev"], monkeypatch)
    result = run(write_config(CONFIG), "--output", "json")

    assert result.exit_code == ExitCode.FAILURE
    assert json.loads(result.output)["error"]["message"].endswith(": vault-dev")


def test_the_one_selected_store_failing_its_listing_is_a_failure(
    write_config: Callable[[str], Path],
    with_records: Records,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stores = with_records(("vault-dev", "acme/alpha/db", PROMOTED), ("vault-old", "x", PROMOTED))
    _refuse_listing(stores["vault-old"], monkeypatch)
    result = run(write_config(CONFIG), "--vault", "vault-old", "--output", "json")

    assert result.exit_code == ExitCode.FAILURE
    document = json.loads(result.output)
    assert document["error"]["message"].endswith(": vault-old")
    assert document["orphans"]["listed"] == []


def test_a_config_with_no_vault_says_so(write_config: Callable[[str], Path]) -> None:
    """Nothing is declared, so nothing failed, and the text does not say a listing failed."""
    config = write_config("version: 1\nvaults: {}\n")
    result = run(config)

    assert result.exit_code == ExitCode.SUCCESS
    assert "no vault in `vaults:`" in result.output


#: `CONFIG` with a second entry for `vault-dev`'s server and mount, as an estate
#: with one entry per auth method has.
TWO_NAMES = CONFIG.replace(
    "  vault-old:\n",
    """  vault-dev-ci:
    type: hashicorp
    addr: https://VAULT-DEV.example.com:8200/
    mount: kv
    auth: { method: approle, role_id: { env: ROLE_ID }, secret_id: { env: SECRET_ID } }
  vault-old:
""",
)


def test_two_entries_for_one_store_are_one_store(
    write_config: Callable[[str], Path], with_records: Records
) -> None:
    """A binding through either name declares the path for both. Surveyed as two,
    the live document would be reported in the other one, with a delete command."""
    stores = with_records(("vault-dev", "acme/db/alpha", PROMOTED))
    stores["vault-dev-ci"] = stores["vault-dev"]  # type: ignore[index]
    result = run(write_config(TWO_NAMES), "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert found(result) == []
    assert "in 2 vaults (vault-dev, vault-old)" in run(write_config(TWO_NAMES)).output


def test_a_declared_path_is_declared_in_every_store(
    write_config: Callable[[str], Path], with_records: Records
) -> None:
    """Two entries can name one store in ways no comparison catches, such as
    127.0.0.1 and localhost. A declared path is never reported in another store."""
    with_records(
        ("vault-old", "acme/db/alpha", PROMOTED),
        ("vault-old", "locks/acme/db/alpha", released()),
    )
    result = run(write_config(CONFIG), "--output", "json")

    assert found(result) == []


def test_two_spellings_of_one_lock_are_two_records(
    write_config: Callable[[str], Path], with_records: Records
) -> None:
    with_records(
        ("vault-dev", "locks/acme/alpha/db", released()),
        ("vault-dev", "locks/acme//alpha/db", held()),
    )
    result = run(write_config(CONFIG), "--output", "json")

    entries = {entry["path"]: entry for entry in found(result)}
    assert set(entries) == {"locks/acme/alpha/db", "locks/acme//alpha/db"}
    assert entries["locks/acme//alpha/db"]["lock"]["held"] is True
    assert entries["locks/acme/alpha/db"]["lock"]["held"] is False


def test_credentials_in_the_address_are_masked() -> None:
    vault = Vault(name="v", type="hashicorp", addr="https://svc:pw@vault.example.com", mount="kv")
    command = delete_command(vault, "a/b")

    assert command is not None
    assert "pw" not in command
    assert "-address=https://***@vault.example.com" in command


def test_a_lock_is_named_by_the_path_the_store_listed(
    write_config: Callable[[str], Path], with_records: Records
) -> None:
    """The key is normalised, and a delete of the normalised path removes nothing."""
    with_records(("vault-dev", "locks/acme//alpha/db", released()))
    result = run(write_config(CONFIG), "--output", "json")

    [entry] = found(result)
    assert entry["path"] == "locks/acme//alpha/db"
    assert entry["delete_command"] == f"{DELETE_DEV} locks/acme//alpha/db"


def test_a_live_lock_withholds_the_command_for_a_secret_spelled_another_way(
    write_config: Callable[[str], Path], with_records: Records
) -> None:
    with_records(
        ("vault-dev", "acme//alpha/db", PROMOTED),
        ("vault-dev", "locks/acme/alpha/db", held()),
    )
    result = run(write_config(CONFIG), "--output", "json")

    assert [entry["delete_command"] for entry in found(result)] == [None, None]


def test_a_secret_on_a_store_with_no_compare_and_set_has_no_version(
    write_config: Callable[[str], Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A KV v1 version is a constant 0, which compares equal to everything."""
    _install(monkeypatch, frozenset({LIST}))(("vault-dev", "acme/alpha/db", PROMOTED))
    result = run(write_config(CONFIG), "--output", "json")

    [entry] = found(result)
    assert entry["version"] is None


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
    assert "No delete command is printed:" in text.output
    assert "To delete them:" not in text.output


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

    document = json.loads(result.output)
    validator.validate(document)
    assert found(result) == []
    assert document["orphans"]["listed"] == ["vault-dev", "vault-old"]
    assert "selection" not in document["invocation"]
    assert "no orphans in 2 vaults (vault-dev, vault-old)" in run(config).output


def _opened(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record the stores the run opens, on top of :func:`_install`'s patch."""
    import sopuli.cli

    opened: list[str] = []
    connect = sopuli.cli.connect  # type: ignore[attr-defined]

    def recording(vault: Vault, **kwargs: Any) -> SecretStore:
        opened.append(vault.name)
        return connect(vault, **kwargs)

    monkeypatch.setattr("sopuli.cli.connect", recording)
    return opened


def test_vault_surveys_only_the_named_store(
    write_config: Callable[[str], Path],
    with_records: Records,
    monkeypatch: pytest.MonkeyPatch,
    validator: Draft202012Validator,
) -> None:
    """#1015: the other store is not opened, so one the run cannot reach can be
    left out, and the run says what it covered."""
    with_records(
        ("vault-dev", "acme/alpha/db", PROMOTED),
        ("vault-old", "acme/gamma/db", PROMOTED),
    )
    opened = _opened(monkeypatch)
    config = write_config(CONFIG)
    result = run(config, "--vault", "vault-old", "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    document = json.loads(result.output)
    validator.validate(document)
    assert opened == ["vault-old"]
    assert [(entry["vault"], entry["path"]) for entry in found(result)] == [
        ("vault-old", "acme/gamma/db")
    ]
    assert document["orphans"]["listed"] == ["vault-old"]
    assert document["invocation"]["selection"] == {"vaults": ["vault-old"]}
    assert "1 orphan in 1 vault (vault-old)" in run(config, "--vault", "vault-old").output


def test_vault_is_repeatable(write_config: Callable[[str], Path], with_records: Records) -> None:
    with_records(("vault-dev", "acme/alpha/db", PROMOTED))
    result = run(
        write_config(CONFIG), "--vault", "vault-old", "--vault", "vault-dev", "--output", "json"
    )

    assert json.loads(result.output)["orphans"]["listed"] == ["vault-dev", "vault-old"]
    assert [entry["vault"] for entry in found(result)] == ["vault-dev"]


def test_a_declared_path_is_declared_in_a_selected_store(
    write_config: Callable[[str], Path], with_records: Records
) -> None:
    """No binding names `vault-old`, and the bound path is still declared there."""
    with_records(("vault-old", "acme/db/alpha", PROMOTED))
    result = run(write_config(CONFIG), "--vault", "vault-old", "--output", "json")

    assert found(result) == []


def test_naming_either_entry_for_one_store_selects_it(
    write_config: Callable[[str], Path], with_records: Records, monkeypatch: pytest.MonkeyPatch
) -> None:
    """It is opened through the entry named, whose login the operator can use."""
    stores = with_records(("vault-dev", "acme/alpha/db", PROMOTED))
    stores["vault-dev-ci"] = stores["vault-dev"]  # type: ignore[index]
    opened = _opened(monkeypatch)
    result = run(write_config(TWO_NAMES), "--vault", "vault-dev-ci", "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert opened == ["vault-dev-ci"]
    assert json.loads(result.output)["orphans"]["listed"] == ["vault-dev-ci"]
    assert [(entry["vault"], entry["path"]) for entry in found(result)] == [
        ("vault-dev-ci", "acme/alpha/db")
    ]


def test_naming_both_entries_for_one_store_lists_it_once(
    write_config: Callable[[str], Path], with_records: Records, monkeypatch: pytest.MonkeyPatch
) -> None:
    stores = with_records(("vault-dev", "acme/alpha/db", PROMOTED))
    stores["vault-dev-ci"] = stores["vault-dev"]  # type: ignore[index]
    opened = _opened(monkeypatch)
    result = run(
        write_config(TWO_NAMES),
        "--vault",
        "vault-dev-ci",
        "--vault",
        "vault-dev",
        "--output",
        "json",
    )

    assert opened == ["vault-dev-ci"]
    assert len(found(result)) == 1


def test_a_vault_the_config_does_not_declare_is_refused(
    write_config: Callable[[str], Path], with_records: Records, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A selector filters the declared set and cannot extend it (invariant 5).

    `main` turns the error into exit 2; `CliRunner` hands back the exception."""
    with_records()
    opened = _opened(monkeypatch)
    result = run(write_config(CONFIG), "--vault", "vault-prod")

    assert isinstance(result.exception, ArgumentError)
    assert "not declared in the configuration: `vault-prod`" in str(result.exception)
    assert "vault-dev, vault-old" in (result.exception.hint or "")
    assert opened == []


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
    write_config: Callable[[str], Path], with_records: Records
) -> None:
    stores = with_records()
    stores["vault-old"] = MemoryStore(capabilities=frozenset({CAS}))  # type: ignore[index]
    config = write_config(CONFIG)
    result = run(config, "--output", "json")

    assert result.exit_code == ExitCode.SUCCESS
    [warning] = json.loads(result.output)["diagnostics"]
    assert warning["code"] == UNLISTABLE_STORE
    assert "could not list store 'vault-old'" in warning["message"]

    text = run(config).output
    assert "no orphans in 1 vault (vault-dev)" in text, "an unlisted store is not counted"


def test_no_store_that_can_list_is_a_capability_refusal(
    write_config: Callable[[str], Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """An empty report would read as a clean estate (invariant 4)."""
    _install(monkeypatch, frozenset({CAS}))()
    result = run(write_config(CONFIG), "--output", "json")

    document = json.loads(result.output)
    assert document["exit_code"] == ExitCode.UNSUPPORTED_CAPABILITY
    assert document["error"]["category"] == "capability"
    assert "orphans" not in document


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
