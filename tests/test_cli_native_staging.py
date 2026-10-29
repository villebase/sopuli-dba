"""The UC-1 verbs on a store that keeps stages as its own versions (#1134).

A one-account document on an OCI-typed store uses native staging: the pending
password is a PENDING version, so an application reading CURRENT never sees
it. A document of several accounts keeps payload fields, as on HashiCorp. The
store is ``MemoryStore`` with ``staging_labels``, patched where ``sopuli.cli``
imported ``connect``. ``apply`` and its rollback are in
``test_cli_creds_apply.py``, beside the database fakes they need.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner, Result
from jsonschema import Draft202012Validator

from native_estate import FIELD, OCI_VAULT, seed, staging_store, view
from sopuli.cli import cli
from sopuli.config.model import Vault
from sopuli.exit_codes import ExitCode
from sopuli.output.document import SCHEMA_VERSION
from sopuli.payload import CURRENT, PENDING, PREVIOUS
from sopuli.store import MemoryStore, SecretStore
from sopuli.store.native_view import PENDING_VERSION, LayoutChangedError

RUN_SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "schemas"
    / f"sopuli-run-{SCHEMA_VERSION}.schema.json"
)

#: One account per secret, the layout native staging is for.
CONFIG = (
    """\
version: 1
defaults:
  policy: app-standard
policies:
  app-standard:
    password: { length: 24, charset: alnum, first_char: alpha }
"""
    + OCI_VAULT
    + """\
targets:
  - name: appdb-alpha
    type: oracle
    dsn: db.example.com:1521/alpha.pdb.example.com
    environment: dev
    vault: vault-oci
applications:
  - name: acme
    accounts: [acme_web_user]
    secret_template: "acme-{account}#password"
"""
)

PATH = "acme-acme_web_user"

#: Two accounts in one secret: payload fields, even on OCI.
SHARED = CONFIG.replace(
    "accounts: [acme_web_user]", "accounts: [acme_web_user, acme_batch_user]"
).replace('"acme-{account}#password"', '"acme-db#DB_CREDENTIALS/{account}"')

SHARED_PATH = "acme-db"

LIVE = "Correct-Horse-Battery-9"
STAGED = "Vertical-Anchor-Marble-4"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(RUN_SCHEMA.read_text(encoding="utf-8")))


@pytest.fixture
def store(monkeypatch: pytest.MonkeyPatch) -> MemoryStore:
    memory = staging_store()

    def fake_connect(
        vault: Vault, *, env: Mapping[str, str], token_file: Path | None = None
    ) -> SecretStore:
        return memory

    monkeypatch.setattr("sopuli.cli.connect", fake_connect)
    return memory


def run(runner: CliRunner, config: Path, *args: str) -> Result:
    return runner.invoke(cli, ["creds", *args, "--config", str(config), "--output", "json"])


def results(result: Result) -> list[dict[str, Any]]:
    return list(json.loads(result.output)["results"])


def refused(result: Result) -> int:
    """The exit code of a run the boundary refused, as ``main`` would exit."""
    assert isinstance(result.exception, LayoutChangedError), result.output
    return int(result.exception.exit_code)


# ------------------------------------------------------------- generate ---


def test_generate_stages_a_pending_version_and_leaves_current_alone(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    # Rotated once, so the token has moved past the version number.
    seed(store, PATH, {FIELD: STAGED}, {FIELD: LIVE, PREVIOUS: STAGED})

    result = run(runner, write_config(CONFIG), "generate")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    current = store.read_stage(PATH, CURRENT)
    pending = store.read_stage(PATH, PENDING)
    assert current is not None
    assert current.data[FIELD] == LIVE
    assert PENDING not in current.data
    assert pending is not None
    assert pending.data[FIELD] != LIVE
    assert current.attributes[PENDING_VERSION] == pending.generation
    assert view(store, PATH)[PENDING] == pending.data[FIELD]
    # The version reported is the one `@version=N` pins, not the token.
    (entry,) = results(result)
    assert pending.version != pending.generation
    assert entry["secret"]["version"] == pending.generation


def test_generate_promote_seeds_a_first_current_version(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    result = run(runner, write_config(CONFIG), "generate", "--promote")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    current = store.read_stage(PATH, CURRENT)
    assert current is not None
    assert current.data[FIELD]
    assert store.read_stage(PATH, PENDING) is None
    (entry,) = results(result)
    assert entry["secret"]["version"] == current.generation


def test_a_shared_secret_on_a_staging_store_keeps_payload_fields(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    result = run(runner, write_config(SHARED), "generate")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    current = store.read_stage(SHARED_PATH, CURRENT)
    assert current is not None
    assert set(current.data[PENDING]) == {"acme_web_user", "acme_batch_user"}
    assert store.read_stage(SHARED_PATH, PENDING) is None


def test_a_selection_does_not_make_a_shared_secret_native(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """Native staging is decided from every account the file declares: a run
    narrowed to one account of a shared secret still writes payload fields."""
    result = run(runner, write_config(SHARED), "generate", "--account", "acme_web_user")

    assert result.exit_code == ExitCode.SUCCESS, result.output
    current = store.read_stage(SHARED_PATH, CURRENT)
    assert current is not None
    assert set(current.data[PENDING]) == {"acme_web_user"}


def test_each_written_secret_says_how_it_was_staged(
    runner: CliRunner,
    write_config: Callable[[str], Path],
    store: MemoryStore,
    validator: Draft202012Validator,
) -> None:
    native = run(runner, write_config(CONFIG), "generate")
    shared = run(runner, write_config(SHARED), "generate")

    for result, staging in ((native, "native"), (shared, "payload")):
        validator.validate(json.loads(result.output))
        assert {entry["secret"]["staging"] for entry in results(result)} == {staging}


# ------------------------------------------------------- layout changes ---


def test_payload_stages_in_a_one_account_secret_are_refused_at_plan_time(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """Staged in payload fields while the secret was shared, and now read as
    one account's: the pending would be lost, so nothing is written."""
    store.write(PATH, {FIELD: LIVE, PENDING: STAGED}, cas=0)

    result = run(runner, write_config(CONFIG), "generate")

    assert refused(result) == ExitCode.CONFIG_INVALID
    assert PATH in result.output
    found = store.read(PATH)
    assert found is not None
    assert found.version == 1


def test_a_secret_that_becomes_shared_with_a_live_pending_is_refused(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """Staged as a version while one account held it; the config now shares
    it. Read in payload fields it has no pending, so the run refuses."""
    seed(store, SHARED_PATH, {"DB_CREDENTIALS": LIVE}, field="DB_CREDENTIALS")
    shared_once = CONFIG.replace('"acme-{account}#password"', '"acme-db#DB_CREDENTIALS"')
    assert run(runner, write_config(shared_once), "generate").exit_code == ExitCode.SUCCESS
    before = store.read_stage(SHARED_PATH, PENDING)

    result = run(runner, write_config(SHARED), "generate")

    assert refused(result) == ExitCode.CONFIG_INVALID
    assert SHARED_PATH in result.output
    assert store.read_stage(SHARED_PATH, PENDING) == before


def test_a_previous_version_alone_does_not_block_sharing(
    runner: CliRunner, write_config: Callable[[str], Path], store: MemoryStore
) -> None:
    """OCI cannot drop a PREVIOUS stage, so refusing over one would refuse the
    secret for good."""
    seed(
        store,
        SHARED_PATH,
        {"DB_CREDENTIALS": LIVE},
        {"DB_CREDENTIALS": STAGED, PREVIOUS: LIVE},
        field="DB_CREDENTIALS",
    )
    assert store.read_stage(SHARED_PATH, PREVIOUS) is not None

    result = run(runner, write_config(SHARED), "generate")

    assert result.exit_code == ExitCode.SUCCESS, result.output
