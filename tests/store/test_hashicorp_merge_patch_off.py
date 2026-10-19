"""``merge_patch: false`` on a store entry (#904).

A proxy or WAF in front of Vault can block the PATCH method and answer 401
itself. The adapter cannot tell that 401 from Vault refusing the token, so the
operator turns the merge patch off in the config, and every write takes
read-modify-write under compare-and-set.

The first tests are tier 0: they build the store and ask what it supports,
which sends nothing. The last one is tier 1 and skips without the container.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.model import Vault
from sopuli.config.secret_refs import parse_secret_ref
from sopuli.config.vaults import build_vaults
from sopuli.secrets import Secret
from sopuli.store.credentials import READ_MODIFY_WRITE, apply_patch, staged_patch
from sopuli.store.protocol import CAS, LIST, MERGE_PATCH, VERSIONING, SecretStore

#: An address nothing listens on. Building a store opens no connection, so the
#: tier-0 tests never reach it.
NOWHERE = "http://127.0.0.1:9"


def _open(*, merge_patch: bool | None) -> SecretStore:
    # Imported here: it pulls in `httpx`, and a base install must reach the skip.
    pytest.importorskip("httpx")
    from sopuli.store.hashicorp import open_store

    vault = Vault(
        name="vault-dev", type="hashicorp", addr=NOWHERE, kv_version=2, merge_patch=merge_patch
    )
    return open_store(vault, token=Secret("not-sent"))


def test_kv2_offers_the_merge_patch_by_default() -> None:
    assert MERGE_PATCH in _open(merge_patch=None).supports()


def test_merge_patch_false_drops_only_the_merge_patch() -> None:
    assert _open(merge_patch=False).supports() == frozenset({CAS, LIST, VERSIONING})


def test_merge_patch_true_is_the_same_as_absent() -> None:
    assert _open(merge_patch=True).supports() == _open(merge_patch=None).supports()


def test_the_key_is_read_from_a_vaults_entry() -> None:
    (vault,) = build_vaults(
        {"vaults": {"vault-dev": {"type": "hashicorp", "kv_version": 2, "merge_patch": False}}}
    )

    assert vault.merge_patch is False


def test_a_value_that_is_not_a_boolean_is_refused() -> None:
    with pytest.raises(ConfigError, match="merge_patch"):
        build_vaults({"vaults": {"vault-dev": {"type": "hashicorp", "merge_patch": "no"}}})


@pytest.fixture
def blocked_store(vault_stack: Any) -> Iterator[tuple[SecretStore, str]]:
    """A real KV v2 store with the merge patch turned off, and a scratch path."""
    from sopuli.store.hashicorp import open_store

    store = open_store(
        Vault(
            name="vault-dev",
            type="hashicorp",
            addr=vault_stack.addr,
            mount=vault_stack.kv2_mount,
            kv_version=2,
            merge_patch=False,
        ),
        token=Secret(vault_stack.token),
    )
    path = f"{vault_stack.scratch}/merge-patch-off"
    yield store, path
    vault_stack.client.delete(f"/v1/{vault_stack.kv2_mount}/metadata/{path}")


def test_a_write_takes_read_modify_write_and_keeps_the_siblings(
    blocked_store: tuple[SecretStore, str],
) -> None:
    """The run reports the mechanism, and a sibling account stays as it was."""
    store, path = blocked_store
    version = store.write(
        path,
        {"DB_CREDENTIALS": {"acme_web_user": "current-one", "acme_api_user": "current-two"}},
        cas=0,
    )

    ref = parse_secret_ref(f"vault-dev:{path}#DB_CREDENTIALS/acme_web_user")
    written = apply_patch(store, path, staged_patch(ref, Secret("x")), cas=version)

    assert written.mechanism == READ_MODIFY_WRITE
    stored = store.read(path)
    assert stored is not None
    assert stored.data["DB_CREDENTIALS"]["acme_api_user"] == "current-two"
