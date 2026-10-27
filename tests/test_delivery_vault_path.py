"""`vault_path` delivery, without a Vault. Tier 0.

What is here is the reading of Vault's answers and the refusals around them. The
socket, and the one thing only a server can show -- that the person's own
identity reads the path and the DBA's token and another identity do not -- is the
tier-1 test against the stack's Vault.

The seam is the transport, handed in: :class:`VaultPath` takes one, so a stub
that answers by path stands in for Vault.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from sopuli.delivery.vault_path import (
    CAPABILITIES_PATH,
    METHOD,
    NotAPathStoreError,
    PathCapabilityError,
    VaultPath,
    for_store,
)
from sopuli.exit_codes import ExitCode
from sopuli.secrets import Secret
from sopuli.store import MemoryStore, StoreError
from sopuli.store.hashicorp._transport import Response, Transport
from sopuli.store.hashicorp.kv1 import Kv1Store
from sopuli.store.hashicorp.kv2 import Kv2Store

PASSWORD = "Correct#Horse9Battery"
ACCOUNT = "ACME_DEV_ALICE"
TARGET = "free-pdb"
DATA = f"secret/data/personal/{ACCOUNT}/{TARGET}"
METADATA = f"secret/metadata/personal/{ACCOUNT}/{TARGET}"

#: Vault 2.0.4's answer to a KV v2 write on a path whose `delete_version_after`
#: is set, in the shape the tier-1 container gave (#447).
WRITTEN = {
    "data": {
        "created_time": "2026-10-27T13:37:48.027607666Z",
        "custom_metadata": None,
        "deletion_time": "2026-10-27T21:37:48.027607666Z",
        "destroyed": False,
        "version": 3,
    }
}


class Scripted:
    """A transport that answers by path, and remembers every call."""

    def __init__(self, answers: Mapping[str, Response]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, str, Any]] = []

    def request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Response:
        self.calls.append((method, path, json))
        return self.answers[path]


def capabilities(data: list[str], metadata: list[str] | None = None) -> Response:
    held = metadata if metadata is not None else ["create", "update"]
    return Response(status=200, body={DATA: data, METADATA: held, "capabilities": data})


def backend(**answers: Response) -> tuple[VaultPath, Scripted]:
    script = Scripted(
        {
            CAPABILITIES_PATH: answers.get("caps", capabilities(["create", "update"])),
            METADATA: answers.get("meta", Response(status=204, body=None)),
            DATA: answers.get("data", Response(status=200, body=WRITTEN)),
        }
    )
    path = VaultPath(
        transport=script,  # type: ignore[arg-type]
        vault="vault-dev",
        mount="secret",
        prefix="personal",
        ttl="8h",
    )
    return path, script


# ---------------------------------------------------------------- the path ---


def test_the_path_is_the_prefix_the_account_and_the_target() -> None:
    path, _ = backend()

    assert path.path(account=ACCOUNT, target=TARGET) == f"personal/{ACCOUNT}/{TARGET}"


def test_a_common_user_s_name_stays_one_segment() -> None:
    """The `#` is percent-encoded by the transport, so it is left as it is here."""
    path, _ = backend()

    assert path.path(account="C##ACME_DBA_CAROL", target=TARGET).split("/")[1] == (
        "C##ACME_DBA_CAROL"
    )


@pytest.mark.parametrize(("account", "target"), [("A/B", TARGET), (ACCOUNT, "pdb/1"), ("", TARGET)])
def test_a_name_that_is_not_one_segment_is_refused(account: str, target: str) -> None:
    path, _ = backend()

    with pytest.raises(PathCapabilityError, match="one segment"):
        path.path(account=account, target=target)


# ---------------------------------------------------------- the preflight ---


def test_the_preflight_asks_about_the_data_and_the_metadata_path() -> None:
    path, script = backend()

    path.preflight(account=ACCOUNT, target=TARGET)

    assert script.calls == [("POST", CAPABILITIES_PATH, {"paths": [DATA, METADATA]})]


@pytest.mark.parametrize("held", [["create", "read", "update"], ["root"]])
def test_a_token_that_could_read_the_path_is_refused(held: list[str]) -> None:
    """H8: a root token answers ``["root"]`` and never lists ``read``."""
    path, _ = backend(caps=capabilities(held))

    with pytest.raises(PathCapabilityError) as caught:
        path.preflight(account=ACCOUNT, target=TARGET)

    assert "could read ACME_DEV_ALICE's password back" in str(caught.value)
    assert caught.value.exit_code is ExitCode.UNSUPPORTED_CAPABILITY


def test_a_token_that_cannot_write_the_metadata_is_refused_before_a_password_is_drawn() -> None:
    path, _ = backend(caps=capabilities(["create", "update"], metadata=["deny"]))

    with pytest.raises(PathCapabilityError, match=f"lacks create, update on {METADATA}"):
        path.preflight(account=ACCOUNT, target=TARGET)


def test_an_answer_without_the_path_s_capabilities_is_not_taken_as_none() -> None:
    path, _ = backend(caps=Response(status=200, body={"capabilities": ["create"]}))

    with pytest.raises(StoreError, match="gave no capabilities"):
        path.preflight(account=ACCOUNT, target=TARGET)


# ------------------------------------------------------------- the writes ---


def test_the_metadata_is_written_before_the_value() -> None:
    """`delete_version_after` applies only to versions written after it is set."""
    path, script = backend()

    path.deliver(Secret(PASSWORD), account=ACCOUNT, target=TARGET)

    assert [(method, where) for method, where, _ in script.calls] == [
        ("POST", METADATA),
        ("POST", DATA),
    ]
    assert script.calls[0][2] == {"delete_version_after": "8h"}


def test_the_value_says_which_account_and_target_it_is_for() -> None:
    path, script = backend()

    path.deliver(Secret(PASSWORD), account=ACCOUNT, target=TARGET)

    assert script.calls[1][2] == {
        "data": {"password": PASSWORD, "account": ACCOUNT, "target": TARGET}
    }


def test_the_write_sends_no_check_and_set() -> None:
    path, script = backend()

    path.deliver(Secret(PASSWORD), account=ACCOUNT, target=TARGET)

    assert "options" not in script.calls[1][2]


def test_the_receipt_has_the_path_the_version_and_vault_s_deletion_time() -> None:
    path, _ = backend()

    receipt = path.deliver(Secret(PASSWORD), account=ACCOUNT, target=TARGET)

    assert receipt.method == METHOD
    assert receipt.token is None
    assert receipt.accessor is None
    assert receipt.path == f"secret/personal/{ACCOUNT}/{TARGET}"
    assert receipt.version == 3
    assert receipt.expires_at == datetime(2026, 10, 27, 21, 37, 48, 27607, tzinfo=UTC)


def test_the_handover_carries_the_path_and_version_and_no_token() -> None:
    path, _ = backend()

    handover = path.deliver(Secret(PASSWORD), account=ACCOUNT, target=TARGET).reported()

    assert handover.path == f"secret/personal/{ACCOUNT}/{TARGET}"
    assert handover.version == 3
    assert not hasattr(handover, "token")


@pytest.mark.parametrize("deletion", ["", None, "not a time"])
def test_an_answer_with_no_deletion_time_fails_before_the_ddl(deletion: Any) -> None:
    """Vault would not delete the value, and the ttl is the method's promise."""
    body = {"data": {**WRITTEN["data"], "deletion_time": deletion}}
    path, _ = backend(data=Response(status=200, body=body))

    with pytest.raises(StoreError, match="will not delete the value"):
        path.deliver(Secret(PASSWORD), account=ACCOUNT, target=TARGET)


def test_an_answer_with_no_version_fails() -> None:
    body = {"data": {"deletion_time": WRITTEN["data"]["deletion_time"]}}
    path, _ = backend(data=Response(status=200, body=body))

    with pytest.raises(StoreError, match="returned no version"):
        path.deliver(Secret(PASSWORD), account=ACCOUNT, target=TARGET)


def test_a_refused_metadata_write_stops_before_the_value_is_written() -> None:
    path, script = backend(meta=Response(status=403, body={"errors": ["permission denied"]}))

    with pytest.raises(StoreError, match="permission denied"):
        path.deliver(Secret(PASSWORD), account=ACCOUNT, target=TARGET)

    assert [where for _, where, _ in script.calls] == [METADATA]


def test_a_check_and_set_mount_s_refusal_is_reported() -> None:
    refused = Response(
        status=400, body={"errors": ["check-and-set parameter required for this call"]}
    )
    path, _ = backend(data=refused)

    with pytest.raises(StoreError, match="check-and-set parameter required"):
        path.deliver(Secret(PASSWORD), account=ACCOUNT, target=TARGET)


# ------------------------------------------------------------- the store ---


def test_a_store_that_is_not_hashicorp_is_refused_by_name() -> None:
    with pytest.raises(NotAPathStoreError) as caught:
        for_store(MemoryStore(), vault="vault-oci", ttl="8h", prefix="personal")

    assert "vault-oci" in str(caught.value)
    assert caught.value.exit_code is ExitCode.UNSUPPORTED_CAPABILITY


def test_a_kv_v1_mount_is_refused() -> None:
    """KV v1 has neither versions nor `delete_version_after` (#447)."""
    store = Kv1Store(transport=Transport(httpx.Client()), mount="kv1")

    with pytest.raises(NotAPathStoreError, match="KV v1"):
        for_store(store, vault="vault-dev", ttl="8h", prefix="personal")


def test_a_kv_v2_mount_gives_a_backend_on_that_mount() -> None:
    store = Kv2Store(transport=Transport(httpx.Client()), mount="secret")

    path = for_store(store, vault="vault-dev", ttl="8h", prefix="personal")

    assert (path.mount, path.prefix, path.ttl, path.vault) == ("secret", "personal", "8h", "vault-dev")
