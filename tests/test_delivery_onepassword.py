"""`onepassword_share` delivery's plan-time check (UC-2 §6.6, #446).

Tier 0 for the rules: which `ttl` the account's sharing policy allows, how the
vault is found, and that the empty note the check creates is deleted whatever
happens. The SDK is replaced by a fake that answers as `onepassword-sdk` 0.4.2
did against a real account, so these run without the SDK installed.

The last test runs against a real 1Password account. It needs a service account
token with read, write and share items on a test vault, so it is
maintainer-only, and skips unless `SOPULI_TEST_ONEPASSWORD_TOKEN_FILE` names
the token's file.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from sopuli.config.delivery import ONEPASSWORD_TTLS
from sopuli.delivery import onepassword
from sopuli.delivery.onepassword import (
    PLACEHOLDER_TITLE,
    OnePassword,
    OnePasswordLoginError,
    OnePasswordNotInstalledError,
    OnePasswordRefusedError,
    refusal,
)
from sopuli.exit_codes import ExitCode
from sopuli.secrets import Secret
from sopuli.store.protocol import StoreError

TOKEN = Secret("ops_acme_not_a_real_token")
VAULT = "acme-handover"
VAULT_ID = "acmehandovervault000000001"

#: What the real SDK's `onepassword.types` provides to the check, and no more.
FAKE_TYPES = SimpleNamespace(
    ItemCreateParams=lambda **params: params,
    ItemCategory=SimpleNamespace(SECURENOTE="SecureNote"),
)


class FakeClient:
    """Answers as 1Password did on 2026-10-30, and records what was asked."""

    def __init__(
        self,
        *,
        vaults: list[tuple[str, str]] | None = None,
        max_expiry: str = "ThirtyDays",
        allowed_types: tuple[str, ...] = ("Public", "Authenticated"),
        fail: tuple[str, ...] = (),
    ) -> None:
        self.calls: list[tuple[str, Any]] = []
        self.live: set[str] = set()
        self._vaults = vaults if vaults is not None else [(VAULT_ID, VAULT)]
        self._max_expiry = max_expiry
        self._allowed_types = allowed_types
        self._fail = fail
        self.vaults = SimpleNamespace(list=self._list_vaults)
        self.items = SimpleNamespace(
            create=self._create,
            delete=self._delete,
            shares=SimpleNamespace(get_account_policy=self._policy),
        )

    async def _list_vaults(self) -> list[Any]:
        self.calls.append(("vaults.list", None))
        return [SimpleNamespace(id=id_, title=title) for id_, title in self._vaults]

    async def _create(self, params: dict[str, Any]) -> Any:
        self.calls.append(("items.create", params))
        self.live.add("note1")
        return SimpleNamespace(id="note1")

    async def _policy(self, vault_id: str, item_id: str) -> Any:
        self.calls.append(("shares.get_account_policy", (vault_id, item_id)))
        if "interrupt" in self._fail:
            raise KeyboardInterrupt
        if "policy" in self._fail:
            # The message 1Password sends when the service account lacks share items.
            raise Exception(  # noqa: TRY002 -- the SDK raises plain Exception
                "you do not have the right permissions to perform this action: sharing an item"
            )
        return SimpleNamespace(
            max_expiry=SimpleNamespace(value=self._max_expiry),
            allowed_types=[SimpleNamespace(value=kind) for kind in self._allowed_types],
        )

    async def _delete(self, vault_id: str, item_id: str) -> None:
        self.calls.append(("items.delete", (vault_id, item_id)))
        if "delete" in self._fail:
            raise Exception("connection reset")  # noqa: TRY002 -- as the SDK does
        self.live.discard(item_id)


def backend(client: FakeClient, *, ttl: str = "24h") -> OnePassword:
    async def factory(token: Secret) -> FakeClient:
        assert token is TOKEN
        return client

    return OnePassword(onepassword_vault=VAULT, ttl=ttl, token=TOKEN, client_factory=factory)


@pytest.fixture(autouse=True)
def fake_types(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(onepassword, "_sdk_types", lambda: FAKE_TYPES)


# ------------------------------------------------------------- the policy ---


PUBLIC = ("Public",)


def test_the_expiries_are_listed_shortest_first() -> None:
    """`refusal` compares by the dict's order, so the order is the contract."""
    hours = [int(ttl.removesuffix("h")) for ttl in ONEPASSWORD_TTLS]

    assert hours == sorted(hours)


@pytest.mark.parametrize("ttl", list(ONEPASSWORD_TTLS))
def test_a_policy_with_the_longest_maximum_allows_every_ttl(ttl: str) -> None:
    assert refusal(ttl=ttl, max_expiry="ThirtyDays", allowed_types=PUBLIC) is None


def test_a_ttl_up_to_the_maximum_is_allowed() -> None:
    assert refusal(ttl="168h", max_expiry="SevenDays", allowed_types=PUBLIC) is None
    assert refusal(ttl="1h", max_expiry="SevenDays", allowed_types=PUBLIC) is None


def test_a_ttl_beyond_the_maximum_is_refused_naming_the_maximum() -> None:
    reason = refusal(ttl="720h", max_expiry="SevenDays", allowed_types=PUBLIC)

    assert reason is not None
    assert "168h at most" in reason
    assert "not 720h" in reason


def test_a_maximum_this_build_does_not_know_is_refused_rather_than_guessed() -> None:
    reason = refusal(ttl="1h", max_expiry="NinetyDays", allowed_types=PUBLIC)

    assert reason is not None
    assert "NinetyDays" in reason


def test_a_policy_without_links_anyone_can_open_is_refused() -> None:
    """The method makes only that kind of share, so the share would fail after
    a password was drawn."""
    reason = refusal(ttl="1h", max_expiry="ThirtyDays", allowed_types=("Authenticated",))

    assert reason is not None
    assert "a link anyone can open" in reason
    assert "Authenticated" in reason


# -------------------------------------------------------------- preflight ---


def test_preflight_reads_the_policy_through_a_note_it_deletes() -> None:
    client = FakeClient()
    backend(client).preflight(account="acme_dba_user", target="acme-prod")

    assert [name for name, _ in client.calls] == [
        "vaults.list",
        "items.create",
        "shares.get_account_policy",
        "items.delete",
    ]
    created = client.calls[1][1]
    assert created == {"category": "SecureNote", "vault_id": VAULT_ID, "title": PLACEHOLDER_TITLE}
    # The note holds no password: it has no fields, notes or anything else.
    assert set(created) == {"category", "vault_id", "title"}
    assert client.live == set()


def test_preflight_runs_once_for_a_run_that_reaches_several_targets() -> None:
    client = FakeClient()
    link = backend(client)
    link.preflight(account="acme_dba_user", target="acme-prod")
    link.preflight(account="acme_dba_user", target="acme-test")

    assert [name for name, _ in client.calls].count("items.create") == 1


def test_a_ttl_the_policy_refuses_is_refused_with_exit_5() -> None:
    client = FakeClient(max_expiry="SevenDays")
    with pytest.raises(OnePasswordRefusedError) as raised:
        backend(client, ttl="720h").preflight(account="acme_dba_user", target="acme-prod")

    assert raised.value.exit_code == ExitCode.UNSUPPORTED_CAPABILITY
    assert "168h at most" in str(raised.value)
    assert "delivery.onepassword_share.ttl" in str(raised.value)
    assert client.live == set()


def test_a_policy_without_links_anyone_can_open_is_refused_with_exit_5() -> None:
    client = FakeClient(allowed_types=("Authenticated",))
    with pytest.raises(OnePasswordRefusedError) as raised:
        backend(client).preflight(account="acme_dba_user", target="acme-prod")

    assert raised.value.exit_code == ExitCode.UNSUPPORTED_CAPABILITY
    assert "a link anyone can open" in str(raised.value)
    assert client.live == set()


def test_a_missing_share_permission_fails_and_still_deletes_the_note() -> None:
    client = FakeClient(fail=("policy",))
    with pytest.raises(StoreError) as raised:
        backend(client).preflight(account="acme_dba_user", target="acme-prod")

    message = str(raised.value)
    assert "sharing an item" in message
    assert "read, write and share items" in message
    assert client.live == set()


def test_a_failed_delete_does_not_hide_why_the_policy_read_failed() -> None:
    client = FakeClient(fail=("policy", "delete"))
    with pytest.raises(StoreError) as raised:
        backend(client).preflight(account="acme_dba_user", target="acme-prod")

    message = str(raised.value)
    assert "sharing an item" in message
    assert "could not be deleted either" in message
    assert "note1" in message


def test_an_interrupt_during_the_read_still_deletes_the_note() -> None:
    client = FakeClient(fail=("interrupt",))
    with pytest.raises(KeyboardInterrupt):
        backend(client).preflight(account="acme_dba_user", target="acme-prod")

    assert client.live == set()


def test_a_failed_delete_after_a_good_read_is_the_failure() -> None:
    client = FakeClient(fail=("delete",))
    with pytest.raises(StoreError, match="could not delete the item"):
        backend(client).preflight(account="acme_dba_user", target="acme-prod")


def test_a_vault_the_service_account_cannot_see_is_refused() -> None:
    client = FakeClient(vaults=[("other1", "acme-other")])
    with pytest.raises(OnePasswordRefusedError) as raised:
        backend(client).preflight(account="acme_dba_user", target="acme-prod")

    assert "sees no vault with that title" in str(raised.value)
    assert "delivery.onepassword_share.onepassword_vault" in str(raised.value)
    assert "items.create" not in [name for name, _ in client.calls]


def test_two_vaults_with_the_title_are_refused_rather_than_one_picked() -> None:
    client = FakeClient(vaults=[("one1", VAULT), ("two2", VAULT)])
    with pytest.raises(OnePasswordRefusedError, match="sees 2 vaults with that title"):
        backend(client).preflight(account="acme_dba_user", target="acme-prod")


def test_a_token_that_does_not_log_in_is_exit_6_and_not_echoed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def refuse(**kwargs: Any) -> Any:
        # Worse than 0.4.2 did: a message that quotes the token it was given.
        raise Exception(f"invalid service account token {kwargs['auth']}")  # noqa: TRY002

    monkeypatch.setattr(
        onepassword, "_sdk", lambda: SimpleNamespace(Client=SimpleNamespace(authenticate=refuse))
    )
    link = OnePassword(onepassword_vault=VAULT, ttl="24h", token=TOKEN)
    with pytest.raises(OnePasswordLoginError) as raised:
        link.preflight(account="acme_dba_user", target="acme-prod")

    assert raised.value.exit_code == ExitCode.AUTH_FAILURE
    assert "invalid service account token ***" in str(raised.value)
    assert "ops_acme" not in str(raised.value)


def test_a_missing_dependency_of_the_sdk_is_not_reported_as_the_sdk_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The SDK is installed, and `pydantic` is not: installing the extra again
    would not help, so the message says the SDK failed to load."""

    def import_module(name: str) -> Any:
        raise ModuleNotFoundError("No module named 'pydantic'", name="pydantic")

    monkeypatch.setattr("sopuli.delivery.onepassword.importlib.import_module", import_module)
    with pytest.raises(OnePasswordNotInstalledError) as raised:
        onepassword._sdk()

    assert "failed to load: no module 'pydantic'" in str(raised.value)


def test_a_missing_sdk_names_the_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    """ADR-006 rule 2, through the real import rather than a stub of it."""
    monkeypatch.setitem(sys.modules, "onepassword", None)
    with pytest.raises(OnePasswordNotInstalledError) as raised:
        onepassword._sdk()

    assert raised.value.exit_code == ExitCode.CONFIG_INVALID
    assert "sopuli-dba[onepassword]" in str(raised.value)


def test_an_sdk_whose_library_does_not_load_names_the_extra(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The SDK's native library needs glibc 2.32, and an older one raises
    ImportError on import, not ModuleNotFoundError."""

    class Unloadable:
        def find_spec(self, fullname: str, path: Any = None, target: Any = None) -> None:
            if fullname == "onepassword" or fullname.startswith("onepassword."):
                raise ImportError("version `GLIBC_2.32' not found")

    monkeypatch.delitem(sys.modules, "onepassword", raising=False)
    monkeypatch.delitem(sys.modules, "onepassword.client", raising=False)
    monkeypatch.setattr(sys, "meta_path", [Unloadable(), *sys.meta_path])
    with pytest.raises(OnePasswordNotInstalledError) as raised:
        onepassword._sdk()

    assert raised.value.exit_code == ExitCode.CONFIG_INVALID
    assert "failed to load: ImportError" in str(raised.value)


def test_the_token_is_not_in_the_backend_s_repr() -> None:
    assert "ops_acme" not in repr(backend(FakeClient()))


# ------------------------------------------- a real account (maintainer) ---


def test_preflight_against_a_real_account(monkeypatch: pytest.MonkeyPatch) -> None:
    """The fake above, checked against 1Password itself.

    Set `SOPULI_TEST_ONEPASSWORD_TOKEN_FILE` to a file holding a service account
    token with read, write and share items on `SOPULI_TEST_ONEPASSWORD_VAULT`
    (default `sopuli-test`).
    """
    token_file = os.environ.get("SOPULI_TEST_ONEPASSWORD_TOKEN_FILE")
    if not token_file:
        pytest.skip("no 1Password account: SOPULI_TEST_ONEPASSWORD_TOKEN_FILE is not set")
    pytest.importorskip("onepassword", reason="1Password's SDK is not installed")
    monkeypatch.undo()  # the real SDK types, not the autouse fake
    vault = os.environ.get("SOPULI_TEST_ONEPASSWORD_VAULT", "sopuli-test")
    token = Secret(Path(token_file).read_text(encoding="utf-8").strip())

    OnePassword(onepassword_vault=vault, ttl="24h", token=token).preflight(
        account="acme_app_user", target="acme-test"
    )

    with pytest.raises(OnePasswordRefusedError, match="sees no vault with that title"):
        OnePassword(onepassword_vault=f"{vault}-absent", ttl="24h", token=token).preflight(
            account="acme_app_user", target="acme-test"
        )
