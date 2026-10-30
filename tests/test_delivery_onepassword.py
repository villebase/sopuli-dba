"""`onepassword_share` delivery (UC-2 §6.6, #446).

Tier 0 for the rules: which `ttl` the account's sharing policy allows, how the
vault is found, that the empty note the plan-time check creates is deleted
whatever happens, and what a delivery creates, shares, deletes and returns.
The SDK is replaced by a fake that answers as `onepassword-sdk` 0.4.2 did
against a real account, so these run without the SDK installed.

The last tests run against a real 1Password account. They need a service
account token with read, write and share items on a test vault, so they are
maintainer-only, and skip unless `SOPULI_TEST_ONEPASSWORD_TOKEN_FILE` names the
token's file.
"""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import UTC, datetime, timedelta
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

PASSWORD = "Correct#Horse9Battery"
LINK = "https://share.1password.com/s#acmeshareid_not_real"

#: What the real SDK's `onepassword.types` provides to the method, and no more.
FAKE_TYPES = SimpleNamespace(
    ItemCreateParams=lambda **params: params,
    ItemField=lambda **params: params,
    ItemShareParams=lambda **params: params,
    ItemShareDuration=lambda value: value,
    ItemCategory=SimpleNamespace(SECURENOTE="SecureNote", LOGIN="Login"),
    ItemFieldType=SimpleNamespace(TEXT="Text", CONCEALED="Concealed"),
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
            shares=SimpleNamespace(get_account_policy=self._policy, create=self._share),
        )

    async def _list_vaults(self) -> list[Any]:
        self.calls.append(("vaults.list", None))
        return [SimpleNamespace(id=id_, title=title) for id_, title in self._vaults]

    async def _create(self, params: dict[str, Any]) -> Any:
        self.calls.append(("items.create", params))
        if "create" in self._fail:
            raise Exception(f"rejected {params}")  # noqa: TRY002 -- quotes what it was given
        self.live.add("note1")
        return SimpleNamespace(id="note1", fields=params.get("fields"))

    async def _share(self, item: Any, policy: Any, params: dict[str, Any]) -> str:
        self.calls.append(("shares.create", params))
        if "share" in self._fail:
            raise Exception(f"rejected {item.fields}")  # noqa: TRY002 -- quotes what it was given
        return "" if "empty" in self._fail else LINK

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


# --------------------------------------------------------------- delivery ---


def deliver(client: FakeClient, *, ttl: str = "24h") -> Any:
    return backend(client, ttl=ttl).deliver(
        Secret(PASSWORD), account="acme_dba_user", target="acme-prod"
    )


def test_a_delivery_creates_shares_and_deletes_the_item() -> None:
    client = FakeClient()
    receipt = deliver(client, ttl="168h")

    assert [name for name, _ in client.calls] == [
        "vaults.list",
        "items.create",
        "shares.get_account_policy",
        "shares.create",
        "items.delete",
    ]
    created = client.calls[1][1]
    assert created["category"] == "Login"
    assert created["title"] == "acme_dba_user on acme-prod"
    assert [(field["id"], field["value"]) for field in created["fields"]] == [
        ("username", "acme_dba_user"),
        ("password", PASSWORD),
    ]
    assert client.calls[3][1] == {"expire_after": "SevenDays", "one_time_only": True}
    assert client.live == set()

    assert receipt.method == "onepassword_share"
    assert receipt.token is not None
    assert receipt.token.reveal() == LINK
    assert receipt.id == "note1"
    assert receipt.left_behind is None
    assert receipt.location == "note1"


def test_the_expiry_is_the_ttl_from_before_the_share() -> None:
    """1Password returns no expiry with the link, so the tool reports one from its
    own clock, read before the share was made: never later than the real one."""
    before = datetime.now(UTC).replace(microsecond=0)
    receipt = deliver(FakeClient(), ttl="24h")
    after = datetime.now(UTC)

    assert receipt.expires_at is not None
    assert receipt.expires_at.microsecond == 0
    assert before + timedelta(hours=24) <= receipt.expires_at <= after + timedelta(hours=24)


def test_the_record_carries_the_item_and_nothing_that_opens_the_link() -> None:
    reported = deliver(FakeClient()).reported()

    assert reported.id == "note1"
    assert "acmeshareid" not in repr(reported)
    assert PASSWORD not in repr(reported)


def test_a_failed_delete_after_the_share_is_reported_and_does_not_fail() -> None:
    """The link exists and the password is about to change, so failing here
    would leave an account whose new password the person cannot get."""
    client = FakeClient(fail=("delete",))
    receipt = deliver(client)

    assert receipt.token is not None
    assert receipt.left_behind is not None
    assert "note1" in receipt.left_behind
    assert "connection reset" in receipt.left_behind


@pytest.mark.parametrize("step", ["create", "share"])
def test_a_failed_call_carrying_the_password_is_named_by_its_type_only(step: str) -> None:
    """The fake's message quotes what it was given, the password included (#785)."""
    client = FakeClient(fail=(step,))
    with pytest.raises(StoreError) as raised:
        deliver(client)

    assert PASSWORD not in str(raised.value)
    assert ": Exception" in str(raised.value)
    assert "message is not shown, because the call carried the password" in str(raised.value)
    assert "message is above" not in str(raised.value)


def test_a_failed_share_deletes_the_item_before_failing() -> None:
    client = FakeClient(fail=("share",))
    with pytest.raises(StoreError, match="could not share the item"):
        deliver(client)

    assert client.live == set()


def test_a_failed_share_and_a_failed_delete_name_the_item_left() -> None:
    client = FakeClient(fail=("share", "delete"))
    with pytest.raises(StoreError) as raised:
        deliver(client)

    assert "The item note1 could not be deleted either" in str(raised.value)
    assert "never set" in str(raised.value)


def test_a_share_that_returns_no_link_fails_and_deletes_the_item() -> None:
    client = FakeClient(fail=("empty",))
    with pytest.raises(StoreError, match="no link") as raised:
        deliver(client)

    assert client.live == set()
    assert "the item was deleted" in str(raised.value)


def test_a_share_with_no_link_and_a_failed_delete_name_the_item_left() -> None:
    """The hint must not say the item was deleted when it was not."""
    client = FakeClient(fail=("empty", "delete"))
    with pytest.raises(StoreError, match="no link") as raised:
        deliver(client)

    assert "the item was deleted" not in str(raised.value)
    assert "The item note1 could not be deleted either" in str(raised.value)


def test_an_interrupt_with_a_failed_delete_notes_the_item_left() -> None:
    """An interrupt has no hint to extend, so the item is named in a note, which
    the traceback shows."""
    client = FakeClient(fail=("interrupt", "delete"))
    with pytest.raises(KeyboardInterrupt) as raised:
        deliver(client)

    assert any("The item note1 could not be deleted" in note for note in raised.value.__notes__)


def test_check_installed_refuses_a_missing_sdk(monkeypatch: pytest.MonkeyPatch) -> None:
    """What a `--dry-run` runs: no token, and the same refusal as the real run."""
    monkeypatch.setitem(sys.modules, "onepassword", None)
    with pytest.raises(OnePasswordNotInstalledError):
        onepassword.check_installed()


# ------------------------------------------- a real account (maintainer) ---


def real_account(monkeypatch: pytest.MonkeyPatch) -> tuple[str, Secret]:
    """The test vault and the token, or a skip.

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
    return vault, Secret(Path(token_file).read_text(encoding="utf-8").strip())


def test_a_delivery_against_a_real_account_leaves_no_item(monkeypatch: pytest.MonkeyPatch) -> None:
    """The link is not opened here, because opening it uses up its one view.
    The maintainer's real run opens it in a browser."""
    vault, token = real_account(monkeypatch)
    share = OnePassword(onepassword_vault=vault, ttl="1h", token=token)

    receipt = share.deliver(Secret(PASSWORD), account="acme_app_user", target="acme-test")

    assert receipt.token is not None
    assert receipt.token.reveal().startswith("https://share.1password.com/")
    assert receipt.left_behind is None

    async def titles() -> list[str]:
        client = await onepassword._authenticate(token)
        vault_id = await share._vault_id(client)
        return [item.title for item in await client.items.list(vault_id)]

    assert "acme_app_user on acme-test" not in asyncio.run(titles())


def test_preflight_against_a_real_account(monkeypatch: pytest.MonkeyPatch) -> None:
    """The fake above, checked against 1Password itself."""
    vault, token = real_account(monkeypatch)

    OnePassword(onepassword_vault=vault, ttl="24h", token=token).preflight(
        account="acme_app_user", target="acme-test"
    )

    with pytest.raises(OnePasswordRefusedError, match="sees no vault with that title"):
        OnePassword(onepassword_vault=f"{vault}-absent", ttl="24h", token=token).preflight(
            account="acme_app_user", target="acme-test"
        )
