"""Plain HTTP off loopback is refused, for a vault address and a webhook URL.

Tier 0, pure. Over ``http://`` the vault token, an AppRole ``secret_id``, every
password written, and a webhook's chat token cross the network in clear. A
loopback host never leaves the machine, so ``127.0.0.1``, ``::1`` and
``localhost`` stay allowed. The host is compared whole, so
``localhost.example.com`` is not loopback.

This module covers the rule and the loader, which refuses a HashiCorp store's
merged address whichever layer set it. The two checks that need ``httpx`` are
beside their modules: the transport's in ``tests/store/test_hashicorp_transport.py``
and the webhook URL's in ``tests/test_notify_webhook.py``.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.loading import build_config
from sopuli.config.model import Vault
from sopuli.config.plain_http import plain_http_scheme

LOOPBACK = ["http://127.0.0.1:8200", "http://[::1]:8200", "http://localhost:8200"]

PLAIN = ["http://vault.example.com:8200", "http://localhost.example.com:8200"]

REFUSED = [
    ("http://vault.example.com:8200", "http"),
    ("http://localhost.example.com:8200", "http"),
    ("http://127.0.0.1.example.com:8200", "http"),
    ("http://192.0.2.10:8200", "http"),
    ("ftp://vault.example.com", "ftp"),
    ("https:/vault.example.com:8200", "a scheme with no //"),
    ("http:vault.example.com", "a scheme with no //"),
    ("vault.example.com:8200", "no scheme"),
    ("127.0.0.1:8200", "no scheme"),
    ("localhost:8200", "no scheme"),
]


def loaded(addr: str | None = None, *, kind: str = "hashicorp", **options: Any) -> Vault:
    """`vault-dev`, the default store, through the whole loader and its layers.

    ``options`` go to ``build_config``: ``env``, ``vault_addr`` and ``profile``.
    A profile named ``standby`` sets ``standby_addr`` when one is given.
    """
    standby_addr = options.pop("standby_addr", None)
    document: dict[str, Any] = {
        "version": 1,
        "defaults": {"vault": "vault-dev"},
        "vaults": {"vault-dev": {"type": kind, **({"addr": addr} if addr else {})}},
    }
    if standby_addr is not None:
        document["profiles"] = {"standby": {"vaults": {"vault-dev": {"addr": standby_addr}}}}
    (vault,) = build_config(document, **options).vaults
    return vault


# ------------------------------------------------------------- the rule ---


def test_https_is_allowed_anywhere() -> None:
    assert plain_http_scheme("https://vault.example.com:8200") is None


@pytest.mark.parametrize("addr", LOOPBACK)
def test_plain_http_to_loopback_is_allowed(addr: str) -> None:
    assert plain_http_scheme(addr) is None


def test_the_scheme_and_the_host_are_compared_without_case() -> None:
    assert plain_http_scheme("HTTP://LOCALHOST:8200") is None


@pytest.mark.parametrize(("addr", "scheme"), REFUSED)
def test_anything_else_is_refused(addr: str, scheme: str) -> None:
    assert plain_http_scheme(addr) == scheme


def test_userinfo_does_not_make_a_host_loopback() -> None:
    """The host is what follows `@`, so this request goes to example.com."""
    assert plain_http_scheme("http://127.0.0.1@vault.example.com") == "http"


def test_a_host_is_never_given_back_as_the_scheme() -> None:
    """`urlsplit` reads `chat.example.com:443/…` as the scheme `chat.example.com`.
    The answer goes into a message, and a webhook URL is a credential."""
    answer = plain_http_scheme("chat.example.com:443/hooks/T0K3N?next=https://x")

    assert answer == "no scheme"


# ------------------------------------------------------- vault addr, at load ---


@pytest.mark.parametrize("addr", LOOPBACK)
def test_a_loopback_addr_in_the_file_loads(addr: str) -> None:
    assert loaded(addr).addr == addr


@pytest.mark.parametrize("addr", PLAIN)
def test_a_plain_http_addr_in_the_file_is_refused(addr: str) -> None:
    with pytest.raises(ConfigError) as caught:
        loaded(addr)

    rendered = str(caught.value)
    assert (
        "vault 'vault-dev': the address vaults.vault-dev.addr gives must use https://, "
        "and this one uses http"
    ) in rendered
    assert "127.0.0.1, ::1 or localhost" in rendered


@pytest.mark.parametrize("addr", PLAIN)
def test_a_plain_http_vault_addr_variable_is_refused(addr: str) -> None:
    """`VAULT_ADDR` is merged into the store at load, and the message names it."""
    with pytest.raises(ConfigError, match="the address VAULT_ADDR gives must use https://"):
        loaded("https://vault.example.com", env={"VAULT_ADDR": addr})


@pytest.mark.parametrize("addr", LOOPBACK)
def test_a_loopback_vault_addr_variable_loads(addr: str) -> None:
    assert loaded("https://vault.example.com", env={"VAULT_ADDR": addr}).addr == addr


def test_a_plain_http_vault_addr_flag_is_refused() -> None:
    with pytest.raises(ConfigError, match="the address --vault-addr gives must use https://"):
        loaded("https://vault.example.com", vault_addr="http://vault.example.com:8200")


def test_a_profile_is_held_to_the_same_rule() -> None:
    with pytest.raises(ConfigError, match="must use https://"):
        loaded(
            "https://vault.example.com",
            profile="standby",
            standby_addr="http://vault.example.com:8200",
        )


def test_a_file_store_reads_addr_as_a_path_and_is_not_checked() -> None:
    """Only a HashiCorp store reads `addr` as a URL."""
    assert loaded("./store.json", kind="file").addr == "./store.json"
