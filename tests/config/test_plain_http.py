"""Plain HTTP off loopback is refused, for a vault address and a webhook URL.

Tier 0. Over ``http://`` the vault token, an AppRole ``secret_id``, every
password written, and a webhook's chat token cross the network in clear. A
loopback host never leaves the machine, so ``127.0.0.1``, ``::1`` and
``localhost`` stay allowed. The host is compared whole, so
``localhost.example.com`` is not loopback.

Each address is tested where the tool refuses it: a vault ``addr`` in the file
when the file is read, any vault address when the store opens (which covers
``VAULT_ADDR``), and a webhook URL when it is resolved.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ROOT, ConfigError
from sopuli.config.plain_http import plain_http_scheme
from sopuli.config.vaults import build_vault_patches, build_vaults
from sopuli.secrets import Secret

httpx = pytest.importorskip("httpx", reason="the hashicorp extra is not installed")

from sopuli.config.model import Vault  # noqa: E402
from sopuli.notify import webhook  # noqa: E402
from sopuli.store.hashicorp._transport import build_transport  # noqa: E402

LOOPBACK = ["http://127.0.0.1:8200", "http://[::1]:8200", "http://localhost:8200"]

REFUSED = [
    ("http://vault.example.com:8200", "http"),
    ("http://localhost.example.com:8200", "http"),
    ("http://127.0.0.1.example.com:8200", "http"),
    ("http://192.0.2.10:8200", "http"),
    ("ftp://vault.example.com", "ftp"),
    ("vault.example.com:8200", "no scheme"),
    ("127.0.0.1:8200", "no scheme"),
]


def vaults(addr: str) -> Any:
    return build_vaults({"vaults": {"vault-dev": {"type": "hashicorp", "addr": addr}}})


def store(addr: str) -> Vault:
    return Vault(name="vault-dev", type="hashicorp", addr=addr)


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


# ----------------------------------------------------- vault addr, the file ---


@pytest.mark.parametrize("addr", LOOPBACK)
def test_a_loopback_addr_in_the_file_loads(addr: str) -> None:
    (vault,) = vaults(addr)

    assert vault.addr == addr


@pytest.mark.parametrize("addr", ["http://vault.example.com:8200", "http://localhost.example.com"])
def test_a_plain_http_addr_in_the_file_is_refused(addr: str) -> None:
    with pytest.raises(ConfigError) as caught:
        vaults(addr)

    rendered = str(caught.value)
    assert "a vault `addr` must use https://, and this one uses http" in rendered
    assert "vaults.vault-dev.addr" in rendered
    assert "127.0.0.1, ::1 or localhost" in rendered


def test_a_profile_patch_is_held_to_the_same_rule() -> None:
    """A profile reaches a store by the same reader, so it cannot write what
    the declaration may not."""
    with pytest.raises(ConfigError, match="must use https://"):
        build_vault_patches(
            {"vaults": {"vault-dev": {"addr": "http://vault.example.com"}}},
            at=ROOT.key("profiles").key("standby"),
        )


# ------------------------------------------- vault addr, at store open ---


@pytest.mark.parametrize("addr", LOOPBACK)
def test_a_loopback_address_opens(addr: str) -> None:
    transport = build_transport(store(addr), token=Secret("t"))
    transport.close()


@pytest.mark.parametrize("addr", ["http://vault.example.com:8200", "http://localhost.example.com"])
def test_a_plain_http_address_from_the_environment_is_refused_at_open(addr: str) -> None:
    """`VAULT_ADDR` and `--vault-addr` never pass through the file's reader, so
    the transport refuses before the token goes anywhere."""
    with pytest.raises(ConfigError) as caught:
        build_transport(store(addr), token=Secret("t"))

    rendered = str(caught.value)
    assert "vault 'vault-dev': its address must use https://, and this one uses http" in rendered
    assert "127.0.0.1, ::1 or localhost" in rendered


# ------------------------------------------------------------ webhook URL ---


@pytest.mark.parametrize("url", LOOPBACK)
def test_a_loopback_webhook_is_allowed(url: str) -> None:
    webhook.check_url(Secret(url))


def test_an_https_webhook_is_allowed() -> None:
    webhook.check_url(Secret("https://chat.example.com/hooks/T0K3N"))


@pytest.mark.parametrize(
    "url",
    ["http://chat.example.com/hooks/T0K3N", "http://localhost.example.com/hooks/T0K3N"],
)
def test_a_plain_http_webhook_is_refused_without_repeating_it(url: str) -> None:
    """The URL is the chat credential, so the message gives the scheme only."""
    with pytest.raises(ConfigError) as caught:
        webhook.check_url(Secret(url))

    rendered = str(caught.value)
    assert "delivery.notify.webhook.url" in rendered
    assert "must use https://, and this one uses http" in rendered
    assert "T0K3N" not in rendered
    assert "chat.example.com" not in rendered
