"""The keys a ``file`` store reads, and the ones it refuses (#1415).

Tier 0, pure: every case builds from a dict. The backend is not built yet
(#1372); these are the config rules it will be opened with.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.codes import THIRD_PARTY_VARIABLE_UNAPPLIED
from sopuli.config.errors import ConfigError
from sopuli.config.loading import build_config
from sopuli.config.model import Config, MaterialRef, Vault

STORE = "vault-local"

#: Two well-formed age public keys. Only their shape is checked, so they need
#: not belong to any key pair.
RECIPIENT = "age1" + "q" * 58
OTHER_RECIPIENT = "age1" + "p" * 58

FILE: dict[str, Any] = {
    "type": "file",
    "addr": "/srv/sopuli/store.age",
    "identity": {"env": "SOPULI_FILE_IDENTITY"},
    "non_production": True,
}


def document(vault: dict[str, Any] | None = None, **sections: Any) -> dict[str, Any]:
    return {"version": 1, "vaults": {STORE: FILE if vault is None else vault}, **sections}


def loaded(
    vault: dict[str, Any] | None = None, *, env: dict[str, str] | None = None, **sections: Any
) -> Config:
    return build_config(document(vault, **sections), env=env or {})


def store(vault: dict[str, Any] | None = None, **sections: Any) -> Vault:
    [one] = loaded(vault, **sections).vaults
    return one


def refused(vault: dict[str, Any] | None = None, **sections: Any) -> str:
    with pytest.raises(ConfigError) as caught:
        loaded(vault, **sections)
    return str(caught.value)


# ----------------------------------------------------------------- the keys ---


def test_a_file_store_reads_its_path_identity_recipients_and_versions() -> None:
    vault = store({**FILE, "recipients": [RECIPIENT, OTHER_RECIPIENT], "max_versions": 3})

    assert vault.addr == "/srv/sopuli/store.age"
    assert vault.identity == MaterialRef(kind="env", location="SOPULI_FILE_IDENTITY")
    assert vault.recipients == (RECIPIENT, OTHER_RECIPIENT)
    assert vault.max_versions == 3


def test_recipients_and_max_versions_are_optional() -> None:
    """Absent recipients means the identity's own key; absent max_versions
    means the store's default. Neither is filled in here."""
    vault = store()

    assert vault.recipients is None
    assert vault.max_versions is None


def test_the_identity_is_required() -> None:
    rendered = refused({key: value for key, value in FILE.items() if key != "identity"})

    assert "needs `identity`" in rendered


def test_an_identity_written_inline_is_refused_without_repeating_it() -> None:
    secret = "AGE-SECRET-KEY-1" + "Q" * 58
    rendered = refused({**FILE, "identity": secret})

    assert "is named, not written here" in rendered
    assert secret not in rendered


def test_the_path_is_required() -> None:
    rendered = refused({key: value for key, value in FILE.items() if key != "addr"})

    assert "needs `addr`, the path of its file" in rendered


def test_the_path_may_come_from_defaults() -> None:
    """`addr` is a reach key, so a layer may supply it."""
    path = "/srv/sopuli/other.age"
    without = {key: value for key, value in FILE.items() if key != "addr"}

    assert store(without, defaults={"vaults": {STORE: {"addr": path}}}).addr == path


@pytest.mark.parametrize("value", [0, -1, True, "10"])
def test_max_versions_is_a_number_of_at_least_one(value: Any) -> None:
    refused({**FILE, "max_versions": value})


def test_one_version_is_allowed() -> None:
    assert store({**FILE, "max_versions": 1}).max_versions == 1


@pytest.mark.parametrize("value", [[], RECIPIENT, {"key": RECIPIENT}])
def test_recipients_is_a_non_empty_list(value: Any) -> None:
    assert "non-empty list of age public keys" in refused({**FILE, "recipients": value})


def test_a_secret_key_in_recipients_is_refused_without_repeating_it() -> None:
    secret = "AGE-SECRET-KEY-1" + "Q" * 58
    rendered = refused({**FILE, "recipients": [RECIPIENT, secret]})

    assert "is not an age public key" in rendered
    assert "recipients[1]" in rendered
    assert secret not in rendered


def test_a_recipient_listed_twice_is_refused() -> None:
    assert "is listed twice" in refused({**FILE, "recipients": [RECIPIENT, RECIPIENT]})


# ------------------------------------------------- keys on the wrong store ---


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("identity", {"env": "SOPULI_FILE_IDENTITY"}),
        ("recipients", [RECIPIENT]),
        ("max_versions", 3),
    ],
)
def test_a_file_key_on_a_hashicorp_store_is_refused(key: str, value: Any) -> None:
    rendered = refused({"type": "hashicorp", "addr": "https://vault.example.com", key: value})

    assert f"`{key}` has no effect on a store of type 'hashicorp'" in rendered


@pytest.mark.parametrize("key", ["identity", "recipients", "max_versions"])
@pytest.mark.parametrize("where", ["defaults", "profile"])
def test_no_layer_may_change_a_file_key(key: str, where: str) -> None:
    value = {"identity": {"env": "OTHER"}, "recipients": [RECIPIENT], "max_versions": 2}[key]
    block = {"vaults": {STORE: {key: value}}}
    sections = {"defaults": block} if where == "defaults" else {"profiles": {"ci": block}}

    rendered = refused(FILE, **sections)

    assert f"`{key}:` cannot be set on a partial `vaults:` entry" in rendered


@pytest.mark.parametrize(
    ("key", "value"), [("mount", "kv"), ("kv_version", 2), ("namespace", "team")]
)
@pytest.mark.parametrize("where", ["declaration", "defaults"])
def test_a_file_store_refuses_hashicorp_keys(key: str, value: Any, where: str) -> None:
    if where == "declaration":
        rendered = refused({**FILE, key: value})
    else:
        rendered = refused(FILE, defaults={"vaults": {STORE: {key: value}}})

    assert f"`{key}`" in rendered
    assert "has no effect on a store of type 'file'" in rendered


def test_a_file_store_refuses_tls() -> None:
    rendered = refused({**FILE, "tls": {"verify": True}})

    assert "`tls`" in rendered
    assert "opens no connection" in rendered


@pytest.mark.parametrize("where", ["declaration", "profile"])
def test_a_file_store_refuses_any_auth_block(where: str) -> None:
    if where == "declaration":
        rendered = refused({**FILE, "auth": {"method": "token"}})
    else:
        with pytest.raises(ConfigError) as caught:
            build_config(
                document(FILE, profiles={"ci": {"vaults": {STORE: {"auth": "token"}}}}),
                profile="ci",
            )
        rendered = str(caught.value)

    assert "has no effect on a store of type 'file'" in rendered
    assert "identity" in rendered


# --------------------------------------------------- HashiCorp's variables ---


def test_vault_addr_is_not_applied_to_a_file_store() -> None:
    """A file store reads `addr` as a path, so a VAULT_ADDR left in the shell
    would make a URL its path. It is not applied, and the run says so."""
    config = loaded(
        FILE, env={"VAULT_ADDR": "https://vault.example.com"}, defaults={"vault": STORE}
    )

    assert config.vaults[0].addr == "/srv/sopuli/store.age"
    [warning] = [one for one in config.warnings if one.code == THIRD_PARTY_VARIABLE_UNAPPLIED]
    assert "is a file store, which reads no HashiCorp setting" in warning.message


def test_the_tool_s_own_address_variable_still_sets_the_path() -> None:
    path = "/srv/sopuli/ci.age"
    config = loaded(FILE, env={"SOPULI_VAULT_ADDR": path}, defaults={"vault": STORE})

    assert config.vaults[0].addr == path


# ----------------------------------------------------------------- UC-2 ---


def test_reset_records_in_a_file_store_are_refused() -> None:
    rendered = refused(FILE, reset_records={"vault": STORE, "prefix": "resets"})

    assert "reset_records.vault" in rendered
    assert "of type 'file'" in rendered


def test_a_file_store_for_application_credentials_still_loads() -> None:
    assert loaded(FILE, defaults={"vault": STORE}).vaults
