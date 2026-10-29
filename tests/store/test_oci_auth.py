"""The OCI store's auth builds signed SDK clients (#1132).

Tier 0. The SDK's entry points are replaced, so nothing reads a real config
file or reaches the network.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import oci
import pytest

from sopuli.config.model import Vault, VaultAuth
from sopuli.config.vaults import OCI_AUTH_METHODS
from sopuli.exit_codes import ExitCode
from sopuli.store.oci._auth import CONFIG_FILE, build_clients
from sopuli.store.protocol import StoreError

#: Passes `oci.config.validate_config`, which therefore is not replaced: the
#: SDK's client modules bind it when they are first imported, so a replacement
#: in place then would outlive the test.
PROFILE = {
    "region": "eu-frankfurt-1",
    "user": "ocid1.user.oc1..exampleuniqueid",
    "tenancy": "ocid1.tenancy.oc1..exampleuniqueid",
    "fingerprint": "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
    "key_file": "~/.oci/acme.pem",
}


def vault(auth: VaultAuth | None = None, **overrides: Any) -> Vault:
    fields: dict[str, Any] = {
        "name": "vault-oci",
        "type": "oci",
        "vault_id": "ocid1.vault.oc1..exampleuniqueid",
        "compartment_id": "ocid1.compartment.oc1..exampleuniqueid",
        "key_id": "ocid1.key.oc1..exampleuniqueid",
    }
    fields.update(overrides)
    return Vault(auth=auth, **fields)


@dataclass
class Sdk:
    """What the replaced SDK entry points were called with."""

    files: list[tuple[str, str]] = field(default_factory=list)
    clients: list[tuple[str, dict[str, Any], dict[str, Any]]] = field(default_factory=list)


@pytest.fixture
def sdk(monkeypatch: pytest.MonkeyPatch) -> Sdk:
    seen = Sdk()

    def from_file(file_location: str, profile_name: str) -> dict[str, Any]:
        seen.files.append((file_location, profile_name))
        if profile_name == "MISSING":
            raise oci.exceptions.ProfileNotFound(f"Profile '{profile_name}' not found")
        return dict(PROFILE)

    def client(kind: str) -> Any:
        def build(config: dict[str, Any], **kwargs: Any) -> str:
            seen.clients.append((kind, config, kwargs))
            return kind

        return build

    monkeypatch.setattr(oci.config, "from_file", from_file)
    monkeypatch.setattr(oci.vault, "VaultsClient", client("vaults"))
    monkeypatch.setattr(oci.secrets, "SecretsClient", client("secrets"))
    monkeypatch.setattr(oci.key_management, "KmsVaultClient", client("kms"))
    return seen


def test_no_auth_block_reads_the_default_profile(sdk: Sdk) -> None:
    clients = build_clients(vault(), env={})

    assert sdk.files == [(oci.config.DEFAULT_LOCATION, "DEFAULT")]
    assert (clients.vaults, clients.secrets, clients.kms) == ("vaults", "secrets", "kms")


def test_the_named_profile_is_read(sdk: Sdk) -> None:
    build_clients(vault(VaultAuth(method="config_file", profile="ACME")), env={})

    assert sdk.files == [(oci.config.DEFAULT_LOCATION, "ACME")]


def test_oci_config_file_comes_from_the_passed_env(
    sdk: Sdk, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OCI_CONFIG_FILE", "/from/os/environ")

    build_clients(vault(), env={"OCI_CONFIG_FILE": "/srv/acme/oci-config"})

    assert sdk.files == [("/srv/acme/oci-config", "DEFAULT")]


def test_region_overrides_the_profile(sdk: Sdk) -> None:
    build_clients(vault(region="eu-stockholm-1"), env={})

    assert {config["region"] for _, config, _ in sdk.clients} == {"eu-stockholm-1"}


def test_the_profiles_region_is_used_when_the_store_names_none(sdk: Sdk) -> None:
    build_clients(vault(), env={})

    assert {config["region"] for _, config, _ in sdk.clients} == {"eu-frankfurt-1"}


def test_a_missing_profile_is_a_config_error_naming_it(sdk: Sdk) -> None:
    with pytest.raises(StoreError, match="'MISSING'") as error:
        build_clients(vault(VaultAuth(method="config_file", profile="MISSING")), env={})

    assert error.value.exit_code == ExitCode.CONFIG_INVALID
    assert error.value.category == "config"


def test_clients_never_retry(sdk: Sdk) -> None:
    build_clients(vault(), env={})

    for _, _, kwargs in sdk.clients:
        assert isinstance(kwargs["retry_strategy"], oci.retry.NoneRetryStrategy)


def test_timeout_s_is_the_request_timeout(sdk: Sdk) -> None:
    build_clients(vault(timeout_s=7), env={})

    assert {kwargs["timeout"] for _, _, kwargs in sdk.clients} == {7.0}


@pytest.mark.parametrize("method", sorted(set(OCI_AUTH_METHODS) - {CONFIG_FILE}))
def test_the_other_oci_methods_are_refused_as_not_built(sdk: Sdk, method: str) -> None:
    with pytest.raises(StoreError, match="not built in this version") as error:
        build_clients(vault(VaultAuth(method=method)), env={})

    assert error.value.exit_code == ExitCode.CONFIG_INVALID
    assert sdk.clients == []


def test_config_file_is_an_oci_method() -> None:
    assert CONFIG_FILE in OCI_AUTH_METHODS
