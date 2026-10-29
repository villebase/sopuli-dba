"""The OCI store's auth builds signed SDK clients (#1132).

Tier 0. The SDK's entry points are replaced, so nothing reads a real config
file or reaches the network.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import oci
import pytest

from sopuli.config.model import Vault, VaultAuth
from sopuli.config.vaults import OCI_AUTH_METHODS
from sopuli.exit_codes import ExitCode
from sopuli.store.oci._auth import (
    CONFIG_FILE,
    INSTANCE_PRINCIPAL,
    RESOURCE_PRINCIPAL,
    SESSION_TOKEN,
    build_clients,
)
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
        if profile_name == "NO-REGION":
            return {key: value for key, value in PROFILE.items() if key != "region"}
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


def test_the_stores_region_completes_a_profile_that_has_none(
    sdk: Sdk, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`validate_config` requires a region, so the store's is applied first."""
    monkeypatch.delenv("OCI_REGION", raising=False)

    build_clients(
        vault(VaultAuth(method="config_file", profile="NO-REGION"), region="eu-stockholm-1"),
        env={},
    )

    assert {config["region"] for _, config, _ in sdk.clients} == {"eu-stockholm-1"}


@pytest.mark.parametrize(
    "failure",
    [FileNotFoundError("acme.pem"), oci.exceptions.InvalidPrivateKey("bad pass phrase")],
)
def test_a_key_that_cannot_be_loaded_is_a_config_error(
    sdk: Sdk, monkeypatch: pytest.MonkeyPatch, failure: Exception
) -> None:
    """A client loads the key when it is built, after `from_file` succeeded."""

    def build(config: dict[str, Any], **kwargs: Any) -> None:
        raise failure

    monkeypatch.setattr(oci.vault, "VaultsClient", build)

    with pytest.raises(StoreError, match=str(failure)) as error:
        build_clients(vault(), env={})

    assert error.value.exit_code == ExitCode.CONFIG_INVALID


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


class FakeSigner:
    region = "eu-amsterdam-1"

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs


class FakeSessionSigner:
    """A class, not a function: `validate_config` passes it to `isinstance`."""

    def __init__(self, token: str, key: Any) -> None:
        self.token = token
        self.key = key


@pytest.mark.parametrize(
    ("method", "factory"),
    [
        ("instance_principal", "InstancePrincipalsSecurityTokenSigner"),
        ("resource_principal", "get_resource_principals_signer"),
    ],
)
def test_a_principal_takes_the_signers_region(
    sdk: Sdk, monkeypatch: pytest.MonkeyPatch, method: str, factory: str
) -> None:
    monkeypatch.setattr(oci.auth.signers, factory, FakeSigner)

    build_clients(vault(VaultAuth(method=method)), env={})

    assert sdk.files == []
    for _, config, kwargs in sdk.clients:
        assert config == {"region": "eu-amsterdam-1"}
        assert isinstance(kwargs["signer"], FakeSigner)


def test_an_instance_principal_does_not_retry_the_metadata_service(
    sdk: Sdk, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Measured: with the SDK's retries a laptop waited 4 m 28 s for the refusal."""
    monkeypatch.setattr(oci.auth.signers, "InstancePrincipalsSecurityTokenSigner", FakeSigner)

    build_clients(vault(VaultAuth(method="instance_principal")), env={})

    signer = sdk.clients[0][2]["signer"]
    # Only the startup probe: token refreshes during a run keep the SDK's retries.
    assert set(signer.kwargs) == {"retry_strategy"}
    assert isinstance(signer.kwargs["retry_strategy"], oci.retry.NoneRetryStrategy)


def test_a_principal_takes_the_stores_region_when_set(
    sdk: Sdk, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(oci.auth.signers, "InstancePrincipalsSecurityTokenSigner", FakeSigner)

    build_clients(vault(VaultAuth(method="instance_principal"), region="eu-stockholm-1"), env={})

    assert {config["region"] for _, config, _ in sdk.clients} == {"eu-stockholm-1"}


def test_a_principal_that_cannot_get_credentials_is_an_auth_failure(
    sdk: Sdk, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_metadata_service(**kwargs: Any) -> None:
        raise OSError("connection refused")

    monkeypatch.setattr(
        oci.auth.signers, "InstancePrincipalsSecurityTokenSigner", no_metadata_service
    )

    with pytest.raises(StoreError, match="connection refused") as error:
        build_clients(vault(VaultAuth(method="instance_principal")), env={})

    assert (error.value.category, error.value.exit_code) == (
        "authentication",
        ExitCode.AUTH_FAILURE,
    )
    assert sdk.clients == []


def test_session_token_signs_with_the_session(
    sdk: Sdk, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    token = tmp_path / "token"
    token.write_text("session-token\n", encoding="utf-8")
    profile = {**PROFILE, "security_token_file": str(token)}
    monkeypatch.setattr(oci.config, "from_file", lambda file_location, profile_name: profile)
    monkeypatch.setattr(oci.signer, "load_private_key_from_file", lambda path, phrase: "key")
    monkeypatch.setattr(oci.auth.signers, "SecurityTokenSigner", FakeSessionSigner)

    build_clients(vault(VaultAuth(method="session_token")), env={})

    signers = [kwargs["signer"] for _, _, kwargs in sdk.clients]
    assert [(one.token, one.key) for one in signers] == [("session-token", "key")] * 3


def test_a_profile_with_no_session_says_how_to_make_one(sdk: Sdk) -> None:
    with pytest.raises(StoreError, match="security_token_file") as error:
        build_clients(vault(VaultAuth(method="session_token")), env={})

    assert error.value.exit_code == ExitCode.CONFIG_INVALID
    assert error.value.hint is not None
    assert "oci session authenticate" in error.value.hint


def test_an_unreadable_session_token_is_a_config_error(
    sdk: Sdk, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    profile = {**PROFILE, "security_token_file": str(tmp_path / "gone")}
    monkeypatch.setattr(oci.config, "from_file", lambda file_location, profile_name: profile)

    with pytest.raises(StoreError, match="gone") as error:
        build_clients(vault(VaultAuth(method="session_token")), env={})

    assert error.value.exit_code == ExitCode.CONFIG_INVALID


def session_profile(monkeypatch: pytest.MonkeyPatch, **fields: Any) -> None:
    profile = {key: value for key, value in {**PROFILE, **fields}.items() if value is not None}
    monkeypatch.setattr(oci.config, "from_file", lambda file_location, profile_name: profile)


def test_a_session_profile_with_no_region_is_a_config_error(
    sdk: Sdk, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`validate_config` skips a session signer; the client would raise ValueError."""
    token = tmp_path / "token"
    token.write_text("session-token", encoding="utf-8")
    session_profile(monkeypatch, region=None, security_token_file=str(token))
    monkeypatch.delenv("OCI_REGION", raising=False)

    with pytest.raises(StoreError, match="has no region") as error:
        build_clients(vault(VaultAuth(method="session_token")), env={})

    assert error.value.exit_code == ExitCode.CONFIG_INVALID


def test_a_session_profile_with_no_key_file_is_a_config_error(
    sdk: Sdk, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    token = tmp_path / "token"
    token.write_text("session-token", encoding="utf-8")
    session_profile(monkeypatch, key_file=None, security_token_file=str(token))

    with pytest.raises(StoreError, match="no key_file") as error:
        build_clients(vault(VaultAuth(method="session_token")), env={})

    assert error.value.exit_code == ExitCode.CONFIG_INVALID


@pytest.mark.parametrize(
    ("content", "message"), [(b"", "is empty"), (b"\xff\xfe\x00", "is not a session token")]
)
def test_a_token_file_that_holds_no_token_is_a_config_error(
    sdk: Sdk, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, content: bytes, message: str
) -> None:
    token = tmp_path / "token"
    token.write_bytes(content)
    session_profile(monkeypatch, security_token_file=str(token))

    with pytest.raises(StoreError, match=message) as error:
        build_clients(vault(VaultAuth(method="session_token")), env={})

    assert error.value.exit_code == ExitCode.CONFIG_INVALID


def test_a_hashicorp_method_is_refused(sdk: Sdk) -> None:
    """Unreachable through a config file, which refuses it at load (#1130)."""
    with pytest.raises(StoreError, match="not an auth method for an OCI store"):
        build_clients(vault(VaultAuth(method="token")), env={})


def test_the_method_names_match_the_config_layer() -> None:
    names = {CONFIG_FILE, SESSION_TOKEN, INSTANCE_PRINCIPAL, RESOURCE_PRINCIPAL}
    assert names == set(OCI_AUTH_METHODS)
