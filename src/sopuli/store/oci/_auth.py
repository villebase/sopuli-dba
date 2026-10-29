"""The OCI SDK clients for one OCI store, signed by the store's auth method.

``01-configuration.md`` §3a lists four methods for an OCI store. The config
layer refuses a HashiCorp method on an OCI store (#1130), so
:func:`build_clients` sees only those four. This build signs with
``config_file``; the other three are refused as not built yet.

An OCI store with no ``auth:`` block uses ``config_file`` with the profile
``DEFAULT``, as the OCI CLI does.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import oci

from sopuli.config.model import Vault
from sopuli.exit_codes import ExitCode
from sopuli.store.protocol import StoreError

CONFIG_FILE = "config_file"

DEFAULT_PROFILE = "DEFAULT"

#: The OCI SDK's variable for its config file. The OCI CLI reads
#: ``OCI_CLI_CONFIG_FILE`` instead, and this store does not.
CONFIG_FILE_VARIABLE = "OCI_CONFIG_FILE"


class OciConfigError(StoreError):
    """The OCI auth settings could not be used. Fixed on this machine."""

    category = "config"
    exit_code = ExitCode.CONFIG_INVALID


@dataclass(frozen=True)
class Clients:
    """The SDK clients one store uses.

    ``vaults`` creates, updates and lists secrets, ``secrets`` reads their
    content, and ``kms`` reads the vault itself, which only the KMS API can do.
    """

    vaults: Any
    secrets: Any
    kms: Any


def build_clients(vault: Vault, *, env: Mapping[str, str]) -> Clients:
    """The three clients for ``vault``, signed by its auth method.

    ``env`` is passed in rather than read here, as everywhere else in the tool:
    it is where ``OCI_CONFIG_FILE`` comes from.
    """
    method = vault.auth.method if vault.auth is not None else CONFIG_FILE
    profile = vault.auth.profile if vault.auth is not None else None
    where = f"vaults.{vault.name}.auth"
    if method != CONFIG_FILE:
        # As the HashiCorp backend words `oidc`: not yet, rather than unsupported.
        raise OciConfigError(
            f"{where}: `{method}` is not implemented in this build yet for an OCI store",
            hint="config_file is the OCI auth method this build can perform",
        )

    location = env.get(CONFIG_FILE_VARIABLE, oci.config.DEFAULT_LOCATION)
    profile = profile or DEFAULT_PROFILE
    try:
        config: dict[str, Any] = oci.config.from_file(file_location=location, profile_name=profile)
        # Before the check, which requires a region: the store's may be the only one.
        if vault.region is not None:
            config["region"] = vault.region
        oci.config.validate_config(config)
        # Building a client loads the profile's private key, so a missing key
        # file or a wrong pass phrase fails here and not in `from_file`.
        return Clients(
            vaults=oci.vault.VaultsClient(config, **_options(vault)),
            secrets=oci.secrets.SecretsClient(config, **_options(vault)),
            kms=oci.key_management.KmsVaultClient(config, **_options(vault)),
        )
    except (oci.exceptions.ClientError, OSError) as exc:
        raise OciConfigError(
            f"{where}: cannot use profile {profile!r} in the OCI config file {location}: {exc}",
            hint=f"check the file and its key_file, or set {CONFIG_FILE_VARIABLE} to another file",
        ) from exc


def _options(vault: Vault) -> dict[str, Any]:
    """What every client is built with.

    No retries. The HashiCorp backend does not retry either, and a write under
    ``if_match`` that the SDK retried by itself would hide what happened.
    """
    options: dict[str, Any] = {"retry_strategy": oci.retry.NoneRetryStrategy()}
    if vault.timeout_s is not None:
        options["timeout"] = float(vault.timeout_s)
    return options
