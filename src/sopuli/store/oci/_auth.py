"""The OCI SDK clients for one OCI store, signed by the store's auth method.

``01-configuration.md`` §3a lists four methods for an OCI store. The config
layer refuses a HashiCorp method on an OCI store (#1130), so
:func:`build_clients` sees only those four.

An OCI store with no ``auth:`` block uses ``config_file`` with the profile
``DEFAULT``, as the OCI CLI does.
"""

from __future__ import annotations

import functools
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import oci

from sopuli.config.model import Vault
from sopuli.exit_codes import ExitCode
from sopuli.store.protocol import StoreError

CONFIG_FILE = "config_file"
SESSION_TOKEN = "session_token"
INSTANCE_PRINCIPAL = "instance_principal"
RESOURCE_PRINCIPAL = "resource_principal"

DEFAULT_PROFILE = "DEFAULT"

#: The OCI SDK's variable for its config file. The OCI CLI reads
#: ``OCI_CLI_CONFIG_FILE`` instead, and this store does not.
CONFIG_FILE_VARIABLE = "OCI_CONFIG_FILE"


class OciConfigError(StoreError):
    """The OCI auth settings could not be used. Fixed on this machine."""

    category = "config"
    exit_code = ExitCode.CONFIG_INVALID


class OciSignerError(StoreError):
    """A principal's credentials could not be fetched from where it runs."""

    category = "authentication"
    exit_code = ExitCode.AUTH_FAILURE


@dataclass(frozen=True)
class Clients:
    """The SDK clients one store uses.

    ``vaults`` creates, updates and lists secrets, ``secrets`` reads their
    content, and ``kms`` reads the vault itself, which only the KMS API can do.
    """

    vaults: Any
    secrets: Any
    kms: Any
    #: The OCI CLI options that reach the store as these clients do: the
    #: config file, profile, auth method and region they were built with
    #: (#1186). Every one the CLI could otherwise take from its own variables
    #: or ``oci_cli_rc`` is named, so a printed command runs as this run did.
    cli_options: tuple[str, ...] = ()


def build_clients(vault: Vault, *, env: Mapping[str, str]) -> Clients:
    """The three clients for ``vault``, signed by its auth method.

    ``env`` is passed in rather than read here, as everywhere else in the tool:
    it is where ``OCI_CONFIG_FILE`` comes from. One exception: the SDK's
    resource-principal signer reads its ``OCI_RESOURCE_PRINCIPAL_*`` variables
    from the process environment itself, and takes no mapping.
    """
    method = vault.auth.method if vault.auth is not None else CONFIG_FILE
    where = f"vaults.{vault.name}.auth"
    if method in (CONFIG_FILE, SESSION_TOKEN):
        profile = (vault.auth.profile if vault.auth is not None else None) or DEFAULT_PROFILE
        return _from_config_file(vault, env, profile, session=method == SESSION_TOKEN, where=where)
    if method == INSTANCE_PRINCIPAL:
        # Without this the signer retries the metadata service for minutes
        # (measured: 4 m 28 s on a laptop) before it says this is no instance.
        # Its token refreshes during a run keep the SDK's retries: a refresh
        # is no write, and failing one between a pending write and its
        # promotion would cost more than a retry.
        factory = functools.partial(
            oci.auth.signers.InstancePrincipalsSecurityTokenSigner,
            retry_strategy=oci.retry.NoneRetryStrategy(),
        )
    elif method == RESOURCE_PRINCIPAL:
        factory = oci.auth.signers.get_resource_principals_signer
    else:
        # Unreachable through a config file: the loader refuses any other
        # method on an OCI store (#1130). Kept because this is reachable from code.
        raise OciConfigError(
            f"{where}: `{method}` is not an auth method for an OCI store",
            hint="use config_file, session_token, instance_principal or resource_principal",
        )

    signer = _principal(factory, where=where)
    region = vault.region if vault.region is not None else signer.region
    return _clients(
        vault, {"region": region}, signer, cli=("--auth", method, "--region", str(region))
    )


def _from_config_file(
    vault: Vault, env: Mapping[str, str], profile: str, *, session: bool, where: str
) -> Clients:
    """The clients for a profile in the OCI config file.

    With ``session``, the profile was made by ``oci session authenticate``, and
    its requests are signed with the session token rather than the user's key.
    """
    location = env.get(CONFIG_FILE_VARIABLE, oci.config.DEFAULT_LOCATION)
    try:
        config: dict[str, Any] = oci.config.from_file(file_location=location, profile_name=profile)
        # Before the check, which requires a region: the store's may be the only one.
        if vault.region is not None:
            config["region"] = vault.region
        if not config.get("region"):
            # `validate_config` checks nothing once it has a session signer,
            # and the client then fails with a bare ValueError.
            raise OciConfigError(
                f"{where}: profile {profile!r} in the OCI config file {location} has no region",
                hint="add a region line to the profile, or set region on the store",
            )
        signer = _security_token_signer(config, where=where) if session else None
        oci.config.validate_config(config, signer=signer)
        cli = (
            # The CLI reads OCI_CLI_CONFIG_FILE, not this variable.
            *(("--config-file", location) if CONFIG_FILE_VARIABLE in env else ()),
            "--profile",
            profile,
            "--auth",
            "security_token" if session else "api_key",
            "--region",
            str(config["region"]),
        )
        # Building a client loads the profile's private key, so a missing key
        # file or a wrong pass phrase fails here and not in `from_file`.
        return _clients(vault, config, signer, cli=cli)
    except (oci.exceptions.ClientError, OSError) as exc:
        raise OciConfigError(
            f"{where}: cannot use profile {profile!r} in the OCI config file {location}: {exc}",
            hint=f"check the file and its key_file, or set {CONFIG_FILE_VARIABLE} to another file",
        ) from exc


def _security_token_signer(config: Mapping[str, Any], *, where: str) -> Any:
    """The signer for a profile made by ``oci session authenticate``."""
    token_file = config.get("security_token_file")
    if not token_file:
        raise OciConfigError(
            f"{where}: the profile has no security_token_file, so it is not a session profile",
            hint="create the session with:  oci session authenticate",
        )
    key_file = config.get("key_file")
    if not key_file:
        raise OciConfigError(
            f"{where}: the session profile has no key_file",
            hint="create the session again with:  oci session authenticate",
        )
    try:
        with open(os.path.expanduser(token_file), encoding="utf-8") as handle:
            token = handle.read().strip()
    except UnicodeDecodeError as exc:
        raise OciConfigError(
            f"{where}: the security_token_file {token_file} is not a session token: {exc}",
            hint="create the session again with:  oci session authenticate",
        ) from exc
    if not token:
        raise OciConfigError(
            f"{where}: the security_token_file {token_file} is empty",
            hint="create the session again with:  oci session authenticate",
        )
    key = oci.signer.load_private_key_from_file(key_file, config.get("pass_phrase"))
    return oci.auth.signers.SecurityTokenSigner(token, key)


def _principal(factory: Any, *, where: str) -> Any:
    """A principal's signer. Building one fetches its credentials."""
    try:
        return factory()
    except Exception as exc:
        # The SDK raises a mix of its own errors and `requests`' here, with no
        # common base, and the message keeps whichever it was.
        raise OciSignerError(
            f"{where}: cannot get credentials for the principal: {exc}",
            hint=(
                "on an OCI instance or function, check its metadata service and its "
                "dynamic group; elsewhere, use auth method config_file"
            ),
        ) from exc


def _clients(
    vault: Vault, config: Mapping[str, Any], signer: Any, *, cli: tuple[str, ...]
) -> Clients:
    return Clients(
        vaults=oci.vault.VaultsClient(config, **_options(vault, signer)),
        secrets=oci.secrets.SecretsClient(config, **_options(vault, signer)),
        kms=oci.key_management.KmsVaultClient(config, **_options(vault, signer)),
        cli_options=cli,
    )


def _options(vault: Vault, signer: Any) -> dict[str, Any]:
    """What every client is built with.

    No retries. The HashiCorp backend does not retry either, and a write under
    ``if_match`` that the SDK retried by itself would hide what happened.
    """
    options: dict[str, Any] = {"retry_strategy": oci.retry.NoneRetryStrategy()}
    if signer is not None:
        options["signer"] = signer
    if vault.timeout_s is not None:
        options["timeout"] = float(vault.timeout_s)
    return options
