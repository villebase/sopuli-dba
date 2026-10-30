"""The OCI Vault backend for P2's store interface (#1128).

What :data:`sopuli.store.registry.BACKENDS` resolves ``type: oci`` to.
Importing this module imports the ``oci`` SDK, so the registry imports it only
when a run connects to an OCI store (ADR-006 rule 1).
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from sopuli.config.model import Vault
from sopuli.store.oci._auth import Clients, build_clients
from sopuli.store.oci.store import OciStore
from sopuli.store.protocol import SecretStore


def connect(vault: Vault, *, env: Mapping[str, str], token_file: Path | None = None) -> SecretStore:
    """A store for ``vault``, signed by its auth method.

    ``token_file`` is ``--vault-token-file``, a HashiCorp token. An OCI store
    signs its requests with its own auth method, so it ignores the token.
    """
    return open_store(vault, build_clients(vault, env=env))


def open_store(vault: Vault, clients: Clients) -> OciStore:
    """The store for ``vault``, with its clients already built."""
    return OciStore(
        vault,
        vaults=clients.vaults,
        secrets=clients.secrets,
        kms=clients.kms,
        cli_options=clients.cli_options,
    )


__all__ = ["Clients", "OciStore", "build_clients", "connect", "open_store"]
