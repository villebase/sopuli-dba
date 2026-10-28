"""Which use cases each store type serves in this build.

An ``oci`` store serves application credentials (UC-1) and not personal
accounts (UC-2). UC-2 needs reset records, which are written per account and
read back by ``account list``, and its unseen delivery ``vault_wrapped`` uses
HashiCorp's response wrapping, which OCI has no equivalent of. Putting UC-2 on
OCI is later work (#1138), so a personal verb that would reach an
OCI store is refused before it reaches one, rather than failing partway
(invariant 4).

Pure: it reads a :class:`~sopuli.config.model.Vault` and opens nothing.
"""

from __future__ import annotations

from sopuli.config.model import Config, Vault
from sopuli.store.registry import BackendNotImplementedError

#: Store types that cannot hold UC-2's reset records or receive its deliveries.
UC1_ONLY_TYPES = ("oci",)


def refuse_personal_on(vault: Vault) -> None:
    """Refuse a personal-account verb that would reach ``vault``, if it cannot serve one.

    ``SOPULI-20005`` and exit 9, the code for a backend this build has no module
    for: the store is declared correctly, and nothing the operator installs adds
    UC-2 support to it.
    """
    if vault.type not in UC1_ONLY_TYPES:
        return
    raise BackendNotImplementedError(
        f'vault "{vault.name}" is an OCI store, and this build supports OCI for '
        f"application credentials (UC-1) only",
        hint="keep personal accounts and reset records in a HashiCorp store",
    )


def refuse_personal_on_named(config: Config, name: str) -> None:
    """:func:`refuse_personal_on` for a store named in ``config``.

    A name that matches no declared store is left alone here: the reference
    checks refuse it with the message every dangling name gets.
    """
    vault = next((vault for vault in config.vaults if vault.name == name), None)
    if vault is not None:
        refuse_personal_on(vault)
