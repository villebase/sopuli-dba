"""Which use cases each store type serves in this build.

An ``oci`` store serves application credentials (UC-1) and not personal
accounts (UC-2). UC-2 needs reset records, which are written per account and
read back by ``account list``, and its unseen delivery ``vault_wrapped`` uses
HashiCorp's response wrapping, which OCI has no equivalent of. Putting UC-2 on
OCI is later work (#1138).

Two places apply the rule. :func:`sopuli.config.references.check_references`
refuses a ``reset_records:`` store or a delivery method's own ``vault:`` that is
an OCI store, when the file is read. ``account reset-password`` refuses a
delivery whose store a target or ``defaults.vault`` supplies, before it builds a
plan, with :func:`refuse_personal_on`.

Pure: it reads a :class:`~sopuli.config.model.Vault` and opens nothing.
"""

from __future__ import annotations

from sopuli.config.errors import ConfigError, KeyPath
from sopuli.config.model import Config

#: Store types that cannot hold UC-2's reset records or receive its deliveries.
UC1_ONLY_TYPES = ("oci",)

HINT = "keep personal accounts, reset records and deliveries in a HashiCorp store"


def refuse_personal_on(config: Config, name: str, *, at: KeyPath, what: str) -> None:
    """Refuse UC-2 use of the store ``name``, if its type serves UC-1 only.

    ``what`` says what would reach it, for the message. A name that matches no
    declared store is left alone: the reference checks refuse it with the
    message every dangling name gets.
    """
    vault = next((vault for vault in config.vaults if vault.name == name), None)
    if vault is None or vault.type not in UC1_ONLY_TYPES:
        return
    raise ConfigError(
        f'{what} is vault "{vault.name}", an OCI store, and this build supports OCI '
        f"for application credentials (UC-1) only",
        at=at,
        hint=HINT,
    )
