"""Vault's reasons for a refused token reach the reported error (#934).

Tier 1, and skips without the container. Vault 2.0.4 answers a wrong token with
one multi-line entry in ``errors[]``, and the CLI keeps only the first line of an
error's message. This sends a real request with a wrong token and checks the
reasons survive both steps.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.model import Vault
from sopuli.secrets import Secret
from sopuli.store.protocol import StoreError


def test_a_wrong_token_keeps_vaults_reasons(vault_stack: Any) -> None:
    from sopuli.cli import _as_error
    from sopuli.store.hashicorp import open_store

    store = open_store(
        Vault(
            name="vault-dev",
            type="hashicorp",
            addr=vault_stack.addr,
            mount=vault_stack.kv2_mount,
            kv_version=2,
        ),
        token=Secret("not-a-token"),
    )

    with pytest.raises(StoreError) as caught:
        store.read(f"{vault_stack.scratch}/refusal-reasons")

    error = _as_error(caught.value)
    assert error.category == "authorization"
    assert error.message.endswith(": permission denied; invalid token"), error.message
