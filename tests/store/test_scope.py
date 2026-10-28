"""Which store types serve personal accounts (UC-2) in this build.

Tier 0, pure: a :class:`~sopuli.config.model.Vault` in, a refusal or nothing out.
"""

from __future__ import annotations

import pytest

from sopuli.config.model import Vault
from sopuli.exit_codes import ExitCode
from sopuli.store.registry import BACKEND_NOT_IMPLEMENTED, BackendNotImplementedError
from sopuli.store.scope import refuse_personal_on


def test_an_oci_store_is_refused_for_personal_accounts() -> None:
    with pytest.raises(BackendNotImplementedError) as caught:
        refuse_personal_on(Vault(name="vault-oci", type="oci"))

    error = caught.value
    assert error.code == BACKEND_NOT_IMPLEMENTED
    assert error.exit_code == ExitCode.CONFIG_INVALID
    assert "application credentials (UC-1) only" in str(error)
    assert "HashiCorp" in str(error)


@pytest.mark.parametrize("kind", ["hashicorp", "file", "keyring"])
def test_other_store_types_are_not_refused_here(kind: str) -> None:
    """`file` and `keyring` have no backend at all, which the registry says
    when they connect; this module is about OCI's scope only."""
    refuse_personal_on(Vault(name="store", type=kind))
