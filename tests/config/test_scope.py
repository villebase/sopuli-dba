"""Which store types serve personal accounts (UC-2) in this build (#1138).

Tier 0, pure: every case builds from a dict.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.loading import build_config

OCI: dict[str, Any] = {
    "type": "oci",
    "vault_id": "ocid1.vault.oc1..exampleuniqueid",
    "compartment_id": "ocid1.compartment.oc1..exampleuniqueid",
    "key_id": "ocid1.key.oc1..exampleuniqueid",
}


def document(**sections: Any) -> dict[str, Any]:
    return {
        "version": 1,
        "vaults": {"vault-oci": OCI, "vault-dev": {"type": "hashicorp"}},
        **sections,
    }


def test_reset_records_in_an_oci_store_are_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_config(document(reset_records={"vault": "vault-oci", "prefix": "resets"}))

    rendered = str(caught.value)
    assert "reset_records.vault" in rendered
    assert "application credentials (UC-1) only" in rendered


def test_reset_records_in_a_hashicorp_store_load() -> None:
    config = build_config(document(reset_records={"vault": "vault-dev", "prefix": "resets"}))

    assert config.reset_records is not None


@pytest.mark.parametrize(
    ("method", "block"),
    [
        ("vault_path", {"ttl": "1h", "prefix": "handover"}),
        ("vault_wrapped", {"ttl": "1h"}),
    ],
)
def test_a_delivery_into_an_oci_store_is_refused(method: str, block: dict[str, Any]) -> None:
    """The method's own `vault:` is in the file, so it is refused at load."""
    with pytest.raises(ConfigError) as caught:
        build_config(document(delivery={"method": method, method: {**block, "vault": "vault-oci"}}))

    assert f"delivery.{method}.vault" in str(caught.value)


def test_an_oci_store_for_application_credentials_still_loads() -> None:
    """UC-1 on OCI is what the store is for."""
    assert build_config(document(defaults={"vault": "vault-oci"})).vaults
