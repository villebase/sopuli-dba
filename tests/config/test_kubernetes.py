"""An application's ``kubernetes:`` block: the ExternalSecret ESO refreshes (C18).

Tier 0: the block is read, merged with the overrides key by key, expanded per
account and target, and checked as Kubernetes names, all without I/O.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.loading import build_config
from sopuli.config.model import Binding, ExternalSecretRef

VAULTS: dict[str, Any] = {"vault-dev": {"type": "hashicorp"}, "vault-test": {"type": "hashicorp"}}

APPDB: dict[str, Any] = {
    "type": "oracle",
    "name": "appdb-{env}-{tenant}",
    "dsn": "{host}:1521/{tenant}.pdb.example.com",
    "environment": "{env}",
    "vault": "{vault}",
    "oracle": {"scope": "pdb", "container": "{tenant}pdb"},
    "for_each": {
        "env": {
            "dev": {"host": "db-dev.example.com", "vault": "vault-dev", "tenant": ["alpha"]},
            "test": {
                "host": "db-test.example.com",
                "vault": "vault-test",
                "tenant": ["alpha", "gamma"],
            },
        }
    },
}

BLOCK: dict[str, Any] = {
    "context": "{env}-cluster",
    "namespace": "acme-{tenant}",
    "external_secret": "acme-db",
}


def bind(**entry: Any) -> tuple[Binding, ...]:
    """One application over the generated PDBs. A key given as ``None`` is left out."""
    application = {
        "name": "acme",
        "accounts": ["acme_web_user"],
        "secret_template": "tenants/{tenant}#DB_CREDENTIALS/{account}",
        **entry,
    }
    application = {key: value for key, value in application.items() if value is not None}
    document = {
        "version": 1,
        "vaults": VAULTS,
        "target_sets": {"appdb": APPDB},
        "applications": [application],
    }
    return build_config(document).bindings


def refs(**entry: Any) -> dict[str, ExternalSecretRef | None]:
    return {binding.target: binding.external_secret for binding in bind(**entry)}


def refusal(**entry: Any) -> ConfigError:
    with pytest.raises(ConfigError) as caught:
        bind(**entry)
    return caught.value


def test_without_a_block_a_binding_names_no_external_secret() -> None:
    assert set(refs().values()) == {None}


def test_the_tokens_expand_per_target() -> None:
    assert refs(kubernetes=BLOCK) == {
        "appdb-dev-alpha": ExternalSecretRef("dev-cluster", "acme-alpha", "acme-db"),
        "appdb-test-alpha": ExternalSecretRef("test-cluster", "acme-alpha", "acme-db"),
        "appdb-test-gamma": ExternalSecretRef("test-cluster", "acme-gamma", "acme-db"),
    }


def test_an_override_patches_one_key_and_keeps_the_others() -> None:
    """One test database whose tenants' applications run on two clusters."""
    resolved = refs(
        kubernetes=BLOCK,
        overrides=[{"where": {"tenant": "gamma"}, "kubernetes": {"context": "test-b-cluster"}}],
    )

    assert resolved["appdb-test-gamma"] == ExternalSecretRef(
        "test-b-cluster", "acme-gamma", "acme-db"
    )
    assert resolved["appdb-test-alpha"] == ExternalSecretRef(
        "test-cluster", "acme-alpha", "acme-db"
    )


def test_a_later_override_wins() -> None:
    resolved = refs(
        kubernetes=BLOCK,
        overrides=[
            {"where": {"env": "test"}, "kubernetes": {"context": "first"}},
            {"where": {"tenant": "gamma"}, "kubernetes": {"context": "second"}},
        ],
    )

    assert resolved["appdb-test-gamma"] is not None
    assert resolved["appdb-test-gamma"].context == "second"


def test_an_override_alone_may_supply_the_block() -> None:
    """Only the targets the override matches get a refresh."""
    resolved = refs(overrides=[{"where": {"env": "test"}, "kubernetes": BLOCK}])

    assert resolved["appdb-dev-alpha"] is None
    assert resolved["appdb-test-alpha"] == ExternalSecretRef(
        "test-cluster", "acme-alpha", "acme-db"
    )


def test_a_block_missing_a_key_is_refused() -> None:
    error = refusal(kubernetes={"context": "dev-cluster", "namespace": "acme"})

    assert "`external_secret`" in str(error)
    assert str(error.at) == "applications[0].kubernetes"


def test_a_key_missing_only_where_no_override_supplies_it_is_refused() -> None:
    """The dev target has no override, so it has no name, and the message says which."""
    error = refusal(
        kubernetes={"context": "{env}-cluster", "namespace": "acme"},
        overrides=[{"where": {"env": "test"}, "kubernetes": {"external_secret": "acme-db"}}],
    )

    assert "`external_secret`" in str(error)
    assert "'appdb-dev-alpha'" in str(error)


def test_a_block_only_an_override_writes_is_reported_where_it_was_written() -> None:
    error = refusal(overrides=[{"where": {"env": "test"}, "kubernetes": {"context": "x"}}])

    assert str(error.at) == "applications[0].overrides[0].kubernetes"


def test_a_block_without_a_secret_ref_is_refused() -> None:
    error = refusal(secret_template=None, kubernetes=BLOCK)

    assert "no secret ref" in str(error)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("namespace", "acme_{tenant}"),
        ("namespace", "Acme"),
        ("namespace", "x" * 64),
        ("external_secret", "{account}"),
        ("external_secret", "-acme"),
        ("external_secret", "acme..db"),
        ("external_secret", "acme.-db"),
        ("external_secret", "acme-.db"),
    ],
)
def test_a_name_kubernetes_refuses_is_refused_where_it_was_written(key: str, value: str) -> None:
    error = refusal(
        kubernetes=BLOCK,
        overrides=[{"where": {"env": "dev"}, "kubernetes": {key: value}}],
    )

    assert "Kubernetes accepts" in str(error)
    assert str(error.at) == f"applications[0].overrides[0].kubernetes.{key}"


def test_a_dotted_external_secret_name_is_accepted() -> None:
    resolved = refs(kubernetes={**BLOCK, "external_secret": "acme.db"})

    assert resolved["appdb-dev-alpha"] is not None
    assert resolved["appdb-dev-alpha"].name == "acme.db"


@pytest.mark.parametrize("context", ["dev\tcluster", "--kubeconfig=/x", " dev", "dev "])
def test_a_context_that_is_not_a_name_is_refused(context: str) -> None:
    error = refusal(kubernetes={**BLOCK, "context": context})

    assert "context name" in str(error)


def test_an_unresolved_token_is_refused() -> None:
    error = refusal(kubernetes={**BLOCK, "context": "{cluster}"})

    assert "{cluster}" in str(error)


def test_an_unknown_key_is_refused() -> None:
    error = refusal(kubernetes={**BLOCK, "secret": "acme-db"})

    assert str(error.at).startswith("applications[0].kubernetes")


def test_an_empty_block_is_refused() -> None:
    error = refusal(kubernetes={})

    assert "at least one key" in str(error)
