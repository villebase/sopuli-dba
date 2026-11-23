"""``run_as:`` -- the account `sql run` connects as (UC-3 §5).

The same model as ``admin:`` with `vault` taken out, read on a target, on a
target set and in ``defaults:``. A target's own block wins over the default.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.loading import build_config
from sopuli.config.targets import ADMIN_METHODS, RUN_AS_METHODS

TARGET: dict[str, Any] = {
    "name": "cdb-root-dev",
    "type": "oracle",
    "dsn": "db-dev.example.com:1521/CDBDEV.pdb.example.com",
}
RUN_AS: dict[str, Any] = {
    "username": "dba_alpha",
    "auth": {"method": "keyring", "entry": "dba-dev"},
}


FOR_EACH: dict[str, Any] = {"env": {"dev": {}, "qa": {}}}


def document(**sections: Any) -> dict[str, Any]:
    return {"version": 1, **sections}


def test_the_methods_are_the_admin_ones_without_vault() -> None:
    assert set(RUN_AS_METHODS) == set(ADMIN_METHODS) - {"vault"}


def test_run_as_on_a_target_parses() -> None:
    config = build_config(document(targets=[{**TARGET, "run_as": RUN_AS}]))

    run_as = config.expanded_targets[0].run_as
    assert run_as is not None
    assert run_as.username == "dba_alpha"
    assert run_as.auth is not None
    assert (run_as.auth.method, run_as.auth.entry) == ("keyring", "dba-dev")


def test_run_as_vault_method_refused() -> None:
    entry = {"username": "dba_alpha", "auth": {"method": "vault", "secret": "ops/dba#password"}}

    with pytest.raises(ConfigError) as caught:
        build_config(document(targets=[{**TARGET, "run_as": entry}]))

    rendered = str(caught.value)
    assert "run_as" in rendered
    assert "'vault'" in rendered


def test_run_as_env_must_name_its_variable() -> None:
    """The default variable holds the admin's password."""
    with pytest.raises(ConfigError) as caught:
        build_config(
            document(targets=[{**TARGET, "run_as": {"username": "dba_alpha", "auth": "env"}}])
        )

    assert "password_env" in str(caught.value)


def test_run_as_external_with_username_refused() -> None:
    entry = {"username": "dba_alpha", "auth": "external"}

    with pytest.raises(ConfigError) as caught:
        build_config(document(targets=[{**TARGET, "dsn": "CDBDEV", "run_as": entry}]))

    assert "cannot be honoured" in str(caught.value)
    assert "targets[0].run_as.username" in str(caught.value)


def test_run_as_external_needs_a_tns_alias() -> None:
    with pytest.raises(ConfigError) as caught:
        build_config(document(targets=[{**TARGET, "run_as": {"auth": "external"}}]))

    assert "must be a TNS alias" in str(caught.value)


def test_run_as_external_on_a_host_and_port_product_is_refused() -> None:
    entry = {"type": "postgresql", "dsn": "db.example.com:5432"}

    with pytest.raises(ConfigError) as caught:
        build_config(document(targets=[{**TARGET, **entry, "run_as": {"auth": "external"}}]))

    assert "external authentication is an Oracle wallet" in str(caught.value)


def test_run_as_without_a_username_is_refused() -> None:
    with pytest.raises(ConfigError) as caught:
        build_config(document(targets=[{**TARGET, "run_as": {"auth": "prompt"}}]))

    assert "run_as.username" in str(caught.value)


def test_run_as_password_key_is_unknown() -> None:
    with pytest.raises(ConfigError) as caught:
        build_config(document(targets=[{**TARGET, "run_as": {**RUN_AS, "password": "x"}}]))

    assert "unknown key 'password'" in str(caught.value)


def test_defaults_run_as_fills_a_target() -> None:
    config = build_config(document(defaults={"run_as": RUN_AS}, targets=[TARGET]))

    run_as = config.expanded_targets[0].run_as
    assert run_as is not None
    assert run_as.username == "dba_alpha"
    assert config.targets[0].run_as is None


def test_target_run_as_beats_defaults() -> None:
    own = {"username": "acme_owner", "auth": "prompt"}

    other = {**TARGET, "name": "cdb-root-qa"}
    config = build_config(
        document(defaults={"run_as": RUN_AS}, targets=[{**TARGET, "run_as": own}, other])
    )

    first, second = (item.run_as for item in config.expanded_targets)
    assert first is not None
    assert second is not None
    assert first.username == "acme_owner"
    assert second.username == "dba_alpha"


def test_a_target_without_either_has_no_run_as() -> None:
    config = build_config(document(targets=[TARGET]))

    assert config.expanded_targets[0].run_as is None


def test_target_set_renders_run_as_entry() -> None:
    template = {
        **TARGET,
        "name": "appdb-{env}",
        "dsn": "db-{env}.example.com:1521/APP.pdb.example.com",
        "run_as": {"username": "dba_alpha", "auth": {"method": "keyring", "entry": "dba-{env}"}},
    }

    config = build_config(document(target_sets={"appdb": {**template, "for_each": FOR_EACH}}))

    entries = {
        item.name: item.run_as.auth.entry
        for item in config.expanded_targets
        if item.run_as is not None and item.run_as.auth is not None
    }
    assert entries == {"appdb-dev": "dba-dev", "appdb-qa": "dba-qa"}


def test_an_override_may_patch_run_as() -> None:
    template = {
        **TARGET,
        "name": "appdb-{env}",
        "dsn": "db-{env}.example.com:1521/APP.pdb.example.com",
        "run_as": RUN_AS,
    }
    config = build_config(
        document(
            target_sets={
                "appdb": {
                    **template,
                    "for_each": FOR_EACH,
                    "overrides": {"appdb-qa": {"run_as": {"username": "acme_owner"}}},
                }
            }
        )
    )

    users = {item.name: item.run_as.username for item in config.expanded_targets if item.run_as}
    assert users == {"appdb-dev": "dba_alpha", "appdb-qa": "acme_owner"}


def test_placeholder_on_explicit_target_refused() -> None:
    entry = {"username": "dba_alpha", "auth": {"method": "keyring", "entry": "dba-{env}"}}

    with pytest.raises(ConfigError) as caught:
        build_config(document(targets=[{**TARGET, "run_as": entry}]))

    assert "still contains a placeholder" in str(caught.value)


def test_placeholder_in_defaults_run_as_refused() -> None:
    entry = {"username": "dba_alpha", "auth": {"method": "keyring", "entry": "dba-{env}"}}

    with pytest.raises(ConfigError) as caught:
        build_config(document(defaults={"run_as": entry}, targets=[TARGET]))

    assert "defaults.run_as.auth.entry" in str(caught.value)


def test_groups_do_not_carry_run_as() -> None:
    with pytest.raises(ConfigError):
        build_config(
            document(targets=[TARGET], groups={"dev": {"match": {"env": "dev"}, "run_as": RUN_AS}})
        )
