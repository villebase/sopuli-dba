"""A MariaDB target, as the config declares it (#1268).

Tier 0, pure. A MariaDB target is the server, as a MySQL target is, and its
`mariadb:` block takes the same keys as `mysql:`. Its accounts are `user@host`,
split and compared as on MySQL (#1267). The shared rules are tested on MySQL in
`test_mysql_targets.py` and `test_mysql_accounts.py`; these tests check that a
MariaDB target goes through them, naming MariaDB, and that its driver, not
written yet, refuses every command.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.loading import build_config
from sopuli.config.model import Config, TargetMysql
from sopuli.driver.registry import (
    DRIVERS,
    require_command,
    resolve,
)
from sopuli.output.config_view import build_section

VAULTS: dict[str, Any] = {"vault-dev": {"type": "hashicorp", "addr": "https://v.example.com"}}

SERVER: dict[str, Any] = {
    "name": "mariadb-dev",
    "type": "mariadb",
    "dsn": "mariadb-dev.example.com:3306",
    "environment": "dev",
    "vault": "vault-dev",
}

MYSQL: dict[str, Any] = {
    "name": "mysql-dev",
    "type": "mysql",
    "dsn": "mysql-dev.example.com:3306",
    "vault": "vault-dev",
}


def document(**sections: Any) -> dict[str, Any]:
    return {"version": 1, "vaults": VAULTS, **sections}


def loaded(**sections: Any) -> Config:
    return build_config(document(**sections))


def refused(**sections: Any) -> str:
    with pytest.raises(ConfigError) as caught:
        build_config(document(**sections))
    return str(caught.value)


def app(*accounts: str, template: str = "apps/acme#DB/{account}") -> dict[str, Any]:
    return {
        "name": "acme",
        "targets": [SERVER["name"]],
        "accounts": list(accounts),
        "secret_template": template,
    }


# ------------------------------------------------------------- the target ---


def test_a_mariadb_target_loads() -> None:
    target = loaded(targets=[SERVER]).expanded_targets[0].target

    assert target.type == "mariadb"
    assert target.mariadb is None
    assert target.mariadb_settings == TargetMysql()


def test_the_mariadb_block_takes_the_mysql_keys() -> None:
    block = {"ssl_mode": "VERIFY_CA", "ssl_ca": "/etc/sopuli/mariadb-ca.pem"}
    target = loaded(targets=[{**SERVER, "mariadb": block}]).expanded_targets[0].target

    assert target.mariadb == TargetMysql(**block)
    assert target.mysql is None


def test_an_empty_mariadb_block_is_refused_by_its_own_name() -> None:
    rendered = refused(targets=[{**SERVER, "mariadb": {}}])

    assert "mariadb" in rendered
    assert "targets[0].mariadb" in rendered


def test_a_mysql_block_on_a_mariadb_target_is_refused() -> None:
    rendered = refused(targets=[{**SERVER, "mysql": {"ssl_mode": "VERIFY_CA"}}])

    assert "'mariadb-dev' is a MariaDB target, so its `mysql:` block would do nothing" in rendered
    assert "targets[0].mysql" in rendered


def test_a_mariadb_block_on_a_mysql_target_is_refused() -> None:
    rendered = refused(targets=[{**MYSQL, "mariadb": {"ssl_mode": "VERIFY_CA"}}])

    assert "'mysql-dev' is a MySQL target, so its `mariadb:` block would do nothing" in rendered
    assert "set `type: mariadb` if this is a MariaDB server" in rendered


def test_a_connection_uri_is_refused_with_the_mariadb_hint() -> None:
    rendered = refused(targets=[{**SERVER, "dsn": "mariadb://acme@db.example.com:3306"}])

    assert "mariadb.ssl_mode" in rendered


def test_a_target_that_does_not_verify_the_server_warns() -> None:
    config = loaded(targets=[{**SERVER, "mariadb": {"ssl_mode": "REQUIRED"}}])
    (warning,) = [w for w in config.warnings if w.code == "SOPULI-W058"]

    assert warning.at == "targets[0].mariadb.ssl_mode"


def test_an_override_patches_the_mariadb_block_key_by_key() -> None:
    config = loaded(
        target_sets={
            "mariadb": {
                "name": "mariadb-{env}",
                "type": "mariadb",
                "dsn": "mariadb-{env}.example.com:3306",
                "mariadb": {"ssl_ca": "/etc/ca-{env}.pem"},
                "for_each": {"env": {"dev": {}, "qa": {}}},
                "overrides": {"mariadb-qa": {"mariadb": {"ssl_mode": "VERIFY_CA"}}},
            }
        }
    )

    rendered = {expanded.name: expanded.target.mariadb for expanded in config.expanded_targets}
    assert rendered == {
        "mariadb-dev": TargetMysql(ssl_ca="/etc/ca-dev.pem"),
        "mariadb-qa": TargetMysql(ssl_mode="VERIFY_CA", ssl_ca="/etc/ca-qa.pem"),
    }


def test_config_show_says_how_the_run_will_connect() -> None:
    raw = document(targets=[SERVER, MYSQL])
    section = build_section(
        [Path("/etc/sopuli/config.yaml")], build_config(raw), raw, resolved=True
    )

    assert [(t["mariadb"], t["mysql"] is None) for t in section["targets"]] == [
        ({"ssl_mode": "VERIFY_IDENTITY", "ssl_ca": None}, True),
        (None, False),
    ]


# ------------------------------------------------------------ the account ---


@pytest.mark.parametrize("account", ["acme_app", "acme_app@", "@10.%"])
def test_an_account_without_a_user_and_a_host_is_refused(account: str) -> None:
    rendered = refused(targets=[SERVER], applications=[app(account)])

    assert "on MariaDB target 'mariadb-dev'" in rendered
    assert "a MariaDB account must name its host as user@host" in rendered
    assert "MariaDB keeps one account per host" in rendered


def test_user_and_host_render_as_on_mysql() -> None:
    config = loaded(
        targets=[SERVER],
        applications=[app("acme_app@10.%", "acme_api@%", template="mariadb/{host}#DB/{user}")],
    )

    assert {b.account: str(b.secret) for b in config.bindings} == {
        "acme_app@10.%": "mariadb/10.any#DB/acme_app",
        "acme_api@%": "mariadb/any#DB/acme_api",
    }


def test_a_personal_account_names_its_host() -> None:
    rendered = refused(
        targets=[SERVER],
        personal_accounts=[{"targets": [SERVER["name"]], "accounts": ["jdoe"]}],
    )

    assert "on MariaDB target 'mariadb-dev'" in rendered


def test_a_role_names_no_host_on_mariadb() -> None:
    """A MariaDB role is stored with an empty host and named without one
    (`sql/mariadb/05_identity_grants_probe.py`, TG7), so a bare `role:` loads.
    On MySQL a role is an account and must name its host (#1225)."""
    rule = {"targets": [SERVER["name"]], "role": "dev_role"}

    loaded(targets=[SERVER], personal_accounts=[rule])
    rendered = refused(targets=[MYSQL], personal_accounts=[{**rule, "targets": [MYSQL["name"]]}])
    assert "on MySQL target 'mysql-dev'" in rendered


# ------------------------------------------------------------- the driver ---


def test_the_driver_serves_exactly_doctor_and_uc1_but_finish_rollover() -> None:
    """`doctor` connects (#1268), and UC-1's commands run (#1270). The exact
    set is pinned, so a merge cannot add a command whose session methods
    still refuse during the run. Which commands are refused is
    `tests/driver/test_driver_registry.py`'s."""
    target = loaded(targets=[SERVER]).expanded_targets[0].target

    # TODO(#1271): `creds.finish-rollover`. TODO(#1272): the `account` commands.
    assert DRIVERS["mariadb"].commands == frozenset(
        {"creds.check", "creds.apply", "creds.rotate", "creds.generate", "creds.status"}
    )
    assert DRIVERS["mariadb"].extra == "mariadb"
    # PyMySQL's `ed25519` extra brings PyNaCl; without it the extra is not installed.
    assert DRIVERS["mariadb"].provides == frozenset({"pymysql", "nacl"})
    require_command(target, "doctor")
    assert resolve(target).__name__ == "sopuli.driver.mariadb.session"
