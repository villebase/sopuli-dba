"""A SQL Server target, as the config declares it (#1549).

Tier 0, pure. A SQL Server target is the instance, and its `mssql:` block
takes the TLS keys the maintainer chose on #1549 from what
`sql/mssql/10_client_tls_probe.py` measured: `encrypt`, `trust_server_certificate`,
`host_name_in_certificate` and `server_certificate`, with no CA file. Its
accounts are login names, with no host part. Its driver is not written yet, so
every command is refused.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.loading import build_config
from sopuli.config.model import Config, TargetMssql
from sopuli.driver.registry import (
    DRIVER_NOT_IMPLEMENTED,
    DRIVERS,
    DriverNotImplementedError,
    require_command,
    resolve,
)
from sopuli.output.config_view import build_section

VAULTS: dict[str, Any] = {"vault-dev": {"type": "hashicorp", "addr": "https://v.example.com"}}

SERVER: dict[str, Any] = {
    "name": "mssql-dev",
    "type": "mssql",
    "dsn": "mssql-dev.example.com:1433",
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


def with_block(**block: Any) -> dict[str, Any]:
    return {**SERVER, "mssql": block}


# ------------------------------------------------------------- the target ---


def test_a_mssql_target_loads_with_mandatory_encryption() -> None:
    target = loaded(targets=[SERVER]).expanded_targets[0].target

    assert target.type == "mssql"
    assert target.mssql is None
    assert target.mssql_settings == TargetMssql(encrypt="mandatory")


def test_the_mssql_block_takes_its_four_keys() -> None:
    block = {"encrypt": "strict", "server_certificate": "/etc/sopuli/mssql-prod.pem"}
    target = loaded(targets=[with_block(**block)]).expanded_targets[0].target

    assert target.mssql == TargetMssql(
        encrypt="strict", server_certificate="/etc/sopuli/mssql-prod.pem"
    )


@pytest.mark.parametrize("key", ["ca", "ssl_ca", "trust_server_certificate_file"])
def test_there_is_no_ca_file_key(key: str) -> None:
    rendered = refused(targets=[with_block(**{key: "/etc/sopuli/ca.pem"})])

    assert f"targets[0].mssql: unknown key '{key}'" in rendered


def test_an_unknown_encrypt_value_is_refused() -> None:
    rendered = refused(targets=[with_block(encrypt="yes")])

    assert "targets[0].mssql.encrypt" in rendered
    assert "optional" in rendered
    assert "strict" in rendered


def test_trust_server_certificate_is_a_boolean() -> None:
    rendered = refused(targets=[with_block(trust_server_certificate="true")])

    assert "must be true or false" in rendered


def test_an_empty_mssql_block_is_refused_by_its_own_name() -> None:
    rendered = refused(targets=[with_block()])

    assert "an empty `mssql:` block says nothing" in rendered


def test_a_mysql_block_on_a_mssql_target_is_refused() -> None:
    rendered = refused(targets=[{**SERVER, "mysql": {"ssl_mode": "VERIFY_CA"}}])

    assert "'mssql-dev' is a SQL Server target, so its `mysql:` block would do nothing" in rendered


def test_a_mssql_block_on_a_mysql_target_is_refused() -> None:
    rendered = refused(targets=[{**MYSQL, "mssql": {"encrypt": "strict"}}])

    assert "so its `mssql:` block would do nothing" in rendered
    assert "set `type: mssql` if this is a SQL Server instance" in rendered


@pytest.mark.parametrize(
    "dsn",
    ["mssql://sa@db.example.com:1433", "Server=db.example.com;Pwd=x", r"db.example.com\SQLEXPRESS"],
)
def test_the_dsn_is_host_and_port(dsn: str) -> None:
    rendered = refused(targets=[{**SERVER, "dsn": dsn}])

    assert "mssql.encrypt" in rendered


# ------------------------------------------------------ the keys together ---


@pytest.mark.parametrize(
    ("block", "key"),
    [
        ({"encrypt": "strict", "trust_server_certificate": True}, "trust_server_certificate"),
        ({"encrypt": "optional", "trust_server_certificate": True}, "trust_server_certificate"),
        ({"server_certificate": "/etc/sopuli/server.pem"}, "server_certificate"),
        (
            {"encrypt": "optional", "server_certificate": "/etc/sopuli/server.pem"},
            "server_certificate",
        ),
        ({"encrypt": "optional", "host_name_in_certificate": "db"}, "host_name_in_certificate"),
        # Measured under `mandatory` only (TL4).
        ({"encrypt": "strict", "host_name_in_certificate": "db"}, "host_name_in_certificate"),
    ],
)
def test_a_key_under_a_mode_where_it_does_nothing_is_refused(
    block: dict[str, Any], key: str
) -> None:
    rendered = refused(targets=[with_block(**block)])

    assert f"sets `mssql.{key}` under `encrypt:" in rendered
    assert f"targets[0].mssql.{key}" in rendered


def test_a_name_to_check_beside_no_check_is_refused() -> None:
    rendered = refused(
        targets=[with_block(trust_server_certificate=True, host_name_in_certificate="db")]
    )

    assert "which checks no name" in rendered


@pytest.mark.parametrize(
    "block",
    [
        {"encrypt": "mandatory", "host_name_in_certificate": "mssql-dev.example.com"},
        {"encrypt": "strict", "server_certificate": "/etc/sopuli/server.pem"},
        {"trust_server_certificate": False, "encrypt": "strict"},
    ],
)
def test_keys_under_a_mode_that_uses_them_load(block: dict[str, Any]) -> None:
    loaded(targets=[with_block(**block)])


# ----------------------------------------------------------- the warning ---


@pytest.mark.parametrize(
    ("block", "at", "advice"),
    [
        ({"encrypt": "optional"}, "targets[0].mssql.encrypt", "`encrypt: mandatory`"),
        (
            {"trust_server_certificate": True},
            "targets[0].mssql.trust_server_certificate",
            "`trust_server_certificate: false`",
        ),
    ],
)
def test_a_target_that_does_not_verify_the_server_warns(
    block: dict[str, Any], at: str, advice: str
) -> None:
    config = loaded(targets=[with_block(**block)])
    (warning,) = [w for w in config.warnings if w.code == "SOPULI-W058"]

    assert warning.at == at
    assert advice in (warning.hint or "")
    assert "operating system's trust store" in (warning.hint or "")


@pytest.mark.parametrize("block", [None, {"encrypt": "strict"}])
def test_a_verifying_target_does_not_warn(block: dict[str, Any] | None) -> None:
    target = SERVER if block is None else with_block(**block)
    config = loaded(targets=[target])

    assert not [w for w in config.warnings if w.code == "SOPULI-W058"]


# --------------------------------------------------------- the overrides ---


def test_an_override_patches_the_mssql_block_key_by_key() -> None:
    config = loaded(
        target_sets={
            "mssql": {
                "name": "mssql-{env}",
                "type": "mssql",
                "dsn": "mssql-{env}.example.com:1433",
                "mssql": {"host_name_in_certificate": "mssql-{env}.example.com"},
                "for_each": {"env": {"dev": {}, "qa": {}}},
                "overrides": {"mssql-qa": {"mssql": {"encrypt": "mandatory"}}},
            }
        }
    )

    rendered = {expanded.name: expanded.target.mssql for expanded in config.expanded_targets}
    assert rendered == {
        "mssql-dev": TargetMssql(host_name_in_certificate="mssql-dev.example.com"),
        "mssql-qa": TargetMssql(
            encrypt="mandatory", host_name_in_certificate="mssql-qa.example.com"
        ),
    }


def test_an_override_that_makes_a_key_do_nothing_is_refused_at_the_override() -> None:
    rendered = refused(
        target_sets={
            "mssql": {
                "name": "mssql-{env}",
                "type": "mssql",
                "dsn": "mssql-{env}.example.com:1433",
                "mssql": {"trust_server_certificate": True},
                "for_each": {"env": {"dev": {}, "qa": {}}},
                "overrides": {"mssql-qa": {"mssql": {"encrypt": "strict"}}},
            }
        }
    )

    assert "'mssql-qa' sets `mssql.trust_server_certificate` under `encrypt: strict`" in rendered
    # The line to change is the override's `encrypt`: it cannot remove the
    # template's key.
    assert "overrides.mssql-qa.mssql.encrypt" in rendered
    assert "an override cannot remove `trust_server_certificate`" in rendered


def test_a_key_the_override_wrote_is_refused_at_its_own_line() -> None:
    rendered = refused(
        target_sets={
            "mssql": {
                "name": "mssql-{env}",
                "type": "mssql",
                "dsn": "mssql-{env}.example.com:1433",
                "for_each": {"env": {"dev": {}, "qa": {}}},
                "overrides": {"mssql-qa": {"mssql": {"server_certificate": "/etc/qa.pem"}}},
            }
        }
    )

    assert "overrides.mssql-qa.mssql.server_certificate" in rendered
    assert "use it only with `encrypt: `strict``" in rendered


# ------------------------------------------------------------ config show ---


def test_config_show_says_how_the_run_will_connect() -> None:
    raw = document(targets=[SERVER, MYSQL])
    section = build_section(
        [Path("/etc/sopuli/config.yaml")], build_config(raw), raw, resolved=True
    )

    assert [(t["mssql"], t["mysql"] is None) for t in section["targets"]] == [
        (
            {
                "encrypt": "mandatory",
                "trust_server_certificate": False,
                "host_name_in_certificate": None,
                "server_certificate": None,
            },
            True,
        ),
        (None, False),
    ]


# ------------------------------------------------------------ the account ---


def test_an_account_is_a_bare_login_name() -> None:
    application = {
        "name": "acme",
        "targets": [SERVER["name"]],
        "accounts": ["acme_app_user"],
        "secret_template": "apps/acme#DB/{account}",
    }

    loaded(targets=[SERVER], applications=[application])


def test_two_spellings_of_one_login_are_refused() -> None:
    """Invariant 5 compares names by `upper()`, which is how the default
    collation compares logins."""
    application = {
        "name": "acme",
        "targets": [SERVER["name"]],
        "accounts": ["acme_app_user", "ACME_APP_USER"],
        "secret_template": "apps/acme#DB/{account}",
    }

    refused(targets=[SERVER], applications=[application])


# ------------------------------------------------------------- the driver ---


def test_the_driver_is_not_written_yet() -> None:
    """Every command, `doctor` aside, is refused before anything connects, and
    resolving the driver says it is not written (#1549)."""
    target = loaded(targets=[SERVER]).expanded_targets[0].target

    assert DRIVERS["mssql"].commands == frozenset()
    assert DRIVERS["mssql"].extra == "mssql"
    assert DRIVERS["mssql"].provides == frozenset({"pyodbc"})
    require_command(target, "doctor")
    with pytest.raises(DriverNotImplementedError) as caught:
        require_command(target, "creds.check")
    assert caught.value.code == DRIVER_NOT_IMPLEMENTED
    with pytest.raises(DriverNotImplementedError) as resolving:
        resolve(target)
    assert "this build has no mssql driver yet" in str(resolving.value)
