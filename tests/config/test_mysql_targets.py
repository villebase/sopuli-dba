"""A MySQL target, as the config declares it (#1221).

Tier 0, pure. A MySQL target is the **server**: every account belongs to the
whole server, so the `mysql:` block names no database, only how to connect.

The refusals keep each product's keys on its own targets, as
`test_postgres_targets.py` does for PostgreSQL. Its tests of the `host:port`
shape cover the parser both products share; the ones here check that a MySQL
target goes through it, with its own hint.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.loading import build_config
from sopuli.config.model import TargetMysql
from sopuli.config.targets import MYSQL_SSL_MODES
from sopuli.driver.registry import DriverNotImplementedError, require_command

VAULTS: dict[str, Any] = {"vault-dev": {"type": "hashicorp", "addr": "https://v.example.com"}}

SERVER: dict[str, Any] = {
    "name": "mysql-dev",
    "type": "mysql",
    "dsn": "mysql-dev.example.com:3306",
    "environment": "dev",
    "vault": "vault-dev",
}

CLUSTER: dict[str, Any] = {
    "name": "pg-dev",
    "type": "postgresql",
    "dsn": "pg-dev.example.com:5432",
    "vault": "vault-dev",
}

ORACLE: dict[str, Any] = {
    "name": "cdb-root-dev",
    "type": "oracle",
    "dsn": "db-dev.example.com:1521/CDBDEV.pdb.example.com",
    "vault": "vault-dev",
}


def document(**sections: Any) -> dict[str, Any]:
    return {"version": 1, "vaults": VAULTS, **sections}


def server(**keys: Any) -> Any:
    config = build_config(document(targets=[{**SERVER, **keys}]))
    return config.expanded_targets[0].target


def refused(sections: dict[str, Any]) -> str:
    with pytest.raises(ConfigError) as caught:
        build_config(document(**sections))
    return str(caught.value)


# ------------------------------------------------------------- the target ---


def test_a_mysql_target_loads() -> None:
    target = server()

    assert target.type == "mysql"
    assert target.dsn == "mysql-dev.example.com:3306"
    assert target.mysql is None
    assert target.mysql_settings == TargetMysql()


def test_the_mysql_block_defaults_to_a_connection_that_verifies_the_server() -> None:
    assert TargetMysql() == TargetMysql(ssl_mode="VERIFY_IDENTITY", ssl_ca=None)


def test_the_mysql_block_is_read_whole() -> None:
    target = server(mysql={"ssl_mode": "VERIFY_CA", "ssl_ca": "/etc/sopuli/mysql-ca.pem"})

    assert target.mysql == TargetMysql(ssl_mode="VERIFY_CA", ssl_ca="/etc/sopuli/mysql-ca.pem")


def test_an_unwritten_key_keeps_its_default() -> None:
    assert server(mysql={"ssl_ca": "/etc/sopuli/mysql-ca.pem"}).mysql.ssl_mode == "VERIFY_IDENTITY"


def test_every_mysql_ssl_mode_is_accepted() -> None:
    assert MYSQL_SSL_MODES == ("DISABLED", "PREFERRED", "REQUIRED", "VERIFY_CA", "VERIFY_IDENTITY")
    for mode in MYSQL_SSL_MODES:
        assert server(mysql={"ssl_mode": mode}).mysql.ssl_mode == mode


@pytest.mark.parametrize("mode", ["verify_identity", "verify-full", "VERIFY_FULL"])
def test_a_misspelled_ssl_mode_is_refused(mode: str) -> None:
    """MySQL's own spelling, in capitals. libpq's `verify-full` is a mistake
    worth catching on a page that shows both."""
    rendered = refused({"targets": [{**SERVER, "mysql": {"ssl_mode": mode}}]})

    assert mode in rendered
    assert "targets[0].mysql.ssl_mode" in rendered


def test_an_unknown_mysql_key_is_refused() -> None:
    rendered = refused({"targets": [{**SERVER, "mysql": {"database": "mysql"}}]})

    assert "database" in rendered
    assert "targets[0].mysql" in rendered


def test_an_empty_mysql_block_is_refused() -> None:
    rendered = refused({"targets": [{**SERVER, "mysql": {}}]})

    assert "an empty `mysql:` block says nothing" in rendered


# ------------------------------------------------------------------ dsn ---


@pytest.mark.parametrize(
    "dsn", ["mysql-dev.example.com:3306", "192.0.2.20:3306", "[2001:db8::20]:3306"]
)
def test_a_host_and_port_is_accepted(dsn: str) -> None:
    assert server(dsn=dsn).dsn == dsn


def test_a_connection_uri_is_refused_because_it_can_carry_a_password() -> None:
    rendered = refused(
        {"targets": [{**SERVER, "dsn": "mysql://sopuli_svc:secret@mysql-dev.example.com:3306"}]}
    )

    assert "a connection URI" in rendered
    assert "mysql.ssl_mode" in rendered
    assert "secret" not in rendered


def test_a_keyword_connection_string_is_refused_too() -> None:
    rendered = refused({"targets": [{**SERVER, "dsn": "host=mysql-dev password=secret"}]})

    assert "a keyword connection string" in rendered
    assert "secret" not in rendered


@pytest.mark.parametrize("dsn", ["mysql-dev.example.com", "mysql-dev.example.com:3306/mysql"])
def test_anything_else_is_not_host_and_port(dsn: str) -> None:
    rendered = refused({"targets": [{**SERVER, "dsn": dsn}]})

    assert "'mysql-dev' is a MySQL target, so its `dsn:` must be host:port" in rendered
    assert "mysql-dev.example.com:3306" in rendered


# ------------------------------------------------- one product's keys only ---


def test_an_oracle_block_on_a_mysql_target_is_refused() -> None:
    rendered = refused({"targets": [{**SERVER, "oracle": {"scope": "pdb"}}]})

    assert "'mysql-dev' is a MySQL target, so its `oracle:` block would do nothing" in rendered
    assert "the whole server" in rendered
    assert "targets[0].oracle" in rendered


def test_a_postgres_block_on_a_mysql_target_is_refused() -> None:
    rendered = refused({"targets": [{**SERVER, "postgres": {"sslmode": "verify-full"}}]})

    assert "'mysql-dev' is a MySQL target, so its `postgres:` block would do nothing" in rendered
    assert "targets[0].postgres" in rendered


@pytest.mark.parametrize(("target", "product"), [(ORACLE, "an Oracle"), (CLUSTER, "a PostgreSQL")])
def test_a_mysql_block_on_another_products_target_is_refused(
    target: dict[str, Any], product: str
) -> None:
    rendered = refused({"targets": [{**target, "mysql": {"ssl_mode": "VERIFY_CA"}}]})

    assert f"is {product} target, so its `mysql:` block would do nothing" in rendered
    assert "set `type: mysql` if this is a MySQL server" in rendered
    assert "targets[0].mysql" in rendered


def test_external_authentication_on_a_mysql_target_is_refused() -> None:
    rendered = refused({"targets": [{**SERVER, "admin": {"auth": "external"}}]})

    assert "'mysql-dev' is a MySQL target, and external authentication is an Oracle wallet" in (
        rendered
    )
    assert "targets[0].admin.auth" in rendered


@pytest.mark.parametrize("mode", ["DISABLED", "PREFERRED", "REQUIRED"])
def test_a_ca_file_without_a_verifying_ssl_mode_is_refused(mode: str) -> None:
    rendered = refused(
        {"targets": [{**SERVER, "mysql": {"ssl_mode": mode, "ssl_ca": "/etc/ca.pem"}}]}
    )

    assert f"names a CA file under `ssl_mode: {mode}`" in rendered
    assert "or drop `ssl_ca`" in rendered
    assert "targets[0].mysql.ssl_ca" in rendered


def _set_with(template: dict[str, Any], override: dict[str, Any]) -> str:
    return refused(
        {
            "target_sets": {
                "mysql": {
                    "name": "mysql-{env}",
                    "type": "mysql",
                    "dsn": "mysql-{env}.example.com:3306",
                    "mysql": template,
                    "for_each": {"env": {"dev": {}, "qa": {}}},
                    "overrides": {"mysql-qa": {"mysql": override}},
                }
            }
        }
    )


def test_a_ca_file_an_override_wrote_under_the_templates_weak_mode_can_be_dropped() -> None:
    """The override wrote the file, so dropping it from the override is a way
    out, and the error names the override's `ssl_ca` line."""
    rendered = _set_with({"ssl_mode": "REQUIRED"}, {"ssl_ca": "/etc/ca.pem"})

    assert "or drop `ssl_ca`" in rendered
    assert "target_sets.mysql.overrides.mysql-qa.mysql.ssl_ca" in rendered


def test_a_mode_an_override_weakened_under_the_templates_ca_file_is_the_line_to_change() -> None:
    """An override cannot clear the template's file, so the hint does not offer
    that, and the error names the override's `ssl_mode` line."""
    rendered = _set_with({"ssl_ca": "/etc/ca.pem"}, {"ssl_mode": "REQUIRED"})

    assert "drop `ssl_ca`" not in rendered
    assert "target_sets.mysql.overrides.mysql-qa.mysql.ssl_mode" in rendered


def test_an_override_patches_the_mysql_block_key_by_key() -> None:
    config = build_config(
        document(
            target_sets={
                "mysql": {
                    "name": "mysql-{env}",
                    "type": "mysql",
                    "dsn": "mysql-{env}.example.com:3306",
                    "mysql": {"ssl_ca": "/etc/ca-{env}.pem"},
                    "for_each": {"env": {"dev": {}, "qa": {}}},
                    "overrides": {"mysql-qa": {"mysql": {"ssl_mode": "VERIFY_CA"}}},
                }
            }
        )
    )

    rendered = {expanded.name: expanded.target.mysql for expanded in config.expanded_targets}
    assert rendered == {
        "mysql-dev": TargetMysql(ssl_ca="/etc/ca-dev.pem"),
        "mysql-qa": TargetMysql(ssl_mode="VERIFY_CA", ssl_ca="/etc/ca-qa.pem"),
    }


def test_an_override_that_makes_a_target_mysql_is_checked_against_the_template() -> None:
    rendered = refused(
        {
            "target_sets": {
                "appdb": {
                    "name": "appdb-{env}",
                    "type": "postgresql",
                    "dsn": "pg-{env}.example.com:5432",
                    "postgres": {"database": "app"},
                    "for_each": {"env": {"dev": {}, "qa": {}}},
                    "overrides": {
                        "appdb-qa": {"type": "mysql", "dsn": "mysql-qa.example.com:3306"}
                    },
                }
            }
        }
    )

    assert "'appdb-qa' is a MySQL target, so its `postgres:` block would do nothing" in rendered
    assert "a target set of their own" in rendered


def test_an_applications_container_clause_on_a_mysql_target_is_refused() -> None:
    rendered = refused(
        {
            "targets": [SERVER],
            "applications": [
                {
                    "name": "acme",
                    "accounts": ["acme_app_user"],
                    "secret_template": "acme/{target}/{account}#password",
                    "oracle": {"container_clause": "CURRENT"},
                }
            ],
        }
    )

    assert "binds to MySQL target 'mysql-dev'" in rendered
    assert "a MySQL account belongs to the whole server" in rendered
    assert "applications[0].oracle.container_clause" in rendered


# ------------------------------------------- a server that is not verified ---


def unverified(sections: dict[str, Any]) -> list[Any]:
    config = build_config(document(**sections))
    return [warning for warning in config.warnings if warning.code == "SOPULI-W058"]


@pytest.mark.parametrize("mode", ["DISABLED", "PREFERRED", "REQUIRED"])
def test_a_target_that_does_not_verify_the_server_warns(mode: str) -> None:
    (warning,) = unverified({"targets": [{**SERVER, "mysql": {"ssl_mode": mode}}]})

    assert warning.message == f"target 'mysql-dev' does not verify the server (`ssl_mode: {mode}`)"
    assert warning.at == "targets[0].mysql.ssl_mode"
    assert "VERIFY_IDENTITY" in str(warning.hint)


@pytest.mark.parametrize(
    "mysql", [None, {"ssl_mode": "VERIFY_CA"}, {"ssl_mode": "VERIFY_IDENTITY"}]
)
def test_a_target_that_verifies_the_server_does_not_warn(mysql: dict[str, str] | None) -> None:
    target = dict(SERVER) if mysql is None else {**SERVER, "mysql": mysql}

    assert unverified({"targets": [target]}) == []


# --------------------------------------------------------- the driver ---


def test_every_command_but_doctor_refuses_a_mysql_target_until_the_driver_is_written() -> None:
    """The config can declare the server before the driver can reach it, so a
    command there is SOPULI-20006 with no install line."""
    target = server()

    require_command(target, "doctor")
    with pytest.raises(DriverNotImplementedError) as caught:
        require_command(target, "creds.apply")

    assert 'target "mysql-dev" declares type "mysql"' in str(caught.value)
    assert "can run only `doctor` there yet" in str(caught.value)
