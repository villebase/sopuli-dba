"""A PostgreSQL target, as the config declares it.

Tier 0, pure. A PostgreSQL target is the **cluster**: every role is
cluster-wide, so `postgres.database` is only the database the tool connects
through, never a scope.

The refusals here keep each product's keys on its own targets. An `oracle:`
block on a PostgreSQL target would load and do nothing, which is the failure a
closed key set exists to prevent. They need the estate expanded, because a
target set's `overrides:` may change a target's `type` or add a block.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.loading import build_config
from sopuli.config.model import TargetPostgres
from sopuli.config.targets import POSTGRES_SSLMODES

VAULTS: dict[str, Any] = {"vault-dev": {"type": "hashicorp", "addr": "https://v.example.com"}}

CLUSTER: dict[str, Any] = {
    "name": "pg-dev",
    "type": "postgresql",
    "dsn": "pg-dev.example.com:5432",
    "environment": "dev",
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


def cluster(**keys: Any) -> Any:
    config = build_config(document(targets=[{**CLUSTER, **keys}]))
    return config.expanded_targets[0].target


def refused(sections: dict[str, Any]) -> str:
    with pytest.raises(ConfigError) as caught:
        build_config(document(**sections))
    return str(caught.value)


# ------------------------------------------------------------- the target ---


def test_a_postgresql_target_loads() -> None:
    target = cluster()

    assert target.type == "postgresql"
    assert target.dsn == "pg-dev.example.com:5432"
    assert target.postgres is None


def test_the_postgres_block_defaults_to_a_verified_connection_to_postgres() -> None:
    assert TargetPostgres() == TargetPostgres(
        database="postgres", sslmode="verify-full", sslrootcert=None
    )


def test_the_postgres_block_is_read_whole() -> None:
    target = cluster(
        postgres={
            "database": "appdb",
            "sslmode": "verify-ca",
            "sslrootcert": "/etc/sopuli/pg-ca.pem",
        }
    )

    assert target.postgres == TargetPostgres(
        database="appdb", sslmode="verify-ca", sslrootcert="/etc/sopuli/pg-ca.pem"
    )


def test_an_unwritten_key_keeps_its_default() -> None:
    target = cluster(postgres={"sslrootcert": "/etc/sopuli/pg-ca.pem"})

    assert target.postgres.database == "postgres"
    assert target.postgres.sslmode == "verify-full"


def test_every_libpq_sslmode_is_accepted() -> None:
    assert POSTGRES_SSLMODES == (
        "disable",
        "allow",
        "prefer",
        "require",
        "verify-ca",
        "verify-full",
    )
    for mode in POSTGRES_SSLMODES:
        assert cluster(postgres={"sslmode": mode}).postgres.sslmode == mode


def test_a_misspelled_sslmode_is_refused() -> None:
    rendered = refused({"targets": [{**CLUSTER, "postgres": {"sslmode": "verify_full"}}]})

    assert "verify_full" in rendered
    assert "targets[0].postgres.sslmode" in rendered


def test_an_unknown_postgres_key_is_refused() -> None:
    rendered = refused({"targets": [{**CLUSTER, "postgres": {"password": "x"}}]})

    assert "password" in rendered
    assert "targets[0].postgres" in rendered


def test_an_empty_postgres_block_is_refused() -> None:
    rendered = refused({"targets": [{**CLUSTER, "postgres": {}}]})

    assert "an empty `postgres:` block says nothing" in rendered


# ------------------------------------------------------------------ dsn ---


@pytest.mark.parametrize(
    "dsn",
    [
        "pg-dev.example.com:5432",
        "192.0.2.10:5432",
        "[2001:db8::10]:6432",
        "[fe80::1%eth0]:5432",
        "pg:1",
        "pg-dev.example.com.:5432",
    ],
)
def test_a_host_and_port_is_accepted(dsn: str) -> None:
    assert cluster(dsn=dsn).dsn == dsn


@pytest.mark.parametrize(
    "dsn",
    [
        "postgresql://sopuli_svc:secret@pg-dev.example.com:5432/postgres",
        "postgres://pg-dev.example.com:5432",
    ],
)
def test_a_connection_uri_is_refused_because_it_can_carry_a_password(dsn: str) -> None:
    rendered = refused({"targets": [{**CLUSTER, "dsn": dsn}]})

    assert "a connection URI" in rendered
    assert "targets[0].dsn" in rendered
    # The message never repeats what was written: a URI may hold a password.
    assert "secret" not in rendered


def test_a_keyword_connection_string_is_refused_too() -> None:
    rendered = refused({"targets": [{**CLUSTER, "dsn": "host=pg-dev.example.com password=secret"}]})

    assert "a keyword connection string" in rendered
    assert "secret" not in rendered


@pytest.mark.parametrize(
    "dsn",
    [
        "pg-dev.example.com",
        "pg-dev.example.com:",
        "pg-dev.example.com:0",
        "pg-dev.example.com:65536",
        "pg-dev.example.com:5432/postgres",
        ":5432",
        "2001:db8::10:5432",
        "-:5432",
        ".:5432",
        "..:5432",
        "pg..example.com:5432",
        "-pg.example.com:5432",
        "[]:5432",
    ],
)
def test_anything_else_is_not_host_and_port(dsn: str) -> None:
    rendered = refused({"targets": [{**CLUSTER, "dsn": dsn}]})

    assert "must be host:port" in rendered
    assert "targets[0].dsn" in rendered


def test_an_oracle_dsn_is_not_checked_for_the_postgresql_shape() -> None:
    config = build_config(document(targets=[ORACLE]))

    assert config.targets[0].dsn == ORACLE["dsn"]


# ------------------------------------------------- one product's keys only ---


def test_an_oracle_block_on_a_postgresql_target_is_refused() -> None:
    rendered = refused({"targets": [{**CLUSTER, "oracle": {"scope": "pdb"}}]})

    assert "`oracle:`" in rendered
    assert "'pg-dev'" in rendered
    assert "targets[0].oracle" in rendered


def test_a_postgres_block_on_an_oracle_target_is_refused() -> None:
    rendered = refused({"targets": [{**ORACLE, "postgres": {"database": "appdb"}}]})

    assert "`postgres:`" in rendered
    assert "'cdb-root-dev'" in rendered
    assert "targets[0].postgres" in rendered


def test_external_authentication_on_a_postgresql_target_is_refused() -> None:
    """`external` is an Oracle wallet. Without this rule the refusal would be
    the wallet rule's, which says the dsn must be a TNS alias."""
    rendered = refused({"targets": [{**CLUSTER, "admin": {"auth": "external"}}]})

    assert "external authentication" in rendered
    assert "targets[0].admin.auth" in rendered
    assert "TNS alias" not in rendered


def test_an_override_that_makes_a_target_postgresql_is_checked_against_the_template() -> None:
    """The template's `oracle:` block is fine on the Oracle targets it generates,
    and wrong on the one an override turns into a PostgreSQL target."""
    rendered = refused(
        {
            "target_sets": {
                "appdb": {
                    "name": "appdb-{env}",
                    "type": "oracle",
                    "dsn": "db-{env}.example.com:1521/APP{env}",
                    "oracle": {"scope": "pdb"},
                    "for_each": {"env": {"dev": {}, "qa": {}}},
                    "overrides": {
                        "appdb-qa": {"type": "postgresql", "dsn": "pg-qa.example.com:5432"}
                    },
                }
            }
        }
    )

    assert "'appdb-qa'" in rendered
    assert "target_sets.appdb.oracle" in rendered
    # An override cannot remove a block the template writes, so the way out is
    # a set per product, and the hint says so.
    assert "a target set of their own" in rendered


@pytest.mark.parametrize("sslmode", ["disable", "allow", "prefer", "require"])
def test_a_ca_file_without_a_verifying_sslmode_is_refused(sslmode: str) -> None:
    """libpq ignores the CA file below `require`, and under `require` it turns
    the mode into `verify-ca` without saying so. Either way the file does not
    do what it reads as."""
    rendered = refused(
        {"targets": [{**CLUSTER, "postgres": {"sslmode": sslmode, "sslrootcert": "/etc/ca.pem"}}]}
    )

    assert "sslrootcert" in rendered
    assert sslmode in rendered
    assert "targets[0].postgres" in rendered


def test_a_ca_file_patched_onto_a_weak_sslmode_is_refused_too() -> None:
    rendered = refused(
        {
            "target_sets": {
                "pg": {
                    "name": "pg-{env}",
                    "type": "postgresql",
                    "dsn": "pg-{env}.example.com:5432",
                    "postgres": {"sslmode": "prefer"},
                    "for_each": {"env": {"dev": {}, "qa": {}}},
                    "overrides": {"pg-qa": {"postgres": {"sslrootcert": "/etc/ca.pem"}}},
                }
            }
        }
    )

    assert "'pg-qa'" in rendered
    assert "target_sets.pg.overrides.pg-qa.postgres" in rendered


def test_an_override_that_weakens_the_mode_under_a_templates_ca_file_says_what_it_can_do() -> None:
    """An override cannot clear a key, so the hint does not tell it to drop the
    CA file its template wrote."""
    rendered = refused(
        {
            "target_sets": {
                "pg": {
                    "name": "pg-{env}",
                    "type": "postgresql",
                    "dsn": "pg-{env}.example.com:5432",
                    "postgres": {"sslrootcert": "/etc/ca.pem"},
                    "for_each": {"env": {"dev": {}, "qa": {}}},
                    "overrides": {"pg-qa": {"postgres": {"sslmode": "require"}}},
                }
            }
        }
    )

    assert "target_sets.pg.overrides.pg-qa.postgres" in rendered
    assert "drop `sslrootcert`" not in rendered
    assert "verify-ca" in rendered


def test_an_oracle_block_an_override_wrote_is_dropped_from_the_override() -> None:
    """Only a block the template wrote needs a set of its own."""
    rendered = refused(
        {
            "target_sets": {
                "pg": {
                    "name": "pg-{env}",
                    "type": "postgresql",
                    "dsn": "pg-{env}.example.com:5432",
                    "for_each": {"env": {"dev": {}, "qa": {}}},
                    "overrides": {"pg-qa": {"oracle": {"scope": "pdb"}}},
                }
            }
        }
    )

    assert "target_sets.pg.overrides.pg-qa.oracle" in rendered
    assert "a target set of their own" not in rendered


def test_a_target_set_renders_the_postgres_block() -> None:
    config = build_config(
        document(
            target_sets={
                "pg": {
                    "name": "pg-{env}",
                    "type": "postgresql",
                    "dsn": "pg-{env}.example.com:5432",
                    "postgres": {"database": "app_{env}", "sslrootcert": "/etc/ca-{env}.pem"},
                    "for_each": {"env": {"dev": {}, "qa": {}}},
                    "overrides": {"pg-qa": {"postgres": {"sslmode": "verify-ca"}}},
                }
            }
        )
    )

    rendered = {expanded.name: expanded.target.postgres for expanded in config.expanded_targets}
    assert rendered == {
        "pg-dev": TargetPostgres(database="app_dev", sslrootcert="/etc/ca-dev.pem"),
        "pg-qa": TargetPostgres(
            database="app_qa", sslmode="verify-ca", sslrootcert="/etc/ca-qa.pem"
        ),
    }


def test_an_applications_container_clause_on_a_postgresql_target_is_refused() -> None:
    rendered = refused(
        {
            "targets": [CLUSTER],
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

    assert "container_clause" in rendered
    assert "'pg-dev'" in rendered
    assert "applications[0].oracle.container_clause" in rendered


def test_an_override_that_sets_a_container_clause_is_named() -> None:
    rendered = refused(
        {
            "targets": [{**CLUSTER, "labels": {"tier": "app"}}],
            "applications": [
                {
                    "name": "acme",
                    "accounts": ["acme_app_user"],
                    "secret_template": "acme/{target}/{account}#password",
                    "overrides": [
                        {"where": {"tier": "app"}, "oracle": {"container_clause": "ALL"}}
                    ],
                }
            ],
        }
    )

    assert "applications[0].overrides[0].oracle.container_clause" in rendered


def test_a_container_clause_on_oracle_targets_beside_a_cluster_is_fine() -> None:
    """The clause is refused only where it would bind to a PostgreSQL target."""
    config = build_config(
        document(
            targets=[ORACLE, CLUSTER],
            applications=[
                {
                    "name": "acme",
                    "targets": ["cdb-root-dev"],
                    "accounts": ["acme_app_user"],
                    "secret_template": "acme/{target}/{account}#password",
                    "oracle": {"container_clause": "CURRENT"},
                },
                {
                    "name": "acme-pg",
                    "targets": ["pg-dev"],
                    "accounts": ["acme_app_user"],
                    "secret_template": "acme-pg/{target}/{account}#password",
                },
            ],
        )
    )

    assert {binding.target for binding in config.bindings} == {"cdb-root-dev", "pg-dev"}


# ------------------------------------------- a server that is not verified ---


def unverified(sections: dict[str, Any]) -> list[Any]:
    config = build_config(document(**sections))
    return [warning for warning in config.warnings if warning.code == "SOPULI-W058"]


@pytest.mark.parametrize("sslmode", ["disable", "allow", "prefer", "require"])
def test_a_target_that_does_not_verify_the_server_warns(sslmode: str) -> None:
    (warning,) = unverified({"targets": [{**CLUSTER, "postgres": {"sslmode": sslmode}}]})

    assert warning.message == f"target 'pg-dev' does not verify the server (`sslmode: {sslmode}`)"
    assert warning.at == "targets[0].postgres.sslmode"
    assert "verify-full" in str(warning.hint)


@pytest.mark.parametrize("postgres", [None, {"sslmode": "verify-ca"}, {"sslmode": "verify-full"}])
def test_a_target_that_verifies_the_server_does_not_warn(postgres: dict[str, str] | None) -> None:
    target = dict(CLUSTER) if postgres is None else {**CLUSTER, "postgres": postgres}

    assert unverified({"targets": [target]}) == []


def test_an_oracle_target_does_not_warn() -> None:
    assert unverified({"targets": [ORACLE]}) == []


def test_each_generated_target_warns_once_and_points_at_its_line() -> None:
    """The override's line for the target it weakened, the template's for the rest."""
    warnings = unverified(
        {
            "target_sets": {
                "pg": {
                    "name": "pg-{env}",
                    "type": "postgresql",
                    "dsn": "pg-{env}.example.com:5432",
                    "postgres": {"sslmode": "require"},
                    "for_each": {"env": {"dev": {}, "qa": {}, "prod": {}}},
                    "overrides": {"pg-prod": {"postgres": {"sslmode": "verify-full"}}},
                }
            }
        }
    )

    assert [(warning.message.split("'")[1], warning.at) for warning in warnings] == [
        ("pg-dev", "target_sets.pg.postgres.sslmode"),
        ("pg-qa", "target_sets.pg.postgres.sslmode"),
    ]
