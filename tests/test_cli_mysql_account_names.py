"""A MySQL account name typed on the command line (#1225).

Tier 0. A `profile:` or `role:` rule admits a name the file never held, so
the config cannot refuse one without a host. Each mutating `account` verb
refuses it at plan time, with exit 9, before anything connects.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner, Result

from conftest import WriteConfig
from sopuli.cli import cli
from sopuli.exit_codes import ExitCode

CONFIG = """version: 1
targets:
  - name: mysql-dev
    type: mysql
    environment: dev
    dsn: mysql-dev.example.com:3306
    admin: { username: "sopuli_svc@%", auth: { method: env } }
personal_accounts:
  - profile: DEVELOPER
delivery:
  method: manual
  manual:
    force_expire: true
"""


def exit_of(result: Result) -> int:
    """The process's exit code. `CliRunner` calls `cli` without `main()`'s
    boundary, so a refusal arrives as the exception that carries it."""
    code = getattr(result.exception, "exit_code", None)
    return int(code) if code is not None else result.exit_code


@pytest.mark.parametrize("verb", ["suspend", "expire-password", "reset-password"])
def test_a_bare_name_is_refused_on_a_mysql_target(write_config: WriteConfig, verb: str) -> None:
    result = CliRunner().invoke(
        cli,
        ["--config", str(write_config(CONFIG)), "account", verb, "--account", "jdoe"]
        + ["--dry-run", "--output", "json"],
    )

    assert exit_of(result) == ExitCode.CONFIG_INVALID, result.output
    error = json.loads(result.output)["error"]
    assert error["message"] == (
        "account 'jdoe' is not user@host without quotes, and target 'mysql-dev' is MySQL"
    )
    assert "jdoe@%" in error["hint"]
    assert "--target" not in error["hint"]


def test_a_bare_name_is_refused_on_a_mariadb_target_by_its_product(
    write_config: WriteConfig,
) -> None:
    """A MariaDB account is `user@host` too (#1268), and the refusal names MariaDB."""
    mariadb = CONFIG.replace("mysql-dev", "mariadb-dev").replace("type: mysql", "type: mariadb")
    result = CliRunner().invoke(
        cli,
        ["--config", str(write_config(mariadb)), "account", "suspend", "--account", "jdoe"]
        + ["--dry-run", "--output", "json"],
    )

    assert exit_of(result) == ExitCode.CONFIG_INVALID, result.output
    error = json.loads(result.output)["error"]
    assert error["message"] == (
        "account 'jdoe' is not user@host without quotes, and target 'mariadb-dev' is MariaDB"
    )
    assert "MariaDB keeps one account per host" in error["hint"]


def test_the_hint_names_every_user_at_host_product_reached(write_config: WriteConfig) -> None:
    """With MySQL and MariaDB targets and an Oracle one, leaving out only the
    first product's targets would be refused again on the second's."""
    both = CONFIG.replace(
        "personal_accounts:",
        "  - name: mariadb-dev\n"
        "    type: mariadb\n"
        "    environment: dev\n"
        "    dsn: mariadb-dev.example.com:3306\n"
        '    admin: { username: "sopuli_svc@%", auth: { method: env } }\n'
        "  - name: appdb-dev\n"
        "    type: oracle\n"
        "    environment: dev\n"
        "    dsn: db-dev.example.com:1521/alpha.pdb.example.com\n"
        "    admin: { username: SOPULI_SVC, auth: { method: env } }\n"
        "personal_accounts:",
    )
    result = CliRunner().invoke(
        cli,
        ["--config", str(write_config(both)), "account", "suspend", "--account", "jdoe"]
        + ["--dry-run", "--output", "json"],
    )

    assert exit_of(result) == ExitCode.CONFIG_INVALID, result.output
    hint = json.loads(result.output)["error"]["hint"]
    assert "MySQL and MariaDB keep one account per host" in hint
    assert "leave the MySQL and MariaDB ones out" in hint


@pytest.mark.parametrize(
    ("typed", "example"), [("'acme_ops'@'%'", "acme_ops@%"), ("acme_ops", "acme_ops@%")]
)
def test_a_quoted_name_is_refused_and_the_hint_uses_the_typed_user(
    write_config: WriteConfig, typed: str, example: str
) -> None:
    """The config's own rule: the file holds names, not the SQL that quotes
    them, so `'acme_ops'@'%'` is refused at plan time too."""
    result = CliRunner().invoke(
        cli,
        ["--config", str(write_config(CONFIG)), "account", "suspend", "--account", typed]
        + ["--dry-run", "--output", "json"],
    )

    assert exit_of(result) == ExitCode.CONFIG_INVALID, result.output
    assert f"`{example}`" in json.loads(result.output)["error"]["hint"]


def test_a_mixed_estate_is_refused_with_a_hint_to_narrow_it(write_config: WriteConfig) -> None:
    """One person is `jdoe` on Oracle and `jdoe@%` on MySQL, so one `--account`
    cannot name both. The run is refused, and the hint says how to narrow it."""
    mixed = CONFIG.replace(
        "personal_accounts:",
        "  - name: appdb-dev\n"
        "    type: oracle\n"
        "    environment: dev\n"
        "    dsn: db-dev.example.com:1521/alpha.pdb.example.com\n"
        "    admin: { username: SOPULI_SVC, auth: { method: env } }\n"
        "personal_accounts:",
    )
    result = CliRunner().invoke(
        cli,
        ["--config", str(write_config(mixed)), "account", "suspend", "--account", "jdoe"]
        + ["--dry-run", "--output", "json"],
    )

    assert exit_of(result) == ExitCode.CONFIG_INVALID, result.output
    hint = json.loads(result.output)["error"]["hint"]
    assert "leave the MySQL ones out with `--target`, `--group` or `--select`" in hint
