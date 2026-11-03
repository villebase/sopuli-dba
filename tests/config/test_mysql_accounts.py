"""A MySQL account names its host, and `{user}` and `{host}` (#1221).

Tier 0, pure. MySQL keeps `acme_app@%` and `acme_app@localhost` as two accounts
with two passwords, so an account bound to a MySQL target is written
`user@host`, split at the last `@` (#1202, decision 4). A bare name is a config
error, for an application and for a personal account rule alike.

`{user}` and `{host}` keep `@` and the host's wildcards out of a vault path:
`{host}` writes `%` as `any` and `_` as `one` (decided on #1221).
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.loading import build_config
from sopuli.config.model import Config

VAULTS: dict[str, Any] = {"vault-dev": {"type": "hashicorp", "addr": "https://v.example.com"}}

SERVER: dict[str, Any] = {
    "name": "mysql-dev",
    "type": "mysql",
    "dsn": "mysql-dev.example.com:3306",
    "vault": "vault-dev",
}

ORACLE: dict[str, Any] = {
    "name": "appdb-dev",
    "type": "oracle",
    "dsn": "db-dev.example.com:1521/alpha.pdb.example.com",
    "vault": "vault-dev",
}


def config(*applications: dict[str, Any], targets: Any = None, **sections: Any) -> Config:
    document: dict[str, Any] = {
        "version": 1,
        "vaults": VAULTS,
        "targets": [SERVER, ORACLE] if targets is None else targets,
        **sections,
    }
    if applications:
        document["applications"] = list(applications)
    return build_config(document)


def app(*accounts: str, template: str = "apps/acme#DB/{account}", **keys: Any) -> dict[str, Any]:
    return {
        "name": "acme",
        "targets": [SERVER["name"]],
        "accounts": list(accounts),
        "secret_template": template,
        **keys,
    }


def refused(*applications: dict[str, Any], **sections: Any) -> ConfigError:
    with pytest.raises(ConfigError) as caught:
        config(*applications, **sections)
    return caught.value


def refs(loaded: Config) -> dict[str, str]:
    return {binding.account: str(binding.secret) for binding in loaded.bindings}


# ---------------------------------------------------------- the account name ---


@pytest.mark.parametrize("account", ["acme_app", "acme_app@", "@10.%"])
def test_an_account_without_a_user_and_a_host_is_refused_on_mysql(account: str) -> None:
    error = refused(app(account))

    assert error.message == (
        f"application 'acme' declares {account!r} on MySQL target 'mysql-dev', "
        "and a MySQL account must name its host as user@host"
    )
    assert "acme_app@10.%" in str(error.hint)
    assert str(error.at) == "applications[0].accounts[0]"


@pytest.mark.parametrize("account", ["acme_app@10.%", "acme_app@%", "acme@app@localhost"])
def test_an_account_with_a_user_and_a_host_is_accepted(account: str) -> None:
    assert list(refs(config(app(account)))) == [account]


@pytest.mark.parametrize(
    "account", ["'acme_app'@'%'", "`acme_app`@%", "acme_app@ %", "acme_app @%", 'acme_app@"%"']
)
def test_a_part_quoted_as_sql_quotes_it_or_padded_is_refused(account: str) -> None:
    error = refused(app(account))

    assert error.message == (
        f"application 'acme' declares {account!r} on MySQL target 'mysql-dev', "
        "whose user or host starts or ends with a quote or a space"
    )
    assert str(error.at) == "applications[0].accounts[0]"


def test_the_error_points_at_the_bare_name_in_the_list() -> None:
    error = refused(app("acme_app@%", "acme_api"))

    assert str(error.at) == "applications[0].accounts[1]"


def test_the_inline_form_is_checked_too() -> None:
    with pytest.raises(ConfigError) as caught:
        build_config(
            {
                "version": 1,
                "vaults": VAULTS,
                "targets": [SERVER],
                "accounts": ["acme_app"],
                "secret_template": "apps/acme#DB/{account}",
            }
        )

    assert caught.value.message.startswith("the application declares 'acme_app'")
    assert str(caught.value.at) == "accounts[0]"


def test_a_bare_name_on_another_products_target_is_unchanged() -> None:
    loaded = config(app("acme_app", targets=[ORACLE["name"]]))

    assert refs(loaded) == {"acme_app": "apps/acme#DB/acme_app"}


def test_an_application_over_both_products_is_refused_for_its_mysql_target() -> None:
    error = refused(app("acme_app", targets=[ORACLE["name"], SERVER["name"]]))

    assert "on MySQL target 'mysql-dev'" in error.message


# ------------------------------------------------------- personal accounts ---


def personal(*accounts: str, **keys: Any) -> dict[str, Any]:
    return {"personal_accounts": [{"accounts": list(accounts), **keys}]}


def test_a_personal_account_on_mysql_names_its_host() -> None:
    error = refused(**personal("jdoe"))

    assert error.message == (
        "a personal account rule declares 'jdoe' on MySQL target 'mysql-dev', "
        "and a MySQL account must name its host as user@host"
    )
    assert str(error.at) == "personal_accounts[0].accounts[0]"


def test_a_personal_account_with_its_host_is_accepted() -> None:
    loaded = config(**personal("jdoe@%"))

    assert loaded.personal_accounts[0].accounts == ("jdoe@%",)


def test_a_personal_rule_that_reaches_no_mysql_target_is_unchanged() -> None:
    loaded = config(**personal("jdoe", targets=[ORACLE["name"]]))

    assert loaded.personal_accounts[0].accounts == ("jdoe",)


def test_a_personal_rule_by_profile_names_no_account_to_check() -> None:
    loaded = config(personal_accounts=[{"profile": "DEVELOPER"}])

    assert loaded.personal_accounts[0].profile == "DEVELOPER"


def test_a_role_on_mysql_names_its_host() -> None:
    """A MySQL role is an account: `CREATE ROLE dev_role` makes `dev_role@%`,
    and a bare name is a guess (decision 4 of #1225)."""
    error = refused(personal_accounts=[{"role": "dev_role"}])

    assert error.message == (
        "a personal account rule's `role:` declares 'dev_role' on MySQL target "
        "'mysql-dev', and a MySQL account must name its host as user@host"
    )
    assert str(error.at) == "personal_accounts[0].role"
    assert "`dev_role@%`" in str(error.hint)


def test_a_role_with_an_empty_host_names_no_stray_at_sign_in_the_hint() -> None:
    error = refused(personal_accounts=[{"role": "acme_dev_team@"}])

    assert "`acme_dev_team@%`" in str(error.hint)
    assert "@@" not in str(error.hint)


def test_a_quoted_role_is_refused_with_the_typed_name_in_the_hint() -> None:
    error = refused(personal_accounts=[{"role": "'acme_dev_team'@'%'"}])

    assert "starts or ends with a quote" in error.message
    assert "`acme_dev_team@10.%`" in str(error.hint)


def test_a_role_with_its_host_is_accepted() -> None:
    loaded = config(personal_accounts=[{"role": "dev_role@%"}])

    assert loaded.personal_accounts[0].role == "dev_role@%"


def test_a_role_that_reaches_no_mysql_target_is_unchanged() -> None:
    loaded = config(personal_accounts=[{"role": "DEV_ROLE", "targets": [ORACLE["name"]]}])

    assert loaded.personal_accounts[0].role == "DEV_ROLE"


# ------------------------------------------------------- {user} and {host} ---


def test_user_and_host_render_without_the_at_sign_or_a_wildcard() -> None:
    loaded = config(
        app(
            "acme_app@10.%",
            "acme_app@%",
            "acme_api@host_1.example.com",
            template="mysql/{host}#DB/{user}",
        )
    )

    assert refs(loaded) == {
        "acme_app@10.%": "mysql/10.any#DB/acme_app",
        "acme_app@%": "mysql/any#DB/acme_app",
        "acme_api@host_1.example.com": "mysql/hostone1.example.com#DB/acme_api",
    }


def test_user_is_the_part_before_the_last_at_sign() -> None:
    loaded = config(app("acme@app@localhost", template="mysql/{host}#DB/{user}"))

    assert refs(loaded) == {"acme@app@localhost": "mysql/localhost#DB/acme@app"}


def test_user_is_the_whole_name_on_another_product() -> None:
    loaded = config(app("acme_app", targets=[ORACLE["name"]], template="apps#DB/{user}"))

    assert refs(loaded) == {"acme_app": "apps#DB/acme_app"}


def test_host_on_another_product_is_refused_and_names_the_target() -> None:
    error = refused(app("acme_app", targets=[ORACLE["name"]], template="apps/{host}#DB/{user}"))

    assert error.message == (
        "secret ref 'apps/{host}#DB/{user}' uses {host}, and target 'appdb-dev' is "
        "oracle, where an account has no host"
    )
    assert str(error.at) == "applications[0].secret_template"


def test_a_label_called_host_fills_host_on_another_product() -> None:
    """As a label called `container` fills `{container}` on a target without one."""
    labelled = {**ORACLE, "labels": {"host": "db-dev"}}
    loaded = config(
        app("acme_app", targets=[ORACLE["name"]], template="apps/{host}#DB/{user}"),
        targets=[SERVER, labelled],
    )

    assert refs(loaded) == {"acme_app": "apps/db-dev#DB/acme_app"}


def test_a_host_with_a_slash_is_refused_where_a_ref_uses_it() -> None:
    """MySQL accepts a netmask host, and a `/` in a name moves the password (#935)."""
    error = refused(app("acme_app@10.0.0.0/255.0.0.0", template="mysql/{host}#DB/{user}"))

    assert error.message == (
        "{host} in secret ref 'mysql/{host}#DB/{user}' is '10.0.0.0/255.0.0.0', which contains `/`"
    )


def test_user_or_host_counts_as_telling_accounts_apart() -> None:
    loaded = config(app("acme_app@%", "acme_api@%", template="mysql#DB/{user}"))

    assert refs(loaded) == {"acme_app@%": "mysql#DB/acme_app", "acme_api@%": "mysql#DB/acme_api"}


def test_two_accounts_that_user_alone_renders_alike_are_refused() -> None:
    error = refused(app("acme_app@10.%", "acme_app@%", template="mysql#DB/{user}"))

    assert error.message == (
        "'acme_app@10.%' and 'acme_app@%' (both in entry 'acme') resolve to one password "
        "at vault-dev:mysql#DB/acme_app"
    )


def test_a_wildcard_host_and_a_literal_host_that_render_alike_are_refused() -> None:
    """`10.%` renders as `10.any`, so it collides with a host literally named
    `10.any` (decided on #1221)."""
    error = refused(app("acme_app@10.%", "acme_app@10.any", template="mysql/{host}#DB/{user}"))

    assert error.message == (
        "'acme_app@10.%' and 'acme_app@10.any' (both in entry 'acme') resolve to one "
        "password at vault-dev:mysql/10.any#DB/acme_app"
    )


def test_one_account_without_user_or_host_is_still_refused_in_a_shared_ref() -> None:
    error = refused(app("acme_app@%", "acme_api@%", template="mysql#DB"))

    assert error.message == "2 accounts would share one secret ref"
    assert "{user} and {host} on MySQL" in str(error.hint)
