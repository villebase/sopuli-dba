"""Reading `SHOW GRANTS` lines. Tier 0: the lines are as MySQL 8.0.46, 8.4.13
and 9.7.4 printed them (`sql/mysql/07_own_grants_probe.py`)."""

from __future__ import annotations

import pytest

from sopuli.driver.mysql.grants import Grant, Privilege, parse, parse_all


def test_static_privileges_on_every_object() -> None:
    grant = parse("GRANT PROCESS, SUPER, CREATE USER ON *.* TO `t_tool`@`%`")

    assert grant == Grant(
        privileges=(Privilege("PROCESS"), Privilege("SUPER"), Privilege("CREATE USER")),
        on="*.*",
    )


def test_dynamic_privileges_are_separated_by_a_bare_comma() -> None:
    grant = parse("GRANT BACKUP_ADMIN,SYSTEM_USER ON *.* TO `t_tool`@`%`")

    assert grant is not None
    assert grant.names() == {"BACKUP_ADMIN", "SYSTEM_USER"}


def test_column_privileges_name_their_columns() -> None:
    grant = parse(
        "GRANT SELECT (`Host`, `User`, `account_locked`, `plugin`) ON `mysql`.`user` "
        "TO `t_tool`@`%`"
    )

    assert grant == Grant(
        privileges=(Privilege("SELECT", ("Host", "User", "account_locked", "plugin")),),
        on="mysql.user",
    )


def test_the_grant_option_is_read() -> None:
    grant = parse("GRANT CREATE USER ON *.* TO `t_tool`@`%` WITH GRANT OPTION")

    assert grant is not None
    assert grant.grant_option is True
    assert grant.on == "*.*"


def test_a_database_pattern_keeps_its_wildcard() -> None:
    grant = parse("GRANT SELECT, INSERT ON `acme%`.* TO `t_tool`@`%`")

    assert grant is not None
    assert grant.on == "acme%.*"
    assert grant.names() == {"SELECT", "INSERT"}


def test_a_proxy_grant_is_on_the_account_it_proxies() -> None:
    grant = parse("GRANT PROXY ON `t_other`@`%` TO `t_tool`@`%`")

    assert grant == Grant(privileges=(Privilege("PROXY"),), on="t_other@%")


def test_a_role_grant_names_its_roles() -> None:
    grant = parse("GRANT `t_all`@`%`,`t_role`@`%` TO `t_tool`@`%` WITH ADMIN OPTION")

    assert grant == Grant(roles=("t_all@%", "t_role@%"), admin_option=True)


def test_quotes_inside_a_name_do_not_split_it() -> None:
    """A doubled backtick is one backtick, and ` ON `, `,` and `@` inside a
    quoted name are part of the name."""
    grant = parse("GRANT `a ON b, c@d``e`@`%` TO `t_tool`@`%`")

    assert grant == Grant(roles=("a ON b, c@d`e@%",))


@pytest.mark.parametrize(
    "line",
    [
        "REVOKE INSERT ON `mysql`.* FROM `t_tool`@`%`",
        "GRANT",
        "GRANT CREATE USER ON *.*",
    ],
)
def test_a_line_of_another_shape_is_not_parsed(line: str) -> None:
    assert parse(line) is None


def test_unparsed_lines_are_kept() -> None:
    found = parse_all(
        [
            "GRANT CREATE USER ON *.* TO `t_tool`@`%`",
            "REVOKE INSERT ON `mysql`.* FROM `t_tool`@`%`",
        ]
    )

    assert len(found.grants) == 1
    assert found.unparsed == ("REVOKE INSERT ON `mysql`.* FROM `t_tool`@`%`",)


@pytest.mark.parametrize(
    ("lines", "holds"),
    [
        (["GRANT CREATE USER ON *.* TO `t`@`%`"], False),
        (["GRANT BACKUP_ADMIN,SYSTEM_USER ON *.* TO `t`@`%`"], True),
        (["GRANT ALL PRIVILEGES ON *.* TO `t`@`%`"], True),
        # SYSTEM_USER is global only; a name in a column list is not it.
        (["GRANT ALL PRIVILEGES ON `acme`.* TO `t`@`%`"], False),
        (["GRANT SELECT (`SYSTEM_USER`) ON `acme`.`t` TO `t`@`%`"], False),
    ],
)
def test_system_user_is_a_global_privilege(lines: list[str], holds: bool) -> None:
    assert parse_all(lines).holds_system_user() is holds
