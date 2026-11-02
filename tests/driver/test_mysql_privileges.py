"""The MySQL tool account's privilege audit. Tier 0: the grants are `SHOW
GRANTS` lines in the shapes 8.0.46, 8.4.13 and 9.7.4 printed
(`sql/mysql/07_own_grants_probe.py`)."""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.driver.mysql import grants as grants_module
from sopuli.driver.mysql.grants import parse_all
from sopuli.driver.mysql.privileges import (
    ALL_ROLES,
    COLUMNS,
    CREATE_USER,
    OVER_GRANTED_REMEDY,
    SELF,
    audit,
    classify,
)

TOOL = "`sopuli_admin`@`192.0.2.10`"
COLUMN_GRANT = (
    "GRANT SELECT (`Host`, `User`, `account_locked`, `password_expired`, "
    "`password_last_changed`, `password_lifetime`, `plugin`) ON `mysql`.`user` TO " + TOOL
)
INSTALL = [f"GRANT CREATE USER ON *.* TO {TOOL}", COLUMN_GRANT]


def _classify(lines: list[str], roles: tuple[str, ...] = ()) -> Any:
    return classify(user="sopuli_admin@192.0.2.10", grants=parse_all(lines), roles=roles)


def test_the_grants_of_section_2_are_held_and_nothing_is_missing() -> None:
    found = _classify(INSTALL)

    assert found.missing == ()
    assert found.over_granted == ()
    assert found.held == tuple(
        sorted([CREATE_USER, *(f"SELECT ({name}) ON mysql.user" for name in COLUMNS)])
    )
    assert found.remedies == ()
    assert found.hint == (
        "02-mysql-privileges.md section 2 has the grants for the tool account "
        "`sopuli_admin@192.0.2.10`"
    )


def test_what_is_not_granted_is_missing() -> None:
    found = _classify([f"GRANT USAGE ON *.* TO {TOOL}"])

    assert found.held == ()
    assert found.missing[0] == CREATE_USER
    assert len(found.missing) == 1 + len(COLUMNS)


def test_column_names_are_compared_without_case() -> None:
    lines = [INSTALL[0], COLUMN_GRANT.replace("`plugin`", "`Plugin`")]

    assert _classify(lines).missing == ()


def test_every_privilege_outside_section_2_is_over_granted() -> None:
    found = _classify(
        [
            f"GRANT PROCESS, SUPER, CREATE USER ON *.* TO {TOOL} WITH GRANT OPTION",
            f"GRANT ROLE_ADMIN,SET_USER_ID ON *.* TO {TOOL}",
            f"GRANT SELECT, INSERT ON `acme%`.* TO {TOOL}",
            f"GRANT SELECT ON `mysql`.`user` TO {TOOL}",
            f"GRANT SELECT (`authentication_string`, `User`) ON `mysql`.`user` TO {TOOL}",
            f"GRANT PROXY ON `acme_app`@`%` TO {TOOL}",
            f"GRANT `acme_ops`@`%` TO {TOOL} WITH ADMIN OPTION",
        ]
    )

    assert found.over_granted == (
        "ADMIN OPTION ON acme_ops@%",
        "GRANT OPTION ON *.*",
        "INSERT ON acme%.*",
        "PROCESS ON *.*",
        "PROXY ON acme_app@%",
        "ROLE_ADMIN ON *.*",
        "SELECT (authentication_string) ON mysql.user",
        "SELECT ON acme%.*",
        "SELECT ON mysql.user",
        "SET_USER_ID ON *.*",
        "SUPER ON *.*",
    )
    assert "CREATE USER" in found.held
    assert "SELECT (User) ON mysql.user" in found.held
    assert found.remedies == (OVER_GRANTED_REMEDY,)


@pytest.mark.parametrize(
    ("line", "over"),
    [
        (f"GRANT SELECT ON `mysql`.`user` TO {TOOL}", "SELECT ON mysql.user"),
        (f"GRANT SELECT ON `mysql`.* TO {TOOL}", "SELECT ON mysql.*"),
        (f"GRANT SELECT ON *.* TO {TOOL}", "SELECT ON *.*"),
    ],
)
def test_a_broader_select_covers_the_columns_and_is_over_granted(line: str, over: str) -> None:
    """The tool can read what it needs, so nothing is missing, and it reads
    the hashes too, so the grant is over-granted."""
    found = _classify([INSTALL[0], line])

    assert found.missing == ()
    assert found.over_granted == (over,)


def test_all_privileges_on_every_object_covers_section_2() -> None:
    found = _classify([f"GRANT ALL PRIVILEGES ON *.* TO {TOOL}"])

    assert found.missing == ()
    assert found.over_granted == ("ALL PRIVILEGES ON *.*",)


def test_a_schema_that_differs_only_in_case_is_not_the_system_schema() -> None:
    """Names are case-sensitive on Linux: `MYSQL`.`USER` is another table."""
    line = COLUMN_GRANT.replace("`mysql`.`user`", "`MYSQL`.`USER`")
    found = _classify([INSTALL[0], line])

    assert len(found.missing) == len(COLUMNS)


def test_the_hint_gives_the_statements_for_what_is_missing() -> None:
    found = _classify([f"GRANT SELECT (`User`, `Host`) ON `mysql`.`user` TO {TOOL}"])

    assert found.hint == (
        "02-mysql-privileges.md section 2 has the grants for the tool account "
        "`sopuli_admin@192.0.2.10`: GRANT CREATE USER ON *.* TO "
        "'sopuli_admin'@'192.0.2.10'; GRANT SELECT (plugin, account_locked, "
        "password_expired, password_last_changed, password_lifetime) ON mysql.user "
        "TO 'sopuli_admin'@'192.0.2.10';"
    )


def test_a_proxy_grant_on_the_anonymous_account_is_named_so() -> None:
    found = _classify([*INSTALL, f"GRANT PROXY ON ``@`` TO {TOOL} WITH GRANT OPTION"])

    assert found.over_granted == ("GRANT OPTION ON ''@''", "PROXY ON ''@''")


def test_a_line_the_parser_cannot_read_is_unaudited() -> None:
    line = "REVOKE INSERT ON `mysql`.* FROM " + TOOL
    found = _classify([*INSTALL, line])

    assert found.unaudited == (f"a SHOW GRANTS line the tool cannot read: {line}",)
    assert found.complete is False


def test_roles_are_reported_sorted() -> None:
    found = _classify(INSTALL, roles=("acme_ro@%", "acme_ops@%"))

    assert found.roles == ("acme_ops@%", "acme_ro@%")


class _Cursor:
    """Answers the four reads: the account, its own roles, its grants with
    the role expanded, and every role it reaches."""

    def __init__(self) -> None:
        self.last = ""
        self.queries: list[str] = []

    def execute(self, query: Any, args: Any = None, /) -> None:
        self.last = query
        self.queries.append(query)

    def fetchone(self) -> Any:
        assert self.last == SELF
        return ("sopuli_admin@192.0.2.10",)

    def fetchall(self) -> Any:
        if self.last == grants_module.DIRECT_ROLES:
            return [("acme_ops", "%")]
        if self.last == ALL_ROLES:
            return [("acme_nested", "%"), ("acme_ops", "%")]
        return [
            (f"GRANT PROCESS, CREATE USER ON *.* TO {TOOL}",),
            (COLUMN_GRANT,),
            (f"GRANT `acme_ops`@`%` TO {TOOL}",),
        ]


def test_audit_reads_the_grants_with_every_role_expanded() -> None:
    cursor = _Cursor()

    found = audit(cursor)

    assert found.over_granted == ("PROCESS ON *.*",)
    assert found.missing == ()
    assert found.roles == ("acme_nested@%", "acme_ops@%")
    assert cursor.queries[2] == grants_module.GRANTS_USING.format(roles="%s@%s")
