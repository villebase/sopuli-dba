"""The MySQL tool account's privilege audit. Tier 0: the grants are `SHOW
GRANTS` lines in the shapes 8.0.46, 8.4.13 and 9.7.4 printed
(`sql/mysql/07_own_grants_probe.py`)."""

from __future__ import annotations

from typing import Any

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
