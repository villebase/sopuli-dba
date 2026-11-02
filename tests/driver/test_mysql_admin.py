"""What makes a MySQL account one the tool must not manage. Tier 0: a fake
cursor answers the grant-table reads by principal, in the shapes 8.4.13 gave
through PyMySQL 1.2.3."""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.driver.mysql.admin import (
    COLUMNS,
    DB_PRIV_COLUMNS,
    DYNAMIC,
    GLOBAL_ROW,
    MANDATORY_ROLES,
    PRIV_COLUMNS,
    PROXIES,
    ROLE_EDGES,
    SCHEMA,
    TABLES,
    Principal,
    global_privileges,
    mandatory_roles,
)

APP = Principal("acme_app", "10.%")


def _flags(*set_: str) -> tuple[str, ...]:
    return tuple("Y" if column in set_ else "N" for column in PRIV_COLUMNS)


class _Cursor:
    """Rows per query and principal. A principal with no entry has none."""

    def __init__(self, mandatory: str = "", **rows: dict[tuple[str, str], Any]) -> None:
        self.mandatory = mandatory
        self.rows = rows
        self.query = ""
        self.args: Any = None
        self.reads: list[tuple[str, Any]] = []

    def execute(self, query: Any, args: Any = None, /) -> None:
        self.query, self.args = query, args
        self.reads.append((query, args))

    def _for(self, name: str) -> Any:
        return self.rows.get(name, {}).get(tuple(self.args))

    def fetchone(self) -> Any:
        if self.query == MANDATORY_ROLES:
            return (self.mandatory,)
        assert self.query == GLOBAL_ROW
        return self._for("global_row")

    def fetchall(self) -> Any:
        names = {
            DYNAMIC: "dynamic",
            SCHEMA: "schema",
            TABLES: "tables",
            COLUMNS: "columns",
            PROXIES: "proxies",
            ROLE_EDGES: "edges",
        }
        return self._for(names[self.query]) or []


def test_an_account_with_nothing_global_holds_nothing() -> None:
    cursor = _Cursor(global_row={("acme_app", "10.%"): _flags()})

    assert global_privileges(cursor, APP) == frozenset()


def test_every_kind_of_grant_is_named_with_its_object() -> None:
    cursor = _Cursor(
        global_row={("acme_app", "10.%"): _flags("Super_priv", "Grant_priv")},
        dynamic={("acme_app", "10.%"): [("BACKUP_ADMIN",)]},
        schema={
            ("acme_app", "10.%"): [
                tuple("Y" if c == "Update_priv" else "N" for c in DB_PRIV_COLUMNS)
            ]
        },
        tables={("acme_app", "10.%"): [("db", "Select,Update"), ("user", "")]},
        columns={("acme_app", "10.%"): [(b"user", b"authentication_string", {"Select"})]},
        proxies={("acme_app", "10.%"): [("root", "localhost"), ("", "")]},
    )

    assert global_privileges(cursor, APP) == {
        "SUPER ON *.*",
        "GRANT OPTION ON *.*",
        "BACKUP_ADMIN ON *.*",
        "UPDATE ON mysql.*",
        "SELECT ON mysql.db",
        "UPDATE ON mysql.db",
        "SELECT (authentication_string) ON mysql.user",
        "PROXY ON root@localhost",
        "PROXY ON ''@''",
    }


def test_roles_are_followed_to_the_end_and_named() -> None:
    """A cycle (`r1` granted to `r2` and back) ends the walk."""
    cursor = _Cursor(
        edges={
            ("acme_app", "10.%"): [("r1", "%")],
            ("r1", "%"): [("r2", "%")],
            ("r2", "%"): [("r1", "%")],
        },
        global_row={("r2", "%"): _flags("Process_priv")},
    )

    assert global_privileges(cursor, APP) == {"PROCESS ON *.* through r2@%"}


def test_a_mandatory_role_counts_though_role_edges_has_no_row() -> None:
    cursor = _Cursor(mandatory="`ops`@`%`", dynamic={("ops", "%"): [("CONNECTION_ADMIN",)]})

    assert global_privileges(cursor, APP) == {"CONNECTION_ADMIN ON *.* through ops@%"}


@pytest.mark.parametrize(
    ("setting", "roles"),
    [
        ("", ()),
        ("ops", (Principal("ops", "%"),)),
        (
            "ops@localhost, 'audit'@'10.%'",
            (Principal("ops", "localhost"), Principal("audit", "10.%")),
        ),
        ("`ops`@`%`,`audit`", (Principal("ops", "%"), Principal("audit", "%"))),
    ],
)
def test_mandatory_roles_are_parsed_as_the_server_accepts_them(
    setting: str, roles: tuple[Principal, ...]
) -> None:
    assert mandatory_roles(setting) == roles


def test_every_read_names_the_principal() -> None:
    cursor = _Cursor()

    global_privileges(cursor, APP)

    assert all(args == ("acme_app", "10.%") for query, args in cursor.reads if args)
