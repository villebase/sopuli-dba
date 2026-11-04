"""What makes a MariaDB account one the tool must not manage (check 9). Tier 0:
a fake cursor answers the grant-table reads by principal, in the shapes
11.8.9 gave through PyMySQL 1.2.3."""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.driver.mariadb.admin import (
    DB_COLUMNS as DB_COLUMNS_QUERY,
)
from sopuli.driver.mariadb.admin import (
    GLOBAL_ROW,
    PUBLIC,
    ROLE_EDGES,
    SCHEMA,
    VIEW_PRIV_COLUMNS,
    global_privileges,
    privilege,
    roles_of,
)
from sopuli.driver.mysql_family.accounts import Principal
from sopuli.driver.mysql_family.grant_tables import (
    COLUMN_GRANTS,
    PROXIES,
    ROUTINE_GRANTS,
    TABLE_GRANTS,
)

APP = Principal("acme_app", "10.%")
KEY = ("acme_app", "10.%")
PUBLIC_KEY = ("PUBLIC", "")

#: mysql.db's columns on 11.8.9, which has Show_create_routine_priv.
DB_COLUMNS = (
    "Host",
    "Db",
    "User",
    "Select_priv",
    "Insert_priv",
    "Update_priv",
    "Delete_priv",
    "Create_priv",
    "Drop_priv",
    "Grant_priv",
    "References_priv",
    "Index_priv",
    "Alter_priv",
    "Create_tmp_table_priv",
    "Lock_tables_priv",
    "Create_view_priv",
    "Show_view_priv",
    "Create_routine_priv",
    "Alter_routine_priv",
    "Execute_priv",
    "Event_priv",
    "Trigger_priv",
    "Delete_history_priv",
    "Show_create_routine_priv",
)


def _flags(*set_: str) -> tuple[str, ...]:
    return tuple("Y" if column in set_ else "N" for column in VIEW_PRIV_COLUMNS)


DB_PRIVS = tuple(c for c in DB_COLUMNS if c.endswith("_priv"))


def _db_row(*set_: str, db: str = "mysql") -> tuple[str, ...]:
    """A ``mysql.db`` row as SCHEMA reads it: ``Db``, then the ``*_priv``
    columns."""
    return (db, *("Y" if c in set_ else "N" for c in DB_PRIVS))


class _Cursor:
    """Rows per query and principal. A principal with no entry has none."""

    def __init__(self, **rows: dict[tuple[str, str], Any]) -> None:
        self.rows = rows
        self.query = ""
        self.args: Any = None
        self.description: Any = None

    def execute(self, query: Any, args: Any = None, /) -> None:
        self.query, self.args = query, args

    def _for(self, name: str) -> Any:
        return self.rows.get(name, {}).get(tuple(self.args))

    def fetchone(self) -> Any:
        assert self.query == GLOBAL_ROW
        return self._for("global_row")

    def fetchall(self) -> Any:
        if self.query == DB_COLUMNS_QUERY:
            # SHOW COLUMNS: Field first, and only the `*_priv` ones.
            return [(c, "enum('N','Y')") for c in DB_COLUMNS if c.endswith("_priv")]
        if self.query == SCHEMA.format(columns=", ".join(DB_PRIVS)):
            return self._for("schema") or []
        names = {
            TABLE_GRANTS: "tables",
            COLUMN_GRANTS: "columns",
            ROUTINE_GRANTS: "routines",
            PROXIES: "proxies",
            ROLE_EDGES: "edges",
        }
        return self._for(names[self.query]) or []


@pytest.mark.parametrize(
    ("column", "spelled"),
    [
        ("Select_priv", "SELECT"),
        ("Grant_priv", "GRANT OPTION"),
        ("Repl_client_priv", "BINLOG MONITOR"),
        ("Repl_slave_priv", "REPLICATION SLAVE"),
        ("Show_db_priv", "SHOW DATABASES"),
        ("Create_tmp_table_priv", "CREATE TEMPORARY TABLES"),
        ("Delete_history_priv", "DELETE HISTORY"),
        ("Show_create_routine_priv", "SHOW CREATE ROUTINE"),
        ("Create_tablespace_priv", "CREATE TABLESPACE"),
    ],
)
def test_a_column_is_named_as_grant_spells_its_privilege(column: str, spelled: str) -> None:
    assert privilege(column) == spelled


def test_an_account_with_nothing_holds_nothing() -> None:
    cursor = _Cursor(global_row={KEY: _flags(), PUBLIC_KEY: _flags()})

    assert global_privileges(cursor, APP) == frozenset()


def test_every_kind_of_grant_is_named_with_its_object() -> None:
    cursor = _Cursor(
        global_row={KEY: _flags("Super_priv", "Repl_client_priv")},
        schema={KEY: [_db_row("Update_priv", "Show_create_routine_priv")]},
        tables={KEY: [("db", "Select,Update"), ("user", "")]},
        columns={KEY: [(b"user", b"authentication_string", {"Select"})]},
        routines={KEY: [("PROCEDURE", "AddGeometryColumn", "Execute")]},
        proxies={KEY: [("root", "localhost"), ("", "")]},
    )

    assert global_privileges(cursor, APP) == {
        "SUPER ON *.*",
        "BINLOG MONITOR ON *.*",
        "UPDATE ON mysql.*",
        "SHOW CREATE ROUTINE ON mysql.*",
        "SELECT ON mysql.db",
        "UPDATE ON mysql.db",
        "SELECT (authentication_string) ON mysql.user",
        "EXECUTE ON PROCEDURE mysql.AddGeometryColumn",
        "PROXY ON root@localhost",
        "PROXY ON ''@''",
    }


def test_roles_are_followed_to_the_end_at_an_empty_host() -> None:
    """A role is at host ``''``; a cycle (`r1` granted to `r2` and back) ends
    the walk (RR1)."""
    cursor = _Cursor(
        edges={KEY: [("r1", "")], ("r1", ""): [("r2", "")], ("r2", ""): [("r1", "")]},
        global_row={("r2", ""): _flags("Process_priv")},
    )

    assert roles_of(cursor, APP) == (PUBLIC, Principal("r1", ""), Principal("r2", ""))
    assert global_privileges(cursor, APP) == {"PROCESS ON *.* through r2"}


def test_what_public_holds_every_account_holds() -> None:
    """PUBLIC, and a role granted to it, give their privileges to every
    account, always active (RR3)."""
    cursor = _Cursor(
        global_row={PUBLIC_KEY: _flags("Process_priv")},
        schema={PUBLIC_KEY: [_db_row("Insert_priv")]},
        edges={PUBLIC_KEY: [("r3", "")]},
        tables={("r3", ""): [("proxies_priv", "Select")]},
    )

    assert global_privileges(cursor, APP) == {
        "PROCESS ON *.* through PUBLIC",
        "INSERT ON mysql.* through PUBLIC",
        "SELECT ON mysql.proxies_priv through r3",
    }


def test_a_schema_pattern_is_named_as_the_grant_names_it() -> None:
    cursor = _Cursor(schema={KEY: [_db_row("Select_priv", db="mysq%")]})

    assert global_privileges(cursor, APP) == {"SELECT ON `mysq%`.*"}


def test_the_host_is_read_in_lower_case() -> None:
    """MariaDB stores a host in lower case, and its grant tables compare it
    byte for byte (ID3)."""
    cursor = _Cursor(global_row={("acme_app", "app.example.com"): _flags("Super_priv")})
    upper = Principal("acme_app", "App.Example.COM")
    assert global_privileges(cursor, upper) == {"SUPER ON *.*"}


def test_a_role_that_holds_nothing_adds_nothing() -> None:
    cursor = _Cursor(edges={KEY: [("r1", "")]}, global_row={("r1", ""): _flags()})

    assert global_privileges(cursor, APP) == frozenset()
