"""sopuli-dba : what guardrail 9 reads about roles and PUBLIC on MariaDB

#1269. Check 9 refuses a managed account that holds, or can get through a role,
a global privilege, a privilege on the `mysql` schema, or a PROXY grant
(02-mariadb-privileges.md §5). This measures, on each server, the role reads
it makes, as a tool account with §2.1's grants, over PyMySQL from the host:

  RR1  an account granted the role r1, which is not its default role. r1 is
       granted r2, and holds SELECT on mysql.db; r2 holds PROCESS ON *.* and
       SELECT on mysql.columns_priv. As the tool account: the
       mysql.roles_mapping rows (Host, User, Role) whose User is the account,
       r1 or r2, and the view's User, Host, is_role and Process_priv for r1
       and r2
  RR2  as the account: SELECT on mysql.db before SET ROLE r1, and after it,
       and SELECT on mysql.columns_priv, r2's grant. Then SET ROLE r2,
       granted to r1 only
  RR3  PROCESS ON *.*, INSERT ON mysql.*, SELECT ON mysql.db and the role r3,
       each granted TO PUBLIC; r3 holds SELECT on mysql.proxies_priv. As the
       tool account: PUBLIC's rows in the view, mysql.db, mysql.tables_priv
       and roles_mapping. As a second account with no grant of its own:
       SELECT on mysql.db, SELECT on mysql.proxies_priv, and SET ROLE r3

A statement answers `ok`, or the error's number.

The probe checks each result against the one RESULTS below records. A
difference, or a step that fails, makes it exit 1.

It MEASURES and decides nothing.

STATUS: run on 10.11.19, 11.4.13, 11.8.9 and 12.3.3, the mariadb:10.11,
mariadb:11.4, mariadb:11.8 and mariadb:12.3 images of test/compose.yaml profile
mariadb-matrix, on 2026-11-04 (#1269), with PyMySQL 1.2.3 and Python 3.13.12
on Windows 11 AMD64. Twice, exit 0, and the same result both times.

RESULTS -- the same on every release

  RR1  roles_mapping holds (`%`, account, r1) and (``, r1, r2): a role's Host
       is empty, and a role granted to a role is a row whose User is the
       role. The view has r1 and r2 at Host ``, is_role `Y`, and Process_priv
       `Y` for r2 only
  RR2  before SET ROLE, 1142; after it, ok, and r2's grant is ok too.
       SET ROLE r2 is refused, 1959: an account activates only a role granted
       to it, and gets a nested role's privileges through the role that
       holds it
  RR3  PUBLIC is a row of the view at Host ``, is_role `Y`, with Process_priv
       `Y`. mysql.db holds (PUBLIC, ``, mysql) with Insert_priv `Y`,
       tables_priv holds (PUBLIC, ``, mysql, db), and roles_mapping holds
       (``, PUBLIC, r3). The second account reads mysql.db and
       mysql.proxies_priv with no SET ROLE, and SET ROLE r3 is refused, 1959.
       What PUBLIC holds, and what a role granted to PUBLIC holds, every
       account holds, always active

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mariadb/10_role_reads_probe.py

It needs PyMySQL in the environment that runs it, and 06 beside it, whose
ports it reads.

THROWAWAY SERVERS ONLY. It creates the accounts sopuli_probe_tool,
sopuli_probe_held and sopuli_probe_plain and the roles sopuli_probe_r1 to
sopuli_probe_r3, and grants to PUBLIC. It revokes PUBLIC's grants and drops
the rest at the end, also after a failed step, and drops leftovers of an
interrupted run first.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pymysql

# 06's name starts with a digit, so it is loaded by its path. It loads 02.
_SPEC = importlib.util.spec_from_file_location(
    "mariadb_pymysql_login_probe", Path(__file__).with_name("06_pymysql_login_probe.py")
)
assert _SPEC is not None
assert _SPEC.loader is not None
pl = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(pl)
ch = pl.ch

TOOL, HELD, PLAIN = "sopuli_probe_tool", "sopuli_probe_held", "sopuli_probe_plain"
R1, R2, R3 = "sopuli_probe_r1", "sopuli_probe_r2", "sopuli_probe_r3"
PASSWORD = "Acme-Roles-pw1"

#: §2.1's grants, as test/mariadb-init/01_tool_account.sql makes them.
VIEW_COLUMNS = "User, Host, plugin, password_expired, is_role, Process_priv"
TOOL_GRANTS = (
    f"GRANT CREATE USER ON *.* TO {TOOL}",
    f"GRANT SELECT ({VIEW_COLUMNS}) ON mysql.user TO {TOOL}",
    *(
        f"GRANT SELECT ON mysql.{table} TO {TOOL}"
        for table in ("roles_mapping", "db", "tables_priv", "columns_priv", "procs_priv")
    ),
)


def connect(service: str, user: str, password: str) -> Any:
    try:
        return pymysql.connect(
            host="127.0.0.1",
            port=pl.PORTS[service],
            user=user,
            password=password,
            ssl_disabled=True,
            autocommit=True,
            connect_timeout=10,
        )
    except pymysql.err.MySQLError as exc:
        raise ch.StepError(f"{service}: login as {user}: {exc}") from exc


def run(cursor: Any, statement: str, args: tuple[str, ...] = ()) -> str:
    """`ok`, or the error's number."""
    try:
        cursor.execute(statement, args or None)
    except pymysql.err.MySQLError as exc:
        return str(exc.args[0])
    return ch.OK


def rows(cursor: Any, statement: str, args: tuple[str, ...] = ()) -> tuple[tuple[str, ...], ...]:
    try:
        cursor.execute(statement, args or None)
    except pymysql.err.MySQLError as exc:
        raise ch.StepError(f"{statement[:60]}: {exc}") from exc
    return tuple(tuple(str(value) for value in row) for row in cursor.fetchall())


def clean(service: str) -> None:
    with connect(service, "root", ch.ROOT_PASSWORD) as root, root.cursor() as cursor:
        for statement in (
            "REVOKE PROCESS ON *.* FROM PUBLIC",
            "REVOKE INSERT ON mysql.* FROM PUBLIC",
            "REVOKE SELECT ON mysql.db FROM PUBLIC",
        ):
            run(cursor, statement)
        for name in (R1, R2, R3):
            run(cursor, f"DROP ROLE IF EXISTS {name}")
        for name in (TOOL, HELD, PLAIN):
            run(cursor, f"DROP USER IF EXISTS '{name}'@'%'")


def probe(service: str) -> None:
    clean(service)
    try:
        cases(service)
    finally:
        clean(service)


def cases(service: str) -> None:
    with connect(service, "root", ch.ROOT_PASSWORD) as root, root.cursor() as cursor:
        print(f"\n== {service}: {rows(cursor, 'SELECT VERSION()')[0][0]}")
        for name in (TOOL, HELD, PLAIN):
            # `%%`: the statement has a parameter, so PyMySQL formats it.
            rows(cursor, f"CREATE USER '{name}'@'%%' IDENTIFIED BY %s", (PASSWORD,))
        for statement in (
            *TOOL_GRANTS,
            f"CREATE ROLE {R1}",
            f"CREATE ROLE {R2}",
            f"CREATE ROLE {R3}",
            f"GRANT PROCESS ON *.* TO {R2}",
            f"GRANT SELECT ON mysql.columns_priv TO {R2}",
            f"GRANT {R2} TO {R1}",
            f"GRANT SELECT ON mysql.db TO {R1}",
            f"GRANT {R1} TO '{HELD}'@'%'",
        ):
            rows(cursor, statement)

    with connect(service, TOOL, PASSWORD) as tool, tool.cursor() as cursor:
        mapping = rows(
            cursor,
            "SELECT Host, User, Role FROM mysql.roles_mapping WHERE User IN (%s, %s, %s) "
            "ORDER BY User",
            (HELD, R1, R2),
        )
        view = rows(
            cursor,
            "SELECT User, Host, is_role, Process_priv FROM mysql.user WHERE User IN (%s, %s) "
            "ORDER BY User",
            (R1, R2),
        )
    print(f"RR1 roles_mapping: {mapping}; view: {view}")
    ch.check(
        "RR1",
        (mapping, view),
        (
            (("%", HELD, R1), ("", R1, R2)),
            ((R1, "", "Y", "N"), (R2, "", "Y", "Y")),
        ),
    )

    with connect(service, HELD, PASSWORD) as held, held.cursor() as cursor:
        before = run(cursor, "SELECT COUNT(*) FROM mysql.db")
        set_r1 = run(cursor, f"SET ROLE {R1}")
        after = run(cursor, "SELECT COUNT(*) FROM mysql.db")
        nested = run(cursor, "SELECT COUNT(*) FROM mysql.columns_priv")
        set_r2 = run(cursor, f"SET ROLE {R2}")
    print(
        f"RR2 before SET ROLE: {before}; SET ROLE r1: {set_r1}; after: {after}; "
        f"r2's grant: {nested}; SET ROLE r2: {set_r2}"
    )
    ch.check("RR2", (before, set_r1, after, nested, set_r2), ("1142", ch.OK, ch.OK, ch.OK, "1959"))

    with connect(service, "root", ch.ROOT_PASSWORD) as root, root.cursor() as cursor:
        for statement in (
            "GRANT PROCESS ON *.* TO PUBLIC",
            "GRANT INSERT ON mysql.* TO PUBLIC",
            "GRANT SELECT ON mysql.db TO PUBLIC",
            f"GRANT SELECT ON mysql.proxies_priv TO {R3}",
            f"GRANT {R3} TO PUBLIC",
        ):
            rows(cursor, statement)
    with connect(service, TOOL, PASSWORD) as tool, tool.cursor() as cursor:
        public = rows(
            cursor,
            "SELECT User, Host, is_role, Process_priv FROM mysql.user WHERE User = 'PUBLIC'",
        )
        schema = rows(
            cursor, "SELECT User, Host, Db, Insert_priv FROM mysql.db WHERE User = 'PUBLIC'"
        )
        table = rows(
            cursor,
            "SELECT User, Host, Db, Table_name FROM mysql.tables_priv WHERE User = 'PUBLIC'",
        )
        mapping = rows(
            cursor, "SELECT Host, User, Role FROM mysql.roles_mapping WHERE User = 'PUBLIC'"
        )
    with connect(service, PLAIN, PASSWORD) as plain, plain.cursor() as cursor:
        own = run(cursor, "SELECT COUNT(*) FROM mysql.db")
        through_role = run(cursor, "SELECT COUNT(*) FROM mysql.proxies_priv")
        set_r3 = run(cursor, f"SET ROLE {R3}")
    print(
        f"RR3 view: {public}; db: {schema}; tables_priv: {table}; roles_mapping: {mapping}; "
        f"PUBLIC's grant: {own}; r3's grant: {through_role}; SET ROLE r3: {set_r3}"
    )
    ch.check(
        "RR3",
        (public, schema, table, mapping, own, through_role, set_r3),
        (
            (("PUBLIC", "", "Y", "Y"),),
            (("PUBLIC", "", "mysql", "Y"),),
            (("PUBLIC", "", "mysql", "db"),),
            (("", "PUBLIC", R3),),
            ch.OK,
            ch.OK,
            "1959",
        ),
    )


def main() -> int:
    ch.base.SERVICES = tuple(pl.PORTS)
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
