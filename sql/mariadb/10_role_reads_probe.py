"""sopuli-dba : what guardrail 9 reads about roles and PUBLIC on MariaDB

#1269. Check 9 refuses a managed account that holds, or can get through a role,
a global privilege, a privilege on the `mysql` schema, or a PROXY grant
(02-mariadb-privileges.md §5). This measures, on each server, how roles and
PUBLIC give privileges, and that a tool account reads each of them, over
PyMySQL from the host. The tool account gets the GRANT statements of
test/mariadb-init/01_tool_account.sql, read from that file, so it holds what
the tier-1 tool account holds.

  RR1  an account granted the role r1, which is not its default role. r1 is
       granted r2, and holds SELECT on mysql.db; r2 holds PROCESS ON *.* and
       SELECT on mysql.columns_priv. As the tool account: the
       mysql.roles_mapping rows (Host, User, Role) whose User is the account,
       r1 or r2, and the view's User, Host, is_role and Process_priv for r1
       and r2
  RR2  as the account: SELECT on mysql.db and on mysql.columns_priv, before
       SET ROLE r1 and after it. Then SET ROLE r2, granted to r1 only
  RR3  as a second account with no grant of its own, before any grant to
       PUBLIC: SELECT on mysql.db, SELECT on sopuli_probe_db.t, and the number
       of root's sessions in information_schema.PROCESSLIST, while root holds
       one open. Then, TO PUBLIC: PROCESS ON *.*, SELECT ON mysql.*, SELECT
       (User) ON mysql.user, EXECUTE ON PROCEDURE mysql.AddGeometryColumn, and
       the role r3, which holds SELECT on sopuli_probe_db.t; and PROXY ON
       root@localhost. As the tool account: PUBLIC's rows in the view,
       mysql.db, columns_priv, procs_priv, proxies_priv and roles_mapping. As
       the second account, the same three reads again, and SET ROLE r3

A statement answers `ok`, or the error's number. A count is the number.

The probe checks each result against the one RESULTS below records. A
difference, or a step that fails, makes it exit 1.

It MEASURES and decides nothing.

STATUS: run on 10.11.19, 11.4.13, 11.8.9 and 12.3.3, the mariadb:10.11,
mariadb:11.4, mariadb:11.8 and mariadb:12.3 images of test/compose.yaml profile
mariadb-matrix, on 2026-11-04 (#1269), with PyMySQL 1.2.3 and Python 3.13.12
on Windows 11 AMD64. Twice, exit 0, and the same result both times.

RESULTS -- the same on every release

  RR1  roles_mapping holds (`%`, account, r1) and (empty, r1, r2): a role's
       Host is empty, and a role granted to a role is a row whose User is the
       role. The view has r1 and r2 at an empty Host, is_role `Y`, and
       Process_priv `Y` for r2 only
  RR2  before SET ROLE, both reads are refused, 1142; after it, both are ok.
       SET ROLE r2 is refused, 1959: an account activates only a role granted
       to it, and gets a nested role's privileges through the role that
       holds it
  RR3  before the grants: 1142, 1142, and 0 of root's sessions. PROXY to
       PUBLIC is refused, 1133; the other grants are ok. PUBLIC is a row of
       the view at an empty Host, is_role `Y`, with Process_priv `Y`; it has a
       row in mysql.db, columns_priv, procs_priv and roles_mapping, and none in
       proxies_priv. After the grants the second account reads mysql.db and
       sopuli_probe_db.t, and sees root's session, with no SET ROLE; SET ROLE
       r3 is refused, 1959. What PUBLIC holds, and what a role granted to
       PUBLIC holds, every account holds, always active

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mariadb/10_role_reads_probe.py

It needs PyMySQL in the environment that runs it, 06 beside it, whose ports it
reads, and test/mariadb-init/01_tool_account.sql.

THROWAWAY SERVERS ONLY. It creates the accounts sopuli_probe_tool,
sopuli_probe_held and sopuli_probe_plain, the roles sopuli_probe_r1 to
sopuli_probe_r3 and the schema sopuli_probe_db, and grants to PUBLIC. It
revokes PUBLIC's grants and drops the rest at the end, also after a failed
step, and first does the same for what an interrupted run left. It then checks
that PUBLIC holds nothing, and fails the step if it does.
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
SCHEMA = "sopuli_probe_db"
PASSWORD = "Acme-Roles-pw1"
INIT = Path(__file__).resolve().parents[2] / "test" / "mariadb-init" / "01_tool_account.sql"

#: What the probe grants PUBLIC, and revokes at the end.
PUBLIC_GRANTS = (
    "PROCESS ON *.*",
    "SELECT ON mysql.*",
    "SELECT (User) ON mysql.user",
    "EXECUTE ON PROCEDURE mysql.AddGeometryColumn",
    R3,
)


#: What the tool account reads of PUBLIC's rows: the columns, and the table.
PUBLIC_READS = (
    ("User, Host, is_role, Process_priv", "user"),
    ("Db, Select_priv", "db"),
    ("Table_name, Column_name", "columns_priv"),
    ("Routine_name", "procs_priv"),
    ("Proxied_user", "proxies_priv"),
    ("Host, Role", "roles_mapping"),
)


def tool_grants() -> tuple[str, ...]:
    """The init script's GRANT statements, to the probe's tool account."""
    lines = [line for line in INIT.read_text("utf-8").splitlines() if not line.startswith("--")]
    statements = (" ".join(part.split()) for part in "\n".join(lines).split(";"))
    return tuple(
        statement.replace("'sopuli_admin'@'%'", f"'{TOOL}'@'%'")
        for statement in statements
        if statement.startswith("GRANT ")
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
    """Revoke PUBLIC's grants and drop the rest. A revoke of a grant PUBLIC
    does not hold is refused, so each answer is ignored, and PUBLIC is then
    checked to hold nothing."""
    with connect(service, "root", ch.ROOT_PASSWORD) as root, root.cursor() as cursor:
        for grant in PUBLIC_GRANTS:
            run(cursor, f"REVOKE {grant} FROM PUBLIC")
        for name in (R1, R2, R3):
            run(cursor, f"DROP ROLE IF EXISTS {name}")
        for name in (TOOL, HELD, PLAIN):
            run(cursor, f"DROP USER IF EXISTS '{name}'@'%'")
        run(cursor, f"DROP DATABASE IF EXISTS {SCHEMA}")
        left = rows(cursor, "SHOW GRANTS FOR PUBLIC")
    if left:
        raise ch.StepError(f"{service}: PUBLIC still holds {left}")


def probe(service: str) -> None:
    clean(service)
    ch.cleaned(service, lambda: cases(service), lambda: clean(service))


def plain_reads(service: str) -> tuple[str, str, str]:
    """As the account with no grant: mysql.db, the probe's table, and how many
    of root's sessions it sees. ``root`` holds one open meanwhile."""
    with (
        connect(service, "root", ch.ROOT_PASSWORD),
        connect(service, PLAIN, PASSWORD) as plain,
        plain.cursor() as cursor,
    ):
        schema = run(cursor, "SELECT COUNT(*) FROM mysql.db")
        table = run(cursor, f"SELECT COUNT(*) FROM {SCHEMA}.t")
        seen = rows(
            cursor, "SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE USER = 'root'"
        )
    return schema, table, seen[0][0]


def cases(service: str) -> None:
    with connect(service, "root", ch.ROOT_PASSWORD) as root, root.cursor() as cursor:
        print(f"\n== {service}: {rows(cursor, 'SELECT VERSION()')[0][0]}")
        for name in (TOOL, HELD, PLAIN):
            # `%%`: the statement has a parameter, so PyMySQL formats it.
            rows(cursor, f"CREATE USER '{name}'@'%%' IDENTIFIED BY %s", (PASSWORD,))
        for statement in (
            *tool_grants(),
            f"CREATE DATABASE {SCHEMA}",
            f"CREATE TABLE {SCHEMA}.t (n int)",
            f"CREATE ROLE {R1}",
            f"CREATE ROLE {R2}",
            f"CREATE ROLE {R3}",
            f"GRANT PROCESS ON *.* TO {R2}",
            f"GRANT SELECT ON mysql.columns_priv TO {R2}",
            f"GRANT {R2} TO {R1}",
            f"GRANT SELECT ON mysql.db TO {R1}",
            f"GRANT {R1} TO '{HELD}'@'%'",
            f"GRANT SELECT ON {SCHEMA}.t TO {R3}",
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
        before = (
            run(cursor, "SELECT COUNT(*) FROM mysql.db"),
            run(cursor, "SELECT COUNT(*) FROM mysql.columns_priv"),
        )
        set_r1 = run(cursor, f"SET ROLE {R1}")
        after = (
            run(cursor, "SELECT COUNT(*) FROM mysql.db"),
            run(cursor, "SELECT COUNT(*) FROM mysql.columns_priv"),
        )
        set_r2 = run(cursor, f"SET ROLE {R2}")
    print(
        f"RR2 before SET ROLE: {before}; SET ROLE r1: {set_r1}; after: {after}; "
        f"SET ROLE r2: {set_r2}"
    )
    ch.check(
        "RR2",
        (before, set_r1, after, set_r2),
        (("1142", "1142"), ch.OK, (ch.OK, ch.OK), "1959"),
    )

    unset = plain_reads(service)
    with connect(service, "root", ch.ROOT_PASSWORD) as root, root.cursor() as cursor:
        granted = tuple(run(cursor, f"GRANT {grant} TO PUBLIC") for grant in PUBLIC_GRANTS)
        proxy = run(cursor, "GRANT PROXY ON 'root'@'localhost' TO PUBLIC")
    with connect(service, TOOL, PASSWORD) as tool, tool.cursor() as cursor:
        public = tuple(
            rows(cursor, f"SELECT {columns} FROM mysql.{table} WHERE User = 'PUBLIC'")
            for columns, table in PUBLIC_READS
        )
    granted_reads = plain_reads(service)
    with connect(service, PLAIN, PASSWORD) as plain, plain.cursor() as cursor:
        set_r3 = run(cursor, f"SET ROLE {R3}")
    print(
        f"RR3 before: {unset}; grants: {granted}; PROXY: {proxy}; as the tool: {public}; "
        f"after: {granted_reads}; SET ROLE r3: {set_r3}"
    )
    ch.check(
        "RR3",
        (unset, granted, proxy, public, granted_reads, set_r3),
        (
            ("1142", "1142", "0"),
            (ch.OK,) * len(PUBLIC_GRANTS),
            "1133",
            (
                (("PUBLIC", "", "Y", "Y"),),
                (("mysql", "Y"),),
                (("user", "User"),),
                (("AddGeometryColumn",),),
                (),
                (("", R3),),
            ),
            (ch.OK, ch.OK, "1"),
            "1959",
        ),
    )


def main() -> int:
    ch.base.SERVICES = tuple(pl.PORTS)
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
