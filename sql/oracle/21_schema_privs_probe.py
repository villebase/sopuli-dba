"""sopuli-dba : what DBA_SCHEMA_PRIVS holds, and who can read it   (v1)

#1389. 23ai grants a system privilege on one schema, such as ``GRANT SELECT
ANY TABLE ON SCHEMA acme_sp_owner TO acme_sp_app``. UC-5's privilege survey
(driver/oracle/grants.py) reads DBA_SYS_PRIVS, DBA_TAB_PRIVS and
DBA_COL_PRIVS. This measures where a schema privilege shows instead:

  SP0  as SYSTEM: the columns of SYS.DBA_SCHEMA_PRIVS, and which of the views
       USER_SCHEMA_PRIVS, ROLE_SCHEMA_PRIVS and SESSION_SCHEMA_PRIVS exist
  SP1  as SYSTEM: fixtures. ACME_SP_OWNER and ACME_SP_OTHER own a table each.
       ACME_SP_APP holds SELECT ANY TABLE on ACME_SP_OWNER directly, and
       UPDATE ANY TABLE on it WITH ADMIN OPTION. ACME_SP_READ holds EXECUTE
       ANY PROCEDURE on ACME_SP_OTHER; ACME_SP_OUTER holds ACME_SP_READ, and
       ACME_SP_APP holds ACME_SP_OUTER as a default role. Then a schema
       privilege on ACME_SP_OTHER to PUBLIC, and what Oracle answers
  SP2  as SYSTEM: every DBA_SCHEMA_PRIVS row for the fixtures and PUBLIC; and
       whether any of those privileges also shows in DBA_SYS_PRIVS or
       DBA_TAB_PRIVS for the same grantee
  SP3  ACME_SP_SVC installed by 00_install.sql in PDB mode with
       grant_report_reads=Y: as ACME_SP_SVC, a COUNT(*) from DBA_SCHEMA_PRIVS
       and from the three views the survey reads
  SP4  as SYSDBA: SELECT on SYS.DBA_SCHEMA_PRIVS to ACME_SP_SVC; then as
       ACME_SP_SVC, the survey's recursive WITH from ACME_SP_APP and PUBLIC,
       joined to DBA_SCHEMA_PRIVS, with the role path
  SP5  drops the fixtures, and ACME_SP_SVC with 99_uninstall.sql

It MEASURES and decides nothing. No statement reads a password or verifier
column. ACME_SP_SVC's password is drawn at random by the probe, set with ALTER
USER as SYSTEM, and never printed.

STATUS: run on 26ai Free 23.26.3.0.0 (gvenzl/oracle-free:latest), with Instant
Client 23.26.3.0.0 for Windows and python-oracledb in thick mode, 2026-11-08.
Run three times. The first stopped at SP4, because SYSTEM cannot grant SELECT
on a SYS view (ORA-01031), so SP4 now grants as SYSDBA. The other two printed
the same results.

RESULTS -- 26ai Free 23.26.3.0.0

  SP0  DBA_SCHEMA_PRIVS has GRANTEE VARCHAR2(128), PRIVILEGE VARCHAR2(40),
       SCHEMA VARCHAR2(128), ADMIN_OPTION, COMMON and INHERITED, each
       VARCHAR2(3). USER_SCHEMA_PRIVS, ROLE_SCHEMA_PRIVS and
       SESSION_SCHEMA_PRIVS exist
  SP1  a schema privilege can be granted to PUBLIC
  SP2  one row per grantee, privilege and schema: ACME_SP_APP's two, with
       ADMIN_OPTION YES for the one granted WITH ADMIN OPTION; ACME_SP_READ's
       one, under the role, not under the account that holds the role; and
       PUBLIC's. COMMON and INHERITED are NO in each. None of the four shows
       in DBA_SYS_PRIVS or DBA_TAB_PRIVS
  SP3  ACME_SP_SVC with grant_report_reads=Y gets ORA-00942 from
       DBA_SCHEMA_PRIVS, and reads DBA_SYS_PRIVS, DBA_TAB_PRIVS and
       DBA_COL_PRIVS
  SP4  with SELECT on it granted, the survey's recursive WITH joined to
       DBA_SCHEMA_PRIVS gives ACME_SP_APP's two direct rows, the role's row
       with the path ACME_SP_OUTER > ACME_SP_READ and DEFAULT_ROLE YES, and
       PUBLIC's row, read from PUBLIC

  Not measured: a release before 23ai, where the view is expected to be
  missing (ORA-00942, which SP3 shows a missing grant also gives); a common
  grant (COMMON = YES) from CDB$ROOT.

HOW TO RUN (from the repo root, against the tier-1 stack):

    python sql/oracle/21_schema_privs_probe.py

It connects as SYSTEM to FREEPDB1 at 127.0.0.1 and SOPULI_TEST_ORACLE_PORT,
with tier 1's public password from test/compose.yaml, and runs 00_install.sql
and 99_uninstall.sql as SYSDBA through SQL*Plus inside the container, with the
SQL on stdin. The container follows COMPOSE_PROJECT_NAME or
SOPULI_TEST_ORACLE_CONTAINER, as probe 14's does. Against any other database,
copy the file, edit the constants in the copy, run the copy and delete it, as
07 prescribes. It first drops every ACME_SP account and role an earlier run
left.

THROWAWAY DATABASES ONLY.
"""

from __future__ import annotations

import os
import secrets
import subprocess
from pathlib import Path

import oracledb

from sopuli.driver.oracle import session as oracle_session

CONTAINER = os.environ.get(
    "SOPULI_TEST_ORACLE_CONTAINER",
    f"{os.environ.get('COMPOSE_PROJECT_NAME', 'sopuli-test')}-oracle-free-1",
)
PORT = os.environ.get("SOPULI_TEST_ORACLE_PORT", "1521")
DSN = f"127.0.0.1:{PORT}/FREEPDB1"
PDB = "FREEPDB1"
USER = "system"
PASSWORD = "sopuli-test"
SVC = "ACME_SP_SVC"
SCRIPTS = Path(__file__).resolve().parent
IN_CONTAINER = "/tmp/sopuli-probe-21"

#: The survey's recursive WITH (grants._ROLES), joined to DBA_SCHEMA_PRIVS.
SCHEMA_PRIVS_QUERY = (
    "with roles (grantee, granted_role, path, first_default) as ("
    "select grantee, granted_role, cast(granted_role as varchar2(4000)), default_role "
    "from dba_role_privs where grantee in (:g0, :g1) "
    "union all "
    "select r.grantee, p.granted_role, r.path || ' > ' || p.granted_role, r.first_default "
    "from dba_role_privs p join roles r on p.grantee = r.granted_role"
    ") cycle granted_role set is_cycle to 'Y' default 'N' "
    "select s.grantee, cast(null as varchar2(4000)), cast(null as varchar2(3)), "
    "s.privilege, s.schema, s.admin_option "
    "from dba_schema_privs s where s.grantee in (:g0, :g1) "
    "union all "
    "select r.grantee, r.path, r.first_default, s.privilege, s.schema, s.admin_option "
    "from roles r join dba_schema_privs s on s.grantee = r.granted_role "
    "where r.is_cycle = 'N' "
    "order by 1, 5, 4, 2 nulls first"
)


def dba(sql: str) -> str:
    """Run SQL as SYSDBA in the PDB, inside the container. The SQL goes on stdin."""
    result = subprocess.run(
        ["docker", "exec", "-i", CONTAINER, "sqlplus", "-S", "/ as sysdba"],
        input=f"whenever sqlerror exit failure\nalter session set container = {PDB};\n"
        f"{sql}\nexit\n".encode(),
        capture_output=True,
        check=False,
    )
    output = result.stdout.decode("utf-8", "replace")
    if result.returncode != 0:
        raise SystemExit(f"DBA step failed, so nothing after it is a measurement:\n{output}")
    return output


def copy_scripts() -> None:
    subprocess.run(["docker", "exec", CONTAINER, "mkdir", "-p", IN_CONTAINER], check=True)
    for name in ("00_install.sql", "99_uninstall.sql"):
        subprocess.run(
            ["docker", "cp", str(SCRIPTS / name), f"{CONTAINER}:{IN_CONTAINER}/{name}"],
            check=True,
        )


def code(error: oracledb.Error) -> str:
    detail = error.args[0] if error.args else None
    return str(getattr(detail, "full_code", error))


def attempt(cursor: oracledb.Cursor, sql: str) -> str:
    try:
        cursor.execute(sql)
        return "succeeded"
    except oracledb.Error as error:
        return code(error)


def rows(cursor: oracledb.Cursor, sql: str, binds: dict[str, str] | None = None) -> list:
    cursor.execute(sql, binds or {})
    return cursor.fetchall()


def drop(cursor: oracledb.Cursor) -> None:
    for (name,) in rows(
        cursor, "select username from dba_users where username like 'ACME\\_SP\\_%' escape '\\'"
    ):
        if name == SVC:
            dba(f"@{IN_CONTAINER}/99_uninstall.sql {SVC} N")
        else:
            cursor.execute(f"drop user {name} cascade")
    for (role,) in rows(
        cursor, "select role from dba_roles where role like 'ACME\\_SP\\_%' escape '\\'"
    ):
        cursor.execute(f"drop role {role}")
    for privilege, schema in rows(
        cursor,
        "select privilege, schema from dba_schema_privs where grantee = 'PUBLIC' "
        "and schema like 'ACME\\_SP\\_%' escape '\\'",
    ):
        cursor.execute(f"revoke {privilege} on schema {schema} from public")


def sp0(cursor: oracledb.Cursor) -> None:
    print("SP0  DBA_SCHEMA_PRIVS columns:")
    for name, data_type, length in rows(
        cursor,
        "select column_name, data_type, data_length from all_tab_columns "
        "where owner = 'SYS' and table_name = 'DBA_SCHEMA_PRIVS' order by column_id",
    ):
        print(f"       {name} {data_type}({length})")
    views = rows(
        cursor,
        "select view_name from all_views where owner = 'SYS' and view_name in "
        "('USER_SCHEMA_PRIVS', 'ROLE_SCHEMA_PRIVS', 'SESSION_SCHEMA_PRIVS') order by 1",
    )
    print(f"     views present: {', '.join(name for (name,) in views) or 'none'}")


def sp1(cursor: oracledb.Cursor) -> None:
    run = cursor.execute
    for owner in ("ACME_SP_OWNER", "ACME_SP_OTHER"):
        run(f"create user {owner} no authentication quota 10m on users")
        run(f"create table {owner}.t1 (n number)")
    run("create user ACME_SP_APP no authentication")
    run("grant create session to ACME_SP_APP")
    run("grant select any table on schema ACME_SP_OWNER to ACME_SP_APP")
    run("grant update any table on schema ACME_SP_OWNER to ACME_SP_APP with admin option")
    run("create role ACME_SP_READ")
    run("create role ACME_SP_OUTER")
    run("grant execute any procedure on schema ACME_SP_OTHER to ACME_SP_READ")
    run("grant ACME_SP_READ to ACME_SP_OUTER")
    run("grant ACME_SP_OUTER to ACME_SP_APP")
    answer = attempt(cursor, "grant select any table on schema ACME_SP_OTHER to public")
    print(f"SP1  fixtures made; a schema privilege to PUBLIC: {answer}")


def sp2(cursor: oracledb.Cursor) -> None:
    print("SP2  DBA_SCHEMA_PRIVS rows, every column:")
    for row in rows(
        cursor,
        "select * from dba_schema_privs where grantee like 'ACME\\_SP\\_%' escape '\\' "
        "or (grantee = 'PUBLIC' and schema like 'ACME\\_SP\\_%' escape '\\') "
        "order by grantee, schema, privilege",
    ):
        print(f"       {row}")
    for view in ("DBA_SYS_PRIVS", "DBA_TAB_PRIVS"):
        found = rows(
            cursor,
            f"select grantee, privilege from {view} where grantee like 'ACME\\_SP\\_%' escape '\\' "
            "and privilege like '% ANY %' order by 1, 2",
        )
        print(f"     the same privileges in {view}: {found or 'none'}")


def sp3(cursor: oracledb.Cursor) -> str:
    dba(f"@{IN_CONTAINER}/00_install.sql PDB {SVC} USERS N N N N Y")
    password = "Sp" + secrets.token_hex(12) + "a1"
    cursor.execute(f'alter user {SVC} identified by "{password}"')
    print("SP3  as ACME_SP_SVC, installed with grant_report_reads=Y:")
    with oracledb.connect(user=SVC, password=password, dsn=DSN) as connection:
        svc = connection.cursor()
        for view in ("DBA_SCHEMA_PRIVS", "DBA_SYS_PRIVS", "DBA_TAB_PRIVS", "DBA_COL_PRIVS"):
            try:
                (count,) = rows(svc, f"select count(*) from {view}")[0]
                print(f"       {view}: {count} rows")
            except oracledb.Error as error:
                print(f"       {view}: {code(error)}")
    return password


def sp4(cursor: oracledb.Cursor, password: str) -> None:
    # As SYSDBA: SYSTEM holds no grant option on SYS's views (ORA-01031).
    dba(f"grant select on sys.dba_schema_privs to {SVC};")
    print("SP4  as ACME_SP_SVC after GRANT SELECT ON SYS.DBA_SCHEMA_PRIVS, the recursive read:")
    print("       (grantee, path, first_default, privilege, schema, admin_option)")
    with oracledb.connect(user=SVC, password=password, dsn=DSN) as connection:
        binds = {"g0": "ACME_SP_APP", "g1": "PUBLIC"}
        for row in rows(connection.cursor(), SCHEMA_PRIVS_QUERY, binds):
            print(f"       {row}")


def main() -> None:
    oracle_session.initialise(env=os.environ)
    copy_scripts()
    with oracledb.connect(user=USER, password=PASSWORD, dsn=DSN) as connection:
        cursor = connection.cursor()
        (release,) = rows(cursor, "select version_full from v$instance")[0]
        print(f"release {release}")
        drop(cursor)
        try:
            sp0(cursor)
            sp1(cursor)
            sp2(cursor)
            password = sp3(cursor)
            sp4(cursor, password)
        finally:
            drop(cursor)
            print("SP5  fixtures dropped")


if __name__ == "__main__":
    main()
