"""sopuli-dba : what the UC-5 report commands can read on MySQL

#1448. The `report` commands read every account on a target (UC-5 §2). The
tool account holds the grants of 02-mysql-privileges.md §2.1: CREATE USER, a
column grant on mysql.user, and SELECT on mysql.global_grants, db, tables_priv,
columns_priv, procs_priv, proxies_priv and role_edges. This measures, on each
server, as that account unless a step says otherwise:

  RE0  what one account is: the rows the tool account reads from mysql.user
       for one user name at three hosts, and for three roles, one of which
       no account holds. Then which columns of mysql.user it is refused, and
       whether SHOW CREATE USER for another account answers
  RE1  the settings: account_locked, password_expired, password_lifetime and
       @@default_password_lifetime. Then FAILED_LOGIN_ATTEMPTS and
       PASSWORD_LOCK_TIME: what INFORMATION_SCHEMA.USER_ATTRIBUTES shows, and
       which column of mysql, performance_schema, information_schema or sys
       could hold them or a count of failed logins, as root lists the column
       names. Then the tool account's row for the account before and after
       three wrong passwords, which block it. Where the server has
       performance_schema.temporary_account_locks, its rows for the account,
       as root reads them, after one wrong password, after three and after
       ACCOUNT UNLOCK, and whether the tool account reads the table, with
       §2.1's grants and with SELECT on it added. Then a view that root
       creates, with SQL SECURITY DEFINER, over the two keys of
       User_attributes that hold the limit, and whether the tool account
       reads it when granted SELECT on it
  RE2  the roles: a recursive query over mysql.role_edges from each fixture
       account, with the path and WITH_ADMIN_OPTION. Then mysql.default_roles,
       with §2.1's grants and with SELECT on it added, and its columns. Then
       @@mandatory_roles and @@activate_all_roles_on_login. Then, for
       sopuli_probe_app@'%', the privileges the tool account reads through its
       roles, against the lines of root's SHOW GRANTS ... USING its role
  RE3  the privilege levels: for each of the global static, global dynamic,
       schema, table, column, routine and proxy grants of the fixture, the
       row the tool account reads. Then a partial revoke, with
       partial_revokes ON: what the tool account reads of the account, and
       what SHOW GRANTS FOR it answers the tool account. Then how many rows of
       information_schema's USER_PRIVILEGES, SCHEMA_PRIVILEGES,
       TABLE_PRIVILEGES and COLUMN_PRIVILEGES the tool account sees for the
       fixture accounts
  RE4  `report history`: password_last_changed before and after the tool
       account sets a password by hash, as the driver does, then after
       ACCOUNT LOCK, after PASSWORD EXPIRE, and after a change with RETAIN
       CURRENT PASSWORD. Each step waits over a second first
  RE5  the cost: after root adds 500 roles in chains of five and 1000
       tables, each granted to one role, the time of RE2's query over every
       account, and of the table grants every account reaches through its
       roles. Each query runs once untimed, then three times timed, by the
       server's clock in the tool account's session

The fixture, which root creates on each server:

  sopuli_probe_tool              the tool account, with §2.1's grants
  sopuli_probe_app@'%'           PASSWORD EXPIRE INTERVAL 90 DAY,
                                 FAILED_LOGIN_ATTEMPTS 3 PASSWORD_LOCK_TIME 1,
                                 the role sopuli_probe_mid as its default role,
                                 INSERT on t, UPDATE on column t.n, EXECUTE
                                 on p
  sopuli_probe_app@'192.0.2.%'   ACCOUNT LOCK, PASSWORD EXPIRE NEVER, the role
                                 sopuli_probe_top WITH ADMIN OPTION, and PROXY
                                 on sopuli_probe_old@'%'
  sopuli_probe_app@'localhost'   PASSWORD EXPIRE
  sopuli_probe_old@'%'           the server's default lifetime
  sopuli_probe_part@'%'          RE3 only: SELECT ON *.*, with SELECT on
                                 sopuli_probe.* revoked
  sopuli_probe_top               a role: PROCESS ON *.*, BACKUP_ADMIN
  sopuli_probe_mid               a role, granted sopuli_probe_top: SELECT ON
                                 sopuli_probe.*
  sopuli_probe_none              a role no account holds
  schema sopuli_probe, with table t and procedure p

It MEASURES and decides nothing. It reads no hash: SHOW CREATE USER, whose
text holds one, is tried by the tool account only for whether it answers.

STATUS: run on 8.0.46, 8.4.13 and 9.7.4, the mysql:8.0, mysql:8.4 and mysql:9
images of test/compose.yaml profile mysql-matrix, on 2026-11-11 (#1448), with
Python 3.13.12 on Windows 11 AMD64. Twice, exit 0, the same result both times
but for the dates and the timings, which are the ranges below.

RESULTS -- the same on every release, except where noted

  RE0  the tool account reads seven rows: sopuli_probe_app at %, 192.0.2.%
       and localhost, each with its own account_locked, password_expired and
       password_lifetime, and the three roles. Each role reads
       account_locked Y and password_expired Y, sopuli_probe_none as the
       others. Every row's plugin is caching_sha2_password.
       authentication_string, User_attributes and Password_reuse_history are
       refused, 1143 (42000). SHOW CREATE USER for sopuli_probe_app@'%' is
       refused, 1044 (42000)
  RE1  @@default_password_lifetime reads 0. password_lifetime reads 90 for
       INTERVAL 90 DAY, 0 for NEVER and NULL for the default.
       USER_ATTRIBUTES shows ATTRIBUTE NULL for each of the three accounts.
       No column of the four schemas holds an account's limit or failed
       logins on 8.0.46 and 8.4.13: the names found are
       host_cache.COUNT_HOST_BLOCKED_ERRORS, per host, and two of
       replication. Three wrong passwords answer 1045 (28000), 1045 (28000)
       and 3955 (HY000), the right one then 3955 (HY000), and the tool
       account's row is unchanged. 9.7.4 also has
       performance_schema.temporary_account_locks, with USER, HOST, LOCKED,
       FAILED_LOGIN_ATTEMPTS, REMAINING_LOGIN_ATTEMPTS, PASSWORD_LOCK_TIME,
       LOCKED_SINCE and LOCKED_UNTIL: after one wrong password NO, 3, 2, 1;
       after three YES, 3, 0, 1, with LOCKED_UNTIL a day after LOCKED_SINCE;
       after ACCOUNT UNLOCK NO, 3, 3, 1. Only sopuli_probe_app@'%', the
       account with a limit, has a row. The tool account is refused it,
       1142 (42000), and reads it with SELECT on it. The definer view gives
       the tool account attempts 3 and days 1 for sopuli_probe_app@'%', and
       NULL for the other two hosts
  RE2  four paths: app@% > mid, app@% > mid > top, app@192.0.2.% > top with
       admin_option Y, and mid > top. mysql.default_roles is refused, 1142
       (42000); with SELECT on it, it reads app@% -> mid. Its columns are
       HOST, USER, DEFAULT_ROLE_HOST and DEFAULT_ROLE_USER.
       @@mandatory_roles reads empty and @@activate_all_roles_on_login 0.
       The six privileges the tool account reads for app@'%' through its
       roles (BACKUP_ADMIN and PROCESS on *.*, SELECT on sopuli_probe.*,
       INSERT on t, UPDATE on t.n, EXECUTE on p) are each in root's SHOW
       GRANTS ... USING sopuli_probe_mid, and it shows no other privilege
  RE3  each grant reads from its table: Process_priv Y for top, BACKUP_ADMIN
       in global_grants, the schema grant in db, INSERT and the column's
       UPDATE in tables_priv, UPDATE on n in columns_priv, EXECUTE in
       procs_priv, and the PROXY grant in proxies_priv. The partial revoke
       reads Select_priv Y and no mysql.db row. SHOW GRANTS FOR another
       account or role is refused, 1142 (42000). The four information_schema
       views show the tool account no fixture row
  RE4  password_last_changed moves with the change by hash and with the
       change with RETAIN CURRENT PASSWORD; ACCOUNT LOCK and PASSWORD EXPIRE
       leave it
  RE5  513 accounts and roles: the role query gives 1517 rows in 0.005 to
       0.043 s, and the table grants reached 3012 rows in 0.012 to 0.119 s

  So the tool account reads each account's lock, expiry, lifetime and last
  change, and every privilege with its role path. It cannot read the
  failed-login limit, which is beside a retained hash in User_attributes, nor
  a partial revoke, nor the default role without SELECT on
  mysql.default_roles. A count of failed logins exists only on 9.7.4, behind
  a grant on its table.

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mysql/10_report_read_probe.py

It needs 02_client_hash_probe.py beside it. The container names follow
COMPOSE_PROJECT_NAME, so a second clone's matrix is the one it uses.

THROWAWAY SERVERS ONLY. It creates the accounts and roles above,
sopuli_probe_r0 to sopuli_probe_r499, and the schema sopuli_probe with 1000
tables, and drops them at the end. It turns partial_revokes on for RE3 and
puts it back. Before it starts, it drops what an interrupted run left.
"""

from __future__ import annotations

import importlib.util
import sys
import time
from pathlib import Path

# 02's name starts with a digit, so it is loaded by its path.
_SPEC = importlib.util.spec_from_file_location(
    "mysql_client_hash_probe", Path(__file__).with_name("02_client_hash_probe.py")
)
assert _SPEC is not None
assert _SPEC.loader is not None
ch = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ch)

TOOL = f"'{ch.TOOL}'@'%'"
SCHEMA = "sopuli_probe"
APP = "sopuli_probe_app"
#: A test password, not a credential.
PASSWORD = "Acme-Report-pw1"
ROLES = ("'sopuli_probe_top'@'%'", "'sopuli_probe_mid'@'%'", "'sopuli_probe_none'@'%'")
BULK_ROLES = 500
BULK_TABLES = 1000
CHAIN = 5
#: §2.1's column grant on mysql.user, as 02-mysql-privileges.md gives it.
STATE = (
    "User, Host, plugin, account_locked, password_expired, password_last_changed, password_lifetime"
)
PRIV_COLUMNS = (
    "Select_priv, Insert_priv, Update_priv, Delete_priv, Create_priv, Drop_priv, Reload_priv,"
    " Shutdown_priv, Process_priv, File_priv, Grant_priv, References_priv, Index_priv,"
    " Alter_priv, Show_db_priv, Super_priv, Create_tmp_table_priv, Lock_tables_priv,"
    " Execute_priv, Repl_slave_priv, Repl_client_priv, Create_view_priv, Show_view_priv,"
    " Create_routine_priv, Alter_routine_priv, Create_user_priv, Event_priv, Trigger_priv,"
    " Create_tablespace_priv, Create_role_priv, Drop_role_priv"
)
TABLES = (
    "global_grants",
    "db",
    "tables_priv",
    "columns_priv",
    "procs_priv",
    "proxies_priv",
    "role_edges",
)
TOOL_GRANTS = (
    f"GRANT CREATE USER ON *.* TO {TOOL}",
    f"GRANT SELECT ({STATE}, {PRIV_COLUMNS}) ON mysql.user TO {TOOL}",
    *(f"GRANT SELECT ON mysql.{table} TO {TOOL}" for table in TABLES),
)
FIXTURE_LIKE = "'sopuli\\_probe\\_%'"
#: The fixture's own names: not the bulk roles, not the tool account.
OWN = (
    f"User LIKE {FIXTURE_LIKE} AND User NOT LIKE 'sopuli\\_probe\\_r%'"
    " AND User <> 'sopuli_probe_tool'"
)
LOCKS = "performance_schema.temporary_account_locks"

#: RE2. Every role an account reaches, with the path, from the account itself
#: at depth 0. Role names hold no `>`, so the path is a string.
ROLE_PATHS = """
WITH RECURSIVE e (u, h, ru, rh, path, admin_option, depth) AS (
    SELECT User, Host, User, Host, CAST(CONCAT(User, '@', Host) AS CHAR(4000)), 'N', 0
      FROM mysql.user {where}
    UNION ALL
    SELECT e.u, e.h, r.FROM_USER, r.FROM_HOST,
           CONCAT(e.path, ' > ', r.FROM_USER, '@', r.FROM_HOST), r.WITH_ADMIN_OPTION,
           e.depth + 1
      FROM e JOIN mysql.role_edges r ON r.TO_USER = e.ru AND r.TO_HOST = e.rh
     WHERE e.depth < 20
)
"""
#: RE2. What an account reaches through its roles, one line per grant.
REACHED = """
SELECT DISTINCT CONCAT(g.PRIV, ' ON *.*') FROM e JOIN mysql.global_grants g
    ON g.USER = e.ru AND g.HOST = e.rh
UNION SELECT DISTINCT 'PROCESS ON *.*' FROM e JOIN mysql.user u
    ON u.User = e.ru AND u.Host = e.rh WHERE u.Process_priv = 'Y'
UNION SELECT DISTINCT CONCAT('SELECT ON ', d.Db, '.*') FROM e JOIN mysql.db d
    ON d.User = e.ru AND d.Host = e.rh WHERE d.Select_priv = 'Y'
UNION SELECT DISTINCT CONCAT(t.Table_priv, ' ON ', t.Db, '.', t.Table_name)
    FROM e JOIN mysql.tables_priv t ON t.User = e.ru AND t.Host = e.rh
    WHERE t.Table_priv <> ''
UNION SELECT DISTINCT CONCAT(c.Column_priv, ' (', c.Column_name, ') ON ', c.Db, '.',
    c.Table_name) FROM e JOIN mysql.columns_priv c ON c.User = e.ru AND c.Host = e.rh
UNION SELECT DISTINCT CONCAT(p.Proc_priv, ' ON ', p.Routine_type, ' ', p.Db, '.',
    p.Routine_name) FROM e JOIN mysql.procs_priv p ON p.User = e.ru AND p.Host = e.rh
ORDER BY 1
"""


def tool(service: str, statement: str) -> str:
    """What the tool account reads, or the refusal's code."""
    ok, out = ch.mysql(service, ch.TOOL, ch.TOOL_PASSWORD, statement)
    return str(out) if ok else str(ch.code(out))


def root(service: str, statement: str) -> str:
    return str(ch.root(service, statement))


def lines(text: str) -> list[str]:
    return [line.replace("\t", " | ") for line in text.splitlines() if line]


def clean(service: str) -> None:
    """Drop what this probe creates, whatever an earlier run left."""
    found = root(
        service,
        "SET SESSION group_concat_max_len = 1000000;"
        "SELECT GROUP_CONCAT(CONCAT(QUOTE(User), '@', QUOTE(Host))) FROM mysql.user"
        f" WHERE User LIKE {FIXTURE_LIKE}",
    )
    if found and found != "NULL":
        root(service, f"DROP USER {found}")
    root(service, f"DROP DATABASE IF EXISTS {SCHEMA}")


def setup(service: str) -> None:
    root(
        service,
        ";".join(
            [
                f"CREATE USER {TOOL} IDENTIFIED BY {ch.quote(ch.TOOL_PASSWORD)}",
                *TOOL_GRANTS,
                f"CREATE DATABASE {SCHEMA}",
                f"CREATE TABLE {SCHEMA}.t (n int)",
                f"CREATE PROCEDURE {SCHEMA}.p() SELECT 1",
                *(f"CREATE ROLE {role}" for role in ROLES),
                "GRANT PROCESS ON *.* TO 'sopuli_probe_top'@'%'",
                "GRANT BACKUP_ADMIN ON *.* TO 'sopuli_probe_top'@'%'",
                f"GRANT SELECT ON {SCHEMA}.* TO 'sopuli_probe_mid'@'%'",
                "GRANT 'sopuli_probe_top'@'%' TO 'sopuli_probe_mid'@'%'",
                f"CREATE USER '{APP}'@'%' IDENTIFIED BY {ch.quote(PASSWORD)}"
                " PASSWORD EXPIRE INTERVAL 90 DAY FAILED_LOGIN_ATTEMPTS 3 PASSWORD_LOCK_TIME 1",
                f"CREATE USER '{APP}'@'192.0.2.%' IDENTIFIED BY {ch.quote(PASSWORD)}"
                " PASSWORD EXPIRE NEVER ACCOUNT LOCK",
                f"CREATE USER '{APP}'@'localhost' IDENTIFIED BY {ch.quote(PASSWORD)}"
                " PASSWORD EXPIRE",
                f"CREATE USER 'sopuli_probe_old'@'%' IDENTIFIED BY {ch.quote(PASSWORD)}",
                f"GRANT 'sopuli_probe_mid'@'%' TO '{APP}'@'%'",
                f"SET DEFAULT ROLE 'sopuli_probe_mid'@'%' TO '{APP}'@'%'",
                f"GRANT 'sopuli_probe_top'@'%' TO '{APP}'@'192.0.2.%' WITH ADMIN OPTION",
                f"GRANT INSERT ON {SCHEMA}.t TO '{APP}'@'%'",
                f"GRANT UPDATE (n) ON {SCHEMA}.t TO '{APP}'@'%'",
                f"GRANT EXECUTE ON PROCEDURE {SCHEMA}.p TO '{APP}'@'%'",
            ]
        ),
    )
    # Only root@localhost holds PROXY WITH GRANT OPTION in the image, so this
    # grant goes over the socket.
    ok, out = ch.mysql(
        service,
        "root",
        ch.ROOT_PASSWORD,
        f"GRANT PROXY ON 'sopuli_probe_old'@'%' TO '{APP}'@'192.0.2.%'",
        "-hlocalhost",
    )
    if not ok:
        raise ch.StepError(f"{service}: GRANT PROXY: {out}")


def re0(service: str) -> None:
    rows = tool(service, f"SELECT {STATE} FROM mysql.user WHERE {OWN} ORDER BY User, Host")
    for row in lines(rows):
        print(f"  RE0  mysql.user: {row}")
    for column in ("authentication_string", "User_attributes", "Password_reuse_history"):
        answer = tool(service, f"SELECT {column} FROM mysql.user LIMIT 0")
        print(f"  RE0  mysql.user.{column}: {answer or 'read'}")
    # Only whether it answers: its text would hold the hash.
    ok, text = ch.mysql(service, ch.TOOL, ch.TOOL_PASSWORD, f"SHOW CREATE USER '{APP}'@'%'")
    print(f"  RE0  SHOW CREATE USER {APP}@'%': {'answers' if ok else ch.code(text)}")


def temporary_account_locks(service: str) -> str:
    """The table's rows for sopuli_probe_app as root reads them, or '' where there is none."""
    exists = root(
        service,
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'performance_schema'"
        " AND table_name = 'temporary_account_locks'",
    )
    if exists != "1":
        return ""
    columns = root(
        service,
        "SELECT GROUP_CONCAT(column_name ORDER BY ordinal_position) FROM information_schema.columns"
        " WHERE table_schema = 'performance_schema' AND table_name = 'temporary_account_locks'",
    )
    rows = root(service, f"SELECT * FROM {LOCKS} WHERE USER = '{APP}' ORDER BY HOST")
    return f"({columns}) " + ("; ".join(lines(rows)) or "no row")


def re1(service: str) -> None:
    lifetime = tool(service, "SELECT @@global.default_password_lifetime")
    print(f"  RE1  as the tool account, @@default_password_lifetime: {lifetime}")
    attributes = tool(
        service,
        "SELECT CONCAT(USER, '@', HOST, ' ', COALESCE(ATTRIBUTE, 'NULL'))"
        f" FROM INFORMATION_SCHEMA.USER_ATTRIBUTES WHERE USER = '{APP}' ORDER BY HOST",
    )
    for row in lines(attributes) or ["no row"]:
        print(f"  RE1  INFORMATION_SCHEMA.USER_ATTRIBUTES: {row}")
    columns = root(
        service,
        "SELECT GROUP_CONCAT(CONCAT(table_schema, '.', table_name, '.', column_name)"
        " ORDER BY 1 SEPARATOR ', ') FROM information_schema.columns"
        " WHERE table_schema IN ('mysql', 'performance_schema', 'information_schema', 'sys')"
        " AND column_name REGEXP 'fail|attempt|login|password_lock|blocked'",
    )
    print(f"  RE1  columns that could hold failed logins: {columns}")
    query = f"SELECT {STATE} FROM mysql.user WHERE User = '{APP}' AND Host = '%'"
    before = tool(service, query)
    answers = [ch.login(service, ch.WRONG, APP)]
    after_one = temporary_account_locks(service)
    answers += [ch.login(service, ch.WRONG, APP) for _ in range(2)]
    right = ch.login(service, PASSWORD, APP)
    after = tool(service, query)
    print(
        f"  RE1  three wrong passwords: {', '.join(answers)}; the right one then: {right};"
        f" the tool account's row unchanged: {before == after}"
    )
    if after_one:
        print(f"  RE1  {LOCKS} after one wrong password, as root: {after_one}")
        print(f"  RE1  {LOCKS} after three, as root: {temporary_account_locks(service)}")
        read = f"SELECT COUNT(*) FROM {LOCKS}"
        print(f"  RE1  {LOCKS}, as the tool account: {tool(service, read)}")
        root(service, f"GRANT SELECT ON {LOCKS} TO {TOOL}")
        print(f"  RE1  {LOCKS}, with SELECT on it, rows: {tool(service, read)}")
        root(service, f"REVOKE SELECT ON {LOCKS} FROM {TOOL}")
    else:
        print(f"  RE1  {LOCKS}: no such table")
    root(service, f"ALTER USER '{APP}'@'%' ACCOUNT UNLOCK")
    if after_one:
        print(f"  RE1  {LOCKS} after ACCOUNT UNLOCK: {temporary_account_locks(service)}")
    root(
        service,
        f"CREATE SQL SECURITY DEFINER VIEW {SCHEMA}.locking AS SELECT User, Host,"
        " JSON_EXTRACT(User_attributes, '$.Password_locking.failed_login_attempts') AS attempts,"
        " JSON_EXTRACT(User_attributes, '$.Password_locking.password_lock_time_days') AS days"
        " FROM mysql.user;"
        f"GRANT SELECT ON {SCHEMA}.locking TO {TOOL}",
    )
    view = tool(
        service,
        "SELECT CONCAT(User, '@', Host, ' attempts=', COALESCE(attempts, 'NULL'), ' days=',"
        f" COALESCE(days, 'NULL')) FROM {SCHEMA}.locking WHERE User = '{APP}' ORDER BY Host",
    )
    for row in lines(view) or [view]:
        print(f"  RE1  the definer view: {row}")


def re2(service: str) -> None:
    paths = tool(
        service,
        ROLE_PATHS.format(where=f"WHERE {OWN}")
        + "SELECT CONCAT(path, ' admin_option=', admin_option) FROM e WHERE depth > 0"
        " ORDER BY path",
    )
    for row in lines(paths):
        print(f"  RE2  role path: {row}")
    query = (
        "SELECT CONCAT(USER, '@', HOST, ' -> ', DEFAULT_ROLE_USER, '@', DEFAULT_ROLE_HOST)"
        " FROM mysql.default_roles"
    )
    print(f"  RE2  mysql.default_roles with 2.1's grants: {tool(service, query) or 'no row'}")
    root(service, f"GRANT SELECT ON mysql.default_roles TO {TOOL}")
    print(f"  RE2  mysql.default_roles with SELECT on it: {tool(service, query) or 'no row'}")
    root(service, f"REVOKE SELECT ON mysql.default_roles FROM {TOOL}")
    columns = root(
        service,
        "SELECT GROUP_CONCAT(column_name ORDER BY ordinal_position) FROM information_schema.columns"
        " WHERE table_schema = 'mysql' AND table_name = 'default_roles'",
    )
    print(f"  RE2  mysql.default_roles columns: {columns}")
    settings = tool(
        service,
        "SELECT CONCAT('[', @@global.mandatory_roles, '] ', @@global.activate_all_roles_on_login)",
    )
    print(
        "  RE2  as the tool account, @@mandatory_roles and @@activate_all_roles_on_login:"
        f" {settings}"
    )
    reached = tool(
        service, ROLE_PATHS.format(where=f"WHERE User = '{APP}' AND Host = '%'") + REACHED
    )
    grants = root(service, f"SHOW GRANTS FOR '{APP}'@'%' USING 'sopuli_probe_mid'@'%'")
    grants = grants.replace("`", "")
    missing = []
    for privilege in lines(reached):
        words, _, target = privilege.partition(" ON ")
        word = words.split(" (")[0].upper()
        shown = any(word in line and target.split(" ")[-1] in line for line in lines(grants))
        if not shown:
            missing.append(privilege)
        print(
            f"  RE2  {APP}@'%' reaches, as the tool account reads it: {privilege};"
            f" in SHOW GRANTS: {shown}"
        )
    for line in lines(grants):
        print(f"  RE2  SHOW GRANTS ... USING, as root: {line}")
    print(f"  RE2  read by the tool account and not in SHOW GRANTS: {missing or 'none'}")


def re3(service: str) -> None:
    reads = {
        "mysql.user Process_priv": "SELECT CONCAT(User, '@', Host, ' Process_priv=', Process_priv)"
        " FROM mysql.user WHERE User = 'sopuli_probe_top'",
        "mysql.global_grants": "SELECT CONCAT(USER, '@', HOST, ' ', PRIV, ' ', WITH_GRANT_OPTION)"
        f" FROM mysql.global_grants WHERE USER LIKE {FIXTURE_LIKE}"
        " AND USER <> 'sopuli_probe_tool'",
        "mysql.db": "SELECT CONCAT(User, '@', Host, ' ', Db, ' Select_priv=', Select_priv)"
        f" FROM mysql.db WHERE {OWN}",
        "mysql.tables_priv": "SELECT CONCAT(User, '@', Host, ' ', Db, '.', Table_name, ' [',"
        f" Table_priv, '] [', Column_priv, ']') FROM mysql.tables_priv WHERE {OWN}",
        "mysql.columns_priv": "SELECT CONCAT(User, '@', Host, ' ', Db, '.', Table_name, '.',"
        f" Column_name, ' ', Column_priv) FROM mysql.columns_priv WHERE {OWN}",
        "mysql.procs_priv": "SELECT CONCAT(User, '@', Host, ' ', Routine_type, ' ', Db, '.',"
        f" Routine_name, ' ', Proc_priv) FROM mysql.procs_priv WHERE {OWN}",
        "mysql.proxies_priv": "SELECT CONCAT(User, '@', Host, ' PROXY ON ', Proxied_user, '@',"
        f" Proxied_host, ' With_grant=', With_grant) FROM mysql.proxies_priv WHERE {OWN}",
    }
    for name, query in reads.items():
        print(f"  RE3  {name}: {'; '.join(lines(tool(service, query))) or 'no row'}")
    was = root(service, "SELECT @@global.partial_revokes")
    root(service, "SET GLOBAL partial_revokes = ON")
    try:
        root(
            service,
            f"CREATE USER 'sopuli_probe_part'@'%' IDENTIFIED BY {ch.quote(PASSWORD)};"
            "GRANT SELECT ON *.* TO 'sopuli_probe_part'@'%';"
            f"REVOKE SELECT ON {SCHEMA}.* FROM 'sopuli_probe_part'@'%'",
        )
        part = tool(
            service,
            "SELECT CONCAT('Select_priv=', Select_priv) FROM mysql.user"
            " WHERE User = 'sopuli_probe_part'",
        )
        db = tool(service, "SELECT COUNT(*) FROM mysql.db WHERE User = 'sopuli_probe_part'")
        print(f"  RE3  partial revoke: the tool account reads {part}, and {db} mysql.db rows")
        for account in ("'sopuli_probe_part'@'%'", f"'{APP}'@'%'", "'sopuli_probe_mid'@'%'"):
            ok, out = ch.mysql(service, ch.TOOL, ch.TOOL_PASSWORD, f"SHOW GRANTS FOR {account}")
            shown = "; ".join(lines(out.replace("`", ""))) if ok else ch.code(out)
            print(f"  RE3  SHOW GRANTS FOR {account}, as the tool account: {shown}")
        root(service, "DROP USER 'sopuli_probe_part'@'%'")
    finally:
        root(service, f"SET GLOBAL partial_revokes = {was}")
    for view in ("USER_PRIVILEGES", "SCHEMA_PRIVILEGES", "TABLE_PRIVILEGES", "COLUMN_PRIVILEGES"):
        count = tool(
            service,
            f"SELECT COUNT(*) FROM information_schema.{view}"
            ' WHERE GRANTEE LIKE "\'sopuli\\_probe\\_%"'
            ' AND GRANTEE NOT LIKE "\'sopuli\\_probe\\_tool%"',
        )
        print(
            f"  RE3  information_schema.{view} rows for the fixture, as the tool account: {count}"
        )


def re4(service: str) -> None:
    account = "'sopuli_probe_old'@'%'"
    query = (
        "SELECT password_last_changed FROM mysql.user"
        " WHERE User = 'sopuli_probe_old' AND Host = '%'"
    )

    def by_hash(password: str) -> str:
        value = ch.caching_sha2_hash(password, ch.draw_salt(), 5000).hex()
        return f"ALTER USER {account} IDENTIFIED WITH caching_sha2_password AS 0x{value}"

    steps = (
        ("the tool account's change by hash", by_hash("Acme-Report-pw2")),
        ("ACCOUNT LOCK", f"ALTER USER {account} ACCOUNT LOCK"),
        ("PASSWORD EXPIRE", f"ALTER USER {account} PASSWORD EXPIRE"),
        (
            "a change with RETAIN CURRENT PASSWORD",
            by_hash("Acme-Report-pw3") + " RETAIN CURRENT PASSWORD",
        ),
    )
    last = tool(service, query)
    print(f"  RE4  password_last_changed before: {last}")
    for label, statement in steps:
        time.sleep(1.2)
        answer = ch.as_tool(service, statement)
        now = tool(service, query)
        print(f"  RE4  after {label} ({answer}): {now}; changed: {now != last}")
        last = now


def bulk(service: str) -> None:
    statements = []
    for n in range(BULK_ROLES):
        statements.append(f"CREATE ROLE 'sopuli_probe_r{n}'")
        if n % CHAIN:
            statements.append(f"GRANT 'sopuli_probe_r{n}' TO 'sopuli_probe_r{n - 1}'")
    for n in range(BULK_TABLES):
        statements.append(f"CREATE TABLE {SCHEMA}.b{n} (n int)")
        statements.append(f"GRANT SELECT ON {SCHEMA}.b{n} TO 'sopuli_probe_r{n % BULK_ROLES}'")
    # A few hundred statements per client call keeps each input small.
    for start in range(0, len(statements), 400):
        root(service, ";".join(statements[start : start + 400]))


def timed(service: str, query: str) -> tuple[str, list[float]]:
    """The query's row count, and three timings by the server's clock, after one untimed run."""
    count = tool(service, f"SELECT COUNT(*) FROM ({query}) x")
    batch = ";".join(
        f"SET @t = NOW(6); SELECT COUNT(*) INTO @n FROM ({query}) x;"
        " SELECT TIMESTAMPDIFF(MICROSECOND, @t, NOW(6))"
        for _ in range(3)
    )
    return count, [int(line) / 1e6 for line in lines(tool(service, batch))]


def re5(service: str) -> None:
    accounts = root(service, "SELECT COUNT(*) FROM mysql.user")
    paths, membership = timed(service, ROLE_PATHS.format(where="") + "SELECT * FROM e")
    grants, privilege = timed(
        service,
        ROLE_PATHS.format(where="")
        + "SELECT e.u, e.h, t.Db, t.Table_name FROM e JOIN mysql.tables_priv t"
        " ON t.User = e.ru AND t.Host = e.rh",
    )
    print(
        f"  RE5  {accounts} accounts and roles: role paths {paths} rows in"
        f" {min(membership):.3f} to {max(membership):.3f} s; table grants reached {grants}"
        f" rows in {min(privilege):.3f} to {max(privilege):.3f} s"
    )


def probe(service: str) -> None:
    release = root(service, "SELECT VERSION()")
    print(f"\n== {service}: {release}")
    clean(service)
    try:
        setup(service)
        re0(service)
        re1(service)
        re2(service)
        re3(service)
        re4(service)
        bulk(service)
        re5(service)
    finally:
        clean(service)


def main() -> int:
    # probe() cleans up after itself; 02's teardown drops 02's own accounts.
    setattr(ch, "teardown", lambda service: None)  # noqa: B010 -- a loaded module
    return int(ch.run(probe))


if __name__ == "__main__":
    sys.exit(main())
