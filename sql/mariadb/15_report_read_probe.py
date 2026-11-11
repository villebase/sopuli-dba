"""sopuli-dba : what the UC-5 report commands can read on MariaDB

#1448. The `report` commands read every account on a target (UC-5 §2). The
tool account holds the grants of 02-mariadb-privileges.md §2.1: CREATE USER, a
column grant on the mysql.user view, and SELECT on mysql.roles_mapping, db,
tables_priv, columns_priv, procs_priv and proxies_priv. This measures, on each
server, as that account unless a step says otherwise:

  RE0  what one account is: the view's rows the tool account reads for one
       user name at three hosts, and for three roles, one of which no account
       holds. Then whether it reads the view's account_locked,
       authentication_string, Password and default_role, mysql.global_priv
       and SHOW CREATE USER for another account, and how many fixture rows
       information_schema.USERS shows it, where the release has the view
  RE1  the settings: @@max_password_errors and @@default_password_lifetime,
       as the tool account reads them. Whether CREATE USER takes
       FAILED_LOGIN_ATTEMPTS. Then, with max_password_errors = 2, set by root
       and put back: three wrong passwords and then the right one, for an
       account with no privilege, one with CONNECTION ADMIN and one with
       SUPER, and what the tool account reads that would tell them apart.
       Then a view that root creates, with SQL SECURITY DEFINER, over the
       keys account_locked, password_lifetime and password_last_changed of
       mysql.global_priv, and whether the tool account reads it when granted
       SELECT on it
  RE2  the roles: a recursive query over mysql.roles_mapping from each
       fixture account, with the path and Admin_option. Then the view's
       default_role, with §2.1's grants and with a column grant on it added.
       10_role_reads_probe.py measured roles granted to PUBLIC
  RE3  the privilege levels: for each of the global, schema, table, column,
       routine and proxy grants of the fixture, and the grant to PUBLIC, the
       row the tool account reads. Then what the tool account reads of an
       account that holds only CONNECTION ADMIN. Then how many rows of
       information_schema's USER_PRIVILEGES, SCHEMA_PRIVILEGES,
       TABLE_PRIVILEGES and COLUMN_PRIVILEGES it sees for the fixture
  RE4  `report history`: password_last_changed, through RE1's view, before
       and after the tool account sets a password by value, as the driver
       does, then after ACCOUNT LOCK, after PASSWORD EXPIRE, and after a
       rollover with OR. Each step waits over a second first
  RE5  the cost: after root adds 500 roles in chains of five and 1000
       tables, each granted to one role, the time of RE2's query over every
       account, and of the table grants every account reaches through its
       roles. Each query runs once untimed, then three times timed, by the
       server's clock in the tool account's session

The fixture, which root creates on each server:

  sopuli_probe_tool              the tool account, with §2.1's grants
  sopuli_probe_app@'%'           PASSWORD EXPIRE INTERVAL 90 DAY, the role
                                 sopuli_probe_mid as its default role, INSERT
                                 on t, UPDATE on column t.n, EXECUTE on p
  sopuli_probe_app@'192.0.2.%'   ACCOUNT LOCK, PASSWORD EXPIRE NEVER, the role
                                 sopuli_probe_top WITH ADMIN OPTION, and PROXY
                                 on sopuli_probe_old@'%'
  sopuli_probe_app@'localhost'   PASSWORD EXPIRE
  sopuli_probe_old@'%'           the server's default lifetime
  sopuli_probe_cadm@'%'          CONNECTION ADMIN ON *.*
  sopuli_probe_super@'%'         SUPER ON *.*
  sopuli_probe_top               a role: PROCESS ON *.*
  sopuli_probe_mid               a role, granted sopuli_probe_top: SELECT ON
                                 sopuli_probe.*
  sopuli_probe_none              a role no account holds
  PUBLIC                         SELECT on sopuli_probe.t
  schema sopuli_probe, with table t and procedure p

It MEASURES and decides nothing. It reads no hash: the definer view selects
three keys of mysql.global_priv, and SHOW CREATE USER, whose text holds the
value, is tried by the tool account only for whether it answers.

STATUS: run on 10.11.19, 11.4.13, 11.8.9 and 12.3.3, the mariadb:10.11,
mariadb:11.4, mariadb:11.8 and mariadb:12.3 images of test/compose.yaml
profile mariadb-matrix, on 2026-11-11 (#1448), with Python 3.13.12 on Windows
11 AMD64. Twice, exit 0, the same result both times but for the times of the
last change and the timings, which are the ranges below.

RESULTS -- the same on every release, except where noted

  RE0  the tool account reads nine rows: sopuli_probe_app at %, 192.0.2.%
       and localhost, cadm, old and super, each with its plugin, and the
       three roles at an empty host with an empty plugin and is_role Y. Only
       app@localhost reads password_expired Y. account_locked,
       authentication_string, Password and default_role are refused, 1143
       (42000); mysql.global_priv, 1142 (42000); SHOW CREATE USER for
       app@'%', 1044 (42000). 10.11.19 and 11.4.13 have no
       information_schema.USERS; on 11.8.9 and 12.3.3 it shows the tool
       account only its own row
  RE1  max_password_errors reads 4294967295 and default_password_lifetime 0.
       CREATE USER ... FAILED_LOGIN_ATTEMPTS 3 is refused, 1064 (42000).
       With max_password_errors = 2, each of the three accounts answers 1045
       (28000), 1045 (28000) and 4150 (HY000), and the right password then
       4150 (HY000): CONNECTION ADMIN and SUPER exempt neither. On 11.8.9 and
       12.3.3 root reads PASSWORD_ERRORS 2 for each, and 0 for the others.
       The tool account reads Super_priv Y for super and N for cadm. The
       definer view gives: app@% lifetime 90; app@192.0.2.% account_locked
       1, lifetime 0; app@localhost lifetime -1 and last change 0; cadm, old
       and super neither key; the roles no key and no last change. Every
       account but app@localhost has a time of the last change
  RE2  three paths: app@% > mid, app@% > mid > top, and app@192.0.2.% > top
       with admin_option Y. default_role is refused, 1143 (42000); with a
       column grant on it, app@% reads sopuli_probe_mid, and no other fixture
       row has one
  RE3  Process_priv Y for top, mid's schema grant in db at its empty host,
       INSERT and the column's UPDATE in tables_priv, PUBLIC's SELECT in
       tables_priv as User PUBLIC at an empty host, UPDATE on n in
       columns_priv, EXECUTE in procs_priv, and the PROXY grant in
       proxies_priv. cadm, which holds only CONNECTION ADMIN, has no *_priv
       column Y. The four information_schema views show the tool account no
       fixture row
  RE4  the time of the last change, in seconds, moves with the change by
       value and with the rollover by OR. ACCOUNT LOCK leaves it. PASSWORD
       EXPIRE sets it to 0
  RE5  517 accounts and roles: the role query gives 3025 rows in 0.059 to
       0.249 s, and the table grants reached 6011 rows in 1.325 to 2.853 s.
       The rows are about twice MySQL's: CREATE ROLE grants each role to
       root, which created it, so root reaches every chain

  So the tool account reads each account and role, its expiry, and every
  privilege that a column or a grant table holds, with its role path. It
  reads no lock, lifetime or last change, on any release: those need a view
  a DBA creates. There is no failed-login limit per account, and the
  server's max_password_errors applies to every account measured.

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mariadb/15_report_read_probe.py

It needs 02_client_hash_probe.py beside it, and what 02 needs:
sql/mysql/02_client_hash_probe.py.

THROWAWAY SERVERS ONLY. It creates the accounts and roles above,
sopuli_probe_r0 to sopuli_probe_r499, and the schema sopuli_probe with 1000
tables, and drops them at the end. It sets max_password_errors for RE1 and
puts it back, also after a failed step. Before it starts, it drops what an
interrupted run left.
"""

from __future__ import annotations

import importlib.util
import sys
import time
from pathlib import Path

# 02's name starts with a digit, so it is loaded by its path.
_SPEC = importlib.util.spec_from_file_location(
    "mariadb_client_hash_probe", Path(__file__).with_name("02_client_hash_probe.py")
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
ROLES = ("sopuli_probe_top", "sopuli_probe_mid", "sopuli_probe_none")
BULK_ROLES = 500
BULK_TABLES = 1000
CHAIN = 5
#: §2.1's column grant on the mysql.user view, as 02-mariadb-privileges.md gives it.
STATE = "User, Host, plugin, password_expired, is_role"
PRIV_COLUMNS = (
    "Select_priv, Insert_priv, Update_priv, Delete_priv, Create_priv, Drop_priv, Reload_priv,"
    " Shutdown_priv, Process_priv, File_priv, Grant_priv, References_priv, Index_priv,"
    " Alter_priv, Show_db_priv, Super_priv, Create_tmp_table_priv, Lock_tables_priv,"
    " Execute_priv, Repl_slave_priv, Repl_client_priv, Create_view_priv, Show_view_priv,"
    " Create_routine_priv, Alter_routine_priv, Create_user_priv, Event_priv, Trigger_priv,"
    " Create_tablespace_priv, Delete_history_priv"
)
TABLES = ("roles_mapping", "db", "tables_priv", "columns_priv", "procs_priv", "proxies_priv")
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

#: RE2. Every role an account reaches, with the path, from the account itself
#: at depth 0. A role granted to a role is a row whose Host is empty.
ROLE_PATHS = """
WITH RECURSIVE e (u, h, ru, rh, path, admin_option, depth) AS (
    SELECT User, Host, User, Host, CAST(CONCAT(User, '@', Host) AS CHAR(4000)), 'N', 0
      FROM mysql.user {where}
    UNION ALL
    SELECT e.u, e.h, r.Role, '', CONCAT(e.path, ' > ', r.Role), r.Admin_option, e.depth + 1
      FROM e JOIN mysql.roles_mapping r ON r.User = e.ru AND r.Host = e.rh
     WHERE e.depth < 20
)
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
        f" WHERE User LIKE {FIXTURE_LIKE} AND is_role = 'N'",
    )
    if found and found != "NULL":
        root(service, f"DROP USER {found}")
    roles = root(
        service,
        "SET SESSION group_concat_max_len = 1000000;"
        "SELECT GROUP_CONCAT(QUOTE(User)) FROM mysql.user"
        f" WHERE User LIKE {FIXTURE_LIKE} AND is_role = 'Y'",
    )
    for role in [] if roles in ("", "NULL") else roles.split(","):
        root(service, f"DROP ROLE {role}")
    root(service, f"REVOKE SELECT ON {SCHEMA}.t FROM PUBLIC") if has_public_grant(service) else None
    root(service, f"DROP DATABASE IF EXISTS {SCHEMA}")


def has_public_grant(service: str) -> bool:
    found = root(
        service,
        f"SELECT COUNT(*) FROM mysql.tables_priv WHERE User = 'PUBLIC' AND Db = '{SCHEMA}'",
    )
    return found != "0"


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
                "GRANT PROCESS ON *.* TO sopuli_probe_top",
                f"GRANT SELECT ON {SCHEMA}.* TO sopuli_probe_mid",
                "GRANT sopuli_probe_top TO sopuli_probe_mid",
                f"CREATE USER '{APP}'@'%' IDENTIFIED BY {ch.quote(PASSWORD)}"
                " PASSWORD EXPIRE INTERVAL 90 DAY",
                f"CREATE USER '{APP}'@'192.0.2.%' IDENTIFIED BY {ch.quote(PASSWORD)}"
                " PASSWORD EXPIRE NEVER ACCOUNT LOCK",
                f"CREATE USER '{APP}'@'localhost' IDENTIFIED BY {ch.quote(PASSWORD)}"
                " PASSWORD EXPIRE",
                f"CREATE USER 'sopuli_probe_old'@'%' IDENTIFIED BY {ch.quote(PASSWORD)}",
                f"CREATE USER 'sopuli_probe_cadm'@'%' IDENTIFIED BY {ch.quote(PASSWORD)}",
                "GRANT CONNECTION ADMIN ON *.* TO 'sopuli_probe_cadm'@'%'",
                f"CREATE USER 'sopuli_probe_super'@'%' IDENTIFIED BY {ch.quote(PASSWORD)}",
                "GRANT SUPER ON *.* TO 'sopuli_probe_super'@'%'",
                f"GRANT sopuli_probe_mid TO '{APP}'@'%'",
                f"SET DEFAULT ROLE sopuli_probe_mid FOR '{APP}'@'%'",
                f"GRANT sopuli_probe_top TO '{APP}'@'192.0.2.%' WITH ADMIN OPTION",
                f"GRANT INSERT ON {SCHEMA}.t TO '{APP}'@'%'",
                f"GRANT UPDATE (n) ON {SCHEMA}.t TO '{APP}'@'%'",
                f"GRANT EXECUTE ON PROCEDURE {SCHEMA}.p TO '{APP}'@'%'",
                f"GRANT SELECT ON {SCHEMA}.t TO PUBLIC",
            ]
        ),
    )
    # CREATE ROLE grants the role to root, which created it. The fixture's
    # paths start from the fixture's accounts, so root's rows are left alone.
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
    for column in ("account_locked", "authentication_string", "Password", "default_role"):
        answer = tool(service, f"SELECT {column} FROM mysql.user LIMIT 0")
        print(f"  RE0  mysql.user.{column}: {answer or 'read'}")
    answer = tool(service, "SELECT User FROM mysql.global_priv LIMIT 0")
    print(f"  RE0  mysql.global_priv: {answer or 'read'}")
    # Only whether it answers: its text would hold the value.
    ok, text = ch.mysql(service, ch.TOOL, ch.TOOL_PASSWORD, f"SHOW CREATE USER '{APP}'@'%'")
    print(f"  RE0  SHOW CREATE USER {APP}@'%': {'answers' if ok else ch.code(text)}")
    if has_users(service):
        count = tool(
            service,
            "SELECT GROUP_CONCAT(USER) FROM information_schema.USERS"
            ' WHERE USER LIKE "\'sopuli\\_probe\\_%"',
        )
        print(f"  RE0  information_schema.USERS fixture rows, as the tool account: {count}")
    else:
        print("  RE0  information_schema.USERS: no such view")


def has_users(service: str) -> bool:
    found = root(
        service,
        "SELECT COUNT(*) FROM information_schema.tables "
        "WHERE table_schema = 'information_schema' AND table_name = 'USERS'",
    )
    return found == "1"


def logins(service: str, account: str) -> str:
    """Three wrong passwords and then the right one, as answered."""
    answers = [ch.login(service, ch.WRONG, account) for _ in range(3)]
    return f"{', '.join(answers)}; right: {ch.login(service, PASSWORD, account)}"


def re1(service: str) -> None:
    settings = tool(
        service,
        "SELECT CONCAT(@@global.max_password_errors, ' ', @@global.default_password_lifetime)",
    )
    print(
        f"  RE1  as the tool account, max_password_errors and default_password_lifetime: {settings}"
    )
    ok, answer = ch.mysql(
        service,
        "root",
        ch.ROOT_PASSWORD,
        "CREATE USER 'sopuli_probe_fla'@'%' IDENTIFIED BY 'x' FAILED_LOGIN_ATTEMPTS 3",
    )
    print(f"  RE1  CREATE USER ... FAILED_LOGIN_ATTEMPTS 3: {'ok' if ok else ch.code(answer)}")
    was = root(service, "SELECT @@global.max_password_errors")
    root(service, "SET GLOBAL max_password_errors = 2")
    try:
        for account in (APP, "sopuli_probe_cadm", "sopuli_probe_super"):
            print(f"  RE1  max_password_errors = 2, {account}: {logins(service, account)}")
        if has_users(service):
            errors = root(
                service,
                "SELECT GROUP_CONCAT(CONCAT(USER, ' ', COALESCE(PASSWORD_ERRORS, 'NULL'))"
                " ORDER BY USER SEPARATOR '; ') FROM information_schema.USERS"
                ' WHERE USER LIKE "\'sopuli\\_probe\\_%"',
            )
            print(f"  RE1  information_schema.USERS PASSWORD_ERRORS, as root: {errors}")
    finally:
        root(service, f"SET GLOBAL max_password_errors = {was}")
        root(service, "FLUSH PRIVILEGES")
    super_priv = tool(
        service,
        "SELECT GROUP_CONCAT(CONCAT(User, ' Super_priv=', Super_priv) ORDER BY User"
        " SEPARATOR '; ') FROM mysql.user"
        " WHERE User IN ('sopuli_probe_cadm', 'sopuli_probe_super')",
    )
    print(f"  RE1  as the tool account: {super_priv}")
    root(
        service,
        f"CREATE SQL SECURITY DEFINER VIEW {SCHEMA}.state AS SELECT User, Host,"
        " JSON_VALUE(Priv, '$.account_locked') AS account_locked,"
        " JSON_VALUE(Priv, '$.password_lifetime') AS password_lifetime,"
        " JSON_VALUE(Priv, '$.password_last_changed') AS password_last_changed"
        " FROM mysql.global_priv;"
        f"GRANT SELECT ON {SCHEMA}.state TO {TOOL}",
    )
    view = tool(
        service,
        "SELECT CONCAT(User, '@', Host, ' account_locked=', COALESCE(account_locked, 'NULL'),"
        " ' password_lifetime=', COALESCE(password_lifetime, 'NULL'), ' last_changed=',"
        " CASE WHEN password_last_changed IS NULL THEN 'NULL'"
        " WHEN password_last_changed = '0' THEN '0' ELSE 'a time' END)"
        f" FROM {SCHEMA}.state"
        f" WHERE {OWN} ORDER BY User, Host",
    )
    for row in lines(view) or [view]:
        print(f"  RE1  the definer view: {row}")


def re2(service: str) -> None:
    paths = tool(
        service,
        ROLE_PATHS.format(where=f"WHERE {OWN} AND is_role = 'N'")
        + "SELECT CONCAT(path, ' admin_option=', admin_option) FROM e WHERE depth > 0"
        " ORDER BY path",
    )
    for row in lines(paths):
        print(f"  RE2  role path: {row}")
    query = (
        "SELECT CONCAT(User, '@', Host, ' ', default_role) FROM mysql.user"
        f" WHERE {OWN} AND default_role <> ''"
    )
    print(f"  RE2  default_role with 2.1's grants: {tool(service, query)}")
    root(service, f"GRANT SELECT (default_role) ON mysql.user TO {TOOL}")
    print(f"  RE2  default_role with a column grant on it: {tool(service, query)}")
    root(service, f"REVOKE SELECT (default_role) ON mysql.user FROM {TOOL}")


def re3(service: str) -> None:
    reads = {
        "mysql.user Process_priv": "SELECT CONCAT(User, '@', Host, ' Process_priv=', Process_priv)"
        " FROM mysql.user WHERE User = 'sopuli_probe_top'",
        "mysql.db": "SELECT CONCAT(User, '@', Host, ' ', Db, ' Select_priv=', Select_priv)"
        f" FROM mysql.db WHERE {OWN} OR User = 'PUBLIC'",
        "mysql.tables_priv": "SELECT CONCAT(User, '@', Host, ' ', Db, '.', Table_name, ' [',"
        f" Table_priv, '] [', Column_priv, ']') FROM mysql.tables_priv WHERE {OWN}"
        " OR User = 'PUBLIC'",
        "mysql.columns_priv": "SELECT CONCAT(User, '@', Host, ' ', Db, '.', Table_name, '.',"
        f" Column_name, ' ', Column_priv) FROM mysql.columns_priv WHERE {OWN}",
        "mysql.procs_priv": "SELECT CONCAT(User, '@', Host, ' ', Routine_type, ' ', Db, '.',"
        f" Routine_name, ' ', Proc_priv) FROM mysql.procs_priv WHERE {OWN}",
        "mysql.proxies_priv": "SELECT CONCAT(User, '@', Host, ' PROXY ON ', Proxied_user, '@',"
        f" Proxied_host, ' With_grant=', With_grant) FROM mysql.proxies_priv WHERE {OWN}",
    }
    for name, query in reads.items():
        print(f"  RE3  {name}: {'; '.join(lines(tool(service, query))) or 'no row'}")
    granted = tool(
        service,
        "SELECT COUNT(*) FROM mysql.user"
        f" WHERE User = 'sopuli_probe_cadm' AND 'Y' IN ({PRIV_COLUMNS})",
    )
    print(
        f"  RE3  sopuli_probe_cadm, CONNECTION ADMIN: view rows with a *_priv column Y: {granted}"
    )
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
        f"SELECT password_last_changed FROM {SCHEMA}.state"
        " WHERE User = 'sopuli_probe_old' AND Host = '%'"
    )
    first, second = ch.native_hash("Acme-Report-pw2"), ch.native_hash("Acme-Report-pw3")
    steps = (
        ("the tool account's change by value",
         f"ALTER USER {account} IDENTIFIED VIA mysql_native_password USING '{first}'"),
        ("ACCOUNT LOCK", f"ALTER USER {account} ACCOUNT LOCK"),
        ("PASSWORD EXPIRE", f"ALTER USER {account} PASSWORD EXPIRE"),
        ("a rollover with OR",
         f"ALTER USER {account} IDENTIFIED VIA mysql_native_password USING '{first}'"
         f" OR mysql_native_password USING '{second}'"),
    )  # fmt: skip
    last = tool(service, query)
    print(f"  RE4  password_last_changed, through the view, before: {last}")
    for label, statement in steps:
        time.sleep(1.2)
        answer = ch.as_tool(service, statement)
        now = tool(service, query)
        print(f"  RE4  after {label} ({answer}): {now}; changed: {now != last}")
        last = now


def bulk(service: str) -> None:
    statements = []
    for n in range(BULK_ROLES):
        statements.append(f"CREATE ROLE sopuli_probe_r{n}")
        if n % CHAIN:
            statements.append(f"GRANT sopuli_probe_r{n} TO sopuli_probe_r{n - 1}")
    for n in range(BULK_TABLES):
        statements.append(f"CREATE TABLE {SCHEMA}.b{n} (n int)")
        statements.append(f"GRANT SELECT ON {SCHEMA}.b{n} TO sopuli_probe_r{n % BULK_ROLES}")
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
    ch.base.teardown = lambda service: None
    return int(ch.run(probe))


if __name__ == "__main__":
    sys.exit(main())
