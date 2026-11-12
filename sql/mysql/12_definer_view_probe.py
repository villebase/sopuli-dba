"""sopuli-dba : the optional definer view on MySQL

#1490, the second step of #1457. The maintainer decided on 2026-11-12 that the
tool may read an optional, read-only view that a DBA creates with SQL SECURITY
DEFINER, found by a fixed name and probed as a capability, with its columns
checked every session. 10_report_read_probe.py (#1448, M1) showed that such a
view reads the two Password_locking keys of mysql.user.User_attributes. This
measures what that probe did not. The tool account holds the grants of
02-mysql-privileges.md §2.1 and SELECT on the view, unless a step says
otherwise. Root creates the view:

    CREATE SQL SECURITY DEFINER VIEW sopuli_probe.account_state AS
    SELECT User, Host,
      JSON_EXTRACT(User_attributes, '$.Password_locking.failed_login_attempts')
        AS failed_login_attempts,
      JSON_EXTRACT(User_attributes, '$.Password_locking.password_lock_time_days')
        AS password_lock_time_days,
      JSON_EXTRACT(User_attributes, '$.Restrictions') AS restrictions,
      COALESCE(JSON_CONTAINS_PATH(User_attributes, 'one', '$.additional_password'), 0)
        AS retained_password
    FROM mysql.user

  DV1  the view: one row as the tool account reads it, and SHOW CREATE VIEW,
       information_schema.VIEWS and EXPLAIN as the tool account. Then whether
       anything the tool account read in DV1 to DV9, rows and refusals and
       their messages, holds a stored value: root reads each fixture
       account's authentication_string and additional_password as hex, and
       the probe looks for each as hex, for each one's 43-character ASCII
       digest, which is how a client prints a leaked value, and for the
       "$A$0" that begins every caching_sha2_password value. It prints only
       whether one was found
  DV2  the failed-login limit, M1: both keys for an account created with
       neither, one created with FAILED_LOGIN_ATTEMPTS 3 PASSWORD_LOCK_TIME
       2, one created with PASSWORD_LOCK_TIME UNBOUNDED, and one altered from
       neither to 4 and UNBOUNDED, and then back to 0 and 0
  DV3  the lockout guard: User_attributes' keys, as root reads them with
       JSON_KEYS, and the view's row, before two wrong passwords to an
       account with a limit of 2, after them, and after ACCOUNT UNLOCK.
       Then a definer view over performance_schema.temporary_account_locks,
       and what the tool account reads through it and without it
  DV4  partial revokes, M5: with partial_revokes ON, restrictions for an
       account granted SELECT and INSERT ON *.*, after REVOKE SELECT ON one
       schema, after REVOKE INSERT ON a second, and after a GRANT SELECT on
       the first schema again
  DV5  a retained password: retained_password before a rollover, after the
       tool account's IDENTIFIED WITH caching_sha2_password AS 0x... RETAIN
       CURRENT PASSWORD, after PASSWORD EXPIRE during it, and after DISCARD
       OLD PASSWORD
  DV6  the shape check: the view's columns as the tool account reads them
       from information_schema.COLUMNS and SHOW COLUMNS. Then a view with an
       extra authentication_string column, granted whole and then by a
       column grant on User and Host. No row of it is read
  DV7  the capability probe: what the tool account gets from a SELECT and
       from information_schema.COLUMNS when the view is absent from an
       existing schema, when the schema is absent, when the view exists
       without the grant, for a view whose definer is a locked account
       holding only SELECT on mysql.user, when that definer loses the
       grant, and whether root can drop the definer
  DV8  the cost, #1457 Q5: how many rows the view gives against mysql.user.
       The tool account's CREATE VIEW over it, CREATE PROCEDURE, CREATE
       TRIGGER on a table, and UPDATE of the view. Then, with CREATE VIEW on
       sopuli_probe.* granted for the step, a view of its own over the view,
       and one over mysql.user's authentication_string. A column grant on part of
       the view. WITH CHECK OPTION. A DBA with every privilege on
       sopuli_probe.* and SELECT on mysql.user, and neither SET_USER_ID nor
       SET_ANY_DEFINER: CREATE DEFINER = root@localhost VIEW, and the view
       with itself as the definer
  DV9  upgrades: a volume of its own, run on mysql:8.0 with the fixture of
       DV2, DV4 and DV5 and the view, and partial_revokes set ON with SET
       PERSIST, then stopped and started on mysql:8.4 and mysql:9 in turn.
       After each start: VERSION(), which must be the matrix server's of the
       same tag, partial_revokes, whether SHOW CREATE VIEW, as root, is the
       text 8.0 gave, and what the tool account reads through the view

The fixture, which root creates on each server, all at '%' unless named:

  sopuli_probe_tool         the tool account, with §2.1's grants
  sopuli_probe_dv_plain     created with a password, nothing else
  sopuli_probe_dv_limit     FAILED_LOGIN_ATTEMPTS 3 PASSWORD_LOCK_TIME 2
  sopuli_probe_dv_unbound   FAILED_LOGIN_ATTEMPTS 2 PASSWORD_LOCK_TIME UNBOUNDED
  sopuli_probe_dv_altered   for DV2's ALTER USER
  sopuli_probe_dv_block     FAILED_LOGIN_ATTEMPTS 2 PASSWORD_LOCK_TIME 1, for DV3
  sopuli_probe_dv_revoke    for DV4
  sopuli_probe_dv_roll      for DV5
  sopuli_probe_dv_dba       DV8's DBA
  sopuli_probe_dv_definer   @localhost, ACCOUNT LOCK, SELECT on mysql.user
  sopuli_probe_dv_role      a role
  schema sopuli_probe, with table t and the views

It MEASURES and decides nothing. It prints no stored value: root reads them
only as hex, to look for them in what the tool account reads.

It prints each result and checks none against RESULTS below: compare a new
run with RESULTS by eye. It exits 1 only when a step fails, or when a stored
value is found in what the tool account read.

STATUS: run on 8.0.46, 8.4.13 and 9.7.4, the mysql:8.0, mysql:8.4 and
mysql:9 images of test/compose.yaml profile mysql-matrix, on 2026-11-12
(#1490), with Python 3.13.12 on Windows 11 AMD64. Twice, exit 0, the same
result both times. Earlier runs are not counted: their leak check compared
only hex, and they did not have DV8's view of its own or DV9's checks.

RESULTS -- the same on every release, except where noted

  DV1  the tool account reads the view's row. It is refused SHOW CREATE
       VIEW, 1142 (42000), and EXPLAIN, 1345 (HY000).
       information_schema.VIEWS shows it the view's row with an empty
       VIEW_DEFINITION and SECURITY_TYPE DEFINER. No stored value was in
       anything the tool account read, as hex or as a digest, and no output
       held "$A$0": 120 outputs on 8.0.46 and 8.4.13, 124 on 9.7.4 and 30 in
       DV9, against 22 values each
  DV2  failed_login_attempts and password_lock_time_days are NULL for an
       account created with neither, 3 and 2 as created, and 2 and -1 for
       PASSWORD_LOCK_TIME UNBOUNDED. The tool account's ALTER USER to 4 and
       UNBOUNDED reads 4 and -1, and to 0 and 0 reads NULL and NULL: the
       server removes the keys
  DV3  User_attributes holds Password_locking with the two keys only,
       before the block, while blocked and after ACCOUNT UNLOCK: two wrong
       passwords give 1045 (28000) and 3955 (HY000), and the right one 3955
       (HY000), with no key changed. The view shows nothing of the block. The
       tool account is refused temporary_account_locks, 1142 (42000). On
       8.0.46 and 8.4.13 a definer view over it is refused, 1146 (42S02): the
       table does not exist. On 9.7.4 the view reads it: LOCKED YES, 2
       attempts, 0 left, as the optional grant on the table reads it
  DV4  restrictions is NULL with no partial revoke, then one entry per
       schema revoked, such as [{"Database": "sopuli_probe", "Privileges":
       ["SELECT"]}], two after a second schema, and the entry goes when the
       privilege is granted on that schema again
  DV5  retained_password is 0 before, 1 after the tool account's RETAIN
       CURRENT PASSWORD, still 1 after PASSWORD EXPIRE during it, and 0 after
       DISCARD OLD PASSWORD
  DV6  information_schema.COLUMNS and SHOW COLUMNS give the tool account the
       six columns, in order. For the wide view granted whole, both give the
       seven, authentication_string last, without a row read. With a column
       grant on User and Host only, both give User and Host
  DV7  a view absent from an existing schema, a schema absent, and a view
       without the grant all answer the SELECT 1142 (42000) and give 0
       COLUMNS rows. A view whose definer is a locked account holding only
       SELECT on mysql.user reads. When that definer loses the grant, the
       SELECT answers 1356 (HY000). Root may drop the definer, and the
       SELECT then answers 1045 (28000), "Access denied for user
       'sopuli_probe_tool'@'%' (using password: YES)", in a session that is
       logged in. COLUMNS still gives 6 rows in both cases
  DV8  the view gives every row of mysql.user, 21 of 21, the role and root's
       two among them. The tool account's CREATE VIEW over it is refused,
       1142 (42000), CREATE PROCEDURE 1044 (42000), and UPDATE of the view
       1142 (42000): it holds none of those privileges. CREATE TRIGGER on
       table t is refused 1419 (HY000), the binary log's check, which runs
       first on the matrix; the account holds no TRIGGER privilege either.
       Granted CREATE VIEW on the schema, it creates a view over the view,
       which has the same six columns, and is refused one over mysql.user's
       authentication_string, 1143 (42000): a view it owns reads with its own
       grants. With a column grant on User, Host and
       retained_password, those read, restrictions is refused 1143 (42000)
       and SELECT * 1142 (42000). WITH CHECK OPTION is accepted. The DBA
       without SET_USER_ID or SET_ANY_DEFINER is refused CREATE DEFINER =
       root@localhost VIEW, 1227 (42000); its CREATE VIEW with itself as the
       definer runs, and after root's grant the tool account reads it
  DV9  on one volume, 8.0.46, then 8.4.13 and 9.7.4, each the matrix's
       release, with partial_revokes 1 after each start: SHOW CREATE VIEW is
       the text 8.0 gave, and the view reads the same for each account: the
       limit 3 and 2, UNBOUNDED -1, the partial revoke, the retained
       password 1

  So the view gives the failed-login limit, the partial revokes and whether
  a password is retained, on every release, through upgrades, and nothing of
  a block after failed logins. It holds no stored value, and the tool
  account cannot reach past it. Its shape is checkable from
  information_schema.COLUMNS, but only for the columns the tool account may
  read. "Absent" and "not granted" answer the same; a broken definer answers
  1045 or 1356.

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mysql/12_definer_view_probe.py

It needs 02_client_hash_probe.py and 10_report_read_probe.py beside it. DV9
needs the three images pulled and docker run; it uses the container
{COMPOSE_PROJECT_NAME}-dv-upgrade-1 and the volume
{COMPOSE_PROJECT_NAME}-dv-upgrade, and removes both.

THROWAWAY SERVERS ONLY. It creates the accounts, role and schema above and
drops them at the end. It turns partial_revokes on for DV4 and puts back the
server's own setting after dropping the accounts, also after a failed step.
Before it starts, it
drops what an interrupted run left.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


def _load(name: str, file: str) -> Any:
    # The probes' names start with a digit, so they are loaded by path.
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rr = _load("mysql_report_read_probe", "10_report_read_probe.py")
ch = rr.ch

TOOL = rr.TOOL
SCHEMA = "sopuli_probe"
VIEW = f"{SCHEMA}.account_state"
#: A test password, not a credential.
PASSWORD = "Acme-View-pw1"
P = "sopuli_probe_dv_"
FIXTURE_LIKE = rr.FIXTURE_LIKE
COLUMNS = (
    "User, Host,"
    " JSON_EXTRACT(User_attributes, '$.Password_locking.failed_login_attempts')"
    " AS failed_login_attempts,"
    " JSON_EXTRACT(User_attributes, '$.Password_locking.password_lock_time_days')"
    " AS password_lock_time_days,"
    " JSON_EXTRACT(User_attributes, '$.Restrictions') AS restrictions,"
    " COALESCE(JSON_CONTAINS_PATH(User_attributes, 'one', '$.additional_password'), 0)"
    " AS retained_password"
)
VIEW_SQL = f"SELECT {COLUMNS} FROM mysql.user"
DEFINER = f"'{P}definer'@'localhost'"
#: Every caching_sha2_password value begins so.
HASH_MARK = "$A$0"

SEEN: list[str] = []
#: The fixture's stored values, as hex, as root reads them. Never printed.
STORED: set[str] = set()
LEAKED: list[str] = []

root = rr.root


def _answer(returncode: int, out: str, err: str, service: str, who: str) -> tuple[bool, str]:
    """``ch.mysql``'s parsing, on the client's whole output: the leak check
    needs the whole message, which ``ch.mysql`` cuts short."""
    if returncode == 0:
        return True, out
    found = re.search(r"^ERROR (\d+ \(\w+\))(?: at line \d+)?: (.*)", err, re.DOTALL | re.MULTILINE)
    if found is None:
        raise ch.StepError(f"{service}: {who}: {(err or out)[:200]}")
    return False, f"{found[1]}: {found[2][:110]}"


def tool(service: str, statement: str) -> str:
    """What the tool account reads, or the refusal's error number and SQLSTATE."""
    returncode, out, err = ch.client(service, ch.TOOL, ch.TOOL_PASSWORD, statement, "-h127.0.0.1")
    SEEN.extend((out, err))
    ok, answer = _answer(returncode, out, err, service, "tool account")
    return answer if ok else answer.split(":")[0]


def sent(service: str, statement: str) -> str:
    """``ok``, or the refusal with its message, for a statement the tool account sends."""
    returncode, out, err = ch.client(service, ch.TOOL, ch.TOOL_PASSWORD, statement, "-h127.0.0.1")
    SEEN.extend((out, err))
    ok, answer = _answer(returncode, out, err, service, "tool account")
    return "ok" if ok else answer


def as_account(service: str, user: str, statement: str) -> str:
    """``ok`` and the output, or the refusal's code, for another fixture account at '%'."""
    returncode, out, err = ch.client(service, user, PASSWORD, statement, "-h127.0.0.1")
    ok, answer = _answer(returncode, out, err, service, user)
    return f"ok {answer}".strip() if ok else answer.split(":")[0]


#: A caching_sha2_password value: "$A$005$", a 20-byte salt, and the digest,
#: 43 characters of ASCII. The digest is the part a client prints as text.
DIGEST = 43


def remember(service: str) -> None:
    """Add the fixture's stored values to STORED: each as hex, which is how
    root reads them, and each one's ASCII digest, which is how a client would
    print one that leaked."""
    rows = root(
        service,
        "SELECT HEX(authentication_string),"
        " COALESCE(HEX(JSON_UNQUOTE(JSON_EXTRACT(User_attributes, '$.additional_password'))), '')"
        f" FROM mysql.user WHERE User LIKE {FIXTURE_LIKE}",
    )
    for line in rows.splitlines():
        for value in line.split("\t"):
            if value and value != "NULL":
                STORED.add(value.upper())
                STORED.add(bytes.fromhex(value)[-DIGEST:].decode("latin-1"))


def row(service: str, user: str, view: str = VIEW, host: str = "%") -> str:
    """The view's row for one account, as the tool account reads it."""
    out = tool(
        service,
        "SELECT CONCAT('attempts=', COALESCE(failed_login_attempts, 'NULL'),"
        " ' lock_days=', COALESCE(password_lock_time_days, 'NULL'),"
        " ' restrictions=', COALESCE(restrictions, 'NULL'),"
        " ' retained=', retained_password)"
        f" FROM {view} WHERE User = '{user}' AND Host = '{host}'",
    )
    return out or "no row"


#: Each server's own partial_revokes, read before the probe first sets it.
PARTIAL_REVOKES: dict[str, str] = {}
#: Each matrix server's VERSION(), which DV9's image of the same tag must give.
RELEASES: dict[str, str] = {}


def clean(service: str) -> None:
    """Drop what this probe creates, whatever an earlier run left, and put
    partial_revokes back to the server's own setting once no fixture account
    holds a restriction."""
    rr.clean(service)
    if service in PARTIAL_REVOKES:
        root(service, f"SET GLOBAL partial_revokes = {PARTIAL_REVOKES[service]}")


def create(account: str, extra: str = "") -> str:
    return f"CREATE USER '{account}'@'%' IDENTIFIED BY {ch.quote(PASSWORD)} {extra}".strip()


def setup(service: str) -> None:
    root(
        service,
        ";".join(
            [
                f"CREATE USER {TOOL} IDENTIFIED BY {ch.quote(ch.TOOL_PASSWORD)}",
                *rr.TOOL_GRANTS,
                f"CREATE DATABASE {SCHEMA}",
                f"CREATE TABLE {SCHEMA}.t (n int)",
                create(f"{P}plain"),
                create(f"{P}limit", "FAILED_LOGIN_ATTEMPTS 3 PASSWORD_LOCK_TIME 2"),
                create(f"{P}unbound", "FAILED_LOGIN_ATTEMPTS 2 PASSWORD_LOCK_TIME UNBOUNDED"),
                create(f"{P}altered"),
                create(f"{P}block", "FAILED_LOGIN_ATTEMPTS 2 PASSWORD_LOCK_TIME 1"),
                create(f"{P}revoke"),
                create(f"{P}roll"),
                create(f"{P}dba"),
                f"GRANT ALL PRIVILEGES ON {SCHEMA}.* TO '{P}dba'@'%'",
                f"GRANT SELECT ON mysql.user TO '{P}dba'@'%'",
                f"CREATE USER {DEFINER} IDENTIFIED BY {ch.quote(PASSWORD)} ACCOUNT LOCK",
                f"GRANT SELECT ON mysql.user TO {DEFINER}",
                f"CREATE ROLE '{P}role'",
                f"CREATE SQL SECURITY DEFINER VIEW {VIEW} AS {VIEW_SQL}",
                f"GRANT SELECT ON {VIEW} TO {TOOL}",
            ]
        ),
    )
    remember(service)


# ------------------------------------------------------------------ steps --


def dv1(service: str) -> None:
    print(f"  DV1  one row, as the tool account reads it: {row(service, P + 'plain')}")
    ddl = tool(service, f"SHOW CREATE VIEW {VIEW}")
    print(f"  DV1  SHOW CREATE VIEW, as the tool account: {ddl if len(ddl) < 20 else 'answers'}")
    definition = tool(
        service,
        "SELECT CONCAT('[', VIEW_DEFINITION, '] SECURITY_TYPE=', SECURITY_TYPE)"
        " FROM information_schema.VIEWS"
        f" WHERE TABLE_SCHEMA = '{SCHEMA}' AND TABLE_NAME = 'account_state'",
    )
    print(f"  DV1  information_schema.VIEWS, as the tool account: {definition or 'no row'}")
    explain = tool(service, f"EXPLAIN SELECT * FROM {VIEW}")
    print(f"  DV1  EXPLAIN, as the tool account: {explain if len(explain) < 20 else 'answers'}")


def dv2(service: str) -> None:
    for user in ("plain", "limit", "unbound"):
        print(f"  DV2  {P}{user}: {row(service, P + user)}")
    account = f"'{P}altered'@'%'"
    for clause in (
        "FAILED_LOGIN_ATTEMPTS 4 PASSWORD_LOCK_TIME UNBOUNDED",
        "FAILED_LOGIN_ATTEMPTS 0 PASSWORD_LOCK_TIME 0",
    ):
        answer = sent(service, f"ALTER USER {account} {clause}")
        print(f"  DV2  after the tool account's {clause} ({answer}): {row(service, P + 'altered')}")


def keys(service: str, user: str) -> str:
    return root(
        service,
        "SELECT CONCAT(COALESCE(JSON_KEYS(User_attributes), 'NULL'), ' ',"
        " COALESCE(JSON_KEYS(User_attributes, '$.Password_locking'), 'NULL'))"
        f" FROM mysql.user WHERE User = '{user}' AND Host = '%'",
    )


def dv3(service: str) -> None:
    user = f"{P}block"
    print(f"  DV3  keys before: {keys(service, user)}; view: {row(service, user)}")
    answers = [ch.login(service, ch.WRONG, user) for _ in range(2)]
    right = ch.login(service, PASSWORD, user)
    print(f"  DV3  two wrong passwords: {', '.join(answers)}; the right one: {right}")
    print(f"  DV3  keys while blocked: {keys(service, user)}; view: {row(service, user)}")
    answer = sent(service, f"ALTER USER '{user}'@'%' ACCOUNT UNLOCK")
    print(f"  DV3  after ACCOUNT UNLOCK ({answer}): keys {keys(service, user)}")
    direct = tool(service, f"SELECT COUNT(*) FROM {rr.LOCKS}")
    print(f"  DV3  temporary_account_locks, as the tool account: {direct}")
    ok, answer = ch.mysql(
        service,
        "root",
        ch.ROOT_PASSWORD,
        f"CREATE SQL SECURITY DEFINER VIEW {SCHEMA}.locks AS SELECT * FROM {rr.LOCKS}",
    )
    if not ok:
        print(f"  DV3  a definer view over it: {ch.code(answer)}")
        return
    root(service, f"GRANT SELECT ON {SCHEMA}.locks TO {TOOL}")
    for _ in range(2):
        ch.login(service, ch.WRONG, user)
    through = tool(
        service,
        "SELECT CONCAT(LOCKED, ' ', FAILED_LOGIN_ATTEMPTS, ' ', REMAINING_LOGIN_ATTEMPTS)"
        f" FROM {SCHEMA}.locks WHERE USER = '{user}'",
    )
    print(f"  DV3  blocked again, through a definer view over it: {through or 'no row'}")
    sent(service, f"ALTER USER '{user}'@'%' ACCOUNT UNLOCK")


def dv4(service: str) -> None:
    root(service, "SET GLOBAL partial_revokes = ON")
    user = f"{P}revoke"
    account = f"'{user}'@'%'"
    steps = (
        ("GRANT SELECT, INSERT ON *.*", f"GRANT SELECT, INSERT ON *.* TO {account}"),
        (f"REVOKE SELECT ON {SCHEMA}.*", f"REVOKE SELECT ON {SCHEMA}.* FROM {account}"),
        ("REVOKE INSERT ON mysql.*", f"REVOKE INSERT ON mysql.* FROM {account}"),
        (f"GRANT SELECT ON {SCHEMA}.* again", f"GRANT SELECT ON {SCHEMA}.* TO {account}"),
    )
    for label, statement in steps:
        root(service, statement)
        print(f"  DV4  after {label}: {row(service, user)}")


def dv5(service: str) -> None:
    user = f"{P}roll"
    account = f"'{user}'@'%'"
    rounds = int(root(service, "SELECT @@global.caching_sha2_password_digest_rounds"))
    value = ch.caching_sha2_hash("Acme-View-pw2", ch.draw_salt(), rounds)
    print(f"  DV5  before: {row(service, user)}")
    steps = (
        ("the tool account's rollover",
         f"ALTER USER {account} IDENTIFIED WITH caching_sha2_password AS 0x{value.hex()}"
         " RETAIN CURRENT PASSWORD"),
        ("PASSWORD EXPIRE during it", f"ALTER USER {account} PASSWORD EXPIRE"),
        ("DISCARD OLD PASSWORD", f"ALTER USER {account} DISCARD OLD PASSWORD"),
    )  # fmt: skip
    for label, statement in steps:
        answer = sent(service, statement)
        remember(service)
        print(f"  DV5  after {label} ({answer}): {row(service, user)}")


def columns(service: str, name: str) -> str:
    return tool(
        service,
        "SELECT GROUP_CONCAT(COLUMN_NAME ORDER BY ORDINAL_POSITION)"
        f" FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = '{SCHEMA}'"
        f" AND TABLE_NAME = '{name}'",
    )


def show_columns(service: str, name: str) -> str:
    out = tool(service, f"SHOW COLUMNS FROM {SCHEMA}.{name}")
    if re.fullmatch(r"\d+ \(\w+\)", out):
        return out
    return ",".join(line.split("\t")[0] for line in out.splitlines()) or "nothing"


def dv6(service: str) -> None:
    print(f"  DV6  information_schema.COLUMNS: {columns(service, 'account_state')}")
    print(f"  DV6  SHOW COLUMNS: {show_columns(service, 'account_state')}")
    root(
        service,
        f"CREATE SQL SECURITY DEFINER VIEW {SCHEMA}.wide AS SELECT {COLUMNS},"
        " authentication_string FROM mysql.user;"
        f"GRANT SELECT ON {SCHEMA}.wide TO {TOOL}",
    )
    print(f"  DV6  wide view, granted whole, COLUMNS: {columns(service, 'wide')}")
    print(f"  DV6  wide view, granted whole, SHOW COLUMNS: {show_columns(service, 'wide')}")
    root(
        service,
        f"REVOKE SELECT ON {SCHEMA}.wide FROM {TOOL};"
        f"GRANT SELECT (User, Host) ON {SCHEMA}.wide TO {TOOL}",
    )
    print(f"  DV6  wide view, column grant on User and Host, COLUMNS: {columns(service, 'wide')}")
    print(
        "  DV6  wide view, column grant on User and Host, SHOW COLUMNS:"
        f" {show_columns(service, 'wide')}"
    )
    root(service, f"DROP VIEW {SCHEMA}.wide")


def probe_read(service: str, name: str) -> str:
    """DV7: a SELECT from the view and its columns, as a capability probe would read them."""
    select = tool(service, f"SELECT COUNT(*) FROM {name}")
    schema, table = name.split(".")
    cols = tool(
        service,
        "SELECT COUNT(*) FROM information_schema.COLUMNS"
        f" WHERE TABLE_SCHEMA = '{schema}' AND TABLE_NAME = '{table}'",
    )
    return f"SELECT: {select if '(' in select else 'rows'}; COLUMNS rows: {cols}"


def dv7(service: str) -> None:
    print(f"  DV7  absent from an existing schema: {probe_read(service, SCHEMA + '.nosuch')}")
    print(f"  DV7  schema absent: {probe_read(service, 'sopuli_nosuch.account_state')}")
    root(service, f"CREATE SQL SECURITY DEFINER VIEW {SCHEMA}.no_grant AS {VIEW_SQL}")
    print(f"  DV7  exists, no grant: {probe_read(service, SCHEMA + '.no_grant')}")
    root(
        service,
        f"CREATE DEFINER = {DEFINER} SQL SECURITY DEFINER VIEW {SCHEMA}.by_definer AS {VIEW_SQL};"
        f"GRANT SELECT ON {SCHEMA}.by_definer TO {TOOL}",
    )
    print(
        "  DV7  definer locked, SELECT on mysql.user only:"
        f" {probe_read(service, SCHEMA + '.by_definer')}"
    )
    root(service, f"REVOKE SELECT ON mysql.user FROM {DEFINER}")
    print(f"  DV7  definer without the grant: {probe_read(service, SCHEMA + '.by_definer')}")
    answer = sent(service, f"SELECT COUNT(*) FROM {SCHEMA}.by_definer")
    print(f"  DV7  definer without the grant, the message: {answer}")
    ok, dropped = ch.mysql(service, "root", ch.ROOT_PASSWORD, f"DROP USER {DEFINER}")
    print(f"  DV7  root's DROP USER of the definer: {'ok' if ok else dropped}")
    if ok:
        print(f"  DV7  definer dropped: {probe_read(service, SCHEMA + '.by_definer')}")
        message = sent(service, f"SELECT COUNT(*) FROM {SCHEMA}.by_definer")
        print(f"  DV7  definer dropped, the message: {message}")


def dv8(service: str) -> None:
    rows = tool(service, f"SELECT COUNT(*) FROM {VIEW}")
    total = root(service, "SELECT COUNT(*) FROM mysql.user")
    roles = tool(service, f"SELECT COUNT(*) FROM {VIEW} WHERE User = '{P}role'")
    has_root = tool(service, f"SELECT COUNT(*) FROM {VIEW} WHERE User = 'root'")
    print(
        f"  DV8  the view's rows: {rows} of mysql.user's {total};"
        f" the role: {roles}; root: {has_root}"
    )
    attempts = {
        "CREATE VIEW over it": f"CREATE VIEW {SCHEMA}.mine AS SELECT * FROM {VIEW}",
        "CREATE PROCEDURE": f"CREATE PROCEDURE {SCHEMA}.mine() SELECT * FROM {VIEW}",
        "CREATE TRIGGER on table t": f"CREATE TRIGGER {SCHEMA}.mine BEFORE INSERT ON {SCHEMA}.t"
        " FOR EACH ROW SET @x = 1",
        "UPDATE the view": f"UPDATE {VIEW} SET retained_password = 0",
    }
    for label, statement in attempts.items():
        print(f"  DV8  the tool account's {label}: {sent(service, statement)}")
    # The refusals above are the tool account's grants: it holds no CREATE
    # VIEW. With CREATE VIEW on the schema, a view over the view is the tool
    # account's own, SQL SECURITY DEFINER with itself as the definer.
    root(service, f"GRANT CREATE VIEW ON {SCHEMA}.* TO {TOOL}")
    wrapped = sent(service, f"CREATE VIEW {SCHEMA}.wrap AS SELECT * FROM {VIEW}")
    print(f"  DV8  with CREATE VIEW on the schema, a view over it: {wrapped}")
    if wrapped == "ok":
        root(service, f"GRANT SELECT ON {SCHEMA}.wrap TO {TOOL}")
        print(f"  DV8    its columns: {columns(service, 'wrap')}")
        reached = sent(
            service,
            f"CREATE VIEW {SCHEMA}.wrap2 AS SELECT authentication_string FROM mysql.user",
        )
        print(f"  DV8    a view of its own over mysql.user's hash: {reached}")
    root(service, f"REVOKE CREATE VIEW ON {SCHEMA}.* FROM {TOOL}")
    root(
        service,
        f"CREATE SQL SECURITY DEFINER VIEW {SCHEMA}.cols AS {VIEW_SQL};"
        f"GRANT SELECT (User, Host, retained_password) ON {SCHEMA}.cols TO {TOOL}",
    )
    part = tool(service, f"SELECT SUM(retained_password) FROM {SCHEMA}.cols")
    rest = tool(service, f"SELECT restrictions FROM {SCHEMA}.cols LIMIT 0")
    star = tool(service, f"SELECT * FROM {SCHEMA}.cols LIMIT 0")
    print(
        f"  DV8  a column grant on User, Host, retained_password: those read ({part});"
        f" restrictions: {rest or 'read'}; SELECT *: {star or 'read'}"
    )
    ok, answer = ch.mysql(
        service,
        "root",
        ch.ROOT_PASSWORD,
        f"CREATE SQL SECURITY DEFINER VIEW {SCHEMA}.checked AS {VIEW_SQL} WITH CHECK OPTION",
    )
    print(f"  DV8  WITH CHECK OPTION: {'accepted' if ok else ch.code(answer)}")
    dba = f"{P}dba"
    as_root = as_account(
        service,
        dba,
        f"CREATE DEFINER = 'root'@'localhost' SQL SECURITY DEFINER VIEW {SCHEMA}.by_dba_root"
        f" AS {VIEW_SQL}",
    )
    print(f"  DV8  the DBA's CREATE DEFINER = root@localhost VIEW: {as_root}")
    as_self = as_account(
        service, dba, f"CREATE SQL SECURITY DEFINER VIEW {SCHEMA}.by_dba AS {VIEW_SQL}"
    )
    print(f"  DV8  the DBA's CREATE VIEW, itself the definer: {as_self}")
    root(service, f"GRANT SELECT ON {SCHEMA}.by_dba TO {TOOL}")
    print(
        "  DV8  root's grant on it, then the tool account reads:"
        f" {row(service, P + 'limit', SCHEMA + '.by_dba')}"
    )


def check_leaks(service: str) -> None:
    remember(service)
    if not STORED:
        raise ch.StepError(f"{service}: no stored value read to compare with")
    # A hex value is matched without case, a digest exactly.
    found = [
        value for value in STORED if any(value in text or value in text.upper() for text in SEEN)
    ]
    marked = sum(1 for text in SEEN if HASH_MARK in text)
    print(
        f"  DV1  stored values in anything the tool account read ({len(SEEN)} outputs,"
        f" {len(STORED)} values): {len(found) or 'none'}; outputs with {HASH_MARK}: {marked}"
    )
    if found or marked:
        LEAKED.append(service)


def probe(service: str) -> None:
    release = root(service, "SELECT VERSION()")
    RELEASES[service] = release
    print(f"\n== {service}: {release}")
    SEEN.clear()
    STORED.clear()
    PARTIAL_REVOKES.setdefault(service, root(service, "SELECT @@global.partial_revokes"))
    clean(service)

    def steps() -> None:
        setup(service)
        dv1(service)
        dv2(service)
        dv3(service)
        dv4(service)
        dv5(service)
        dv6(service)
        dv7(service)
        dv8(service)
        check_leaks(service)

    try:
        steps()
    finally:
        try:
            clean(service)
        except ch.StepError as exc:
            print(f"CLEAN-UP FAILED: {service}: {exc}")


# --------------------------------------------------------------- upgrades --

UPGRADE = "dv-upgrade"
IMAGES = ("mysql:8.0", "mysql:8.4", "mysql:9")


def docker(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=False)


def upgrade_names() -> tuple[str, str]:
    return ch.container(UPGRADE), f"{ch.PROJECT}-{UPGRADE}"


def upgrade_clean() -> None:
    container, volume = upgrade_names()
    docker("rm", "-f", container)
    docker("volume", "rm", "-f", volume)


def start(image: str) -> None:
    container, volume = upgrade_names()
    docker("rm", "-f", container)
    started = docker(
        "run", "-d", "--name", container, "-v", f"{volume}:/var/lib/mysql",
        "-e", f"MYSQL_ROOT_PASSWORD={ch.ROOT_PASSWORD}", image,
    )  # fmt: skip
    if started.returncode:
        raise ch.StepError(f"docker run {image}: {started.stderr.strip()[:200]}")
    # The entrypoint's first server listens on the socket only, so a login
    # over TCP reaches the real one.
    for _ in range(120):
        time.sleep(2)
        try:
            ok, _out = ch.mysql(UPGRADE, "root", ch.ROOT_PASSWORD, "SELECT 1")
        except ch.StepError:
            continue
        if ok:
            return
    tail = docker("logs", "--tail", "5", container).stderr[-300:]
    raise ch.StepError(f"{image}: no login after 4 minutes: {tail}")


def dv9() -> None:
    print(f"\n== DV9: upgrades, {' > '.join(IMAGES)}")
    upgrade_clean()
    SEEN.clear()
    STORED.clear()
    try:
        start(IMAGES[0])
        setup(UPGRADE)
        # PERSIST, so each later image starts with it on, as DV4 measured it.
        root(UPGRADE, "SET PERSIST partial_revokes = ON")
        revoke = f"'{P}revoke'@'%'"
        root(
            UPGRADE,
            f"GRANT SELECT ON *.* TO {revoke}; REVOKE SELECT ON {SCHEMA}.* FROM {revoke}",
        )
        rounds = int(root(UPGRADE, "SELECT @@global.caching_sha2_password_digest_rounds"))
        value = ch.caching_sha2_hash("Acme-View-pw2", ch.draw_salt(), rounds)
        root(
            UPGRADE,
            f"ALTER USER '{P}roll'@'%' IDENTIFIED WITH caching_sha2_password AS 0x{value.hex()}"
            " RETAIN CURRENT PASSWORD",
        )
        remember(UPGRADE)
        ddl = root(UPGRADE, f"SHOW CREATE VIEW {VIEW}")
        container, _ = upgrade_names()
        for image, service in zip(IMAGES, ch.SERVICES, strict=True):
            if image != IMAGES[0]:
                stopped = docker("stop", "-t", "60", container)
                if stopped.returncode:
                    raise ch.StepError(f"docker stop: {stopped.stderr.strip()[:200]}")
                start(image)
            release = root(UPGRADE, "SELECT VERSION()")
            # A floating tag must give the release the matrix measured.
            if release != RELEASES.get(service, release):
                raise ch.StepError(f"{image} is {release}, but {service} is {RELEASES[service]}")
            partial = root(UPGRADE, "SELECT @@global.partial_revokes")
            same = root(UPGRADE, f"SHOW CREATE VIEW {VIEW}") == ddl
            print(
                f"  DV9  {image}: {release}; partial_revokes {partial};"
                f" view text as 8.0 gave it: {same}"
            )
            for user in ("limit", "unbound", "revoke", "roll", "plain"):
                print(f"  DV9    {P}{user}: {row(UPGRADE, P + user)}")
        check_leaks(UPGRADE)
    finally:
        upgrade_clean()


def main() -> int:
    """Run the probe on each server, then DV9. Exit 1 when a step fails or a value leaks."""
    failed = False
    for service in ch.SERVICES:
        try:
            probe(service)
        except (ch.StepError, ValueError) as exc:
            print(f"STEP FAILED: {service}: {type(exc).__name__}: {exc}")
            failed = True
    try:
        dv9()
    except (ch.StepError, ValueError) as exc:
        print(f"STEP FAILED: DV9: {type(exc).__name__}: {exc}")
        failed = True
    if LEAKED:
        print(f"\nA STORED VALUE REACHED THE TOOL ACCOUNT on {', '.join(LEAKED)}")
    print("\nA STEP FAILED" if failed else "\nevery step ran; no result is checked")
    return 1 if failed or LEAKED else 0


if __name__ == "__main__":
    sys.exit(main())
