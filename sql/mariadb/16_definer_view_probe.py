"""sopuli-dba : the optional definer view on MariaDB

#1479, the first step of #1457. The maintainer decided on 2026-11-12 that the
tool may read an optional, read-only view that a DBA creates with SQL SECURITY
DEFINER over mysql.global_priv, found by a fixed name and probed as a
capability, with its columns checked every session. 15_report_read_probe.py
(#1448) showed that such a view reads the lock, the lifetime and the last
change. This measures what that probe did not. The tool account holds the
grants of 02-mariadb-privileges.md §2.1 and SELECT on the view, unless a step
says otherwise. Root creates the view:

    CREATE SQL SECURITY DEFINER VIEW sopuli_probe.account_state AS
    SELECT User, Host,
           JSON_VALUE(Priv, '$.account_locked')        AS account_locked,
           JSON_VALUE(Priv, '$.password_lifetime')     AS password_lifetime,
           JSON_VALUE(Priv, '$.password_last_changed') AS password_last_changed,
           COALESCE(JSON_LENGTH(Priv, '$.auth_or'), 0) > 1 AS rollover_open
      FROM mysql.global_priv

  DV1  the view: what root reads of JSON_EXISTS, JSON_EXTRACT and JSON_LENGTH
       on Priv's auth_or, for an account never in a rollover, during one and
       after it is closed (DV3 sends the statements). Then whether anything
       the tool account reads through the view, in any step, holds a stored
       value: its rows, SHOW CREATE VIEW, information_schema.VIEWS, EXPLAIN,
       and every error message. Root reads the fixture's stored values to
       compare and the probe prints only whether one was found
  DV2  the lock, LK2: account_locked through the view for an account never
       locked, after the tool account's ACCOUNT LOCK and ACCOUNT UNLOCK, and
       for one created with ACCOUNT LOCK
  DV3  an open rollover, DP4: rollover_open before a rollover, after the
       tool account's IDENTIFIED VIA ... USING ... OR ..., after PASSWORD
       EXPIRE during it, and after the close with the current value alone
  DV4  the lifetime and the last change, RD1, and `report history`'s date:
       password_lifetime for INTERVAL 90 DAY, NEVER, the default and an
       account created with PASSWORD EXPIRE. password_last_changed against
       the server's UNIX_TIMESTAMP(), after a change by value, after PASSWORD
       EXPIRE and after a second change by value. Each step waits over a
       second first
  DV5  the failed-login block, LK4/RD6: Priv's keys, as root reads them with
       JSON_KEYS, before and after max_password_errors = 2 blocks an account,
       and what the view gives for it
  DV6  the shape check: the view's columns as the tool account reads them
       from information_schema.COLUMNS and SHOW COLUMNS. Then a view with an
       extra authentication_string column, granted to the tool account whole
       and then by a column grant on User and Host only. No row of it is read
  DV7  the capability probe: what the tool account gets from a SELECT and
       from information_schema.COLUMNS when the view is absent from an
       existing schema, when the schema is absent, when the view exists
       without the grant, and when its definer has been dropped
  DV8  the cost, #1457 Q5: how many rows the view gives against
       mysql.global_priv's, with roles and root. Whether the tool account can
       CREATE VIEW over it, CREATE PROCEDURE, CREATE TRIGGER, or UPDATE it. A
       column grant on part of the view. WITH CHECK OPTION. A definer that is
       a locked account holding only SELECT on mysql.global_priv. And a DBA
       with every privilege on sopuli_probe.* and SELECT on mysql.global_priv,
       without SET USER or SUPER: CREATE DEFINER = root@localhost VIEW, and
       the same view with itself as the definer
  DV9  upgrades: a volume of its own, run on mariadb:10.11 with the fixture
       of DV2 to DV4 and the view, then started on mariadb:11.4, 11.8 and
       12.3 in turn with MARIADB_AUTO_UPGRADE=1. After each start: the
       upgrade file the image's entrypoint wrote, whether SHOW CREATE VIEW,
       as root, is the text 10.11 gave, and what the tool account reads
       through the view

The fixture, which root creates on each server, all at '%' unless named:

  sopuli_probe_tool         the tool account, with §2.1's grants
  sopuli_probe_dv_plain     created with a password, nothing else
  sopuli_probe_dv_lock      for DV2
  sopuli_probe_dv_born_lock created with ACCOUNT LOCK
  sopuli_probe_dv_roll      for DV3
  sopuli_probe_dv_life90    PASSWORD EXPIRE INTERVAL 90 DAY
  sopuli_probe_dv_never     PASSWORD EXPIRE NEVER
  sopuli_probe_dv_born_exp  created with PASSWORD EXPIRE
  sopuli_probe_dv_block     for DV5
  sopuli_probe_dv_dba       DV8's DBA
  sopuli_probe_dv_definer   @localhost, ACCOUNT LOCK, SELECT on
                            mysql.global_priv: DV8's and DV7's definer
  sopuli_probe_dv_role      a role
  schema sopuli_probe, with table t and the views

It MEASURES and decides nothing. It prints no stored value: root reads them
only to look for them in what the tool account reads.

It prints each result and checks none against RESULTS below: compare a new
run with RESULTS by eye. It exits 1 only when a step fails, or when a stored
value is found in what the tool account read.

STATUS: run on 10.11.19, 11.4.13, 11.8.9 and 12.3.3, the mariadb:10.11,
mariadb:11.4, mariadb:11.8 and mariadb:12.3 images of test/compose.yaml
profile mariadb-matrix, on 2026-11-12 (#1479), with Python 3.13.12 on Windows
11 AMD64. Twice, exit 0, the same result both times but for the times of the
last change. The first run did not yet have DV7's message and the definer
created again, or DV8's read after root's grant.

RESULTS -- the same on every release, except where noted

  DV1  for an account never in a rollover, JSON_EXISTS, JSON_EXTRACT IS NOT
       NULL and JSON_LENGTH on auth_or give 0, 0 and NULL. During a rollover
       they give 1, 1 and 2. **After the close they give 1, 1 and 1**: the
       close leaves auth_or as an array of one empty entry. So whether the
       key exists is not the flag; JSON_LENGTH(...) > 1 is, and the view's
       rollover_open gives 0, 1 and 0. The tool account is refused SHOW
       CREATE VIEW, 1142 (42000), and EXPLAIN, 1345 (HY000).
       information_schema.VIEWS shows it the view's row with an empty
       VIEW_DEFINITION and SECURITY_TYPE DEFINER. No stored value of the
       fixture was in anything the tool account read: 110 outputs, rows and
       refusals, against 7 values
  DV2  account_locked is NULL for an account never locked, 1 after ACCOUNT
       LOCK, **0 after ACCOUNT UNLOCK**, and 1 for an account created with
       ACCOUNT LOCK. The tool account's own ACCOUNT LOCK and UNLOCK run, and
       the view follows each
  DV3  rollover_open is 0 before, 1 after the tool account's OR, still 1
       after PASSWORD EXPIRE during it, 0 after the close with the current
       value alone, and the same again for a second rollover. PASSWORD EXPIRE
       sets password_lifetime to -1 and password_last_changed to 0; the close
       sets a new time and leaves the lifetime at -1
  DV4  password_lifetime is NULL for an account created with neither, 90
       for INTERVAL 90 DAY, 0 for NEVER, and -1 for one created with PASSWORD
       EXPIRE. password_last_changed is seconds since 1970 by the server's
       clock: 0 to 7 s before UNIX_TIMESTAMP() just after the change. It
       moves with a change by value, PASSWORD EXPIRE sets it to 0, and a
       second change by value sets a new time. ACCOUNT LOCK and a lifetime
       of 30 days leave it. An account created with PASSWORD EXPIRE reads 0,
       and a time after its first change by value
  DV5  Priv's keys are access, version_id, plugin, authentication_string and
       password_last_changed, before the block and while blocked: three
       wrong passwords give 1045, 1045 and 4150, and the right one 4150. The
       view shows nothing of the block. On 11.8.9 and 12.3.3 root reads
       PASSWORD_ERRORS 2 in information_schema.USERS. So the view does not
       close LK4/RD6
  DV6  information_schema.COLUMNS and SHOW COLUMNS give the tool account the
       six columns, in order. For the wide view granted whole, both give the
       seven, authentication_string last, without a row read. **With a
       column grant on User and Host only, both give User and Host**: the
       columns the tool account may read, not the columns the view has
  DV7  a view absent from an existing schema, a schema absent, and a view
       without the grant all answer the SELECT 1142 (42000) and give 0
       COLUMNS rows: the tool account cannot tell them apart. A view whose
       definer is a locked account holding only SELECT on mysql.global_priv
       reads, with every column. **When the definer is dropped, the SELECT
       answers 1045 (28000), "Access denied for user
       'sopuli_probe_tool'@'%' (using password: YES)"**, in a session that
       is logged in, and COLUMNS still gives 6 rows. When the definer exists
       without SELECT on global_priv, the SELECT answers 1356 (HY000), and
       COLUMNS gives 6 rows
  DV8  the view gives every row of mysql.global_priv, 19 on 19 in the second
       run, roles at an empty host and root's two among them, and no other
       column. The tool account's CREATE VIEW over it is refused, 1142
       (42000), CREATE PROCEDURE 1044 (42000), CREATE TRIGGER 1419 (HY000)
       (the matrix has the binary log on), and UPDATE of the view 1142
       (42000). With a column grant on User, Host and account_locked, those
       read, password_lifetime is refused 1143 (42000) and SELECT * 1142
       (42000). WITH CHECK OPTION is accepted. The DBA without SET USER or
       SUPER is refused CREATE DEFINER = root@localhost VIEW, 1227 (42000);
       its CREATE VIEW with itself as the definer runs, its GRANT to the
       tool account is refused 1142 (42000) (it has no GRANT OPTION), and
       after root's grant the tool account reads the view
  DV9  on one volume, 10.11.19, then 11.4.13, 11.8.9 and 12.3.3, each with
       its upgrade file naming the release: SHOW CREATE VIEW is the text
       10.11 gave, and the view reads the same for each account: locked 1,
       the open rollover 1, lifetime 90, the expired account's -1 and 0, and
       the same time of the last change

  So the view gives the lock, an open rollover, the lifetime and the last
  change on every release, through upgrades, and nothing of a failed-login
  block. It holds no stored value, and the tool account cannot reach past
  it. Its shape is checkable from information_schema.COLUMNS, but only for
  the columns the tool account may read. "Absent" and "not granted" answer
  the same; a broken definer answers 1045 or 1356.

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mariadb/16_definer_view_probe.py

It needs 02_client_hash_probe.py and 15_report_read_probe.py beside it, and
what 02 needs: sql/mysql/02_client_hash_probe.py. DV9 needs the four images
pulled and docker run; it uses the container {COMPOSE_PROJECT_NAME}-dv-upgrade-1
and the volume {COMPOSE_PROJECT_NAME}-dv-upgrade, and removes both.

THROWAWAY SERVERS ONLY. It creates the accounts, role and schema above and
drops them at the end. It sets max_password_errors for DV5 and puts it back,
also after a failed step. Before it starts, it drops what an interrupted run
left.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
import time
from pathlib import Path


def _load(name: str, file: str):  # type: ignore[no-untyped-def]
    # The probes' names start with a digit, so they are loaded by path.
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rr = _load("mariadb_report_read_probe", "15_report_read_probe.py")
ch = rr.ch

TOOL = rr.TOOL
SCHEMA = "sopuli_probe"
VIEW = f"{SCHEMA}.account_state"
#: A test password, not a credential.
PASSWORD = "Acme-View-pw1"
P = "sopuli_probe_dv_"
FIXTURE_LIKE = "'sopuli\\_probe\\_%'"
COLUMNS = (
    "User, Host,"
    " JSON_VALUE(Priv, '$.account_locked') AS account_locked,"
    " JSON_VALUE(Priv, '$.password_lifetime') AS password_lifetime,"
    " JSON_VALUE(Priv, '$.password_last_changed') AS password_last_changed,"
    " COALESCE(JSON_LENGTH(Priv, '$.auth_or'), 0) > 1 AS rollover_open"
)
VIEW_SQL = f"SELECT {COLUMNS} FROM mysql.global_priv"
DEFINER = f"'{P}definer'@'localhost'"

#: Everything the tool account read on this server, refusals included, to
#: look for a stored value in at the end.
SEEN: list[str] = []
#: The fixture's stored values, as root reads them after each change. Never printed.
STORED: set[str] = set()
LEAKED: list[str] = []


def tool(service: str, statement: str) -> str:
    """What the tool account reads, or the refusal's error number and SQLSTATE."""
    returncode, out, err = ch.client(service, ch.TOOL, ch.TOOL_PASSWORD, statement, "-h127.0.0.1")
    SEEN.append(out)
    SEEN.append(err)
    if returncode == 0:
        return out
    found = re.search(r"^ERROR (\d+ \(\w+\))", err, re.MULTILINE)
    if found is None:
        raise ch.StepError(f"{service}: tool account: {(err or out)[:200]}")
    return found[1]


def as_account(service: str, user: str, statement: str, host: str = "%") -> str:
    """`ok` and the output, or the refusal's code, for another fixture account."""
    returncode, out, err = ch.client(service, user, PASSWORD, statement, "-h127.0.0.1")
    if returncode == 0:
        return f"ok {out}".strip()
    found = re.search(r"^ERROR (\d+ \(\w+\))", err, re.MULTILINE)
    if found is None:
        raise ch.StepError(f"{service}: {user}: {(err or out)[:200]}")
    return found[1]


def root(service: str, statement: str) -> str:
    return str(ch.root(service, statement))


def lines(text: str) -> list[str]:
    return [line.replace("\t", " | ") for line in text.splitlines() if line]


def remember(service: str) -> None:
    """Add the fixture's stored values, as they are now, to STORED."""
    rows = root(
        service,
        f"SELECT Priv FROM mysql.global_priv WHERE User LIKE {FIXTURE_LIKE}",
    )
    for row in rows.splitlines():
        for value in re.findall(r'"authentication_string":"([^"]+)"', row):
            STORED.add(value)


def row(service: str, user: str, view: str = VIEW, host: str = "%") -> str:
    """The view's row for one account, as the tool account reads it."""
    out = tool(
        service,
        "SELECT CONCAT('locked=', COALESCE(account_locked, 'NULL'),"
        " ' lifetime=', COALESCE(password_lifetime, 'NULL'),"
        " ' last=', COALESCE(password_last_changed, 'NULL'),"
        " ' rollover_open=', rollover_open)"
        f" FROM {view} WHERE User = '{user}' AND Host = '{host}'",
    )
    return out or "no row"


def last_changed(service: str, user: str) -> str:
    return tool(
        service,
        f"SELECT COALESCE(password_last_changed, 'NULL') FROM {VIEW}"
        f" WHERE User = '{user}' AND Host = '%'",
    )


def age(service: str, value: str) -> str:
    """How the last change compares with the server's clock, in words."""
    if not value.isdigit():
        return value
    if value == "0":
        return "0"
    now = int(root(service, "SELECT UNIX_TIMESTAMP()"))
    return f"a time {now - int(value)} s before UNIX_TIMESTAMP()"


def clean(service: str) -> None:
    """Drop what this probe creates, whatever an earlier run left."""
    found = root(
        service,
        "SELECT GROUP_CONCAT(CONCAT(QUOTE(User), '@', QUOTE(Host))) FROM mysql.user"
        f" WHERE User LIKE {FIXTURE_LIKE} AND is_role = 'N'",
    )
    if found and found != "NULL":
        root(service, f"DROP USER {found}")
    roles = root(
        service,
        "SELECT GROUP_CONCAT(QUOTE(User)) FROM mysql.user"
        f" WHERE User LIKE {FIXTURE_LIKE} AND is_role = 'Y'",
    )
    if roles not in ("", "NULL"):
        root(service, f"DROP ROLE {roles}")
    root(service, f"DROP DATABASE IF EXISTS {SCHEMA}")


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
                create(f"{P}lock"),
                create(f"{P}born_lock", "ACCOUNT LOCK"),
                create(f"{P}roll"),
                create(f"{P}life90", "PASSWORD EXPIRE INTERVAL 90 DAY"),
                create(f"{P}never", "PASSWORD EXPIRE NEVER"),
                create(f"{P}born_exp", "PASSWORD EXPIRE"),
                create(f"{P}block"),
                create(f"{P}dba"),
                f"GRANT ALL PRIVILEGES ON {SCHEMA}.* TO '{P}dba'@'%'",
                f"GRANT SELECT ON mysql.global_priv TO '{P}dba'@'%'",
                f"CREATE USER {DEFINER} IDENTIFIED BY {ch.quote(PASSWORD)} ACCOUNT LOCK",
                f"GRANT SELECT ON mysql.global_priv TO {DEFINER}",
                f"CREATE ROLE {P}role",
                f"CREATE SQL SECURITY DEFINER VIEW {VIEW} AS {VIEW_SQL}",
                f"GRANT SELECT ON {VIEW} TO {TOOL}",
            ]
        ),
    )
    remember(service)


# ------------------------------------------------------------------ steps --


def auth_or(service: str, user: str) -> str:
    """DV1: what root reads of the auth_or key, never its values."""
    return root(
        service,
        "SELECT CONCAT('JSON_EXISTS=', COALESCE(JSON_EXISTS(Priv, '$.auth_or'), 'NULL'),"
        " ' JSON_EXTRACT IS NOT NULL=', JSON_EXTRACT(Priv, '$.auth_or') IS NOT NULL,"
        " ' JSON_LENGTH=', COALESCE(JSON_LENGTH(Priv, '$.auth_or'), 'NULL'))"
        f" FROM mysql.global_priv WHERE User = '{user}' AND Host = '%'",
    )


def dv1(service: str) -> None:
    print(f"  DV1  view columns, as the tool account reads one row: {row(service, P + 'plain')}")
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
    account = f"'{P}lock'@'%'"
    print(f"  DV2  never locked: {row(service, P + 'lock')}")
    for statement in ("ACCOUNT LOCK", "ACCOUNT UNLOCK", "ACCOUNT LOCK", "ACCOUNT UNLOCK"):
        answer = ch.as_tool(service, f"ALTER USER {account} {statement}")
        print(f"  DV2  after the tool account's {statement} ({answer}): {row(service, P + 'lock')}")
    print(f"  DV2  created with ACCOUNT LOCK: {row(service, P + 'born_lock')}")


def dv3(service: str) -> None:
    user = f"{P}roll"
    account = f"'{user}'@'%'"
    first, second = ch.native_hash("Acme-View-pw2"), ch.native_hash("Acme-View-pw3")
    print(f"  DV3  never in a rollover: {row(service, user)}; root: {auth_or(service, user)}")
    steps = (
        ("the tool account's rollover with OR",
         f"ALTER USER {account} IDENTIFIED VIA mysql_native_password USING '{second}'"
         f" OR mysql_native_password USING '{first}'"),
        ("PASSWORD EXPIRE during it", f"ALTER USER {account} PASSWORD EXPIRE"),
        ("the close, the current value alone",
         f"ALTER USER {account} IDENTIFIED VIA mysql_native_password USING '{second}'"),
        ("a second rollover with OR",
         f"ALTER USER {account} IDENTIFIED VIA mysql_native_password USING '{first}'"
         f" OR mysql_native_password USING '{second}'"),
        ("its close", f"ALTER USER {account} IDENTIFIED VIA mysql_native_password USING '{first}'"),
    )  # fmt: skip
    for label, statement in steps:
        answer = ch.as_tool(service, statement)
        remember(service)
        print(
            f"  DV3  after {label} ({answer}): {row(service, user)}; root: {auth_or(service, user)}"
        )


def dv4(service: str) -> None:
    for user in ("plain", "life90", "never", "born_exp"):
        print(f"  DV4  {P}{user}: {row(service, P + user)}")
    user = f"{P}plain"
    account = f"'{user}'@'%'"
    steps = (
        ("a change by value",
         f"ALTER USER {account} IDENTIFIED VIA mysql_native_password USING"
         f" '{ch.native_hash('Acme-View-pw4')}'"),
        ("PASSWORD EXPIRE", f"ALTER USER {account} PASSWORD EXPIRE"),
        ("a second change by value",
         f"ALTER USER {account} IDENTIFIED VIA mysql_native_password USING"
         f" '{ch.native_hash('Acme-View-pw5')}'"),
        ("ACCOUNT LOCK", f"ALTER USER {account} ACCOUNT LOCK"),
        ("a lifetime of 30 days", f"ALTER USER {account} PASSWORD EXPIRE INTERVAL 30 DAY"),
    )  # fmt: skip
    last = last_changed(service, user)
    print(f"  DV4  {user} last change, before: {age(service, last)}")
    for label, statement in steps:
        time.sleep(1.2)
        answer = ch.as_tool(service, statement)
        remember(service)
        now = last_changed(service, user)
        print(f"  DV4  after {label} ({answer}): {age(service, now)}; moved: {now != last}")
        last = now
    exp = f"{P}born_exp"
    time.sleep(1.2)
    answer = ch.as_tool(
        service,
        f"ALTER USER '{exp}'@'%' IDENTIFIED VIA mysql_native_password USING"
        f" '{ch.native_hash('Acme-View-pw6')}'",
    )
    remember(service)
    print(
        f"  DV4  {exp}, after a change by value ({answer}):"
        f" {age(service, last_changed(service, exp))}; {row(service, exp)}"
    )


def keys(service: str, user: str) -> str:
    return root(
        service,
        f"SELECT JSON_KEYS(Priv) FROM mysql.global_priv WHERE User = '{user}' AND Host = '%'",
    )


def dv5(service: str) -> None:
    user = f"{P}block"
    print(f"  DV5  Priv's keys before: {keys(service, user)}")
    was = root(service, "SELECT @@global.max_password_errors")
    root(service, "SET GLOBAL max_password_errors = 2")
    try:
        answers = [ch.login(service, ch.WRONG, user) for _ in range(3)]
        right = ch.login(service, PASSWORD, user)
        print(f"  DV5  three wrong passwords: {', '.join(answers)}; the right one: {right}")
        print(f"  DV5  Priv's keys while blocked: {keys(service, user)}")
        print(f"  DV5  the view while blocked: {row(service, user)}")
        if rr.has_users(service):
            errors = root(
                service,
                "SELECT PASSWORD_ERRORS FROM information_schema.USERS"
                f" WHERE USER = \"'{user}'@'%'\"",
            )
            print(f"  DV5  information_schema.USERS PASSWORD_ERRORS, as root: {errors}")
    finally:
        root(service, f"SET GLOBAL max_password_errors = {was}")
        root(service, "FLUSH PRIVILEGES")


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
        f"CREATE SQL SECURITY DEFINER VIEW {SCHEMA}.account_state_wide AS SELECT {COLUMNS},"
        " JSON_VALUE(Priv, '$.authentication_string') AS authentication_string"
        " FROM mysql.global_priv;"
        f"GRANT SELECT ON {SCHEMA}.account_state_wide TO {TOOL}",
    )
    print(f"  DV6  wide view, granted whole, COLUMNS: {columns(service, 'account_state_wide')}")
    print(
        "  DV6  wide view, granted whole, SHOW COLUMNS:"
        f" {show_columns(service, 'account_state_wide')}"
    )
    root(
        service,
        f"REVOKE SELECT ON {SCHEMA}.account_state_wide FROM {TOOL};"
        f"GRANT SELECT (User, Host) ON {SCHEMA}.account_state_wide TO {TOOL}",
    )
    print(
        "  DV6  wide view, column grant on User and Host, COLUMNS:"
        f" {columns(service, 'account_state_wide')}"
    )
    print(
        "  DV6  wide view, column grant on User and Host, SHOW COLUMNS:"
        f" {show_columns(service, 'account_state_wide')}"
    )
    root(service, f"DROP VIEW {SCHEMA}.account_state_wide")


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
        "  DV7  definer locked, SELECT on global_priv only:"
        f" {probe_read(service, SCHEMA + '.by_definer')}"
    )
    print(f"  DV7  its row for {P}plain: {row(service, P + 'plain', SCHEMA + '.by_definer')}")
    root(service, f"DROP USER {DEFINER}")
    print(f"  DV7  definer dropped: {probe_read(service, SCHEMA + '.by_definer')}")
    answer = ch.as_tool(service, f"SELECT COUNT(*) FROM {SCHEMA}.by_definer")
    print(f"  DV7  definer dropped, the message: {answer}")
    root(service, f"CREATE USER {DEFINER} IDENTIFIED BY {ch.quote(PASSWORD)} ACCOUNT LOCK")
    print(
        "  DV7  definer created again, without SELECT on global_priv:"
        f" {probe_read(service, SCHEMA + '.by_definer')}"
    )


def dv8(service: str) -> None:
    rows = tool(service, f"SELECT COUNT(*) FROM {VIEW}")
    total = root(service, "SELECT COUNT(*) FROM mysql.global_priv")
    roles = tool(service, f"SELECT COUNT(*) FROM {VIEW} WHERE Host = ''")
    has_root = tool(service, f"SELECT COUNT(*) FROM {VIEW} WHERE User = 'root'")
    print(
        f"  DV8  the view's rows: {rows} of global_priv's {total};"
        f" at an empty host: {roles}; root: {has_root}"
    )
    attempts = {
        "CREATE VIEW over it": f"CREATE VIEW {SCHEMA}.mine AS SELECT * FROM {VIEW}",
        "CREATE PROCEDURE": f"CREATE PROCEDURE {SCHEMA}.mine() SELECT * FROM {VIEW}",
        "CREATE TRIGGER": f"CREATE TRIGGER {SCHEMA}.mine BEFORE INSERT ON {SCHEMA}.t"
        " FOR EACH ROW SET @x = 1",
        "UPDATE the view": f"UPDATE {VIEW} SET account_locked = NULL",
    }
    for label, statement in attempts.items():
        print(f"  DV8  the tool account's {label}: {ch.as_tool(service, statement)}")
    root(
        service,
        f"CREATE SQL SECURITY DEFINER VIEW {SCHEMA}.cols AS {VIEW_SQL};"
        f"GRANT SELECT (User, Host, account_locked) ON {SCHEMA}.cols TO {TOOL}",
    )
    part = tool(service, f"SELECT COUNT(account_locked) FROM {SCHEMA}.cols")
    rest = tool(service, f"SELECT password_lifetime FROM {SCHEMA}.cols LIMIT 0")
    star = tool(service, f"SELECT * FROM {SCHEMA}.cols LIMIT 0")
    print(
        f"  DV8  a column grant on User, Host, account_locked: those read ({part} locked);"
        f" password_lifetime: {rest or 'read'}; SELECT *: {star or 'read'}"
    )
    ok, answer = ch.mysql(
        service,
        "root",
        ch.ROOT_PASSWORD,
        f"CREATE SQL SECURITY DEFINER VIEW {SCHEMA}.checked AS {VIEW_SQL} WITH CHECK OPTION",
    )
    print(f"  DV8  WITH CHECK OPTION: {'accepted' if ok else ch.code(answer)}")
    dba = f"{P}dba"
    as_root_definer = as_account(
        service,
        dba,
        f"CREATE DEFINER = 'root'@'localhost' SQL SECURITY DEFINER VIEW {SCHEMA}.by_dba_root"
        f" AS {VIEW_SQL}",
    )
    print(f"  DV8  the DBA's CREATE DEFINER = root@localhost VIEW: {as_root_definer}")
    as_self = as_account(
        service, dba, f"CREATE SQL SECURITY DEFINER VIEW {SCHEMA}.by_dba AS {VIEW_SQL}"
    )
    print(f"  DV8  the DBA's CREATE VIEW, itself the definer: {as_self}")
    grant = as_account(service, dba, f"GRANT SELECT ON {SCHEMA}.by_dba TO {TOOL}")
    print(f"  DV8  the DBA's GRANT SELECT on it to the tool account: {grant}")
    root(service, f"GRANT SELECT ON {SCHEMA}.by_dba TO {TOOL}")
    print(
        "  DV8  root's grant on it, then the tool account reads:"
        f" {row(service, P + 'plain', SCHEMA + '.by_dba')}"
    )


def check_leaks(service: str) -> None:
    remember(service)
    found = [value for value in STORED if any(value in text for text in SEEN)]
    print(
        f"  DV1  stored values in anything the tool account read ({len(SEEN)} outputs,"
        f" {len(STORED)} values): {len(found) or 'none'}"
    )
    if found:
        LEAKED.append(service)


def probe(service: str) -> None:
    release = root(service, "SELECT VERSION()")
    print(f"\n== {service}: {release}")
    SEEN.clear()
    STORED.clear()
    clean(service)
    try:
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
    finally:
        clean(service)


# --------------------------------------------------------------- upgrades --

UPGRADE = "dv-upgrade"
IMAGES = ("mariadb:10.11", "mariadb:11.4", "mariadb:11.8", "mariadb:12.3")


def docker(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=False)


def upgrade_names() -> tuple[str, str]:
    return ch.base.container(UPGRADE), f"{ch.base.PROJECT}-{UPGRADE}"


def upgrade_clean() -> None:
    container, volume = upgrade_names()
    docker("rm", "-f", container)
    docker("volume", "rm", "-f", volume)


def start(image: str) -> None:
    container, volume = upgrade_names()
    docker("rm", "-f", container)
    started = docker(
        "run", "-d", "--name", container, "-v", f"{volume}:/var/lib/mysql",
        "-e", f"MARIADB_ROOT_PASSWORD={ch.ROOT_PASSWORD}", "-e", "MARIADB_AUTO_UPGRADE=1",
        image,
    )  # fmt: skip
    if started.returncode:
        raise ch.StepError(f"docker run {image}: {started.stderr.strip()[:200]}")
    for _ in range(90):
        time.sleep(2)
        ready = docker("exec", container, "healthcheck.sh", "--connect", "--innodb_initialized")
        if ready.returncode == 0:
            # The entrypoint starts a temporary server first; wait for the real one.
            time.sleep(3)
            ready = docker("exec", container, "healthcheck.sh", "--connect", "--innodb_initialized")
            if ready.returncode == 0:
                return
    raise ch.StepError(
        f"{image}: not healthy after 3 minutes:"
        f" {docker('logs', '--tail', '5', container).stderr[-300:]}"
    )


def dv9() -> None:
    print(f"\n== DV9: upgrades, {' > '.join(IMAGES)}")
    upgrade_clean()
    try:
        start(IMAGES[0])
        setup(UPGRADE)
        lock, roll = f"'{P}lock'@'%'", f"'{P}roll'@'%'"
        first, second = ch.native_hash("Acme-View-pw2"), ch.native_hash("Acme-View-pw3")
        root(
            UPGRADE,
            f"ALTER USER {lock} ACCOUNT LOCK;"
            f"ALTER USER {roll} IDENTIFIED VIA mysql_native_password USING '{second}'"
            f" OR mysql_native_password USING '{first}'",
        )
        ddl = root(UPGRADE, f"SHOW CREATE VIEW {VIEW}")
        container, _ = upgrade_names()
        for image in IMAGES:
            if image != IMAGES[0]:
                docker("stop", "-t", "30", container)
                start(image)
            release = root(UPGRADE, "SELECT VERSION()")
            info = docker(
                "exec", container, "sh", "-c", "cat /var/lib/mysql/*upgrade_info 2>/dev/null"
            ).stdout.strip()
            same = root(UPGRADE, f"SHOW CREATE VIEW {VIEW}") == ddl
            print(
                f"  DV9  {image}: {release}; upgrade file: {info or 'none'};"
                f" view text as 10.11 gave it: {same}"
            )
            for user in ("lock", "roll", "life90", "born_exp", "plain"):
                print(f"  DV9    {P}{user}: {row(UPGRADE, P + user)}")
    finally:
        upgrade_clean()


def main() -> int:
    """Run the probe on each server, then DV9. Exit 1 when a step fails or a value leaks."""
    failed = False
    for service in ch.base.SERVICES:
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
