"""sopuli-dba : what a read-only report login can read on SQL Server

#1538, M9. UC-5's reports list every login on a target, its server and
database roles and permissions, and its password and login dates. This
measures, for a reader login holding each candidate grant and nothing else,
what each read returns about one subject login:

  RP1  the login: its row in sys.server_principals, and in sys.sql_logins,
       with is_policy_checked and is_expiration_checked, and whether
       password_hash reads as a value or NULL
  RP2  its dates: LOGINPROPERTY's PasswordLastSetTime, BadPasswordTime and
       DaysUntilExpiration, as a value or NULL
  RP3  its server roles and permissions: its rows in sys.server_role_members
       and sys.server_permissions
  RP4  its database user, database roles and database permissions in a
       database the reader has no user in: its rows in that database's
       sys.database_principals, sys.database_role_members and
       sys.database_permissions, or the error that stops the read
  RP5  sessions: whether sys.dm_exec_sessions shows the reader a session not
       its own
  RP6  the error log: whether xp_readerrorlog runs for the reader
  RP7  the last login, as sa: whether the error log records the subject's
       good login and its failed one, with the images' default login
       auditing. No catalog view keeps a login's last login

The subject is a member of processadmin, holds VIEW SERVER STATE besides
CONNECT SQL, and has a user in the probe's database, in db_datareader and
granted SELECT on a table there. So RP3 can find 1 role row and 2 permission
rows, and RP4 1 user, 1 role row and 2 permission rows (CONNECT and SELECT).

The readers: no grant; ALTER ANY LOGIN, the tool's grant; VIEW ANY
DEFINITION; VIEW ANY SECURITY DEFINITION, where the release has it; VIEW
SERVER STATE; CONNECT ANY DATABASE; CONNECT ANY DATABASE with VIEW ANY
DEFINITION; and membership of securityadmin.

STATUS: run on 15.0.4510.2, 16.0.4325.4 and 17.0.5065.9, the
mcr.microsoft.com/mssql/server 2019-latest, 2022-latest and 2025-latest images
of test/compose.yaml profile mssql-matrix, as pulled on 2026-11-15, with
Python 3.13.12 on Windows 11 AMD64, on 2026-11-15 (#1538). Twice, exit 0, and
the same result every time.

RESULTS -- the same on every release that has the grant. 15.0.4510.2 has
neither VIEW ANY SECURITY DEFINITION nor VIEW ANY ERROR LOG: each GRANT is a
syntax error, 102

  RP1-3  a reader with no grant sees nothing of the subject: no row, NULL
       dates, no role or permission rows. **VIEW ANY DEFINITION alone reads
       all of RP1 to RP3**: the login, its policy flags, its dates, its 1
       role row and its 2 permission rows. So do ALTER ANY LOGIN, VIEW ANY
       SECURITY DEFINITION and securityadmin. password_hash reads NULL for
       every reader. VIEW SERVER STATE, CONNECT ANY DATABASE and VIEW ANY
       ERROR LOG alone read none of it
  RP4  every reader without CONNECT ANY DATABASE is refused the database,
       916, VIEW ANY DEFINITION and securityadmin included. CONNECT ANY
       DATABASE alone opens it and sees no row of the subject (0, 0, 0);
       **with VIEW ANY DEFINITION it reads them all** (1, 1, 2)
  RP5  only VIEW SERVER STATE shows another session
  RP6  xp_readerrorlog is refused to every reader, 229, securityadmin
       included. sp_readerrorlog runs for securityadmin, VIEW SERVER STATE
       and VIEW ANY ERROR LOG, and is refused to the others, 27219
  RP7  with the images' default auditing, the error log records the failed
       login and not the good one. So no source measured gives a login's
       last good login

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mssql/07_report_reads_probe.py

It needs 02_client_hash_probe.py beside it.

THROWAWAY SERVERS ONLY. It creates the logins sopuli_probe_rp_subject and
sopuli_probe_rp_<reader>, and the database sopuli_probe_rp, and drops them
at the end.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

# 02's name starts with a digit, so it is loaded by its path.
_SPEC = importlib.util.spec_from_file_location(
    "mssql_client_hash_probe", Path(__file__).with_name("02_client_hash_probe.py")
)
assert _SPEC is not None
assert _SPEC.loader is not None
ch = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ch)

SUBJECT = "sopuli_probe_rp_subject"
DATABASE = "sopuli_probe_rp"
#: Test passwords, not credentials.
PASSWORD = "Acme-Report-pw1"

#: Each reader's grant, by short name. The login is sopuli_probe_rp_<short>.
READERS = {
    "none": "",
    "tool": "GRANT ALTER ANY LOGIN TO [{name}]",
    "viewdef": "GRANT VIEW ANY DEFINITION TO [{name}]",
    "viewsec": "GRANT VIEW ANY SECURITY DEFINITION TO [{name}]",
    "viewstate": "GRANT VIEW SERVER STATE TO [{name}]",
    "connectany": "GRANT CONNECT ANY DATABASE TO [{name}]",
    "connectdef": ("GRANT CONNECT ANY DATABASE TO [{name}]; GRANT VIEW ANY DEFINITION TO [{name}]"),
    "errorlog": "GRANT VIEW ANY ERROR LOG TO [{name}]",
    "securityadmin": "ALTER SERVER ROLE securityadmin ADD MEMBER [{name}]",
}


def reader(short: str) -> str:
    return f"sopuli_probe_rp_{short}"


def subject_id(view: str) -> str:
    return f"(SELECT principal_id FROM {view} WHERE name = '{SUBJECT}')"


#: Each read, by label: a T-SQL expression of one value, or a statement run
#: by EXEC, whose success reads `ok`. A read that fails reads as its error
#: number.
DB = f"[{DATABASE}].sys"
READS: dict[str, str] = {
    "RP1 server_principals": (
        f"(SELECT COUNT(*) FROM sys.server_principals WHERE name = '{SUBJECT}')"
    ),
    "RP1 sql_logins": f"(SELECT COUNT(*) FROM sys.sql_logins WHERE name = '{SUBJECT}')",
    "RP1 policy flags": (
        "(SELECT CAST(is_policy_checked AS varchar(1)) + ',' "
        "+ CAST(is_expiration_checked AS varchar(1)) "
        f"FROM sys.sql_logins WHERE name = '{SUBJECT}')"
    ),
    "RP1 password_hash": (
        "(SELECT CASE WHEN password_hash IS NULL THEN 'NULL' ELSE 'value' END "
        f"FROM sys.sql_logins WHERE name = '{SUBJECT}')"
    ),
    **{
        f"RP2 {prop}": (
            f"(SELECT CASE WHEN LOGINPROPERTY('{SUBJECT}', '{prop}') IS NULL "
            "THEN 'NULL' ELSE 'value' END)"
        )
        for prop in ("PasswordLastSetTime", "BadPasswordTime", "DaysUntilExpiration")
    },
    "RP3 server_role_members": (
        "(SELECT COUNT(*) FROM sys.server_role_members "
        f"WHERE member_principal_id = {subject_id('sys.server_principals')})"
    ),
    "RP3 server_permissions": (
        "(SELECT COUNT(*) FROM sys.server_permissions "
        f"WHERE grantee_principal_id = {subject_id('sys.server_principals')})"
    ),
    "RP4 database_principals": (
        f"EXEC:SELECT @v = COUNT(*) FROM {DB}.database_principals WHERE name = '{SUBJECT}'"
    ),
    "RP4 database_role_members": (
        f"EXEC:SELECT @v = COUNT(*) FROM {DB}.database_role_members "
        f"WHERE member_principal_id = {subject_id(DB + '.database_principals')}"
    ),
    "RP4 database_permissions": (
        f"EXEC:SELECT @v = COUNT(*) FROM {DB}.database_permissions "
        f"WHERE grantee_principal_id = {subject_id(DB + '.database_principals')}"
    ),
    "RP5 other sessions": (
        "(SELECT CASE WHEN COUNT(*) > 0 THEN 'seen' ELSE 'none' END "
        "FROM sys.dm_exec_sessions WHERE session_id <> @@SPID)"
    ),
    "RP6 xp_readerrorlog": (
        "EXEC:DECLARE @log TABLE (d datetime, p nvarchar(64), t nvarchar(max)); "
        "INSERT INTO @log EXEC xp_readerrorlog 0, 1, N'sopuli'; SET @v = 0"
    ),
    "RP6 sp_readerrorlog": (
        "EXEC:DECLARE @log TABLE (d datetime, p nvarchar(64), t nvarchar(max)); "
        "INSERT INTO @log EXEC sp_readerrorlog 0, 1, N'sopuli'; SET @v = 0"
    ),
}


def batch() -> str:
    """One batch of every read, each in its own TRY, as `label|value` lines."""
    parts = []
    for label, read in READS.items():
        if read.startswith("EXEC:"):
            # Dynamic SQL, so that a database the reader cannot open is an
            # error the CATCH sees, not one that stops the whole batch.
            statement = read.removeprefix("EXEC:").replace("'", "''")
            body = (
                "SET @v = NULL; "
                f"EXEC sp_executesql N'{statement}', N'@v int OUTPUT', @v OUTPUT; "
                f"SELECT '{label}|' + CASE WHEN '{label}' LIKE 'RP6%' THEN 'ok' "
                "ELSE CAST(@v AS varchar(10)) END"
            )
        else:
            body = f"SELECT '{label}|' + ISNULL(CAST({read} AS varchar(32)), 'no row')"
        parts.append(
            f"BEGIN TRY {body}; END TRY "
            f"BEGIN CATCH SELECT '{label}|' + CAST(ERROR_NUMBER() AS varchar(10)); END CATCH;"
        )
    return "DECLARE @v int;\n" + "\n".join(parts)


def reads(service: str, login: str, password: str) -> dict[str, str]:
    out, errors = ch.client(service, login, password, batch())
    if errors:
        raise ch.StepError(f"{service}: {login}'s reads: {errors}")
    return dict(line.split("|", 1) for line in out.splitlines() if "|" in line)


def drop_all(service: str) -> None:
    ch.sa(
        service,
        f"IF DB_ID('{DATABASE}') IS NOT NULL BEGIN "
        f"ALTER DATABASE [{DATABASE}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; "
        f"DROP DATABASE [{DATABASE}] END;\n"
        + ";\n".join(ch.drop_login(name) for name in [SUBJECT, *map(reader, READERS)]),
    )


def setup(service: str) -> list[str]:
    """Create the subject and the readers; return the readers that could be made."""
    drop_all(service)
    q = ch.quote(PASSWORD)
    ch.sa(
        service,
        f"CREATE LOGIN [{SUBJECT}] WITH PASSWORD = {q}, CHECK_POLICY = ON, "
        "CHECK_EXPIRATION = ON;\n"
        f"ALTER SERVER ROLE processadmin ADD MEMBER [{SUBJECT}];\n"
        f"GRANT VIEW SERVER STATE TO [{SUBJECT}];\n"
        f"CREATE DATABASE [{DATABASE}];\n"
        + ";\n".join(
            f"CREATE LOGIN [{reader(short)}] WITH PASSWORD = {q}, CHECK_POLICY = OFF"
            for short in READERS
        ),
    )
    ch.sa(
        service,
        f"CREATE USER [{SUBJECT}] FOR LOGIN [{SUBJECT}];\n"
        f"ALTER ROLE db_datareader ADD MEMBER [{SUBJECT}];\n"
        "CREATE TABLE dbo.sopuli_probe_t (i int);\n"
        f"GRANT SELECT ON dbo.sopuli_probe_t TO [{SUBJECT}]",
        DATABASE,
    )
    made = []
    for short, grant in READERS.items():
        if grant:
            _, errors = ch.client(service, "sa", ch.SA_PASSWORD, grant.format(name=reader(short)))
            if errors:
                print(f"reader {short}: its grant is refused: {ch.code(errors)}")
                REFUSED[short] = ch.code(errors)
                continue
        made.append(short)
    return made


def last_login(service: str) -> dict[str, str]:
    """RP7: what the error log keeps of the subject's good and failed login."""
    _, errors = ch.client(service, SUBJECT, PASSWORD, "SELECT 1")
    if errors:
        raise ch.StepError(f"{service}: the subject's login: {errors}")
    _, errors = ch.client(service, SUBJECT, ch.WRONG, "SELECT 1")
    if not errors:
        raise ch.StepError(f"{service}: the subject logged in with a wrong password")
    found = {}
    for label, words in (("good", "Login succeeded"), ("failed", "Login failed")):
        count = ch.sa(
            service,
            "DECLARE @log TABLE (d datetime, p nvarchar(64), t nvarchar(max)); "
            f"INSERT INTO @log EXEC xp_readerrorlog 0, 1, N'{words}', N'{SUBJECT}'; "
            "SELECT CAST(COUNT(*) AS varchar(10)) FROM @log",
        )
        found[f"RP7 {label} login in the error log"] = (
            "recorded" if int(count) > 0 else "not recorded"
        )
    return found


def cases(service: str) -> None:
    found = ch.release(service)
    print(f"\n== {service}: {found}")
    made = setup(service)
    major = found.split(".")[0]
    for short in READERS:
        if short not in made:
            recorded = RECORDED_REFUSED.get((major, short))
            ch.check(f"{service} reader {short}", REFUSED[short], recorded)
            continue
        got = reads(service, reader(short), PASSWORD)
        for label in READS:
            value = got.get(label)
            print(f"{label} [{short}]: {value}")
            ch.check(f"{service} {short} {label}", value, RECORDED.get((short, label)))
    for label, value in last_login(service).items():
        print(f"{label}: {value}")
        ch.check(f"{service} {label}", value, RECORDED.get(("sa", label)))


def probe(service: str) -> None:
    ch.cleaned(service, lambda: cases(service), lambda: drop_all(service))


#: Each reader whose grant the server refused, on the server run last.
REFUSED: dict[str, str] = {}
#: The refused grants, by major release and reader: 15 has neither permission.
RECORDED_REFUSED = {("15", "viewsec"): "102", ("15", "errorlog"): "102"}

#: What a reader with no grant reads: nothing of the subject.
NOTHING = {
    "RP1 server_principals": "0",
    "RP1 sql_logins": "0",
    "RP1 policy flags": "no row",
    "RP1 password_hash": "no row",
    "RP2 PasswordLastSetTime": "NULL",
    "RP2 BadPasswordTime": "NULL",
    "RP2 DaysUntilExpiration": "NULL",
    "RP3 server_role_members": "0",
    "RP3 server_permissions": "0",
    "RP4 database_principals": "916",
    "RP4 database_role_members": "916",
    "RP4 database_permissions": "916",
    "RP5 other sessions": "none",
    "RP6 xp_readerrorlog": "229",
    "RP6 sp_readerrorlog": "27219",
}
#: What a reader that sees the server's metadata reads. password_hash stays NULL.
SERVER = {
    **NOTHING,
    "RP1 server_principals": "1",
    "RP1 sql_logins": "1",
    "RP1 policy flags": "1,1",
    "RP1 password_hash": "NULL",
    "RP2 PasswordLastSetTime": "value",
    "RP2 BadPasswordTime": "value",
    "RP2 DaysUntilExpiration": "value",
    "RP3 server_role_members": "1",
    "RP3 server_permissions": "2",
}
#: The database's rows, for a reader that can open it, and that is denied none.
DATABASE_ROWS = {
    "RP4 database_principals": "1",
    "RP4 database_role_members": "1",
    "RP4 database_permissions": "2",
}
ERROR_LOG = {"RP6 sp_readerrorlog": "ok"}
#: What each reader read, the same on every release that has its grant.
BY_READER: dict[str, dict[str, str]] = {
    "none": NOTHING,
    "tool": SERVER,
    "viewdef": SERVER,
    "viewsec": SERVER,
    "viewstate": {**NOTHING, "RP5 other sessions": "seen", **ERROR_LOG},
    # Opens the database, but sees no row of the subject without VIEW ANY
    # DEFINITION.
    "connectany": {**NOTHING, **dict.fromkeys(DATABASE_ROWS, "0")},
    "connectdef": {**SERVER, **DATABASE_ROWS},
    "errorlog": {**NOTHING, **ERROR_LOG},
    "securityadmin": {**SERVER, **ERROR_LOG},
}
RECORDED: dict[tuple[str, str], str] = {
    **{
        (short, label): value
        for short, reads in BY_READER.items()
        for label, value in reads.items()
    },
    ("sa", "RP7 good login in the error log"): "not recorded",
    ("sa", "RP7 failed login in the error log"): "recorded",
}


def main() -> int:
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
