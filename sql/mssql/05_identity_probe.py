"""sopuli-dba : accounts and server identity on SQL Server

#1538, M3. What an account is, how its name is compared, and what tells two
servers apart:

  ID1  login names: whether a second login whose name differs only in case
       can be created, and whether ALTER LOGIN reaches a login by another
       case of its name, under the server's collation
  ID2  what the tool login reads that could identify a server: @@SERVERNAME,
       SERVERPROPERTY's MachineName and ServerName, compared with the
       container's hostname, and the service_broker_guid of master and of
       msdb; and whether the servers' msdb values differ
  ID3  contained database users: with contained database authentication on,
       in a database with CONTAINMENT = PARTIAL, whether the tool, with ALTER
       ANY LOGIN, can set a contained user's password; whether a contained
       user granted ALTER ANY USER can, for an ordinary user and for a
       db_owner member; whether a HASHED value is accepted for one; and how
       the user logs in, naming its database and naming master
  ID4  a contained user and a login with the same name: whether both can
       exist, and which one a login to the contained database reaches
  ID5  msdb's service_broker_guid on a second container of each server's
       image, which the probe starts for this and removes

STATUS: run on 15.0.4510.2, 16.0.4325.4 and 17.0.5065.9, the
mcr.microsoft.com/mssql/server 2019-latest, 2022-latest and 2025-latest images
of test/compose.yaml profile mssql-matrix, as pulled on 2026-11-15, with
Python 3.13.12 on Windows 11 AMD64, on 2026-11-15 (#1538). Twice, exit 0, and
the same result every time.

RESULTS -- the same on every release

  ID1  the collation is SQL_Latin1_General_CP1_CI_AS, so login names compare
       without case: a second login that differs only in case is refused,
       15025, and ALTER LOGIN reaches the login by its name in upper case
  ID2  @@SERVERNAME, MachineName and ServerName are each the container's
       hostname. master's service_broker_guid is all zeros. msdb's differs
       between the three images
  ID5  but comes with the image: a second container of each image reads the
       same msdb value as the first. So nothing measured tells two servers
       of one image apart but the hostname, which docker chooses
  ID3  **ALTER ANY LOGIN does not reach a contained user.** The tool login
       cannot even open the contained database: "Cannot open database",
       18456. A contained user granted ALTER ANY USER sets an ordinary
       contained user's password, and is refused for a db_owner member,
       15151. The contained user logs in to its database, and is refused at
       master, 18456. ALTER USER ... WITH PASSWORD = 0x... HASHED is a
       syntax error, 102: there is no client-side value for a contained user
  ID4  a contained user may have a login's name. In its database the user
       wins: the user's password logs in, and the login's is refused, 18456.
       The login still logs in at master

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mssql/05_identity_probe.py

It needs 02_client_hash_probe.py beside it.

THROWAWAY SERVERS ONLY. It creates the logins sopuli_probe_tool,
sopuli_probe_hash, Sopuli_Probe_Case and sopuli_probe_twin, and the contained
database sopuli_probe_cdb with its users, and drops them at the end. It turns
on `contained database authentication` and sets it back to 0, the images'
default. ID5 starts a container `<server's container>-second` of each image,
with the matrix's sa password, and removes it.
"""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
import time
from pathlib import Path

# 02's name starts with a digit, so it is loaded by its path.
_SPEC = importlib.util.spec_from_file_location(
    "mssql_client_hash_probe", Path(__file__).with_name("02_client_hash_probe.py")
)
assert _SPEC is not None
assert _SPEC.loader is not None
ch = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ch)

CASED = "Sopuli_Probe_Case"
TWIN = "sopuli_probe_twin"
DATABASE = "sopuli_probe_cdb"
CONTAINED = "sopuli_probe_cuser"
#: A contained user in db_owner, and one granted ALTER ANY USER.
OWNER = "sopuli_probe_cowner"
KEEPER = "sopuli_probe_ckeeper"
#: Test passwords, not credentials.
FIRST = "Acme-Ident-pw1"
SECOND = "Acme-Ident-pw2"
LOGIN_SIDE = "Acme-Ident-login1"
USER_SIDE = "Acme-Ident-user1"


def drop_all(service: str) -> None:
    ch.sa(
        service,
        f"IF DB_ID('{DATABASE}') IS NOT NULL BEGIN "
        f"ALTER DATABASE [{DATABASE}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; "
        f"DROP DATABASE [{DATABASE}] END",
    )
    # CASED.lower() too, which ID1 creates where names compare with case. One
    # call each: drop_login's variable is named after the login, and two
    # names that differ only in case would clash under this collation.
    for name in (CASED, CASED.lower(), TWIN):
        ch.sa(service, ch.drop_login(name))


def restore(service: str) -> None:
    """Set `contained database authentication` back to 0, the images' default.

    Not to what the run read at its start, which an interrupted run may have
    left at 1.
    """
    ch.sa(service, "EXEC sp_configure 'contained database authentication', 0; RECONFIGURE")


def setting(service: str) -> str:
    return ch.sa(
        service,
        "SELECT CAST(value_in_use AS varchar(2)) FROM sys.configurations "
        "WHERE name = 'contained database authentication'",
    )


def tool_read(service: str, statement: str, database: str = "master") -> str:
    """The tool's output, `ok` for a statement with none, or the refusal."""
    out, errors = ch.client(service, ch.TOOL, ch.TOOL_PASSWORD, statement, database)
    return (out or "ok") if not errors else ch.code(errors)


def login_to(service: str, user: str, password: str, database: str) -> str:
    out, errors = ch.client(
        service, user, password, "SELECT SUSER_SNAME() + '|' + USER_NAME()", database
    )
    return out if not errors else ch.code(errors)


def probe(service: str) -> None:
    # The restore is a clean-up of its own: ch.cleaned() runs each clean-up even
    # when one before it fails, so a failed drop does not skip it.
    ch.cleaned(service, lambda: cases(service), lambda: drop_all(service), lambda: restore(service))


def cases(service: str) -> None:
    ch.setup(service)
    drop_all(service)
    before = setting(service)

    collation = tool_read(service, "SELECT CAST(SERVERPROPERTY('Collation') AS nvarchar(128))")
    ch.sa(service, f"CREATE LOGIN [{CASED}] WITH PASSWORD = N'{FIRST}', CHECK_POLICY = OFF")
    _, errors = ch.client(
        service,
        "sa",
        ch.SA_PASSWORD,
        f"CREATE LOGIN [{CASED.lower()}] WITH PASSWORD = N'{FIRST}', CHECK_POLICY = OFF",
    )
    other_case = ch.as_tool(service, f"ALTER LOGIN [{CASED.upper()}] WITH PASSWORD = N'{SECOND}'")
    reached = login_to(service, CASED, SECOND, "master")
    line = (
        f"ID1 collation {collation}; a second login in lower case: {ch.code(errors)}; "
        f"ALTER LOGIN in upper case: {other_case}; the login with the new password: {reached}"
    )
    print(line)
    ch.check("ID1", line, ID1)

    names, master, msdb = tool_read(
        service,
        "SELECT CAST(@@SERVERNAME AS nvarchar(128)) + ',' "
        "+ CAST(SERVERPROPERTY('MachineName') AS nvarchar(128)) + ',' "
        "+ CAST(SERVERPROPERTY('ServerName') AS nvarchar(128)) + '|' "
        "+ (SELECT CONVERT(nvarchar(36), service_broker_guid) FROM sys.databases "
        "WHERE name = 'master') + '|' "
        "+ (SELECT CONVERT(nvarchar(36), service_broker_guid) FROM sys.databases "
        "WHERE name = 'msdb')",
    ).split("|")
    found_name = hostname(service)
    same = set(names.split(",")) == {found_name}
    print(
        f"ID2 @@SERVERNAME, MachineName and ServerName are the container's hostname: {same}; "
        f"master's service_broker_guid {master}; msdb's {msdb}"
    )
    ch.check("ID2", (same, master), (True, "00000000-0000-0000-0000-000000000000"))
    MSDB[service] = msdb
    second = second_msdb(service)
    print(f"ID5 a second container of the image: msdb's service_broker_guid {second}")
    ch.check("ID5", second, msdb)

    # probe() drops what follows creates, and restores the setting, as its
    # clean-ups.
    ch.check("contained database authentication before the run", before, "0")
    ch.sa(
        service,
        "EXEC sp_configure 'contained database authentication', 1; RECONFIGURE;\n"
        f"CREATE DATABASE [{DATABASE}] CONTAINMENT = PARTIAL",
    )
    ch.sa(
        service,
        f"CREATE USER [{CONTAINED}] WITH PASSWORD = N'{FIRST}';\n"
        f"CREATE USER [{OWNER}] WITH PASSWORD = N'{FIRST}';\n"
        f"ALTER ROLE db_owner ADD MEMBER [{OWNER}];\n"
        f"CREATE USER [{KEEPER}] WITH PASSWORD = N'{FIRST}';\n"
        f"GRANT ALTER ANY USER TO [{KEEPER}]",
        DATABASE,
    )
    by_tool = tool_read(service, f"ALTER USER [{CONTAINED}] WITH PASSWORD = N'{SECOND}'", DATABASE)
    by_keeper = in_database(
        service, KEEPER, f"ALTER USER [{CONTAINED}] WITH PASSWORD = N'{SECOND}'"
    )
    owner = in_database(service, KEEPER, f"ALTER USER [{OWNER}] WITH PASSWORD = N'{SECOND}'")
    owner_in = login_to(service, OWNER, SECOND, DATABASE)
    with_db = login_to(service, CONTAINED, SECOND, DATABASE)
    without_db = login_to(service, CONTAINED, SECOND, "master")
    value = ch.password_hash(SECOND, ch.draw_salt())
    _, errors = ch.client(
        service,
        "sa",
        ch.SA_PASSWORD,
        f"ALTER USER [{CONTAINED}] WITH PASSWORD = 0x{value.hex()} HASHED",
        DATABASE,
    )
    line = (
        f"ID3 the tool login sets a contained user's password: {by_tool}; a contained "
        f"user with ALTER ANY USER: {by_keeper}; it sets a db_owner's: {owner}, which "
        f"logs in: {owner_in}; the user logs in to its database: {with_db}; to master: "
        f"{without_db}; HASHED: {ch.code(errors)}"
    )
    print(line)
    ch.check("ID3", line, ID3)

    ch.sa(service, f"CREATE LOGIN [{TWIN}] WITH PASSWORD = N'{LOGIN_SIDE}', CHECK_POLICY = OFF")
    _, errors = ch.client(
        service,
        "sa",
        ch.SA_PASSWORD,
        f"CREATE USER [{TWIN}] WITH PASSWORD = N'{USER_SIDE}'",
        DATABASE,
    )
    line = (
        f"ID4 a contained user named as a login: {ch.code(errors)}; to the database "
        f"with the user's password: {login_to(service, TWIN, USER_SIDE, DATABASE)}; with "
        f"the login's: {login_to(service, TWIN, LOGIN_SIDE, DATABASE)}; to master with "
        f"the login's: {login_to(service, TWIN, LOGIN_SIDE, 'master')}"
    )
    print(line)
    ch.check("ID4", line, ID4)


def in_database(service: str, user: str, statement: str) -> str:
    """`ok`, or the refusal, for a statement a contained user sends in its database."""
    _, errors = ch.client(service, user, FIRST, statement, DATABASE)
    return ch.code(errors)


def hostname(service: str) -> str:
    """The container's hostname, which docker sets."""
    done = subprocess.run(
        ["docker", "inspect", "-f", "{{.Config.Hostname}}", ch.container(service)],
        capture_output=True,
        check=False,
    )
    if done.returncode != 0:
        raise ch.StepError(f"{service}: docker inspect: {done.stderr[:200]!r}")
    return done.stdout.decode().strip()


#: The lines each release prints, where the line is the same on every release.
ID1 = (
    "ID1 collation SQL_Latin1_General_CP1_CI_AS; a second login in lower case: 15025; "
    "ALTER LOGIN in upper case: ok; the login with the new password: Sopuli_Probe_Case|guest"
)
ID3 = (
    "ID3 the tool login sets a contained user's password: \"Cannot open database "
    '"sopuli_probe_cdb" requested by the login",18456; a contained user with ALTER ANY '
    "USER: ok; it sets a db_owner's: 15151, which logs in: 18456; the user logs in to its "
    "database: sopuli_probe_cuser|sopuli_probe_cuser; to master: 18456; HASHED: 102"
)
ID4 = (
    "ID4 a contained user named as a login: ok; to the database with the user's password: "
    "sopuli_probe_twin|sopuli_probe_twin; with the login's: 18456; to master with the "
    "login's: sopuli_probe_twin|guest"
)


#: What each server's msdb read as its service_broker_guid.
MSDB: dict[str, str] = {}


def second_msdb(service: str) -> str:
    """msdb's service_broker_guid on a second container of the server's image.

    The container is started for this, from the image ID the server runs (not
    its tag, which a later pull may have moved), read once it answers, and
    removed.
    """
    image = (
        subprocess.run(
            ["docker", "inspect", "-f", "{{.Image}}", ch.container(service)],
            capture_output=True,
            check=False,
        )
        .stdout.decode()
        .strip()
    )
    name = f"{ch.container(service)}-second"
    subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
    started = subprocess.run(
        [
            "docker", "run", "-d", "--rm", "--name", name,
            "-e", "ACCEPT_EULA=Y", "-e", "MSSQL_SA_PASSWORD", image,
        ],
        env={**os.environ, "MSSQL_SA_PASSWORD": ch.SA_PASSWORD},
        capture_output=True,
        check=False,
    )  # fmt: skip
    if started.returncode != 0:
        raise ch.StepError(f"{service}: a second container: {started.stderr[:200]!r}")
    try:
        for _ in range(60):
            # -b: a failed query exits non-zero, so its message is never read
            # as the value.
            read = subprocess.run(
                [
                    "docker", "exec", "-e", "SQLCMDPASSWORD", name,
                    *ch.sqlcmd_path(service), "-S", "localhost", "-U", "sa", "-h", "-1", "-W",
                    "-b", "-Q", "SET NOCOUNT ON; SELECT CONVERT(varchar(36), "
                    "service_broker_guid) FROM sys.databases WHERE name = 'msdb'",
                ],
                env={**os.environ, "SQLCMDPASSWORD": ch.SA_PASSWORD},
                capture_output=True,
                check=False,
            )  # fmt: skip
            value = read.stdout.decode().strip()
            if read.returncode == 0 and GUID.fullmatch(value):
                return value
            time.sleep(2)
        logs = subprocess.run(["docker", "logs", "--tail", "5", name], capture_output=True)
        raise ch.StepError(
            f"{service}: the second container never answered: {logs.stdout[-300:]!r}"
        )
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)


GUID = re.compile(r"[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}")


def across() -> None:
    """Each image's msdb value is its own. Every server must have reached ID2,
    or there is nothing to compare."""
    distinct = len(MSDB) == len(ch.SERVICES) and len(set(MSDB.values())) == len(MSDB)
    print(f"\nID2 each image's msdb service_broker_guid is its own: {distinct}")
    ch.check("ID2 across the servers", distinct, True)


def main() -> int:
    return ch.run(probe, finish=across)


if __name__ == "__main__":
    sys.exit(main())
