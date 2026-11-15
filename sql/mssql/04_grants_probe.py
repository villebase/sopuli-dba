"""sopuli-dba : the tool login's grants on SQL Server, and what it can reach

#1538, M5 and M6. A tool login holds only ALTER ANY LOGIN, the grant 02 found
enough to set a password. This measures which logins it can then change, and
what logins with each grant can read of the others' privileges:

  GR1  for each target login, whether the tool can set its password, and if
       it can, whether the login then logs in with sysadmin, CONTROL SERVER
       or ALTER ANY LOGIN. The targets: a member of each fixed server role
       but public (sysadmin, securityadmin, serveradmin, setupadmin,
       processadmin, diskadmin, dbcreator, bulkadmin); a member of a server
       role of the probe's that holds CONTROL SERVER; logins granted CONTROL
       SERVER, ALTER ANY LOGIN, IMPERSONATE ANY LOGIN, ALTER ANY SERVER ROLE,
       ALTER ANY CONNECTION, ALTER SETTINGS, SHUTDOWN or VIEW SERVER STATE;
       the db_owner of a database; and a login with no grant
  GR2  whether the tool may alter sa, by a statement that changes nothing if
       it is accepted: ALTER LOGIN [sa] WITH DEFAULT_DATABASE = [master],
       sa's default database already
  GR3  what each reader sees of each target: its rows in
       sys.server_role_members and sys.server_permissions, and
       IS_SRVROLEMEMBER('sysadmin', name). The readers: a login with no
       grant; the tool, with ALTER ANY LOGIN; a login with VIEW ANY
       DEFINITION alone; and, on releases that have it, a login with VIEW
       ANY SECURITY DEFINITION alone. Only server-level catalogs are read,
       so a database role, such as db_owner, is not seen here
  GR4  whether the login with ALTER ANY SERVER ROLE, once the tool has set
       its password, can add itself to the probe's role that holds CONTROL
       SERVER, and to sysadmin, and what it then holds

STATUS: run on 15.0.4510.2, 16.0.4325.4 and 17.0.5065.9, the
mcr.microsoft.com/mssql/server 2019-latest, 2022-latest and 2025-latest images
of test/compose.yaml profile mssql-matrix, as pulled on 2026-11-15, with
Python 3.13.12 on Windows 11 AMD64, on 2026-11-15 (#1538). Twice, exit 0, and
the same result every time.

RESULTS -- the same on every release, except where noted

  GR1  the tool is refused, 15151, "does not exist or you do not have
       permission", for six targets: the members of sysadmin, securityadmin
       and the role that holds CONTROL SERVER, and the logins granted
       CONTROL SERVER, ALTER ANY LOGIN or IMPERSONATE ANY LOGIN. It sets the
       password of every other target, and each logs in holding none of
       sysadmin, CONTROL SERVER and ALTER ANY LOGIN: serveradmin,
       setupadmin, processadmin, diskadmin, dbcreator and bulkadmin; ALTER
       ANY SERVER ROLE, ALTER ANY CONNECTION, ALTER SETTINGS, SHUTDOWN and
       VIEW SERVER STATE; the db_owner; and no grant. 15.0.4510.2 refuses to
       add a member to bulkadmin on Linux, 16202, so it has no bulkadmin
       target
  GR2  the tool's ALTER LOGIN [sa] WITH DEFAULT_DATABASE = [master] is
       accepted: ALTER ANY LOGIN reaches at least one of sa's settings. The
       probe sends sa nothing that would change it, so whether the tool may
       set sa's password or disable it is not measured here
  GR3  the tool, with ALTER ANY LOGIN alone, and a login with VIEW ANY
       DEFINITION alone or VIEW ANY SECURITY DEFINITION alone, each see
       every target's server role and server permission rows, and
       IS_SRVROLEMEMBER('sysadmin') for each. A login with no grant sees none
       of the targets' rows, but IS_SRVROLEMEMBER('sysadmin') still answers
       1 for the sysadmin member. The db_owner reads as a login with no
       grant. 15.0.4510.2 has no VIEW ANY SECURITY DEFINITION, and refuses
       its GRANT, 102
  GR4  **ALTER ANY LOGIN reaches CONTROL SERVER.** The login with ALTER ANY
       SERVER ROLE, whose password the tool set, adds itself to the role
       that holds CONTROL SERVER, and then holds CONTROL SERVER and ALTER
       ANY LOGIN. Adding itself to sysadmin is refused, 15151

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mssql/04_grants_probe.py

It needs 02_client_hash_probe.py beside it.

THROWAWAY SERVERS ONLY. It creates the logins sopuli_probe_tool,
sopuli_probe_t_* and sopuli_probe_r_*, the server role sopuli_probe_role and
the database sopuli_probe_grants, and drops them at the end. It sets each
target login's password, and never changes sa: GR2's statement sets what sa
already has.
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

ROLE = "sopuli_probe_role"
DATABASE = "sopuli_probe_grants"
#: Test passwords, not credentials.
FIRST = "Acme-Target-pw1"
SECOND = "Acme-Target-pw2"


def member(role: str) -> str:
    return f"ALTER SERVER ROLE [{role}] ADD MEMBER [{{name}}]"


def granted(permission: str) -> str:
    return f"GRANT {permission} TO [{{name}}]"


#: Each target, by its short name, and the statement that gives it its power.
#: The login is sopuli_probe_t_<short name>.
TARGETS = {
    "sysadmin": member("sysadmin"),
    "securityadmin": member("securityadmin"),
    "serveradmin": member("serveradmin"),
    "setupadmin": member("setupadmin"),
    "processadmin": member("processadmin"),
    "diskadmin": member("diskadmin"),
    "dbcreator": member("dbcreator"),
    "bulkadmin": member("bulkadmin"),
    "role": member(ROLE),
    "control": granted("CONTROL SERVER"),
    "altany": granted("ALTER ANY LOGIN"),
    "impersonate": granted("IMPERSONATE ANY LOGIN"),
    "altrole": granted("ALTER ANY SERVER ROLE"),
    "altconn": granted("ALTER ANY CONNECTION"),
    "settings": granted("ALTER SETTINGS"),
    "shutdown": granted("SHUTDOWN"),
    "viewstate": granted("VIEW SERVER STATE"),
    "dbowner": (
        f"EXEC (N'USE [{DATABASE}]; CREATE USER [{{name}}] FOR LOGIN [{{name}}]; "
        f"ALTER ROLE db_owner ADD MEMBER [{{name}}]')"
    ),
    "plain": "",
}
#: The readers of GR3, by short name, and the grant each holds besides the
#: tool's. The login is sopuli_probe_r_<short name>; the tool is itself.
READERS = {
    "none": "",
    "viewdef": "VIEW ANY DEFINITION",
    "viewsec": "VIEW ANY SECURITY DEFINITION",
}
#: What a login checks of its own power once it has logged in.
POWER = (
    "SELECT CAST(IS_SRVROLEMEMBER('sysadmin') AS varchar(2)) + ',' "
    "+ CAST(HAS_PERMS_BY_NAME(NULL, NULL, 'CONTROL SERVER') AS varchar(2)) + ',' "
    "+ CAST(HAS_PERMS_BY_NAME(NULL, NULL, 'ALTER ANY LOGIN') AS varchar(2))"
)


def target(short: str) -> str:
    return f"sopuli_probe_t_{short}"


def reader(short: str) -> str:
    return f"sopuli_probe_r_{short}"


def drop_all(service: str) -> None:
    ch.sa(
        service,
        f"IF DB_ID('{DATABASE}') IS NOT NULL BEGIN "
        f"ALTER DATABASE [{DATABASE}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; "
        f"DROP DATABASE [{DATABASE}] END",
    )
    for name in [*map(target, TARGETS), *map(reader, READERS)]:
        ch.sa(service, ch.drop_login(name))
    ch.sa(
        service,
        f"IF EXISTS (SELECT 1 FROM sys.server_principals WHERE name = '{ROLE}' AND type = 'R') "
        f"DROP SERVER ROLE [{ROLE}]",
    )


def setup(service: str) -> tuple[str, list[str]]:
    """Create the targets and the readers.

    Returns the release, and the short names of the targets and the readers
    that could be made. A target or reader whose grant the server refuses is
    recorded in REFUSED and left out.
    """
    found = ch.setup(service)
    drop_all(service)
    ch.sa(
        service,
        f"CREATE SERVER ROLE [{ROLE}];\nGRANT CONTROL SERVER TO [{ROLE}];\n"
        f"CREATE DATABASE [{DATABASE}]",
    )
    targets = []
    for short, grant in TARGETS.items():
        name = target(short)
        ch.sa(
            service, f"CREATE LOGIN [{name}] WITH PASSWORD = {ch.quote(FIRST)}, CHECK_POLICY = OFF"
        )
        if grant:
            _, errors = ch.client(service, "sa", ch.SA_PASSWORD, grant.format(name=name))
            if errors:
                print(f"GR1 target {short}: its grant is refused: {ch.code(errors)}")
                REFUSED[f"target {short}"] = ch.code(errors)
                continue
        targets.append(short)
    made = []
    for short, grant in READERS.items():
        name = reader(short)
        ch.sa(
            service, f"CREATE LOGIN [{name}] WITH PASSWORD = {ch.quote(FIRST)}, CHECK_POLICY = OFF"
        )
        if grant:
            _, errors = ch.client(service, "sa", ch.SA_PASSWORD, f"GRANT {grant} TO [{name}]")
            if errors:
                print(f"GR3 reader {short}: GRANT {grant}: {ch.code(errors)}")
                REFUSED[f"reader {short}"] = ch.code(errors)
                continue
        made.append(short)
    return found, targets, made


def reads(service: str, login: str, password: str) -> dict[str, str]:
    """What `login` sees of each target, as `role rows,permission rows,sysadmin`."""
    names = ", ".join(f"('{short}')" for short in TARGETS)
    out, errors = ch.client(
        service,
        login,
        password,
        "SELECT t.short + '|' "
        "+ CAST((SELECT COUNT(*) FROM sys.server_role_members m "
        "JOIN sys.server_principals p ON p.principal_id = m.member_principal_id "
        "WHERE p.name = 'sopuli_probe_t_' + t.short) AS varchar(5)) + ',' "
        "+ CAST((SELECT COUNT(*) FROM sys.server_permissions s "
        "JOIN sys.server_principals p ON p.principal_id = s.grantee_principal_id "
        "WHERE p.name = 'sopuli_probe_t_' + t.short) AS varchar(5)) + ',' "
        "+ ISNULL(CAST(IS_SRVROLEMEMBER('sysadmin', 'sopuli_probe_t_' + t.short) "
        "AS varchar(2)), 'NULL') "
        f"FROM (VALUES {names}) AS t(short)",
    )
    if errors:
        raise ch.StepError(f"{service}: {login}'s read: {errors}")
    return dict(line.split("|", 1) for line in out.splitlines())


#: Each target or reader whose grant the server refused, on the server run last.
REFUSED: dict[str, str] = {}


def probe(service: str) -> None:
    ch.cleaned(service, lambda: cases(service), lambda: drop_all(service))


def cases(service: str) -> None:
    REFUSED.clear()
    found, targets, made = setup(service)
    major = found.split(".")[0]

    for short in targets:
        name = target(short)
        answer = ch.as_tool(service, f"ALTER LOGIN [{name}] WITH PASSWORD = {ch.quote(SECOND)}")
        if answer == "ok":
            out, errors = ch.client(service, name, SECOND, POWER)
            power = out if not errors else ch.code(errors)
        else:
            power = "-"
        print(f"GR1 {short}: set by the tool {answer}; sysadmin,CONTROL SERVER,ALTER ANY: {power}")
        expected = ("15151", "-") if short in PROTECTED else ("ok", "0,0,0")
        ch.check(f"GR1 {short}", (answer, power), expected)

    default = ch.sa(
        service, "SELECT default_database_name FROM sys.server_principals WHERE name = 'sa'"
    )
    noop = ch.as_tool(service, f"ALTER LOGIN [sa] WITH DEFAULT_DATABASE = [{default}]")
    print(f"GR2 sa's default database {default}; the tool sets it again: {noop}")
    ch.check("GR2", (default, noop), ("master", "ok"))

    seen = {"tool": reads(service, ch.TOOL, ch.TOOL_PASSWORD)}
    for short in made:
        seen[short] = reads(service, reader(short), FIRST)
    for who, rows in seen.items():
        print(f"GR3 {who} (role rows,permission rows,sysadmin): {rows}")
        for short in targets:
            ch.check(f"GR3 {who} {short}", rows.get(short), SEES[who](short))
    refused = {"target bulkadmin": "16202", "reader viewsec": "102"} if major == "15" else {}
    ch.check("refused grants", dict(REFUSED), refused)

    # The login with ALTER ANY SERVER ROLE, whose password the tool set in GR1,
    # adds itself to roles.
    name = target("altrole")
    steps = []
    for role in (ROLE, "sysadmin"):
        _, errors = ch.client(
            service, name, SECOND, f"ALTER SERVER ROLE [{role}] ADD MEMBER [{name}]"
        )
        steps.append(f"to {role}: {ch.code(errors)}")
    out, errors = ch.client(service, name, SECOND, POWER)
    power = out if not errors else ch.code(errors)
    joined = "; ".join(steps)
    print(f"GR4 altrole adds itself {joined}; then sysadmin,CONTROL SERVER,ALTER ANY: {power}")
    ch.check("GR4", (steps, power), ([f"to {ROLE}: ok", "to sysadmin: 15151"], "0,1,1"))


#: The targets the tool cannot change, by short name.
PROTECTED = frozenset({"sysadmin", "securityadmin", "role", "control", "altany", "impersonate"})


def all_rows(short: str) -> str:
    """What a reader that sees every row reads of a target."""
    roles = 1 if TARGETS[short].startswith("ALTER SERVER ROLE") else 0
    # Every login holds CONNECT SQL; a GRANT adds one row.
    permissions = 2 if TARGETS[short].startswith("GRANT") else 1
    return f"{roles},{permissions},{1 if short == 'sysadmin' else 0}"


def none_but_own(short: str) -> str:
    """What a reader that sees no other login's rows reads of a target."""
    return f"0,0,{1 if short == 'sysadmin' else 0}"


SEES = {"tool": all_rows, "none": none_but_own, "viewdef": all_rows, "viewsec": all_rows}


def main() -> int:
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
