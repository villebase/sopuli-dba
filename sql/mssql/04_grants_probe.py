"""sopuli-dba : the tool login's grants on SQL Server, and what it can reach

#1538, M5 and M6. A tool login holds only ALTER ANY LOGIN, the grant 02 found
enough to set a password. This measures which logins it can then change, and
what it can read of their privileges:

  GR1  for logins that hold each kind of administrative power, whether the
       tool can set the password, and if it can, whether the login then has
       that power: a member of sysadmin, of securityadmin, of a server role
       of the probe's that holds CONTROL SERVER, and logins granted CONTROL
       SERVER, ALTER ANY LOGIN or IMPERSONATE ANY LOGIN. And, to contrast,
       logins with power that is not over logins: one granted VIEW SERVER
       STATE, a member of dbcreator, the db_owner of a database, and one
       with no grant
  GR2  whether the tool can disable sa, or set sa's password
  GR3  what the tool reads of each login's privileges: its rows in
       sys.server_role_members and sys.server_permissions, and
       IS_SRVROLEMEMBER for it. Read first by a login with no grant, then by
       the tool with ALTER ANY LOGIN alone, and then with VIEW ANY
       DEFINITION, and on releases that have it VIEW ANY SECURITY
       DEFINITION, granted to the tool too

STATUS: run on 15.0.4510.2, 16.0.4325.4 and 17.0.5065.9, the
mcr.microsoft.com/mssql/server 2019-latest, 2022-latest and 2025-latest images
of test/compose.yaml profile mssql-matrix, as pulled on 2026-11-15, with
Python 3.13.12 on Windows 11 AMD64, on 2026-11-15 (#1538). Twice, exit 0, and
the same result every time.

RESULTS -- the same on every release, except where noted

  GR1  **The server keeps ALTER ANY LOGIN away from every administrative
       login.** The tool is refused, 15151, "does not exist or you do not
       have permission", for the members of sysadmin, securityadmin and the
       role that holds CONTROL SERVER, and for the logins granted CONTROL
       SERVER, ALTER ANY LOGIN or IMPERSONATE ANY LOGIN. It sets the
       password of the four others: VIEW SERVER STATE, dbcreator, db_owner of
       a database, and no grant. Each of the four then logs in, and holds
       none of sysadmin, CONTROL SERVER and ALTER ANY LOGIN. So a db_owner
       or a dbcreator can be taken over by the tool
  GR2  the tool can neither disable sa nor set its password, 15151
  GR3  the tool, with ALTER ANY LOGIN alone, sees every target's server role
       rows and server permission rows, and IS_SRVROLEMEMBER('sysadmin') for
       each. VIEW ANY DEFINITION and VIEW ANY SECURITY DEFINITION change
       nothing it sees. A login with no grant sees none of the others' rows,
       only its own CONNECT SQL, but IS_SRVROLEMEMBER('sysadmin') still
       answers 1 for the sysadmin member. 15.0.4510.2 has no VIEW ANY
       SECURITY DEFINITION, and refuses its GRANT, 102

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mssql/04_grants_probe.py

It needs 02_client_hash_probe.py beside it.

THROWAWAY SERVERS ONLY. It creates the logins sopuli_probe_tool and
sopuli_probe_t_*, and the server role sopuli_probe_role, and drops them at
the end. It sets each target login's password, and never sa's: GR2 sends
sa's statement only as the tool, and records the refusal.
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
#: Each target login, and the statements that give it its power.
TARGETS = {
    "sopuli_probe_t_sysadmin": ["ALTER SERVER ROLE sysadmin ADD MEMBER [{name}]"],
    "sopuli_probe_t_secadmin": ["ALTER SERVER ROLE securityadmin ADD MEMBER [{name}]"],
    "sopuli_probe_t_role": [f"ALTER SERVER ROLE [{ROLE}] ADD MEMBER [{{name}}]"],
    "sopuli_probe_t_control": ["GRANT CONTROL SERVER TO [{name}]"],
    "sopuli_probe_t_altany": ["GRANT ALTER ANY LOGIN TO [{name}]"],
    "sopuli_probe_t_imp": ["GRANT IMPERSONATE ANY LOGIN TO [{name}]"],
    # Contrasts: a server grant that is not administrative, a fixed role
    # that is not about logins, and the owner's role in one database.
    "sopuli_probe_t_view": ["GRANT VIEW SERVER STATE TO [{name}]"],
    "sopuli_probe_t_dbcreator": ["ALTER SERVER ROLE dbcreator ADD MEMBER [{name}]"],
    "sopuli_probe_t_dbowner": [
        f"EXEC (N'USE [{DATABASE}]; CREATE USER [{{name}}] FOR LOGIN [{{name}}]; "
        f"ALTER ROLE db_owner ADD MEMBER [{{name}}]')"
    ],
    "sopuli_probe_t_plain": [],
}
#: What a login checks of its own power once it has logged in.
POWER = (
    "SELECT CAST(IS_SRVROLEMEMBER('sysadmin') AS varchar(2)) + ',' "
    "+ CAST(HAS_PERMS_BY_NAME(NULL, NULL, 'CONTROL SERVER') AS varchar(2)) + ',' "
    "+ CAST(HAS_PERMS_BY_NAME(NULL, NULL, 'ALTER ANY LOGIN') AS varchar(2))"
)


def drop_all(service: str) -> None:
    ch.sa(
        service,
        f"IF DB_ID('{DATABASE}') IS NOT NULL BEGIN "
        f"ALTER DATABASE [{DATABASE}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; "
        f"DROP DATABASE [{DATABASE}] END",
    )
    for name in TARGETS:
        ch.sa(service, ch.drop_login(name))
    ch.sa(
        service,
        f"IF EXISTS (SELECT 1 FROM sys.server_principals WHERE name = '{ROLE}' AND type = 'R') "
        f"DROP SERVER ROLE [{ROLE}]",
    )


def setup(service: str) -> str:
    found = ch.setup(service)
    drop_all(service)
    ch.sa(
        service,
        f"CREATE SERVER ROLE [{ROLE}];\nGRANT CONTROL SERVER TO [{ROLE}];\n"
        f"CREATE DATABASE [{DATABASE}]",
    )
    for name, grants in TARGETS.items():
        ch.sa(
            service,
            f"CREATE LOGIN [{name}] WITH PASSWORD = {ch.quote(FIRST)}, CHECK_POLICY = OFF;\n"
            + ";\n".join(grant.format(name=name) for grant in grants),
        )
    return found


def reads(service: str, name: str, reader: str = ch.TOOL, password: str = ch.TOOL_PASSWORD) -> str:
    """What `reader` sees of `name`: role rows, permission rows, IS_SRVROLEMEMBER."""
    out, errors = ch.client(
        service,
        reader,
        password,
        "SELECT CAST((SELECT COUNT(*) FROM sys.server_role_members m "
        "JOIN sys.server_principals p ON p.principal_id = m.member_principal_id "
        f"WHERE p.name = '{name}') AS varchar(5)) + ',' "
        "+ CAST((SELECT COUNT(*) FROM sys.server_permissions s "
        "JOIN sys.server_principals p ON p.principal_id = s.grantee_principal_id "
        f"WHERE p.name = '{name}') AS varchar(5)) + ',' "
        f"+ ISNULL(CAST(IS_SRVROLEMEMBER('sysadmin', '{name}') AS varchar(2)), 'NULL')",
    )
    return out if not errors else ch.code(errors)


#: Each result line, as the probe prints it.
SEEN: list[str] = []


def report(line: str) -> None:
    print(line)
    SEEN.append(line)


def probe(service: str) -> None:
    SEEN.clear()
    ch.cleaned(service, lambda: cases(service), lambda: drop_all(service))


def cases(service: str) -> None:
    major = setup(service).split(".")[0]
    for name in TARGETS:
        answer = ch.as_tool(service, f"ALTER LOGIN [{name}] WITH PASSWORD = {ch.quote(SECOND)}")
        if answer == "ok":
            out, errors = ch.client(service, name, SECOND, POWER)
            power = out if not errors else ch.code(errors)
        else:
            power = "-"
        report(f"GR1 {name}: set by the tool {answer}; sysadmin,CONTROL SERVER,ALTER ANY: {power}")

    report(f"GR2 DISABLE sa: {ch.as_tool(service, 'ALTER LOGIN [sa] DISABLE')}")
    report(
        "GR2 sa's password: "
        f"{ch.as_tool(service, f'ALTER LOGIN [sa] WITH PASSWORD = {ch.quote(SECOND)}')}"
    )

    plain = "sopuli_probe_t_plain"
    rows = {
        name.removeprefix("sopuli_probe_t_"): reads(service, name, plain, SECOND)
        for name in TARGETS
    }
    report(f"GR3 a login with no grant (role rows,permission rows,IS_SRVROLEMEMBER): {rows}")
    for label, grant in (
        ("ALTER ANY LOGIN alone", ""),
        ("and VIEW ANY DEFINITION", "VIEW ANY DEFINITION"),
        ("and VIEW ANY SECURITY DEFINITION", "VIEW ANY SECURITY DEFINITION"),
    ):
        if grant:
            _, errors = ch.client(service, "sa", ch.SA_PASSWORD, f"GRANT {grant} TO [{ch.TOOL}]")
            if errors:
                report(f"GR3 {label}: GRANT {ch.code(errors)}")
                continue
        rows = {name.removeprefix("sopuli_probe_t_"): reads(service, name) for name in TARGETS}
        report(f"GR3 {label} (role rows,permission rows,IS_SRVROLEMEMBER): {rows}")

    recorded = recorded_lines(major)
    # By content, not position, so that one line missing or added is named alone.
    for line in recorded:
        if line not in SEEN:
            ch.check("missing", line, "printed")
    for line in SEEN:
        if line not in recorded:
            ch.check("not recorded", line, "in RECORDED")


#: GR1's line for each target: the tool sets the password of only the four
#: with no administrative power.
REFUSED = (
    "sysadmin",
    "secadmin",
    "role",
    "control",
    "altany",
    "imp",
)
#: GR3's reads, (role rows,permission rows,IS_SRVROLEMEMBER), as the tool sees
#: each target, and as a login with no grant sees it.
BY_TOOL = (
    "{'sysadmin': '1,1,1', 'secadmin': '1,1,0', 'role': '1,1,0', 'control': '0,2,0', "
    "'altany': '0,2,0', 'imp': '0,2,0', 'view': '0,2,0', 'dbcreator': '1,1,0', "
    "'dbowner': '0,1,0', 'plain': '0,1,0'}"
)
BY_PLAIN = (
    "{'sysadmin': '0,0,1', 'secadmin': '0,0,0', 'role': '0,0,0', 'control': '0,0,0', "
    "'altany': '0,0,0', 'imp': '0,0,0', 'view': '0,0,0', 'dbcreator': '0,0,0', "
    "'dbowner': '0,0,0', 'plain': '0,1,0'}"
)
READS = "(role rows,permission rows,IS_SRVROLEMEMBER)"


def recorded_lines(major: str) -> list[str]:
    """The lines a release prints. Only 2019, major release 15, differs: it has
    no VIEW ANY SECURITY DEFINITION, and refuses the GRANT as a syntax error."""
    lines = []
    for name in TARGETS:
        short = name.removeprefix("sopuli_probe_t_")
        if short in REFUSED:
            lines.append(f"GR1 {name}: set by the tool 15151; sysadmin,CONTROL SERVER,ALTER ANY: -")
        else:
            lines.append(
                f"GR1 {name}: set by the tool ok; sysadmin,CONTROL SERVER,ALTER ANY: 0,0,0"
            )
    lines += [
        "GR2 DISABLE sa: 15151",
        "GR2 sa's password: 15151",
        f"GR3 a login with no grant {READS}: {BY_PLAIN}",
        f"GR3 ALTER ANY LOGIN alone {READS}: {BY_TOOL}",
        f"GR3 and VIEW ANY DEFINITION {READS}: {BY_TOOL}",
        "GR3 and VIEW ANY SECURITY DEFINITION: GRANT 102"
        if major == "15"
        else f"GR3 and VIEW ANY SECURITY DEFINITION {READS}: {BY_TOOL}",
    ]
    return lines


def main() -> int:
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
