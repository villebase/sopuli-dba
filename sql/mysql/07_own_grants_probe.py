"""sopuli-dba : what a MySQL tool account can read of its own grants and roles

#1221. The tool refuses a tool account that can use SYSTEM_USER, and audits
what else it holds, so it must read everything the account holds or can
activate, roles included, with no grant of its own. This measures, on each
server:

  OG1  SHOW GRANTS from a tool account with CREATE USER WITH GRANT OPTION,
       the dynamic privileges BACKUP_ADMIN and FLUSH_TABLES, SELECT on chosen
       columns of mysql.user, SELECT and INSERT on a database pattern, and
       PROXY on another account: the lines it prints
  OG2  the same account without the dynamic privileges, the pattern and the
       proxy, granted role r1 (PROCESS, and role r2 with SUPER) as its
       default role, and role r3 (SYSTEM_USER) as a role that is not default:
       CURRENT_ROLE(), then SHOW GRANTS, then the roles
       INFORMATION_SCHEMA.APPLICABLE_ROLES lists with the account itself as
       the grantee, then SHOW GRANTS FOR CURRENT_USER() USING r1, r3
  OG3  the same account: SHOW GRANTS FOR r3, and the privileges
       INFORMATION_SCHEMA.USER_PRIVILEGES lists
  OG4  root sets mandatory_roles to a role that holds SYSTEM_USER
  OG5  root sets mandatory_roles to a role m with SUPER, and role n granted
       to m, neither granted to the tool account. The tool account reads the
       roles APPLICABLE_ROLES lists with itself as the grantee, as in OG2,
       CURRENT_ROLE() and SHOW GRANTS FOR CURRENT_USER() USING m. Then root
       grants SYSTEM_USER to m
  OG6  root grants r3 to m, then SYSTEM_USER to n, and the tool account runs
       SHOW GRANTS FOR CURRENT_USER() USING m again

A refusal is its error number and SQLSTATE.

The probe checks each result against the one RESULTS below records, as 02
does. A difference, or a step that fails, makes it exit 1.

It MEASURES and decides nothing.

STATUS: run on 8.0.46, 8.4.13 and 9.7.4, the mysql:8.0, mysql:8.4 and mysql:9
images of test/compose.yaml profile mysql-matrix, on 2026-11-02 (#1221), with
Python 3.13.12 on Windows 11 AMD64. Twice, exit 0, and the same result both
times.

RESULTS -- the same on all three releases, except OG5's CURRENT_ROLE()

  OG1  five lines, one per grant, in this order: CREATE USER ON *.* WITH
       GRANT OPTION; BACKUP_ADMIN,FLUSH_TABLES ON *.*; the database pattern
       as `acme%`.*; SELECT (`Host`, `User`, `plugin`) ON `mysql`.`user`;
       PROXY ON `sopuli_probe_other`@`%`. Static privileges are separated by
       ", ", dynamic ones by ","
  OG2  CURRENT_ROLE() is r1. SHOW GRANTS lists PROCESS and SUPER beside
       CREATE USER, so it expands the active role and the role granted to
       it, and leaves out r3's SYSTEM_USER. APPLICABLE_ROLES lists r1 and r3
       as the account's own. With USING r1, r3, SHOW GRANTS lists SYSTEM_USER
       on a line of its own, then the column grant, then one line naming both
       roles
  OG3  SHOW GRANTS FOR r3 is refused, 1142 (42000). USER_PRIVILEGES lists
       only CREATE USER: a direct grant, and no role's
  OG4  refused, 3880 (HY000): a role that holds SYSTEM_USER cannot be
       mandatory
  OG5  APPLICABLE_ROLES, filtered as in OG2, lists m with IS_DEFAULT NO and
       IS_MANDATORY YES beside r1 and r3. USING m is accepted, and lists
       SUPER and not r1's PROCESS: USING expands the roles it names and no
       others. Its line of role grants names r1 and r3 and not m, so only
       APPLICABLE_ROLES shows the mandatory role. CURRENT_ROLE() is r1 on 8.0.46 and 8.4.13, and m and r1 on
       9.7.4, with activate_all_roles_on_login 0 on all three: 9.7.4
       activates a mandatory role at login. Granting SYSTEM_USER to m is
       refused, 3897 (HY000)
  OG6  granting r3 to m is refused, 4027 (HY000), with a message about a
       loop. Granting SYSTEM_USER to n, a role already granted to m, is
       accepted, and USING m then lists SYSTEM_USER

  So two reads give everything the tool account holds or can activate, with
  no grant: its own roles from APPLICABLE_ROLES, then SHOW GRANTS FOR
  CURRENT_USER() USING every one of them. Neither read alone is enough. A
  mandatory role cannot hold SYSTEM_USER itself, but a role granted to it
  can, so a mandatory role is read as any other role is.

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mysql/07_own_grants_probe.py

It needs only the standard library and the docker CLI, and
02_client_hash_probe.py beside it. The container names follow
COMPOSE_PROJECT_NAME, so a second clone's matrix is the one it uses.

THROWAWAY SERVERS ONLY. On each server it creates the accounts
sopuli_probe_tool and sopuli_probe_hash, as 02 does, the account
sopuli_probe_other and the roles sopuli_probe_r1, _r2, _r3, _m and _n, and
sets mandatory_roles for the length of OG4 to OG6. It drops them and empties
mandatory_roles at the end, also after a failed step, and before it starts.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

# 02's name starts with a digit, so it is loaded by its path.
_SPEC = importlib.util.spec_from_file_location(
    "client_hash_probe", Path(__file__).with_name("02_client_hash_probe.py")
)
assert _SPEC is not None
assert _SPEC.loader is not None
ch = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ch)

OTHER = "sopuli_probe_other"
R1, R2, R3 = "sopuli_probe_r1", "sopuli_probe_r2", "sopuli_probe_r3"
M, N = "sopuli_probe_m", "sopuli_probe_n"
TOOL = f"`{ch.TOOL}`@`%`"
DENIED_TABLE = "1142 (42000)"
SYSTEM_USER_MANDATORY = "3880 (HY000)"
MANDATORY_SYSTEM_USER = "3897 (HY000)"
GRANT_LOOP = "4027 (HY000)"
OWN_ROLES = (
    "SELECT ROLE_NAME, IS_DEFAULT, IS_MANDATORY FROM information_schema.APPLICABLE_ROLES "
    "WHERE GRANTEE = USER AND GRANTEE_HOST = HOST ORDER BY ROLE_NAME"
)
#: The lines every USING read below ends with, once the roles are set up.
COLUMNS = f"GRANT SELECT (`Host`, `User`, `plugin`) ON `mysql`.`user` TO {TOOL}"
ROLES = f"GRANT `{R1}`@`%`,`{R3}`@`%` TO {TOOL}"
#: OG5's CURRENT_ROLE(): the one result that differs between releases. Keyed
#: by the full release, as every result is: a release not listed here is not
#: measured, and reports a difference until it is.
ACTIVE_AT_LOGIN = {
    "8.0.46": f"`{R1}`@`%` 0",
    "8.4.13": f"`{R1}`@`%` 0",
    "9.7.4": f"`{M}`@`%`,`{R1}`@`%` 0",
}


def tool_out(service: str, statement: str) -> str:
    """What the tool account's statement printed, or the refusal's error
    number and SQLSTATE."""
    ok, out = ch.mysql(service, ch.TOOL, ch.TOOL_PASSWORD, statement)
    return out if ok else ch.code(out)


def tool_lines(service: str, statement: str) -> list[str]:
    """The lines a statement printed, tabs as spaces. Every statement here
    prints at least one line, so none is a failed step."""
    lines = tool_out(service, statement).replace("\t", " ").splitlines()
    if not lines:
        raise ch.StepError(f"{service}: {statement[:60]}: printed nothing")
    return lines


def root_answer(service: str, statement: str) -> str:
    """`ok`, or the refusal's error number and SQLSTATE, for root."""
    ok, out = ch.mysql(service, "root", ch.ROOT_PASSWORD, statement)
    return "ok" if ok else ch.code(out)


def socket_root(service: str, statement: str) -> None:
    """A statement only root@localhost may send: it holds PROXY ON ''@'' WITH
    GRANT OPTION, and root@'%', which a TCP login reaches, does not."""
    ok, out = ch.mysql(service, "root", ch.ROOT_PASSWORD, statement, "--protocol=SOCKET")
    if not ok:
        raise ch.StepError(f"{service}: {statement[:60]}: {out}")


def drop(service: str) -> None:
    ch.root(
        service,
        "SET GLOBAL mandatory_roles = '';"
        f"DROP ROLE IF EXISTS '{R1}', '{R2}', '{R3}', '{M}', '{N}';"
        f"DROP USER IF EXISTS '{OTHER}'@'%'",
    )


def probe(service: str) -> None:
    """Run the cases, and undo this probe's own state whatever happens.

    02's run() drops only the accounts 02's setup() creates.
    """
    try:
        cases(service)
    except BaseException:
        # Keep the step's own error: a failed clean-up is only reported.
        try:
            drop(service)
        except ch.StepError as exc:
            print(f"CLEAN-UP FAILED: {exc}")
        raise
    drop(service)


def cases(service: str) -> None:
    release = ch.setup(service, "Acme-Probe-pw0")
    drop(service)
    own_grants(service)
    roles(service)
    mandatory(service, release)


def own_grants(service: str) -> None:
    ch.root(
        service,
        f"CREATE USER '{OTHER}'@'%';"
        f"GRANT CREATE USER ON *.* TO '{ch.TOOL}'@'%' WITH GRANT OPTION;"
        f"GRANT BACKUP_ADMIN, FLUSH_TABLES ON *.* TO '{ch.TOOL}'@'%';"
        f"GRANT SELECT (User, Host, plugin) ON mysql.user TO '{ch.TOOL}'@'%';"
        f"GRANT SELECT, INSERT ON `acme%`.* TO '{ch.TOOL}'@'%'",
    )
    socket_root(service, f"GRANT PROXY ON '{OTHER}'@'%' TO '{ch.TOOL}'@'%'")
    lines = tool_lines(service, "SHOW GRANTS")
    print("OG1 SHOW GRANTS:\n  " + "\n  ".join(lines))
    ch.check(
        "OG1",
        lines,
        [
            f"GRANT CREATE USER ON *.* TO {TOOL} WITH GRANT OPTION",
            f"GRANT BACKUP_ADMIN,FLUSH_TABLES ON *.* TO {TOOL}",
            f"GRANT SELECT, INSERT ON `acme%`.* TO {TOOL}",
            COLUMNS,
            f"GRANT PROXY ON `{OTHER}`@`%` TO {TOOL}",
        ],
    )


def roles(service: str) -> None:
    socket_root(service, f"REVOKE PROXY ON '{OTHER}'@'%' FROM '{ch.TOOL}'@'%'")
    ch.root(
        service,
        f"REVOKE BACKUP_ADMIN, FLUSH_TABLES ON *.* FROM '{ch.TOOL}'@'%';"
        f"REVOKE SELECT, INSERT ON `acme%`.* FROM '{ch.TOOL}'@'%';"
        f"CREATE ROLE '{R1}', '{R2}', '{R3}';"
        f"GRANT PROCESS ON *.* TO '{R1}'; GRANT SUPER ON *.* TO '{R2}';"
        f"GRANT SYSTEM_USER ON *.* TO '{R3}'; GRANT '{R2}' TO '{R1}';"
        f"GRANT '{R1}', '{R3}' TO '{ch.TOOL}'@'%';"
        f"SET DEFAULT ROLE '{R1}' TO '{ch.TOOL}'@'%'",
    )
    current = tool_out(service, "SELECT CURRENT_ROLE()")
    active = tool_lines(service, "SHOW GRANTS")
    own = tool_lines(service, OWN_ROLES)
    using = tool_lines(service, f"SHOW GRANTS FOR CURRENT_USER() USING '{R1}', '{R3}'")
    print(f"OG2 CURRENT_ROLE(): {current}")
    print("OG2 SHOW GRANTS:\n  " + "\n  ".join(active))
    print(f"OG2 own roles: {own}")
    print("OG2 USING r1, r3:\n  " + "\n  ".join(using))
    static = f"GRANT PROCESS, SUPER, CREATE USER ON *.* TO {TOOL} WITH GRANT OPTION"
    ch.check(
        "OG2",
        (current, active, own, using),
        (
            f"`{R1}`@`%`",
            [static, COLUMNS, ROLES],
            [f"{R1} YES NO", f"{R3} NO NO"],
            [static, f"GRANT SYSTEM_USER ON *.* TO {TOOL}", COLUMNS, ROLES],
        ),
    )

    role_grants = tool_out(service, f"SHOW GRANTS FOR '{R3}'")
    direct = tool_lines(service, "SELECT PRIVILEGE_TYPE FROM information_schema.USER_PRIVILEGES")
    print(f"OG3 SHOW GRANTS FOR r3: {role_grants}; USER_PRIVILEGES: {direct}")
    ch.check("OG3", (role_grants, direct), (DENIED_TABLE, ["CREATE USER"]))


def mandatory(service: str, release: str) -> None:
    answer = root_answer(service, f"SET GLOBAL mandatory_roles = '{R3}'")
    print(f"OG4 mandatory_roles = r3: {answer}")
    ch.check("OG4", answer, SYSTEM_USER_MANDATORY)

    ch.root(
        service,
        f"CREATE ROLE '{M}', '{N}'; GRANT SUPER ON *.* TO '{M}'; GRANT '{N}' TO '{M}';"
        f"SET GLOBAL mandatory_roles = '{M}'",
    )
    own = tool_lines(service, OWN_ROLES)
    current = tool_out(service, "SELECT CURRENT_ROLE(), @@activate_all_roles_on_login")
    current = current.replace("\t", " ")
    using_m = tool_lines(service, f"SHOW GRANTS FOR CURRENT_USER() USING '{M}'")
    system_user_to_m = root_answer(service, f"GRANT SYSTEM_USER ON *.* TO '{M}'")
    print(f"OG5 own roles: {own}")
    print(f"OG5 CURRENT_ROLE(), activate_all_roles_on_login: {current}")
    print("OG5 USING m:\n  " + "\n  ".join(using_m))
    print(f"OG5 GRANT SYSTEM_USER TO m: {system_user_to_m}")
    super_line = f"GRANT SUPER, CREATE USER ON *.* TO {TOOL} WITH GRANT OPTION"
    ch.check(
        "OG5",
        (own, current, using_m, system_user_to_m),
        (
            [f"{M} NO YES", f"{R1} YES NO", f"{R3} NO NO"],
            ACTIVE_AT_LOGIN.get(release, "not measured"),
            [super_line, COLUMNS, ROLES],
            MANDATORY_SYSTEM_USER,
        ),
    )

    r3_to_m = root_answer(service, f"GRANT '{R3}' TO '{M}'")
    system_user_to_n = root_answer(service, f"GRANT SYSTEM_USER ON *.* TO '{N}'")
    using_m = tool_lines(service, f"SHOW GRANTS FOR CURRENT_USER() USING '{M}'")
    print(f"OG6 GRANT r3 TO m: {r3_to_m}; GRANT SYSTEM_USER TO n: {system_user_to_n}")
    print("OG6 USING m:\n  " + "\n  ".join(using_m))
    ch.check(
        "OG6",
        (r3_to_m, system_user_to_n, using_m),
        (
            GRANT_LOOP,
            "ok",
            [super_line, f"GRANT SYSTEM_USER ON *.* TO {TOOL}", COLUMNS, ROLES],
        ),
    )


def main() -> int:
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
