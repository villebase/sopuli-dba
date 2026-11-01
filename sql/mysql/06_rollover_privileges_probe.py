"""sopuli-dba : MySQL rollover state and administrative privileges, as the tool reads them

#1220, for two decisions taken on #1202. Decision 6: the tool never reads
`mysql.user.User_attributes`, because that column holds every retained hash,
so `finish-rollover` needs a narrower source that says whether an account has a
retained password. Decision 7: a guardrail refuses a managed account that holds
a global administrative privilege, so the tool account must read another
account's global privileges, static and dynamic, without reading anything
sensitive. This measures, on each server:

  RS1  INFORMATION_SCHEMA.USER_ATTRIBUTES, read by the tool account with only
       CREATE USER: which accounts it sees, and the account's row before
       and after ALTER USER ... RETAIN CURRENT PASSWORD. Then the account's
       row while root has granted it SYSTEM_USER
  RS2  SHOW CREATE USER for the account after RETAIN, run by root: how many
       hashes it shows, and whether it says anything of a retained password
  RS3  ALTER USER ... DISCARD OLD PASSWORD from the tool account, with a
       retained password and again without one: ROW_COUNT() and SHOW WARNINGS
       in the same session. After the first, the state as root reads it, and
       a login with the old password
  RS4  a view that root creates with SQL SECURITY DEFINER, exposing only
       JSON_CONTAINS_PATH(User_attributes, 'one', '$.additional_password') for
       each account, and SELECT on the view granted to the tool account. The
       tool reads it with a password retained and after DISCARD, and then
       reads User_attributes itself, holding no grant on mysql.user yet
  PV1  SELECT on User, Host and every *_priv column of mysql.user, granted to
       the tool account. It reads which of them are Y for an account that
       holds SUPER and CREATE USER WITH GRANT OPTION, then reads
       authentication_string and User_attributes
  PV2  SELECT on mysql.global_grants, granted to the tool account. It reads
       that account's dynamic privileges, and the table's columns
  PV3  INFORMATION_SCHEMA.USER_PRIVILEGES, read by the tool account: whose
       privileges it shows
  PV4  SHOW GRANTS FOR that account, from the tool account with PV1's and
       PV2's grants
  PV5  a role that holds SUPER and CONNECTION_ADMIN, granted to the account as
       its default role. The tool reads the account's and the role's
       Super_priv, the role's dynamic privileges, then mysql.role_edges and
       mysql.default_roles without and with SELECT on each
  PV6  mandatory_roles set to that role, by root, for the case. PV1's account,
       which was never granted the role, runs SET ROLE to it before and while
       the setting holds it. The tool reads mandatory_roles and
       activate_all_roles_on_login, and mysql.role_edges for that account
  PV7  PROXY on root@'localhost', UPDATE on mysql.* and UPDATE on mysql.user,
       granted to PV1's account. The tool reads mysql.proxies_priv, mysql.db
       and mysql.tables_priv for it, without and with SELECT on each

The probe checks each result against the one RESULTS below records, as 02
does. A difference, or a step that fails, makes it exit 1.

It MEASURES and decides nothing.

STATUS: run on 8.0.46, 8.4.13 and 9.7.4, the mysql:8.0, mysql:8.4 and mysql:9
images of test/compose.yaml profile mysql-matrix, on 2026-11-01 (#1220), with
Python 3.13.12 on Windows 11 AMD64. Twice, exit 0, and the same result both
times.

RESULTS -- the same on all three releases

  RS1  the tool sees the rows of sopuli_probe_hash and of itself, and not
       those of root, mysql.infoschema, mysql.session and mysql.sys, which
       hold SYSTEM_USER. The account's row is its ATTRIBUTE metadata,
       {"tenant": "alpha"}, the same before and after RETAIN. While the
       account holds SYSTEM_USER, the tool sees no row for it
  RS2  one hash, the current one, and nothing that says a password is
       retained
  RS3  ROW_COUNT() is 0 and there are no warnings, with a retained password
       and without one. After the first, root reads no retained password, and
       the old password is refused, 1045 (28000)
  RS4  the tool reads 1 with a password retained and 0 after DISCARD, and is
       refused User_attributes, 1142 (42000)
  PV1  31 *_priv columns are granted. Grant_priv, Super_priv and
       Create_user_priv read Y, and no other. authentication_string and
       User_attributes are refused, 1143 (42000)
  PV2  the tool reads BINLOG_ADMIN without and SYSTEM_VARIABLES_ADMIN with
       the grant option. The table's columns are USER, HOST, PRIV and
       WITH_GRANT_OPTION
  PV3  only the tool account's own privileges
  PV4  refused, 1142 (42000), for the table user
  PV5  the account's Super_priv is N and the role's is Y, and the role's
       dynamic privilege is CONNECTION_ADMIN. Both role tables are refused,
       1142 (42000), without the grant. With it, mysql.role_edges shows the
       role granted to the account, and mysql.default_roles shows it as the
       account's default role
  PV6  before, SET ROLE is refused, 3530 (HY000); while the setting holds the
       role, it is accepted and the role is current. The tool reads
       mandatory_roles as the role and activate_all_roles_on_login as 0, and
       mysql.role_edges has no row for the account: a mandatory role is in the
       setting, not in role_edges
  PV7  each table is refused, 1142 (42000), without the grant. With it,
       proxies_priv shows the proxy on root, mysql.db UPDATE on the schema
       mysql, and tables_priv UPDATE on mysql.user

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mysql/06_rollover_privileges_probe.py

It needs only the standard library and the docker CLI, and
02_client_hash_probe.py beside it. The container names follow
COMPOSE_PROJECT_NAME, so a second clone's matrix is the one it uses.

THROWAWAY SERVERS ONLY. On each server it creates the accounts
sopuli_probe_tool and sopuli_probe_hash, as 02 does, sopuli_probe_admin@'%',
the role sopuli_probe_role and the schema sopuli_probe. It drops them at the
end, also after a failed step, and before it starts it drops ones an
interrupted run left. It sets mandatory_roles for PV6 and empties it again,
also at the end; a server that had its own mandatory_roles loses them.
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

ADMIN = "sopuli_probe_admin"
ROLE = "sopuli_probe_role"
SCHEMA = "sopuli_probe"
ACCOUNT = f"'{ch.ACCOUNT}'@'%'"
ATTRIBUTE = '{"tenant": "alpha"}'
DENIED_TABLE, DENIED_COLUMN = "1142 (42000)", "1143 (42000)"


def tool(service: str, statement: str) -> str:
    """The output of a statement the tool account sends, or the refusal's code."""
    ok, out = ch.mysql(service, ch.TOOL, ch.TOOL_PASSWORD, statement)
    return out if ok else ch.code(out)


def drop(service: str) -> None:
    ch.root(
        service,
        # A role in mandatory_roles cannot be dropped, so PV6 is undone first.
        "SET GLOBAL mandatory_roles = '';"
        f"DROP USER IF EXISTS '{ADMIN}'@'%'; DROP ROLE IF EXISTS '{ROLE}';"
        f"DROP DATABASE IF EXISTS {SCHEMA}",
    )


def probe(service: str) -> None:
    """Run the cases, and drop this probe's own objects whatever happens.

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
    ch.setup(service, "Acme-Probe-old1")
    drop(service)
    ch.root(service, f"ALTER USER {ACCOUNT} ATTRIBUTE {ch.quote(ATTRIBUTE)}")
    rollover(service)
    privileges(service)


def rollover(service: str) -> None:
    attributes = (
        f"SELECT ATTRIBUTE FROM INFORMATION_SCHEMA.USER_ATTRIBUTES "
        f"WHERE USER = '{ch.ACCOUNT}' AND HOST = '%'"
    )
    seen = tool(
        service,
        "SELECT GROUP_CONCAT(CONCAT(USER, '@', HOST) ORDER BY USER, HOST) "
        "FROM INFORMATION_SCHEMA.USER_ATTRIBUTES",
    )
    before = tool(service, attributes)
    ch.root(
        service, f"ALTER USER {ACCOUNT} IDENTIFIED BY 'Acme-Probe-new1' RETAIN CURRENT PASSWORD"
    )
    after = tool(service, attributes)
    print(f"RS1 rows the tool sees: {seen}; before RETAIN: {before}; after: {after}")
    ch.check(
        "RS1",
        (seen, before, after),
        (f"{ch.ACCOUNT}@%,{ch.TOOL}@%", ATTRIBUTE, ATTRIBUTE),
    )
    # Whether SYSTEM_USER is what hides an account: the same account, given it.
    ch.root(service, f"GRANT SYSTEM_USER ON *.* TO {ACCOUNT}")
    hidden = tool(service, attributes)
    ch.root(service, f"REVOKE SYSTEM_USER ON *.* FROM {ACCOUNT}")
    print(f"RS1 the account's row while it holds SYSTEM_USER: {hidden!r}")
    ch.check("RS1 SYSTEM_USER", hidden, "")

    shown = ch.root(service, f"SHOW CREATE USER {ACCOUNT}")
    hashes = shown.count("$A$")
    mentions = any(word in shown.upper() for word in ("RETAIN", "ADDITIONAL", "OLD PASSWORD"))
    print(f"RS2 hashes shown: {hashes}; mentions a retained password: {mentions}")
    ch.check("RS2", (hashes, mentions), (1, False))

    discard = f"ALTER USER {ACCOUNT} DISCARD OLD PASSWORD; SELECT ROW_COUNT(); SHOW WARNINGS"
    with_retained = tool(service, discard)
    # That the tool's DISCARD took effect: the state, as root reads it, and the
    # old password.
    state = ch.root(
        service,
        "SELECT JSON_CONTAINS_PATH(User_attributes, 'one', '$.additional_password') "
        f"FROM mysql.user WHERE user = '{ch.ACCOUNT}' AND host = '%'",
    )
    old = ch.login(service, "Acme-Probe-old1")
    without = tool(service, discard)
    print(
        f"RS3 ROW_COUNT() and warnings, retained: {with_retained!r}; none: {without!r}; "
        f"after the first, retained: {state}, old password: {old}"
    )
    ch.check("RS3", (with_retained, without, state, old), ("0", "0", "0", "1045 (28000)"))

    ch.root(
        service,
        f"CREATE DATABASE {SCHEMA};"
        f"CREATE SQL SECURITY DEFINER VIEW {SCHEMA}.retained AS "
        "SELECT user, host, JSON_CONTAINS_PATH(User_attributes, 'one', "
        "'$.additional_password') AS retained FROM mysql.user;"
        f"GRANT SELECT ON {SCHEMA}.retained TO '{ch.TOOL}'@'%'",
    )
    read = f"SELECT retained FROM {SCHEMA}.retained WHERE user = '{ch.ACCOUNT}' AND host = '%'"
    ch.root(
        service, f"ALTER USER {ACCOUNT} IDENTIFIED BY 'Acme-Probe-new2' RETAIN CURRENT PASSWORD"
    )
    retained = tool(service, read)
    ch.root(service, f"ALTER USER {ACCOUNT} DISCARD OLD PASSWORD")
    discarded = tool(service, read)
    column = tool(service, "SELECT User_attributes FROM mysql.user LIMIT 1")
    print(f"RS4 the view, retained: {retained}; after DISCARD: {discarded}; column: {column}")
    ch.check("RS4", (retained, discarded, column), ("1", "0", DENIED_TABLE))


def privileges(service: str) -> None:
    priv_columns = ch.root(
        service,
        "SELECT GROUP_CONCAT(COLUMN_NAME ORDER BY ORDINAL_POSITION) "
        "FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'mysql' "
        "AND TABLE_NAME = 'user' AND COLUMN_NAME LIKE '%\\_priv'",
    )
    ch.root(
        service,
        f"CREATE USER '{ADMIN}'@'%' IDENTIFIED BY 'Acme-Admin-pw1';"
        f"GRANT SUPER, CREATE USER ON *.* TO '{ADMIN}'@'%' WITH GRANT OPTION;"
        f"GRANT BINLOG_ADMIN ON *.* TO '{ADMIN}'@'%';"
        f"GRANT SYSTEM_VARIABLES_ADMIN ON *.* TO '{ADMIN}'@'%' WITH GRANT OPTION;"
        f"GRANT SELECT (User, Host, {priv_columns}) ON mysql.user TO '{ch.TOOL}'@'%';"
        f"GRANT SELECT ON mysql.global_grants TO '{ch.TOOL}'@'%'",
    )
    yes = tool(
        service,
        "SELECT CONCAT_WS(',', "
        + ", ".join(f"IF({c} = 'Y', '{c}', NULL)" for c in priv_columns.split(","))
        + f") FROM mysql.user WHERE user = '{ADMIN}' AND host = '%'",
    )
    secret = tool(service, "SELECT authentication_string FROM mysql.user LIMIT 1")
    attributes = tool(service, "SELECT User_attributes FROM mysql.user LIMIT 1")
    count = len(priv_columns.split(","))
    print(
        f"PV1 *_priv columns granted: {count}; reading Y: {yes}; "
        f"hash: {secret}; User_attributes: {attributes}"
    )
    ch.check(
        "PV1",
        (count, yes, secret, attributes),
        (31, "Grant_priv,Super_priv,Create_user_priv", DENIED_COLUMN, DENIED_COLUMN),
    )

    dynamic = tool(
        service,
        "SELECT GROUP_CONCAT(CONCAT(priv, '=', with_grant_option) ORDER BY priv) "
        f"FROM mysql.global_grants WHERE user = '{ADMIN}' AND host = '%'",
    )
    columns = tool(
        service,
        "SELECT GROUP_CONCAT(COLUMN_NAME ORDER BY ORDINAL_POSITION) "
        "FROM INFORMATION_SCHEMA.COLUMNS "
        "WHERE TABLE_SCHEMA = 'mysql' AND TABLE_NAME = 'global_grants'",
    )
    print(f"PV2 dynamic: {dynamic}; columns: {columns}")
    ch.check(
        "PV2",
        (dynamic, columns),
        ("BINLOG_ADMIN=N,SYSTEM_VARIABLES_ADMIN=Y", "USER,HOST,PRIV,WITH_GRANT_OPTION"),
    )

    grantees = tool(
        service,
        "SELECT GROUP_CONCAT(DISTINCT GRANTEE) FROM INFORMATION_SCHEMA.USER_PRIVILEGES",
    )
    print(f"PV3 grantees the tool sees: {grantees}")
    ch.check("PV3", grantees, f"'{ch.TOOL}'@'%'")

    shown = tool(service, f"SHOW GRANTS FOR '{ADMIN}'@'%'")
    print(f"PV4 SHOW GRANTS: {shown}")
    ch.check("PV4", shown, DENIED_TABLE)

    ch.root(
        service,
        f"CREATE ROLE '{ROLE}';"
        f"GRANT SUPER, CONNECTION_ADMIN ON *.* TO '{ROLE}';"
        f"GRANT '{ROLE}' TO {ACCOUNT};"
        f"SET DEFAULT ROLE '{ROLE}' TO {ACCOUNT}",
    )
    supers = tool(
        service,
        "SELECT GROUP_CONCAT(CONCAT(user, '=', Super_priv) ORDER BY user) FROM mysql.user "
        f"WHERE user IN ('{ch.ACCOUNT}', '{ROLE}')",
    )
    role_dynamic = tool(
        service, f"SELECT GROUP_CONCAT(priv) FROM mysql.global_grants WHERE user = '{ROLE}'"
    )
    edges = (
        "SELECT CONCAT(from_user, '>', to_user) FROM mysql.role_edges "
        f"WHERE to_user = '{ch.ACCOUNT}'"
    )
    defaults = (
        f"SELECT CONCAT(user, '>', default_role_user) FROM mysql.default_roles "
        f"WHERE user = '{ch.ACCOUNT}'"
    )
    without = (tool(service, edges), tool(service, defaults))
    ch.root(
        service,
        f"GRANT SELECT ON mysql.role_edges TO '{ch.TOOL}'@'%';"
        f"GRANT SELECT ON mysql.default_roles TO '{ch.TOOL}'@'%'",
    )
    with_grant = (tool(service, edges), tool(service, defaults))
    print(
        f"PV5 Super_priv: {supers}; role's dynamic: {role_dynamic}; "
        f"role tables without the grant: {without}; with it: {with_grant}"
    )
    ch.check(
        "PV5",
        (supers, role_dynamic, without, with_grant),
        (
            f"{ch.ACCOUNT}=N,{ROLE}=Y",
            "CONNECTION_ADMIN",
            (DENIED_TABLE, DENIED_TABLE),
            (f"{ROLE}>{ch.ACCOUNT}", f"{ch.ACCOUNT}>{ROLE}"),
        ),
    )

    # Whether PV1's account holds the role: it can make the role current only
    # if it does.
    take_role = f"SET ROLE '{ROLE}'; SELECT CURRENT_ROLE()"
    ok, out = ch.mysql(service, ADMIN, "Acme-Admin-pw1", take_role)
    before = out if ok else ch.code(out)
    ch.root(service, f"SET GLOBAL mandatory_roles = '`{ROLE}`@`%`'")
    ok, out = ch.mysql(service, ADMIN, "Acme-Admin-pw1", take_role)
    during = out if ok else ch.code(out)
    settings = tool(
        service,
        "SELECT CONCAT(@@GLOBAL.mandatory_roles, ';', @@GLOBAL.activate_all_roles_on_login)",
    )
    admin_edges = tool(service, f"SELECT COUNT(*) FROM mysql.role_edges WHERE to_user = '{ADMIN}'")
    ch.root(service, "SET GLOBAL mandatory_roles = ''")
    print(
        f"PV6 {ADMIN} takes the role, before: {before}; while mandatory: {during}; "
        f"mandatory_roles;activate_all_roles_on_login: {settings}; "
        f"role_edges rows for {ADMIN}: {admin_edges}"
    )
    ch.check(
        "PV6",
        (before, during, settings, admin_edges),
        ("3530 (HY000)", f"`{ROLE}`@`%`", f"`{ROLE}`@`%`;0", "0"),
    )

    # Only root@'localhost' holds PROXY WITH GRANT OPTION, so this grant goes
    # over the socket, where root logs in as that account.
    returncode, _, err = ch.client(
        service,
        "root",
        ch.ROOT_PASSWORD,
        f"GRANT PROXY ON 'root'@'localhost' TO '{ADMIN}'@'%'",
        "--protocol=SOCKET",
    )
    if returncode:
        raise ch.StepError(f"{service}: GRANT PROXY: {err[:200]}")
    ch.root(
        service,
        f"GRANT UPDATE ON mysql.* TO '{ADMIN}'@'%';GRANT UPDATE ON mysql.user TO '{ADMIN}'@'%'",
    )
    reads = (
        f"SELECT CONCAT(user, '>', proxied_user) FROM mysql.proxies_priv WHERE user = '{ADMIN}'",
        f"SELECT CONCAT(db, ':', update_priv) FROM mysql.db WHERE user = '{ADMIN}'",
        "SELECT CONCAT(db, '.', table_name, ':', table_priv) FROM mysql.tables_priv "
        f"WHERE user = '{ADMIN}'",
    )
    before = tuple(tool(service, read) for read in reads)
    ch.root(
        service,
        f"GRANT SELECT ON mysql.proxies_priv TO '{ch.TOOL}'@'%';"
        f"GRANT SELECT ON mysql.db TO '{ch.TOOL}'@'%';"
        f"GRANT SELECT ON mysql.tables_priv TO '{ch.TOOL}'@'%'",
    )
    after = tuple(tool(service, read) for read in reads)
    print(f"PV7 proxies_priv, db, tables_priv without the grant: {before}; with it: {after}")
    ch.check(
        "PV7",
        (before, after),
        (
            (DENIED_TABLE,) * 3,
            (f"{ADMIN}>root", "mysql:Y", "mysql.user:Update"),
        ),
    )


def main() -> int:
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
