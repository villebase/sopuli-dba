"""sopuli-dba : MariaDB account identity, and the tool account's grants

#1220, as sql/mysql/05_identity_grants_probe.py measured on MySQL. A MariaDB
account is a user name and a host, as on MySQL, but MariaDB has no
SYSTEM_USER, and since 10.5 it splits SUPER into privileges of their own. This
measures, on each server:

  ID1  one user name at the hosts '%' and 'localhost', each with its own
       password. Then a login over TCP from 127.0.0.1 and one over the socket,
       with each password, and the account CURRENT_USER() names
  ID2  ALTER USER with the user name alone, no host, then which of ID1's
       accounts it changed
  ID3  a user name that differs from ID1's only in case. A host that differs
       only in case from one that exists. A new account at 'LOCALHOST', and
       the host it is stored with
  ID4  ALTER USER for a host the user name does not have, 192.0.2.99
  TG1  the tool account, with only CREATE USER, alters root@'%',
       root@'localhost' and mariadb.sys@'localhost', each with a statement that
       leaves its password, plugin and lock as they were: root@'%''s own
       password on mysql_native_password, which root@'%' is on in these images
       (the probe stops if it is not), ACCOUNT UNLOCK for root, and ACCOUNT LOCK
       for mariadb.sys, which is locked. password_last_changed does change.
       Then whether root@'%' still logs in, and its plugin
  TG2  GRANT SYSTEM_USER, as root
  TG3  the tool account alters, then drops, an account that holds ALL
       PRIVILEGES WITH GRANT OPTION
  TG4  the tool account grants a privilege
  TG5  the tool account reads mysql.user, runs SHOW CREATE USER and SHOW
       GRANTS FOR another account, and reads INFORMATION_SCHEMA.USER_PRIVILEGES.
       Then, given SELECT on chosen columns of the mysql.user view, it reads
       them, then Password, then authentication_string
  TG6  an account that holds BINLOG ADMIN, CONNECTION ADMIN and READ_ONLY
       ADMIN: how many of the view's *_priv columns read Y for it, its access
       bits in mysql.global_priv, and whether SHOW GRANTS, run by root, names
       the privileges and prints the hash
  TG7  a role that holds SUPER, granted to an account as its default role.
       The view's Super_priv and is_role for both, read by the tool account,
       and mysql.roles_mapping, without and with SELECT on it

A login is "ok" and the account CURRENT_USER() names, or the error number and
SQLSTATE of the refusal.

The probe checks each result against the one RESULTS below records, as
02_client_hash_probe.py does. A difference, or a step that fails, makes it exit
1.

It MEASURES and decides nothing.

STATUS: run on 10.11.19 and 12.3.3, the mariadb:10.11 and mariadb:12.3 images
of test/compose.yaml profile mariadb-matrix, on 2026-11-01 (#1220), with Python
3.13.12 on Windows 11 AMD64. Twice, exit 0, and the same result both times.

RESULTS -- the same on both releases

  ID1  two accounts, each with its own password. The servers run with
       skip_name_resolve = 1. Over TCP from 127.0.0.1, the '%' password logs
       in as sopuli_probe_id@% and the 'localhost' one is refused, 1045
       (28000). Over the socket, the 'localhost' password logs in as
       sopuli_probe_id@localhost and the '%' one is refused
  ID2  accepted, and only sopuli_probe_id@% is locked: a user name alone
       means the host '%'. The 'localhost' account, never locked or
       unlocked, has no account_locked key in global_priv
  ID3  Sopuli_Probe_Id@% is created beside sopuli_probe_id@%, and a lookup of
       sopuli_probe_id at '%' finds one account, so the two are two accounts
       that differ only in case. 'LOCALHOST' is refused, 1396
       (HY000), because 'localhost' exists. A new account at 'LOCALHOST' is
       stored at 'localhost': host names are not case-sensitive
  ID4  refused, 1396 (HY000)
  TG1  all four accepted, root@'%' still logs in and is still on
       mysql_native_password: nothing keeps an account with CREATE USER off
       root
  TG2  refused, 1064 (42000): MariaDB has no SYSTEM_USER
  TG3  the tool account changes the password of, and then drops, an account
       that holds ALL PRIVILEGES WITH GRANT OPTION
  TG4  refused, 1044 (42000)
  TG5  reading mysql.user is refused, 1142 (42000), and so are SHOW CREATE
       USER and SHOW GRANTS, 1044 (42000). USER_PRIVILEGES shows only the tool
       account's own privileges. With the column grant, the columns read, and
       Password and authentication_string are refused, 1143 (42000)
  TG6  none of the view's *_priv columns reads Y. The access bits are a
       number above 0.
       SHOW GRANTS names the three privileges and prints the hash, IDENTIFIED
       BY PASSWORD '*...'
  TG7  the account's Super_priv is N, and the role's is Y with is_role Y.
       mysql.roles_mapping is refused, 1142 (42000), without the grant. With
       it, it shows the role granted to the account

  So on MariaDB an account with CREATE USER can change root's password, and
  every other administrative account's. Lock and the privileges split from
  SUPER cannot be read from the view; global_priv and SHOW GRANTS hold them
  beside the hash.

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mariadb/05_identity_grants_probe.py

It needs 02_client_hash_probe.py beside it.

THROWAWAY SERVERS ONLY. On each server it creates the accounts
sopuli_probe_tool and sopuli_probe_hash, as 02 does, sopuli_probe_id at two
hosts, Sopuli_Probe_Id@'%', sopuli_probe_host@'localhost', sopuli_probe_dba@'%',
sopuli_probe_split@'%' and the role sopuli_probe_role. It drops them at the
end, also after a failed step, and before it starts it drops ones an
interrupted run left. TG1 sets root@'%' to the matrix's password it already
has.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

# 02's name starts with a digit, so it is loaded by its path.
_SPEC = importlib.util.spec_from_file_location(
    "mariadb_client_hash_probe", Path(__file__).with_name("02_client_hash_probe.py")
)
assert _SPEC is not None
assert _SPEC.loader is not None
ch = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ch)

NAME = "sopuli_probe_id"
OTHER_CASE = "Sopuli_Probe_Id"
HOST_CASE = "sopuli_probe_host"
DBA = "sopuli_probe_dba"
SPLIT = "sopuli_probe_split"
ROLE = "sopuli_probe_role"
HOSTS = {"%": "Acme-Id-pw1", "localhost": "Acme-Id-pw2"}
OK, REFUSED = ch.OK, ch.REFUSED
NO_SUCH = ch.FAILED
EVERY_ACCOUNT = (
    f"'{NAME}'@'%', '{NAME}'@'localhost', '{OTHER_CASE}'@'%', '{HOST_CASE}'@'localhost', "
    f"'{DBA}'@'%', '{SPLIT}'@'%'"
)
COLUMNS = "User, Host, password_expired, is_role, Super_priv, Create_user_priv, Grant_priv"


def login(service: str, password: str, *, socket: bool) -> str:
    """`ok` and CURRENT_USER(), or the refusal, over TCP or over the socket."""
    flags = ("--protocol=SOCKET",) if socket else ("-h127.0.0.1",)
    ok, out = ch.mysql(service, NAME, password, "SELECT CURRENT_USER()", *flags)
    return f"ok {out}" if ok else ch.code(out)


def tool(service: str, statement: str) -> str:
    """The output of a statement the tool account sends, or the refusal's code."""
    ok, out = ch.mysql(service, ch.TOOL, ch.TOOL_PASSWORD, statement)
    return (out or OK) if ok else ch.code(out)


def drop(service: str) -> None:
    ch.root(service, f"DROP USER IF EXISTS {EVERY_ACCOUNT}; DROP ROLE IF EXISTS '{ROLE}'")


def probe(service: str) -> None:
    """Run the cases, and drop this probe's own accounts whatever happens."""
    ch.cleaned(service, lambda: cases(service), lambda: drop(service))


def cases(service: str) -> None:
    ch.base.setup(service, "Acme-Probe-pw0")
    drop(service)
    identity(service)
    grants(service)
    reading(service)


def identity(service: str) -> None:
    for host, password in HOSTS.items():
        ch.root(service, f"CREATE USER '{NAME}'@'{host}' IDENTIFIED BY '{password}'")
    skip = ch.root(service, "SELECT @@skip_name_resolve")
    got = tuple(
        login(service, HOSTS[host], socket=socket)
        for host in ("%", "localhost")
        for socket in (False, True)
    )
    print(
        f"ID1 skip_name_resolve={skip}; '%' over TCP, socket; 'localhost' over TCP, socket: {got}"
    )
    ch.check(
        "ID1",
        (skip, *got),
        ("1", f"ok {NAME}@%", REFUSED, REFUSED, f"ok {NAME}@localhost"),
    )

    answer = tool(service, f"ALTER USER '{NAME}' ACCOUNT LOCK")
    locked = ch.root(
        service,
        # An account never locked or unlocked has no key at all.
        "SELECT GROUP_CONCAT(CONCAT(host, '=', IFNULL(JSON_VALUE(Priv, '$.account_locked'), "
        f"'no key')) ORDER BY host) FROM mysql.global_priv WHERE user = '{NAME}'",
    )
    print(f"ID2 {answer}; locked: {locked}")
    ch.check("ID2", (answer, locked), (OK, "%=1,localhost=no key"))

    ok, out = ch.mysql(
        service,
        "root",
        ch.ROOT_PASSWORD,
        f"CREATE USER '{OTHER_CASE}'@'%' IDENTIFIED BY 'Acme-Id-pw4'",
    )
    other = OK if ok else ch.code(out)
    # The view's User compares as stored, so this counts only the one spelling
    # if the two are two accounts.
    names = ch.root(
        service, f"SELECT COUNT(*) FROM mysql.user WHERE host = '%' AND user = '{NAME}'"
    )
    ok, out = ch.mysql(
        service, "root", ch.ROOT_PASSWORD, f"CREATE USER '{NAME}'@'LOCALHOST' IDENTIFIED BY 'x'"
    )
    host_case = OK if ok else ch.code(out)
    ch.root(service, f"CREATE USER '{HOST_CASE}'@'LOCALHOST' IDENTIFIED BY 'Acme-Id-pw5'")
    stored = ch.root(service, f"SELECT host FROM mysql.user WHERE user = '{HOST_CASE}'")
    print(
        f"ID3 other case: {other}, accounts at '%' named exactly {NAME}: {names}; "
        f"'LOCALHOST' beside 'localhost': "
        f"{host_case}; a new 'LOCALHOST' is stored as: {stored}"
    )
    ch.check("ID3", (other, names, host_case, stored), (OK, "1", NO_SUCH, "localhost"))

    answer = tool(service, f"ALTER USER '{NAME}'@'192.0.2.99' ACCOUNT LOCK")
    print(f"ID4 {answer}")
    ch.check("ID4", answer, NO_SUCH)


def grants(service: str) -> None:
    sys_locked = ch.root(
        service,
        "SELECT JSON_VALUE(Priv, '$.account_locked') FROM mysql.global_priv "
        "WHERE user = 'mariadb.sys' AND host = 'localhost'",
    )
    if sys_locked != "1":
        raise ch.StepError(f"{service}: mariadb.sys is not locked, so TG1 would change it")
    # IDENTIFIED BY sets the default plugin, so TG1 leaves root@'%' on the
    # plugin it had only if that is mysql_native_password, as on these images.
    root_plugin = "SELECT plugin FROM mysql.user WHERE user = 'root' AND host = '%'"
    if ch.root(service, root_plugin) != "mysql_native_password":
        raise ch.StepError(f"{service}: root@'%' is on another plugin, so TG1 would change it")
    got = (
        tool(service, f"ALTER USER 'root'@'%' IDENTIFIED BY {ch.quote(ch.ROOT_PASSWORD)}"),
        tool(service, "ALTER USER 'root'@'%' ACCOUNT UNLOCK"),
        tool(service, "ALTER USER 'root'@'localhost' ACCOUNT UNLOCK"),
        tool(service, "ALTER USER 'mariadb.sys'@'localhost' ACCOUNT LOCK"),
    )
    still = ch.login(service, ch.ROOT_PASSWORD, "root")
    plugin = ch.root(service, root_plugin)
    print(
        f"TG1 root@'%' password, root@'%', root@'localhost', mariadb.sys: {got}; "
        f"root logs in: {still}; root@'%''s plugin: {plugin}"
    )
    ch.check("TG1", (*got, still, plugin), (OK, OK, OK, OK, OK, "mysql_native_password"))

    ok, out = ch.mysql(
        service, "root", ch.ROOT_PASSWORD, f"GRANT SYSTEM_USER ON *.* TO '{ch.TOOL}'@'%'"
    )
    answer = OK if ok else ch.code(out)
    print(f"TG2 GRANT SYSTEM_USER: {answer}")
    ch.check("TG2", answer, "1064 (42000)")

    ch.root(
        service,
        f"CREATE USER '{DBA}'@'%' IDENTIFIED BY 'Acme-Dba-pw1';"
        f"GRANT ALL PRIVILEGES ON *.* TO '{DBA}'@'%' WITH GRANT OPTION",
    )
    got = (
        tool(service, f"ALTER USER '{DBA}'@'%' IDENTIFIED BY 'Acme-Dba-pw2'"),
        tool(service, f"DROP USER '{DBA}'@'%'"),
        tool(service, f"GRANT SELECT ON mysql.* TO '{NAME}'@'%'"),
    )
    print(f"TG3 alters, drops an account with ALL PRIVILEGES: {got[:2]}")
    print(f"TG4 grants: {got[2]}")
    ch.check("TG3 TG4", got, (OK, OK, "1044 (42000)"))


def reading(service: str) -> None:
    got = (
        tool(service, "SELECT User FROM mysql.user LIMIT 1"),
        tool(service, f"SHOW CREATE USER '{NAME}'@'%'"),
        tool(service, "SHOW GRANTS FOR 'root'@'%'"),
        tool(
            service, "SELECT GROUP_CONCAT(DISTINCT GRANTEE) FROM information_schema.USER_PRIVILEGES"
        ),
    )
    print(f"TG5 mysql.user, SHOW CREATE USER, SHOW GRANTS, USER_PRIVILEGES: {got}")
    ch.check(
        "TG5 without", got, ("1142 (42000)", "1044 (42000)", "1044 (42000)", f"'{ch.TOOL}'@'%'")
    )

    ch.root(service, f"GRANT SELECT ({COLUMNS}) ON mysql.user TO '{ch.TOOL}'@'%'")
    got = (
        tool(
            service,
            f"SELECT CONCAT_WS(',', {COLUMNS}) FROM mysql.user WHERE User = 'root' AND Host = '%'",
        ),
        tool(service, "SELECT Password FROM mysql.user LIMIT 1"),
        tool(service, "SELECT authentication_string FROM mysql.user LIMIT 1"),
    )
    print(f"TG5 with the column grant: root@'%', Password, authentication_string: {got}")
    ch.check("TG5 with", got, ("root,%,N,N,Y,Y,Y", "1143 (42000)", "1143 (42000)"))

    ch.root(
        service,
        f"CREATE USER '{SPLIT}'@'%' IDENTIFIED BY 'Acme-Split-pw1';"
        f"GRANT BINLOG ADMIN, CONNECTION ADMIN, READ_ONLY ADMIN ON *.* TO '{SPLIT}'@'%'",
    )
    priv_columns = ch.root(
        service,
        "SELECT GROUP_CONCAT(COLUMN_NAME) FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = 'mysql' AND TABLE_NAME = 'user' AND COLUMN_NAME LIKE '%\\_priv'",
    ).split(",")
    yes = ch.root(
        service,
        "SELECT "
        + " + ".join(f"({c} = 'Y')" for c in priv_columns)
        + f" FROM mysql.user WHERE User = '{SPLIT}'",
    )
    access = ch.root(
        service,
        f"SELECT JSON_VALUE(Priv, '$.access') FROM mysql.global_priv WHERE user = '{SPLIT}'",
    )
    shown = ch.root(service, f"SHOW GRANTS FOR '{SPLIT}'@'%'")
    names = all(p in shown for p in ("BINLOG ADMIN", "CONNECTION ADMIN", "READ_ONLY ADMIN"))
    hashed = "IDENTIFIED BY PASSWORD '*" in shown
    print(
        f"TG6 *_priv columns reading Y: {yes} of {len(priv_columns)}; access: {access}; "
        f"SHOW GRANTS names them: {names}, prints the hash: {hashed}"
    )
    # A missing key reads NULL, which is not a number.
    bits = access.isdigit() and int(access) > 0
    ch.check("TG6", (yes, bits, names, hashed), ("0", True, True, True))

    ch.root(
        service,
        f"CREATE ROLE '{ROLE}'; GRANT SUPER ON *.* TO '{ROLE}';"
        f"GRANT '{ROLE}' TO '{NAME}'@'%'; SET DEFAULT ROLE '{ROLE}' FOR '{NAME}'@'%'",
    )
    supers = tool(
        service,
        "SELECT GROUP_CONCAT(CONCAT(User, '=', Super_priv, is_role) ORDER BY User) FROM mysql.user "
        f"WHERE (User = '{NAME}' AND Host = '%') OR User = '{ROLE}'",
    )
    mapping = f"SELECT CONCAT(User, '>', Role) FROM mysql.roles_mapping WHERE User = '{NAME}'"
    without = tool(service, mapping)
    ch.root(service, f"GRANT SELECT ON mysql.roles_mapping TO '{ch.TOOL}'@'%'")
    with_grant = tool(service, mapping)
    print(
        f"TG7 Super_priv and is_role: {supers}; "
        f"roles_mapping without: {without}; with: {with_grant}"
    )
    ch.check(
        "TG7",
        (supers, without, with_grant),
        (f"{NAME}=NN,{ROLE}=YY", "1142 (42000)", f"{NAME}>{ROLE}"),
    )


def main() -> int:
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
