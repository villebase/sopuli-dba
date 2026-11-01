"""sopuli-dba : MySQL account identity, and the tool account's grants

#1202. Invariant 5 binds one database user on one target to one place, with
names compared by upper(). A MySQL account is a user name and a host pattern.
And the tool account needs a privilege that changes other accounts'
passwords without reaching the administrative ones. This measures, on each
server:

  ID1  one user name with three host patterns, '%', 'localhost' and
       '192.0.2.%', each with its own password. Then a login over TCP from
       127.0.0.1 and one over the socket, with each of the first two
       passwords, and the account CURRENT_USER() names
  ID2  ALTER USER with the user name alone, no host, then which of ID1's
       accounts it changed
  ID3  a user name that differs from ID1's only in case, and a host that
       differs only in case
  ID4  ALTER USER for a host pattern the user name does not have
  TG1  the tool account, with only CREATE USER, alters root@'%' and
       root@'localhost'
  TG2  the accounts that hold SYSTEM_USER on a new server
  TG3  the tool account alters, then drops, an account that holds every
       privilege but SYSTEM_USER
  TG4  the tool account grants a privilege
  TG5  the tool account, given SELECT on chosen columns of mysql.user, reads
       the lock and expiry columns, then authentication_string, then
       User_attributes
  TG6  the tool account, given SYSTEM_USER as well, alters root@'%'

A login is "ok" and the account CURRENT_USER() names, or the error number and
SQLSTATE of the refusal.

The probe checks each result against the one RESULTS below records, as 02
does. A difference, or a step that fails, makes it exit 1.

It MEASURES and decides nothing.

STATUS: run on 8.0.46, 8.4.13 and 9.7.4, the mysql:8.0, mysql:8.4 and mysql:9
images of test/compose.yaml profile mysql-matrix, on 2026-11-01 (#1202), with
Python 3.13.12 on Windows 11 AMD64. Twice, exit 0, and the same result both
times.

RESULTS -- the same on all three releases

  ID1  three accounts, each with its own password. The servers run with
       skip_name_resolve = 1. Over TCP from 127.0.0.1, the '%' password logs
       in as sopuli_probe_id@% and the 'localhost' one is refused, 1045
       (28000). Over the socket, the 'localhost' password logs in as
       sopuli_probe_id@localhost and the '%' one is refused
  ID2  accepted, and only sopuli_probe_id@% is locked: a user name alone
       means the host '%'
  ID3  Sopuli_Probe_Id@% is created beside sopuli_probe_id@%, so two
       accounts at '%' differ only in case. 'LOCALHOST' is refused, 1396
       (HY000), because 'localhost' exists: host names are not case-sensitive
  ID4  refused, 1396 (HY000)
  TG1  both refused, 1227 (42000), "you need (at least one of) the
       SYSTEM_USER privilege(s) for this operation"
  TG2  mysql.infoschema@localhost, mysql.session@localhost,
       mysql.sys@localhost, root@% and root@localhost
  TG3  the tool account changes the password of, and then drops, an account
       that holds every privilege but SYSTEM_USER
  TG4  refused, 1044 (42000)
  TG5  the lock and expiry columns are read. authentication_string and
       User_attributes are refused, 1143 (42000), "SELECT command denied ...
       for column"
  TG6  accepted: with SYSTEM_USER the tool account changes root's password

  So an account is a user name and a host pattern, the user name is
  case-sensitive, and one name can have a password per host. CREATE USER is
  enough to change other accounts' passwords, and SYSTEM_USER is what keeps
  it off root and the system accounts, as long as the tool account does not
  hold it. An administrative account without SYSTEM_USER is not protected.
  Column grants on mysql.user let the tool read lock and expiry without the
  hashes, but not a retained password's state.

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mysql/05_identity_grants_probe.py

It needs only the standard library and the docker CLI, and
02_client_hash_probe.py beside it. The container names follow
COMPOSE_PROJECT_NAME, so a second clone's matrix is the one it uses.

THROWAWAY SERVERS ONLY. On each server it creates the tool account
sopuli_probe_tool and the accounts sopuli_probe_id and Sopuli_Probe_Id at
three hosts, and sopuli_probe_dba, and drops them at the end, and before it
starts it drops ones an interrupted run left. TG6 sets root@'%' to the
matrix's password it already has.
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

NAME = "sopuli_probe_id"
OTHER_CASE = "Sopuli_Probe_Id"
DBA = "sopuli_probe_dba"
HOSTS = {"%": "Acme-Id-pw1", "localhost": "Acme-Id-pw2", "192.0.2.%": "Acme-Id-pw3"}
OK, REFUSED = "ok", "1045 (28000)"
NO_SUCH = "1396 (HY000)"
NEEDS_SYSTEM_USER = "1227 (42000)"
EVERY_ACCOUNT = (
    f"'{NAME}'@'%', '{NAME}'@'localhost', '{NAME}'@'192.0.2.%', '{OTHER_CASE}'@'%', '{DBA}'@'%'"
)


def login(service: str, password: str, *, socket: bool) -> str:
    """`ok` and CURRENT_USER(), or the refusal, over TCP or over the socket."""
    # With no -h, the client uses the server's socket.
    flags = ("--protocol=SOCKET",) if socket else ("-h127.0.0.1",)
    returncode, out, err = ch.client(service, NAME, password, "SELECT CURRENT_USER()", *flags)
    if returncode == 0:
        return f"ok {out}"
    if not err.startswith("ERROR "):
        raise ch.StepError(f"{service}: login: {err[:200]}")
    return err.removeprefix("ERROR ").split(":")[0].split(" at line")[0]


def tool(service: str, statement: str) -> str:
    return ch.code(ch.as_tool(service, statement))


def locked(service: str) -> str:
    return ch.root(
        service,
        f"SELECT GROUP_CONCAT(CONCAT(host, '=', account_locked) ORDER BY host) "
        f"FROM mysql.user WHERE user = '{NAME}'",
    )


def drop(service: str) -> None:
    ch.root(service, f"DROP USER IF EXISTS {EVERY_ACCOUNT}")


def probe(service: str) -> None:
    ch.setup(service, "Acme-Probe-pw0")
    drop(service)
    for host, password in HOSTS.items():
        ch.root(service, f"CREATE USER '{NAME}'@'{host}' IDENTIFIED BY '{password}'")
    skip = ch.root(service, "SELECT @@skip_name_resolve")
    accounts = ch.root(
        service,
        f"SELECT GROUP_CONCAT(host ORDER BY host) FROM mysql.user WHERE user = '{NAME}'",
    )
    got = tuple(
        login(service, HOSTS[host], socket=socket)
        for host in ("%", "localhost")
        for socket in (False, True)
    )
    print(f"ID1 hosts: {accounts}; skip_name_resolve={skip}")
    print(f"ID1 '%' password over TCP, socket; 'localhost' password over TCP, socket: {got}")
    ch.check(
        "ID1",
        (accounts, skip, *got),
        (
            "%,192.0.2.%,localhost", "1",
            f"ok {NAME}@%", REFUSED, REFUSED, f"ok {NAME}@localhost",
        ),
    )  # fmt: skip

    answer = tool(service, f"ALTER USER '{NAME}' ACCOUNT LOCK")
    print(f"ID2 {answer}; locked: {locked(service)}")
    ch.check("ID2", (answer, locked(service)), (OK, "%=Y,192.0.2.%=N,localhost=N"))

    other = ch.code(
        ch.mysql(
            service, "root", ch.ROOT_PASSWORD,
            f"CREATE USER '{OTHER_CASE}'@'%' IDENTIFIED BY 'Acme-Id-pw4'",
        )[1] or OK
    )  # fmt: skip
    names = ch.root(
        service,
        f"SELECT COUNT(*) FROM mysql.user WHERE host = '%' AND user IN ('{NAME}', '{OTHER_CASE}')",
    )
    ok, out = ch.mysql(
        service, "root", ch.ROOT_PASSWORD, f"CREATE USER '{NAME}'@'LOCALHOST' IDENTIFIED BY 'x'"
    )
    host_case = OK if ok else ch.code(out)
    print(f"ID3 other case: {other}, accounts at '%': {names}; host in capitals: {host_case}")
    ch.check("ID3", (other, names, host_case), (OK, "2", NO_SUCH))

    answer = tool(service, f"ALTER USER '{NAME}'@'198.51.100.%' ACCOUNT LOCK")
    print(f"ID4 {answer}")
    ch.check("ID4", answer, NO_SUCH)

    got = (
        tool(service, "ALTER USER 'root'@'%' ACCOUNT LOCK"),
        tool(service, "ALTER USER 'root'@'localhost' ACCOUNT LOCK"),
    )
    print(f"TG1 root@'%', root@'localhost': {got}")
    ch.check("TG1", got, (NEEDS_SYSTEM_USER, NEEDS_SYSTEM_USER))

    holders = ch.root(
        service,
        "SELECT GROUP_CONCAT(CONCAT(user, '@', host) ORDER BY user, host) "
        f"FROM mysql.global_grants WHERE priv = 'SYSTEM_USER' AND user <> '{ch.TOOL}'",
    )
    print(f"TG2 {holders}")
    ch.check(
        "TG2",
        holders,
        "mysql.infoschema@localhost,mysql.session@localhost,mysql.sys@localhost,"
        "root@%,root@localhost",
    )

    ch.root(
        service,
        f"CREATE USER '{DBA}'@'%' IDENTIFIED BY 'Acme-Dba-pw1';"
        f"GRANT ALL ON *.* TO '{DBA}'@'%' WITH GRANT OPTION;"
        f"REVOKE SYSTEM_USER ON *.* FROM '{DBA}'@'%'",
    )
    got = (
        tool(service, f"ALTER USER '{DBA}'@'%' IDENTIFIED BY 'Acme-Dba-pw2'"),
        tool(service, f"DROP USER '{DBA}'@'%'"),
        tool(service, f"GRANT SELECT ON mysql.* TO '{NAME}'@'%'"),
    )
    print(f"TG3 alters, drops an account with every privilege but SYSTEM_USER: {got[:2]}")
    print(f"TG4 grants: {got[2]}")
    ch.check("TG3 TG4", got, (OK, OK, "1044 (42000)"))

    ch.root(
        service,
        "GRANT SELECT (User, Host, account_locked, password_expired, password_last_changed, "
        f"password_lifetime) ON mysql.user TO '{ch.TOOL}'@'%'",
    )
    got = (
        tool(
            service,
            "SELECT GROUP_CONCAT(CONCAT(host, '=', account_locked, password_expired) "
            f"ORDER BY host) FROM mysql.user WHERE user = '{NAME}'",
        ),
        tool(service, "SELECT authentication_string FROM mysql.user LIMIT 1"),
        tool(service, "SELECT User_attributes FROM mysql.user LIMIT 1"),
    )
    print(f"TG5 lock and expiry, authentication_string, User_attributes: {got}")
    ch.check("TG5", got, (OK, "1143 (42000)", "1143 (42000)"))

    ch.root(service, f"GRANT SYSTEM_USER ON *.* TO '{ch.TOOL}'@'%'")
    answer = tool(service, f"ALTER USER 'root'@'%' IDENTIFIED BY '{ch.ROOT_PASSWORD}'")
    print(f"TG6 {answer}")
    ch.check("TG6", answer, OK)

    drop(service)


def main() -> int:
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
