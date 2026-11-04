"""sopuli-dba : where the tool account reads the privileges MariaDB split from SUPER

#1267, M4. Check 9 refuses a managed account that holds an administrative
privilege (#1222). 05 found that the privileges MariaDB split from SUPER, such
as SET USER and BINLOG ADMIN, set no column of the mysql.user view: they are in
mysql.global_priv's access bits and in SHOW GRANTS, both beside the hash. This
looks for any other place the tool account can read them from. On each server:

  SP1  the privileges SHOW PRIVILEGES gives the context Server: the split ones
  SP2  an account granted each of them alone ON *.*, and a role granted SET
       USER and given to a second account as its default role. As root: which
       of the view's *_priv columns read Y for the account and for the role,
       and whether global_priv's access bits are above 0. Then how many rows
       information_schema.USER_PRIVILEGES shows root for the role
  SP3  the account, now granted all of them, and the tool account, which
       holds CREATE USER, with each of these grants,
       one at a time: none; SELECT on the view's columns User, Host, plugin,
       password_expired and is_role; SELECT (User, Host) on mysql.global_priv;
       SELECT on mysql.user; SELECT on mysql.global_priv; SELECT on mysql.*.
       With each: how many rows information_schema.USER_PRIVILEGES shows it
       for the account and for the role, and SHOW GRANTS FOR the account:
       refused, or shown, and whether it prints the hash

The probe checks each result against the one RESULTS below records, as
02_client_hash_probe.py does. A difference, or a step that fails, makes it exit
1.

It MEASURES and decides nothing.

STATUS: run on 10.11.19, 11.4.13, 11.8.9 and 12.3.3, the mariadb:10.11,
mariadb:11.4, mariadb:11.8 and mariadb:12.3 images of test/compose.yaml profile
mariadb-matrix, on 2026-11-04 (#1267), with Python 3.13.12 on Windows 11 AMD64.
Twice, exit 0, and the same result both times.

RESULTS -- the same on every release

  SP1  ten: BINLOG ADMIN, BINLOG MONITOR, BINLOG REPLAY, CONNECTION ADMIN,
       FEDERATED ADMIN, READ_ONLY ADMIN, REPLICATION MASTER ADMIN,
       REPLICATION SLAVE ADMIN, SET USER and SLAVE MONITOR
  SP2  BINLOG MONITOR, once called REPLICATION CLIENT, sets Repl_client_priv.
       The other nine, and the role's SET USER, set no column. Each sets
       global_priv's access bits. USER_PRIVILEGES shows root no row for the
       role
  SP3  with each grant but the last, USER_PRIVILEGES shows the tool account no
       row, and SHOW GRANTS is refused, 1044 (42000). With SELECT on mysql.*,
       USER_PRIVILEGES shows the account's ten rows, still none for the role,
       and SHOW GRANTS shows the grants with the hash

  So the tool account can read nine of the ten split privileges only through
  SELECT on mysql.*, which also reads mysql.global_priv and its hashes. A
  role's split privileges are not in USER_PRIVILEGES even then.

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mariadb/08_split_privileges_probe.py

It needs 02_client_hash_probe.py beside it.

THROWAWAY SERVERS ONLY. It creates the accounts sopuli_probe_hash,
sopuli_probe_tool, as 02 does, sopuli_probe_split and sopuli_probe_member, and
the role sopuli_probe_role. It drops them at the end, also after a failed step,
and before it starts it drops ones an interrupted run left.
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

SPLIT = "sopuli_probe_split"
MEMBER = "sopuli_probe_member"
ROLE = "sopuli_probe_role"
TOOL = f"'{ch.TOOL}'@'%'"
GRANTS = (
    "",
    "SELECT (User, Host, plugin, password_expired, is_role) ON mysql.user",
    "SELECT (User, Host) ON mysql.global_priv",
    "SELECT ON mysql.user",
    "SELECT ON mysql.global_priv",
    "SELECT ON mysql.*",
)


def drop_extra(service: str) -> None:
    ch.root(service, f"DROP USER IF EXISTS '{SPLIT}'@'%', '{MEMBER}'@'%'")
    ch.root(service, f"DROP ROLE IF EXISTS {ROLE}")


def tool_reads(service: str, statement: str) -> tuple[bool, str]:
    return ch.mysql(service, ch.TOOL, ch.TOOL_PASSWORD, statement)


def priv_columns(service: str, user: str, host: str) -> str:
    """The view's *_priv columns that read Y for this row, or `-`."""
    columns = ch.root(
        service,
        "SELECT GROUP_CONCAT(column_name) FROM information_schema.columns "
        "WHERE table_schema = 'mysql' AND table_name = 'user' AND column_name LIKE '%\\_priv'",
    ).split(",")
    listed = ", ".join(f"IF(`{c}` = 'Y', '{c}', NULL)" for c in columns)
    found = ch.root(
        service,
        f"SELECT CONCAT_WS(',', {listed}) FROM mysql.user "
        f"WHERE user = '{user}' AND host = '{host}'",
    )
    return found or "-"


def access_bits(service: str, user: str, host: str) -> int:
    return int(
        ch.root(
            service,
            "SELECT JSON_VALUE(Priv, '$.access') FROM mysql.global_priv "
            f"WHERE user = '{user}' AND host = '{host}'",
        )
    )


def privilege_rows(service: str, grantee: str) -> str:
    ok, out = tool_reads(
        service,
        "SELECT COUNT(*) FROM information_schema.USER_PRIVILEGES "
        f"WHERE grantee = {ch.quote(grantee)}",
    )
    return out if ok else ch.code(out)


def show_grants(service: str, hash_: str) -> str:
    ok, out = tool_reads(service, f"SHOW GRANTS FOR '{SPLIT}'@'%'")
    if not ok:
        return ch.code(out)
    return "shown, with the hash" if hash_ in out else "shown, without the hash"


def probe(service: str) -> None:
    ch.cleaned(service, lambda: cases(service), lambda: drop_extra(service))


def cases(service: str) -> None:
    ch.base.setup(service, "Acme-Split-pw0")
    drop_extra(service)

    ok, listed = ch.mysql(service, "root", ch.ROOT_PASSWORD, "SHOW PRIVILEGES")
    if not ok:
        raise ch.StepError(f"{service}: SHOW PRIVILEGES: {listed}")
    split_list = [
        line.split("\t")[0] for line in listed.splitlines() if line.split("\t")[1:2] == ["Server"]
    ]
    split = ",".join(sorted(split_list))
    print(f"SP1 Server privileges: {split}")
    ch.check("SP1", split, SP1)

    password = "Acme-Split-pw1"
    value = ch.native_hash(password)
    ch.root(service, f"CREATE USER '{SPLIT}'@'%' IDENTIFIED BY {ch.quote(password)}")
    columns = {}
    for privilege in split_list:
        ch.root(service, f"GRANT {privilege} ON *.* TO '{SPLIT}'@'%'")
        columns[privilege] = (
            priv_columns(service, SPLIT, "%"),
            access_bits(service, SPLIT, "%") > 0,
        )
        ch.root(service, f"REVOKE ALL PRIVILEGES ON *.* FROM '{SPLIT}'@'%'")
    print(f"SP2 alone, the *_priv columns that read Y, and access bits > 0: {columns}")
    ch.check("SP2 alone", columns, sp2(split_list))

    ch.root(
        service,
        f"GRANT {', '.join(split_list)} ON *.* TO '{SPLIT}'@'%';"
        f"CREATE ROLE {ROLE}; GRANT SET USER ON *.* TO {ROLE};"
        f"CREATE USER '{MEMBER}'@'%' IDENTIFIED BY 'Acme-Member-pw1';"
        f"GRANT {ROLE} TO '{MEMBER}'@'%'; SET DEFAULT ROLE {ROLE} FOR '{MEMBER}'@'%'",
    )
    role = (priv_columns(service, ROLE, ""), access_bits(service, ROLE, "") > 0)
    print(f"SP2 role with SET USER: {role}")
    ch.check("SP2 role", role, ("-", True))

    role_as_root = ch.root(
        service,
        "SELECT COUNT(*) FROM information_schema.USER_PRIVILEGES "
        f"WHERE grantee LIKE {ch.quote('%' + ROLE + '%')}",
    )
    print(f"SP2 USER_PRIVILEGES rows for the role, as root: {role_as_root}")
    ch.check("SP2 role as root", role_as_root, "0")

    seen = []
    for grant in GRANTS:
        if grant:
            ch.root(service, f"GRANT {grant} TO {TOOL}")
        row = (
            privilege_rows(service, f"'{SPLIT}'@'%'"),
            privilege_rows(service, f"'{ROLE}'@''"),
            show_grants(service, value),
        )
        if grant:
            ch.root(service, f"REVOKE {grant} FROM {TOOL}")
        print(f"SP3 {grant or 'no grant'}: {row}")
        seen.append(row)
    ch.check("SP3", seen, SP3)


SP1 = (
    "Binlog admin,Binlog monitor,Binlog replay,Connection admin,Federated admin,"
    "Read_only admin,Replication master admin,Replication slave admin,Set user,Slave monitor"
)


def sp2(split_list: list[str]) -> dict[str, tuple[str, bool]]:
    """Only BINLOG MONITOR, once REPLICATION CLIENT, sets a column."""
    return {
        privilege: ("Repl_client_priv" if privilege == "Binlog monitor" else "-", True)
        for privilege in split_list
    }


#: For each of GRANTS: USER_PRIVILEGES rows for the account and for the role,
#: and SHOW GRANTS FOR the account. Only SELECT on mysql.* shows anything.
SP3 = [("0", "0", "1044 (42000)")] * 5 + [("10", "0", "shown, with the hash")]


def main() -> int:
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
