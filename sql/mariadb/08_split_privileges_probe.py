"""sopuli-dba : where the tool account reads MariaDB's Server privileges

#1267, M4. Check 9 refuses a managed account that holds an administrative
privilege (#1222). 05 found that privileges MariaDB split from SUPER, such as
SET USER and BINLOG ADMIN, set no column of the mysql.user view: they are in
mysql.global_priv's access bits and in SHOW GRANTS, both beside the hash. This
looks for any other place the tool account can read them from. It takes the
privileges SHOW PRIVILEGES gives the context Server. Most of these were split
from SUPER; BINLOG MONITOR is REPLICATION CLIENT renamed, and SLAVE MONITOR was
split from it. On each server:

  SP1  the privileges SHOW PRIVILEGES gives the context Server
  SP2  an account granted each of them alone ON *.*, and a role granted SET
       USER and PROCESS, which has a column, and given to a second account as
       its default role. As root: which
       of the view's *_priv columns read Y for the account, the role and the
       second account, and whether global_priv's access bits are above 0 for
       the account and the role. Then, in information_schema.USER_PRIVILEGES,
       the second account's privileges and how many rows root sees for the
       role
  SP3  the account, now granted all of them, and the tool account, which
       holds CREATE USER, with each of these grants, one at a time: none;
       SELECT on the view's columns User, Host, plugin, password_expired,
       is_role and Repl_client_priv; SELECT (User, Host) on
       mysql.global_priv; SELECT on mysql.user; SELECT on mysql.global_priv;
       SELECT on mysql.*. With each: how many USER_PRIVILEGES rows the tool
       account sees for the account and for the role; SHOW GRANTS FOR the
       account, refused, or shown, and whether it prints the hash; and the
       account's Repl_client_priv as the tool account reads it

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
  SP2  BINLOG MONITOR sets Repl_client_priv, the column of REPLICATION
       CLIENT. The other nine set no column. The role reads Process_priv only,
       and the second account has no column set. Each sets global_priv's
       access bits. USER_PRIVILEGES shows root only USAGE for the second
       account, and no row at all for the role, PROCESS included
  SP3  with each grant but the last, USER_PRIVILEGES shows the tool account no
       row, and SHOW GRANTS is refused, 1044 (42000). With SELECT on mysql.*,
       USER_PRIVILEGES shows the account's ten rows, still none for the role,
       and SHOW GRANTS shows the grants with the hash. Repl_client_priv reads
       Y with the column grant, SELECT on mysql.user and SELECT on mysql.*,
       and is refused, 1142 (42000), otherwise

  So the tool account reads BINLOG MONITOR, the renamed REPLICATION CLIENT,
  from the view's column, without the hash. It can read the other nine, which
  include every one split from SUPER, only through SELECT on mysql.*, which
  also reads mysql.global_priv and its hashes. A role has no row in
  USER_PRIVILEGES even then, and an account that holds privileges through a
  role shows only its own there, USAGE.

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mariadb/08_split_privileges_probe.py

It needs 02_client_hash_probe.py beside it, and what 02 needs:
sql/mysql/02_client_hash_probe.py.

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
    "SELECT (User, Host, plugin, password_expired, is_role, Repl_client_priv) ON mysql.user",
    "SELECT (User, Host) ON mysql.global_priv",
    "SELECT ON mysql.user",
    "SELECT ON mysql.global_priv",
    "SELECT ON mysql.*",
)


def drop_extra(service: str) -> None:
    ch.root(service, f"DROP USER IF EXISTS '{SPLIT}'@'%', '{MEMBER}'@'%'")
    ch.root(service, f"DROP ROLE IF EXISTS {ROLE}")


def tool_reads(service: str, statement: str) -> str:
    """What the tool account reads, or its refusal's code."""
    ok, out = ch.mysql(service, ch.TOOL, ch.TOOL_PASSWORD, statement)
    return out if ok else ch.code(out)


def priv_column_names(service: str) -> list[str]:
    return ch.root(
        service,
        "SELECT GROUP_CONCAT(column_name ORDER BY column_name) FROM information_schema.columns "
        "WHERE table_schema = 'mysql' AND table_name = 'user' AND column_name LIKE '%\\_priv'",
    ).split(",")


def priv_columns(service: str, columns: list[str], user: str, host: str) -> str:
    """The view's *_priv columns that read Y for this row, or `-`. A missing row fails."""
    listed = ", ".join(f"IF(`{c}` = 'Y', '{c}', NULL)" for c in columns)
    found = ch.root(
        service,
        f"SELECT CONCAT('row:', CONCAT_WS(',', {listed})) FROM mysql.user "
        f"WHERE user = '{user}' AND host = '{host}'",
    )
    if not found.startswith("row:"):
        raise ch.StepError(f"{service}: no mysql.user row for {user!r}@{host!r}")
    return found.removeprefix("row:") or "-"


def access_bits(service: str, user: str, host: str) -> int:
    return int(
        ch.root(
            service,
            "SELECT JSON_VALUE(Priv, '$.access') FROM mysql.global_priv "
            f"WHERE user = '{user}' AND host = '{host}'",
        )
    )


def grantee_like(name: str) -> str:
    """A USER_PRIVILEGES predicate for a grantee named `name`, at any host or none.

    `_` is a LIKE wildcard, so it is escaped. The pattern is the quoted name,
    as USER_PRIVILEGES writes it, followed by anything.
    """
    pattern = "'" + name.replace("_", "\\_") + "'%"
    return f"grantee LIKE {ch.quote(pattern)}"


def privilege_rows(service: str, name: str) -> str:
    """How many USER_PRIVILEGES rows the tool account sees for this name."""
    return tool_reads(
        service,
        f"SELECT COUNT(*) FROM information_schema.USER_PRIVILEGES WHERE {grantee_like(name)}",
    )


def repl_client(service: str) -> str:
    """The account's Repl_client_priv, as the tool account reads it."""
    return tool_reads(
        service, f"SELECT Repl_client_priv FROM mysql.user WHERE user = '{SPLIT}' AND host = '%'"
    )


def show_grants(service: str) -> str:
    """SHOW GRANTS FOR the account: the refusal, or whether it prints the stored value.

    It is printed as IDENTIFIED BY PASSWORD '...' or IDENTIFIED VIA ... USING
    '...', whichever plugin the account is on.
    """
    ok, out = ch.mysql(service, ch.TOOL, ch.TOOL_PASSWORD, f"SHOW GRANTS FOR '{SPLIT}'@'%'")
    if not ok:
        return ch.code(out)
    printed = "IDENTIFIED BY PASSWORD '" in out or " USING '" in out
    return "shown, with the hash" if printed else "shown, without the hash"


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
    ch.root(service, f"CREATE USER '{SPLIT}'@'%' IDENTIFIED BY {ch.quote(password)}")
    names = priv_column_names(service)
    columns = {}
    for privilege in split_list:
        ch.root(service, f"GRANT {privilege} ON *.* TO '{SPLIT}'@'%'")
        columns[privilege] = (
            priv_columns(service, names, SPLIT, "%"),
            access_bits(service, SPLIT, "%") > 0,
        )
        ch.root(service, f"REVOKE ALL PRIVILEGES ON *.* FROM '{SPLIT}'@'%'")
    print(f"SP2 alone, the *_priv columns that read Y, and access bits > 0: {columns}")
    ch.check("SP2 alone", columns, sp2(split_list))

    ch.root(
        service,
        f"GRANT {', '.join(split_list)} ON *.* TO '{SPLIT}'@'%';"
        # PROCESS has a column, Process_priv, and SET USER has none.
        f"CREATE ROLE {ROLE}; GRANT SET USER, PROCESS ON *.* TO {ROLE};"
        f"CREATE USER '{MEMBER}'@'%' IDENTIFIED BY 'Acme-Member-pw1';"
        f"GRANT {ROLE} TO '{MEMBER}'@'%'; SET DEFAULT ROLE {ROLE} FOR '{MEMBER}'@'%'",
    )
    role = (priv_columns(service, names, ROLE, ""), access_bits(service, ROLE, "") > 0)
    member = (
        priv_columns(service, names, MEMBER, "%"),
        ch.root(
            service,
            "SELECT GROUP_CONCAT(privilege_type) FROM information_schema.USER_PRIVILEGES "
            f"WHERE {grantee_like(MEMBER)}",
        ),
    )
    role_as_root = ch.root(
        service,
        f"SELECT COUNT(*) FROM information_schema.USER_PRIVILEGES WHERE {grantee_like(ROLE)}",
    )
    print(
        f"SP2 role with SET USER and PROCESS: {role}; its member's *_priv columns and "
        f"USER_PRIVILEGES: {member}; USER_PRIVILEGES rows for the role, as root: {role_as_root}"
    )
    ch.check(
        "SP2 role", (role, member, role_as_root), (("Process_priv", True), ("-", "USAGE"), "0")
    )

    seen = []
    for grant in GRANTS:
        if grant:
            ch.root(service, f"GRANT {grant} TO {TOOL}")
        row = (
            privilege_rows(service, SPLIT),
            privilege_rows(service, ROLE),
            show_grants(service),
            repl_client(service),
        )
        if grant:
            ch.root(service, f"REVOKE {grant} FROM {TOOL}")
        print(f"SP3 {grant or 'no grant'}: {row}")
        seen.append(row)
    ch.check("SP3", seen, sp3(len(split_list)))


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


def sp3(split_count: int) -> object:
    """For each of GRANTS: USER_PRIVILEGES rows for the account and for the role,
    SHOW GRANTS FOR the account, and its Repl_client_priv as the tool account reads it.
    """
    refused = ("0", "0", "1044 (42000)")
    return [
        (*refused, "1142 (42000)"),
        (*refused, "Y"),
        (*refused, "1142 (42000)"),
        (*refused, "Y"),
        (*refused, "1142 (42000)"),
        (str(split_count), "0", "shown, with the hash", "Y"),
    ]


def main() -> int:
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
