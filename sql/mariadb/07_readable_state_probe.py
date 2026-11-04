"""sopuli-dba : what the tool account reads of another MariaDB account, without the hash

#1267, M2 and M3. `creds apply` decides `changed` from what it reads of an
account, and `account list` shows a lock, an expiry and a block. On MariaDB the
hash, the lock and the time of the last password change are in
mysql.global_priv, which the tool account must not read (05). This measures
what it can read elsewhere, on each server. The tool account holds CREATE USER,
and from RD2 on also SELECT on the mysql.user view's columns User, Host,
plugin, password_expired and is_role:

  RD1  the view's columns that name a password, a lock, a lifetime or a change.
       information_schema.USERS where the release has it, its columns, and how
       many rows the tool account sees there with each of these grants, one at
       a time: none beyond CREATE USER; the column grant; SELECT (User, Host)
       on mysql.global_priv; SELECT on mysql.user; SELECT on mysql.global_priv;
       SELECT on mysql.*
  RD2  a password change by the tool account, by value, with IDENTIFIED VIA
       ... USING. Then whether the account's view row, as the tool account
       reads it, or its USERS row, as the tool account and as root read it,
       changed
  RD3  the same, with PASSWORD EXPIRE INTERVAL 1000 DAY on the account
  RD4  a rollover, IDENTIFIED VIA ... USING '<old>' OR ... USING '<new>': the
       same three reads, before and during it
  RD5  ACCOUNT LOCK, then PASSWORD EXPIRE: the same three reads after each
  RD6  with max_password_errors = 2, set by root and put back: PASSWORD_ERRORS
       as root reads it, after one wrong password, after a second, which
       blocks the account, after ACCOUNT UNLOCK, and after a wrong one then the
       right one

RD2 to RD5 wait over a second before each change, so a time stored in seconds
would differ.

The probe checks each result against the one RESULTS below records, as
02_client_hash_probe.py does. A difference, or a step that fails, makes it exit
1.

It MEASURES and decides nothing.

STATUS: run on 10.11.19, 11.4.13, 11.8.9 and 12.3.3, the mariadb:10.11,
mariadb:11.4, mariadb:11.8 and mariadb:12.3 images of test/compose.yaml profile
mariadb-matrix, on 2026-11-04 (#1267), with Python 3.13.12 on Windows 11 AMD64.
Twice, exit 0, and the same result both times.

RESULTS -- the same on every release, except where noted

  RD1  the view's columns are Password, Lock_tables_priv and password_expired:
       none for the time of a change, a lifetime or a lock. 10.11.19 and
       11.4.13 have no information_schema.USERS. 11.8.9 and 12.3.3 have it,
       with USER, PASSWORD_ERRORS and PASSWORD_EXPIRATION_TIME. The tool
       account sees only its own row with each grant but the last: SELECT on
       mysql.* shows every account, and it also reads mysql.global_priv
  RD2  nothing the tool account reads changed. Root's USERS row did not either:
       PASSWORD_EXPIRATION_TIME is NULL
  RD3  nothing the tool account reads changed. Root's USERS row did:
       PASSWORD_EXPIRATION_TIME moved by the time between the two changes
  RD4  nothing changed, for the tool account or for root
  RD5  the lock changes nothing. The expiry sets the view's password_expired
       to Y, and root's PASSWORD_EXPIRATION_TIME to 0000-00-00 00:00:00
  RD6  as root reads it, PASSWORD_ERRORS goes 0, 1, 2 with the wrong
       passwords, stays 2 when the right one is refused, 4150, and goes back
       to 0 after ACCOUNT UNLOCK, and after the right password logs in

  So the tool account reads the plugin and the expiry, and nothing else:
  neither when a password changed, nor a rollover, a lock or a block. A block
  is readable on 11.8.9 and 12.3.3, in USERS, but only with SELECT on mysql.*,
  which also reads the hashes.

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mariadb/07_readable_state_probe.py

It needs 02_client_hash_probe.py beside it.

THROWAWAY SERVERS ONLY. It installs the ed25519 plugin, creates the accounts
sopuli_probe_hash and sopuli_probe_tool, as 02 does, and drops them at the end.
It uninstalls ed25519 if the server did not have it. It sets
max_password_errors for RD6 and puts it back, also after a failed step.
"""

from __future__ import annotations

import importlib.util
import sys
import time
from pathlib import Path

# 02's name starts with a digit, so it is loaded by its path.
_SPEC = importlib.util.spec_from_file_location(
    "mariadb_client_hash_probe", Path(__file__).with_name("02_client_hash_probe.py")
)
assert _SPEC is not None
assert _SPEC.loader is not None
ch = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ch)

ACCOUNT = f"'{ch.ACCOUNT}'@'%'"
TOOL = f"'{ch.TOOL}'@'%'"
GRANTED = "User, Host, plugin, password_expired, is_role"
VIEW = f"SELECT {GRANTED} FROM mysql.user WHERE user = '{ch.ACCOUNT}' AND host = '%'"
USERS = f"SELECT * FROM information_schema.USERS WHERE user = {ch.quote(ACCOUNT)}"
#: RD1's grants, each given alone and taken back.
GRANTS = (
    f"SELECT ({GRANTED}) ON mysql.user",
    "SELECT (User, Host) ON mysql.global_priv",
    "SELECT ON mysql.user",
    "SELECT ON mysql.global_priv",
    "SELECT ON mysql.*",
)
PASSWORD = "Acme-Read-pw1"


def tool_reads(service: str, statement: str) -> str:
    """What the tool account reads, or its refusal's code."""
    ok, out = ch.mysql(service, ch.TOOL, ch.TOOL_PASSWORD, statement)
    return out if ok else ch.code(out)


def has_users(service: str) -> bool:
    found = ch.root(
        service,
        "SELECT COUNT(*) FROM information_schema.tables "
        "WHERE table_schema = 'information_schema' AND table_name = 'USERS'",
    )
    return found == "1"


def state(service: str) -> tuple[str, str, str]:
    """The view row as the tool reads it, and the USERS row as the tool and root read it."""
    if not has_users(service):
        return tool_reads(service, VIEW), "-", "-"
    return tool_reads(service, VIEW), tool_reads(service, USERS), ch.root(service, USERS)


def set_value(service: str, password: str) -> str:
    """Set the account's password by value, after a pause of over a second."""
    time.sleep(1.5)
    value = ch.native_hash(password)
    return ch.code(
        ch.as_tool(
            service, f"ALTER USER {ACCOUNT} IDENTIFIED VIA mysql_native_password USING '{value}'"
        )
    )


def probe(service: str) -> None:
    saved = ch.root(service, "SELECT @@GLOBAL.max_password_errors")
    if not saved.isdigit():
        raise ch.StepError(f"{service}: max_password_errors reads {saved!r}")
    had = ch.plugins(service)
    ch.cleaned(
        service,
        lambda: cases(service),
        lambda: ch.root(service, f"SET GLOBAL max_password_errors = {saved}"),
        lambda: ch.uninstall_plugins(service, keep=had + ",parsec"),
    )


def rows_seen(service: str) -> str:
    return tool_reads(service, "SELECT COUNT(*) FROM information_schema.USERS")


def cases(service: str) -> None:
    ch.base.setup(service, PASSWORD)
    users = has_users(service)

    columns = ch.root(
        service,
        "SELECT GROUP_CONCAT(column_name ORDER BY ordinal_position) "
        "FROM information_schema.columns WHERE table_schema = 'mysql' AND table_name = 'user' "
        "AND (column_name LIKE '%passw%' OR column_name LIKE '%lifetime%' "
        "OR column_name LIKE '%changed%' OR column_name LIKE '%lock%')",
    )
    users_columns = "-"
    seen = ["-"]
    if users:
        users_columns = ch.root(
            service,
            "SELECT GROUP_CONCAT(column_name ORDER BY ordinal_position) "
            "FROM information_schema.columns "
            "WHERE table_schema = 'information_schema' AND table_name = 'USERS'",
        )
        seen = [rows_seen(service)]
        for grant in GRANTS:
            ch.root(service, f"GRANT {grant} TO {TOOL}")
            seen.append(rows_seen(service))
            ch.root(service, f"REVOKE {grant} FROM {TOOL}")
        every = ch.root(service, "SELECT COUNT(*) FROM information_schema.USERS")
        seen.append(f"of {every}")
    print(f"RD1 view columns: {columns}; USERS: {users_columns}; rows seen: {seen}")
    ch.check("RD1", (columns, users_columns, seen), rd1(users, len(seen) and seen[-1]))

    ch.root(service, f"GRANT {GRANTS[0]} TO {TOOL}")

    before = state(service)
    changed = set_value(service, "Acme-Read-pw2")
    after = state(service)
    print(f"RD2 change: {changed}; before: {before}; after: {after}")
    ch.check("RD2", (changed, before == after), (ch.OK, True))

    ch.root(service, f"ALTER USER {ACCOUNT} PASSWORD EXPIRE INTERVAL 1000 DAY")
    before = state(service)
    changed = set_value(service, "Acme-Read-pw3")
    after = state(service)
    print(f"RD3 change: {changed}; before: {before}; after: {after}")
    same = tuple(b == a for b, a in zip(before, after, strict=True))
    ch.check("RD3", (changed, same), (ch.OK, (True, True, not users)))
    ch.root(service, f"ALTER USER {ACCOUNT} PASSWORD EXPIRE DEFAULT")

    ch.root(service, "INSTALL PLUGIN IF NOT EXISTS ed25519 SONAME 'auth_ed25519'")
    before = state(service)
    time.sleep(1.5)
    old, new = ch.native_hash("Acme-Read-pw3"), ch.ed25519_value("Acme-Read-pw4")
    opened = ch.code(
        ch.as_tool(
            service,
            f"ALTER USER {ACCOUNT} IDENTIFIED VIA mysql_native_password USING '{old}' "
            f"OR ed25519 USING '{new}'",
        )
    )
    during = state(service)
    print(f"RD4 rollover: {opened}; before: {before}; during: {during}")
    ch.check("RD4", (opened, before == during), (ch.OK, True))
    set_value(service, "Acme-Read-pw3")

    before = state(service)
    ch.as_tool(service, f"ALTER USER {ACCOUNT} ACCOUNT LOCK")
    locked = state(service)
    ch.as_tool(service, f"ALTER USER {ACCOUNT} ACCOUNT UNLOCK")
    ch.as_tool(service, f"ALTER USER {ACCOUNT} PASSWORD EXPIRE")
    expired = state(service)
    print(f"RD5 before: {before}; locked: {locked}; expired: {expired}")
    ch.check("RD5", (before == locked, expired), (True, rd5(users)))
    set_value(service, "Acme-Read-pw3")

    if not users:
        print("RD6 no information_schema.USERS")
        return
    errors = (
        f"SELECT PASSWORD_ERRORS FROM information_schema.USERS WHERE user = {ch.quote(ACCOUNT)}"
    )
    ch.root(service, "SET GLOBAL max_password_errors = 2")
    got = [ch.root(service, errors)]
    for step in ("wrong", "wrong", "right", "unlock", "wrong", "right"):
        if step == "unlock":
            got.append(ch.code(ch.as_tool(service, f"ALTER USER {ACCOUNT} ACCOUNT UNLOCK")))
        else:
            got.append(ch.login(service, ch.WRONG if step == "wrong" else "Acme-Read-pw3"))
        got.append(ch.root(service, errors))
    print(f"RD6 errors, then each of wrong, wrong, right, unlock, wrong, right and errors: {got}")
    ch.check("RD6", tuple(got), RD6)


COLUMNS = "Password,Lock_tables_priv,password_expired"
USERS_COLUMNS = "USER,PASSWORD_ERRORS,PASSWORD_EXPIRATION_TIME"
EXPIRED_VIEW = f"{ch.ACCOUNT}\t%\tmysql_native_password\tY\tN"


def rd1(users: bool, every: object) -> object:
    """Only SELECT on mysql.*, which reads global_priv, shows every row."""
    if not users:
        return COLUMNS, "-", ["-"]
    total = str(every).removeprefix("of ")
    # No grant, then GRANTS one at a time, then how many rows there are.
    return COLUMNS, USERS_COLUMNS, ["1", "1", "1", "1", "1", total, f"of {total}"]


def rd5(users: bool) -> object:
    """After PASSWORD EXPIRE. The tool account sees no USERS row."""
    if not users:
        return EXPIRED_VIEW, "-", "-"
    return EXPIRED_VIEW, "", f"'{ch.ACCOUNT}'@'%'\t0\t0000-00-00 00:00:00"


#: PASSWORD_ERRORS counts each wrong password, stays at 2 through the blocked
#: login, and goes back to 0 on ACCOUNT UNLOCK and on a login.
RD6 = ("0", ch.REFUSED, "1", ch.REFUSED, "2", "4150 (HY000)", "2", ch.OK, "0",
       ch.REFUSED, "1", ch.OK, "0")  # fmt: skip


def main() -> int:
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
