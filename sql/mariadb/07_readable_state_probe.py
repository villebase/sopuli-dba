"""sopuli-dba : what the tool account reads of another MariaDB account, without the hash

#1267, M2 and M3. `creds apply` decides `changed` from what it reads of an
account, and `account list` shows a lock, an expiry and a block. On MariaDB the
hash, the lock and the time of the last password change are in
mysql.global_priv, which the tool account must not read (05). This measures
what it can read elsewhere, on each server. The tool account holds CREATE USER,
and from RD2 on also SELECT on the mysql.user view's columns User, Host,
plugin, password_expired and is_role:

  RD1  the view's columns that name a password, a lock, a lifetime or a change.
       information_schema.USERS where the release has it, and its columns.
       Then, with each of these grants given to the tool account one at a
       time, how many USERS rows it sees, and whether it reads the account's
       hash in mysql.global_priv: none beyond CREATE USER; the column grant;
       SELECT (User, Host) on mysql.global_priv; SELECT on mysql.user; SELECT
       on mysql.global_priv; SELECT on mysql.*
  RD2  a password change by the tool account, by value, with IDENTIFIED VIA
       ... USING. Then whether the account's view row, as the tool account
       reads it, or its USERS row, as the tool account and as root read it,
       changed
  RD3  the same, with PASSWORD EXPIRE INTERVAL 1000 DAY on the account, which
       stays on it to the end of RD5
  RD4  a rollover, IDENTIFIED VIA ... USING '<old>' OR ... USING '<new>': the
       same three reads, before and during it
  RD5  ACCOUNT LOCK, ACCOUNT UNLOCK and PASSWORD EXPIRE from the tool account,
       and the same three reads before, after the lock, and after the expiry
  RD6  with max_password_errors = 2, set by root and put back: PASSWORD_ERRORS
       as root reads it, after one wrong password, after a second, which
       blocks the account, after ACCOUNT UNLOCK, and after a wrong one then the
       right one

Each change between a before and an after read in RD2 to RD5 waits over a
second first, so a time stored in seconds would differ.

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
       with USER, PASSWORD_ERRORS and PASSWORD_EXPIRATION_TIME. With each
       grant but the last, the tool account sees one row, its own,
       'sopuli_probe_tool'@'%'. SELECT on mysql.* shows it every row root
       sees. The hash: refused, 1142 (42000), with no grant, the column grant
       and SELECT on mysql.user; refused, 1143 (42000), with SELECT (User,
       Host) on global_priv; read with SELECT on mysql.global_priv and with
       SELECT on mysql.*
  RD2  nothing the tool account reads changed. Root's USERS row did not either:
       PASSWORD_EXPIRATION_TIME is NULL
  RD3  nothing the tool account reads changed. In root's USERS row only
       PASSWORD_EXPIRATION_TIME changed, and it moved later
  RD4  nothing the tool account reads changed. Root's PASSWORD_EXPIRATION_TIME
       moved later, as in RD3
  RD5  each statement accepted. The lock changes nothing, for the tool
       account or for root, under the lifetime too. The expiry sets the view's
       password_expired to Y, and root's PASSWORD_EXPIRATION_TIME to
       0000-00-00 00:00:00
  RD6  as root reads it, PASSWORD_ERRORS goes 0, 1, 2 with the wrong
       passwords, stays 2 when the right one is refused, 4150, and goes back
       to 0 after ACCOUNT UNLOCK, and after the right password logs in

  So the tool account reads the plugin and the expiry, and nothing else:
  neither when a password changed, nor a rollover, a lock or a block. A block
  is readable on 11.8.9 and 12.3.3, in USERS, but only with SELECT on mysql.*,
  which also reads the hashes.

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mariadb/07_readable_state_probe.py

It needs 02_client_hash_probe.py beside it, and what 02 needs:
sql/mysql/02_client_hash_probe.py.

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


def state(service: str, users: bool) -> tuple[str, str, str]:
    """The view row as the tool reads it, and the USERS row as the tool and root read it."""
    if not users:
        return tool_reads(service, VIEW), "-", "-"
    return tool_reads(service, VIEW), tool_reads(service, USERS), ch.root(service, USERS)


def tool_does(service: str, statement: str, *, pause: bool = True) -> str:
    """`ok`, or the refusal's code, for a change the tool account makes.

    A change between a before and an after read waits over a second first, so
    that a time stored in seconds would differ.
    """
    if pause:
        time.sleep(1.5)
    return ch.code(ch.as_tool(service, statement))


def set_value(service: str, password: str, *, pause: bool = True) -> str:
    """Set the account's password by value."""
    value = ch.native_hash(password)
    return tool_does(
        service,
        f"ALTER USER {ACCOUNT} IDENTIFIED VIA mysql_native_password USING '{value}'",
        pause=pause,
    )


def restore(service: str, password: str) -> None:
    """Set the password back between cases. A refusal is a failed step."""
    answer = set_value(service, password, pause=False)
    if answer != ch.OK:
        raise ch.StepError(f"{service}: setting the password back: {answer}")


def hash_read(service: str) -> str:
    """Whether the tool account reads the account's hash in mysql.global_priv."""
    got = tool_reads(
        service,
        "SELECT JSON_VALUE(Priv, '$.authentication_string') FROM mysql.global_priv "
        f"WHERE user = '{ch.ACCOUNT}' AND host = '%'",
    )
    return "the hash" if got == ch.native_hash(PASSWORD) else got


def probe(service: str) -> None:
    saved = ch.root(service, "SELECT @@GLOBAL.max_password_errors")
    if not saved.isdigit():
        raise ch.StepError(f"{service}: max_password_errors reads {saved!r}")
    had = ch.plugins(service)
    ch.cleaned(
        service,
        lambda: cases(service),
        lambda: ch.root(service, f"SET GLOBAL max_password_errors = {saved}"),
        lambda: ch.uninstall_plugins(service, keep=had),
    )


def rows_seen(service: str) -> str:
    """The one USERS row the tool account sees, by name, or how many it sees."""
    count = tool_reads(service, "SELECT COUNT(*) FROM information_schema.USERS")
    if count != "1":
        return count
    return tool_reads(service, "SELECT user FROM information_schema.USERS")


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
    every = "-"
    seen: list[tuple[str, str]] = []
    if users:
        users_columns = ch.root(
            service,
            "SELECT GROUP_CONCAT(column_name ORDER BY ordinal_position) "
            "FROM information_schema.columns "
            "WHERE table_schema = 'information_schema' AND table_name = 'USERS'",
        )
        every = ch.root(service, "SELECT COUNT(*) FROM information_schema.USERS")
    for grant in ("", *GRANTS):
        if grant:
            ch.root(service, f"GRANT {grant} TO {TOOL}")
        seen.append((rows_seen(service) if users else "-", hash_read(service)))
        if grant:
            ch.root(service, f"REVOKE {grant} FROM {TOOL}")
    print(
        f"RD1 view columns: {columns}; USERS: {users_columns}, {every} rows; "
        f"with each grant, USERS rows seen and global_priv's hash read: {seen}"
    )
    ch.check("RD1", (columns, users_columns, seen), rd1(users, every))

    ch.root(service, f"GRANT {GRANTS[0]} TO {TOOL}")

    before = state(service, users)
    changed = set_value(service, "Acme-Read-pw2")
    after = state(service, users)
    print(f"RD2 change: {changed}; before: {before}; after: {after}")
    ch.check("RD2", (changed, before == after), (ch.OK, True))

    # From here to the end of RD5 the account has a lifetime, so that USERS'
    # PASSWORD_EXPIRATION_TIME is a time that could move.
    ch.root(service, f"ALTER USER {ACCOUNT} PASSWORD EXPIRE INTERVAL 1000 DAY")
    before = state(service, users)
    changed = set_value(service, "Acme-Read-pw3")
    after = state(service, users)
    print(f"RD3 change: {changed}; before: {before}; after: {after}")
    ch.check("RD3", (changed, compare(before, after)), (ch.OK, moved_later(users)))

    ch.root(service, "INSTALL PLUGIN IF NOT EXISTS ed25519 SONAME 'auth_ed25519'")
    before = state(service, users)
    old, new = ch.native_hash("Acme-Read-pw3"), ch.ed25519_value("Acme-Read-pw4")
    opened = tool_does(
        service,
        f"ALTER USER {ACCOUNT} IDENTIFIED VIA mysql_native_password USING '{old}' "
        f"OR ed25519 USING '{new}'",
    )
    during = state(service, users)
    print(f"RD4 rollover: {opened}; before: {before}; during: {during}")
    ch.check("RD4", (opened, compare(before, during)), (ch.OK, moved_later(users)))
    restore(service, "Acme-Read-pw3")

    before = state(service, users)
    lock = tool_does(service, f"ALTER USER {ACCOUNT} ACCOUNT LOCK")
    locked = state(service, users)
    unlock = tool_does(service, f"ALTER USER {ACCOUNT} ACCOUNT UNLOCK", pause=False)
    expire = tool_does(service, f"ALTER USER {ACCOUNT} PASSWORD EXPIRE", pause=False)
    expired = state(service, users)
    print(
        f"RD5 lock: {lock}, unlock: {unlock}, expire: {expire}; before: {before}; "
        f"locked: {locked}; expired: {expired}"
    )
    ch.check(
        "RD5",
        (lock, unlock, expire, compare(before, locked), expired),
        (ch.OK, ch.OK, ch.OK, (True, True, "same" if users else "-"), rd5(users)),
    )
    ch.root(service, f"ALTER USER {ACCOUNT} PASSWORD EXPIRE DEFAULT")
    restore(service, "Acme-Read-pw3")

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


def compare(before: tuple[str, str, str], after: tuple[str, str, str]) -> tuple[bool, bool, str]:
    """Whether each of the tool account's two reads is unchanged, and how root's USERS row moved.

    Root's row: `-` without USERS, `same`, `later` when only
    PASSWORD_EXPIRATION_TIME changed and moved later, or `other`.
    """
    root = "-" if before[2] == "-" else "same" if before[2] == after[2] else "other"
    if root == "other":
        (user_b, errors_b, time_b), (user_a, errors_a, time_a) = (
            before[2].split("\t"),
            after[2].split("\t"),
        )
        # The times are YYYY-MM-DD HH:MM:SS, so they sort as strings.
        if (user_b, errors_b) == (user_a, errors_a) and time_a > time_b:
            root = "later"
    return before[0] == after[0], before[1] == after[1], root


def moved_later(users: bool) -> tuple[bool, bool, str]:
    """Under a lifetime: the tool account reads no change; root's time moves later."""
    return True, True, "later" if users else "-"


#: global_priv's hash, for no grant and then each of GRANTS.
HASH_READ = ["1142 (42000)", "1142 (42000)", "1143 (42000)", "1142 (42000)", "the hash", "the hash"]


def rd1(users: bool, every: str) -> object:
    """With no grant, then GRANTS one at a time: USERS rows seen, and global_priv's hash.

    Only SELECT on mysql.* shows every USERS row, and it reads the hash too.
    """
    if not users:
        return COLUMNS, "-", [("-", read) for read in HASH_READ]
    own = f"'{ch.TOOL}'@'%'"
    rows = [own, own, own, own, own, every]
    return COLUMNS, USERS_COLUMNS, list(zip(rows, HASH_READ, strict=True))


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
