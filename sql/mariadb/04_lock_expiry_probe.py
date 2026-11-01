"""sopuli-dba : MariaDB account lock, password expiry and max_password_errors

#1220, as sql/mysql/04_lock_expiry_probe.py measured on MySQL. Lock and expiry
are how UC-2 holds a personal account, and a MariaDB driver would read them
back. On MariaDB, mysql.user is a view over mysql.global_priv, which holds an
account's settings as JSON beside its hash. This measures, on each server:

  LK1  ACCOUNT LOCK from the tool account, which holds only CREATE USER. Then
       a login with the password and one with a wrong password, and a second
       ACCOUNT LOCK
  LK2  where the lock can be read back, as root: a column account_locked in
       the mysql.user view, the key account_locked in mysql.global_priv, and
       SHOW CREATE USER
  LK3  ACCOUNT UNLOCK, then PASSWORD EXPIRE, from the tool account. Then the
       view's password_expired, a login that runs SELECT 1, and one that runs
       SET PASSWORD = PASSWORD('<new>') and is followed by a login with the
       new password. And disconnect_on_expired_password
  LK4  max_password_errors = 2, set by root for the case and put back. Two
       logins with a wrong password, then one with the right password. Then
       whether mysql.global_priv or SHOW CREATE USER changed, and a login after
       ACCOUNT UNLOCK from the tool account

The probe checks each result against the one RESULTS below records, as
02_client_hash_probe.py does. A difference, or a step that fails, makes it exit
1.

It MEASURES and decides nothing.

STATUS: run on 10.11.19 and 12.3.3, the mariadb:10.11 and mariadb:12.3 images
of test/compose.yaml profile mariadb-matrix, on 2026-11-01 (#1220), with Python
3.13.12 on Windows 11 AMD64. Twice, exit 0, and the same result both times.

RESULTS -- the same on both releases

  LK1  accepted. The password is refused, 4151 (HY000), "Access denied, this
       account is locked", and a wrong one 1045 (28000). The second lock is
       accepted
  LK2  the view has no such column, 1054 (42S22). In global_priv the key is
       JSON true, which JSON_VALUE reads as 1, and SHOW CREATE USER says
       ACCOUNT LOCK
  LK3  password_expired reads Y. The login connects, and SELECT 1 is refused,
       1820 (HY000), "You must SET PASSWORD before executing this statement".
       SET PASSWORD is accepted, and the new password logs in.
       disconnect_on_expired_password is 0
  LK4  both wrong passwords are refused, 1045 (28000), and then the right one,
       4150 (HY000), "User is blocked because of too many credential errors".
       Neither global_priv nor SHOW CREATE USER changed. After ACCOUNT UNLOCK
       the password logs in

  So the tool account can lock, unlock and expire an account with CREATE USER
  alone. The lock can be read only where the hash is too, in global_priv or in
  SHOW CREATE USER. The block that max_password_errors sets shows in neither of
  those; other places, such as information_schema and performance_schema,
  were not read.

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mariadb/04_lock_expiry_probe.py

It needs 02_client_hash_probe.py beside it.

THROWAWAY SERVERS ONLY. It creates the accounts sopuli_probe_hash and
sopuli_probe_tool, as 02 does, and drops them at the end. It sets
max_password_errors for LK4 and puts it back, also after a failed step.
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

ACCOUNT = f"'{ch.ACCOUNT}'@'%'"
PASSWORD = "Acme-Lock-pw1"
WHERE = f"WHERE user = '{ch.ACCOUNT}' AND host = '%'"


def tool(service: str, statement: str) -> str:
    return ch.code(ch.as_tool(service, statement))


def run_as(service: str, password: str, statement: str) -> str:
    """`ok`, or the refusal's code, for a statement the account runs."""
    ok, out = ch.mysql(service, ch.ACCOUNT, password, statement)
    return ch.OK if ok else ch.code(out)


def priv(service: str) -> str:
    return ch.root(service, f"SELECT Priv FROM mysql.global_priv {WHERE}")


def probe(service: str) -> None:
    # Put back the value the server had, not the compiled default.
    saved = ch.root(service, "SELECT @@GLOBAL.max_password_errors")
    if not saved.isdigit():
        raise ch.StepError(f"{service}: max_password_errors reads {saved!r}")
    ch.cleaned(
        service,
        lambda: cases(service),
        lambda: ch.root(service, f"SET GLOBAL max_password_errors = {saved}"),
    )


def cases(service: str) -> None:
    ch.base.setup(service, PASSWORD)

    answer = tool(service, f"ALTER USER {ACCOUNT} ACCOUNT LOCK")
    right, wrong = ch.login(service, PASSWORD), ch.login(service, ch.WRONG)
    again = tool(service, f"ALTER USER {ACCOUNT} ACCOUNT LOCK")
    print(f"LK1 lock: {answer}; password: {right}; wrong: {wrong}; second lock: {again}")
    ch.check("LK1", (answer, right, wrong, again), (ch.OK, "4151 (HY000)", ch.REFUSED, ch.OK))

    ok, column = ch.mysql(
        service, "root", ch.ROOT_PASSWORD, f"SELECT account_locked FROM mysql.user {WHERE}"
    )
    in_priv = ch.root(
        service, f"SELECT JSON_VALUE(Priv, '$.account_locked') FROM mysql.global_priv {WHERE}"
    )
    shown = "ACCOUNT LOCK" in ch.root(service, f"SHOW CREATE USER {ACCOUNT}")
    got = (column if ok else ch.code(column), in_priv, shown)
    print(f"LK2 view column, global_priv, SHOW CREATE USER: {got}")
    ch.check("LK2", got, ("1054 (42S22)", "1", True))

    unlock = tool(service, f"ALTER USER {ACCOUNT} ACCOUNT UNLOCK")
    expire = tool(service, f"ALTER USER {ACCOUNT} PASSWORD EXPIRE")
    expired = ch.root(service, f"SELECT password_expired FROM mysql.user {WHERE}")
    select = run_as(service, PASSWORD, "SELECT 1")
    changed = run_as(service, PASSWORD, "SET PASSWORD = PASSWORD('Acme-Lock-pw2')")
    after = ch.login(service, "Acme-Lock-pw2")
    disconnect = ch.root(service, "SELECT @@disconnect_on_expired_password")
    got = (unlock, expire, expired, select, changed, after, disconnect)
    print(
        "LK3 unlock, expire, password_expired, SELECT 1, SET PASSWORD, new password, "
        f"disconnect_on_expired_password: {got}"
    )
    ch.check("LK3", got, (ch.OK, ch.OK, "Y", "1820 (HY000)", ch.OK, ch.OK, "0"))

    before = (priv(service), ch.root(service, f"SHOW CREATE USER {ACCOUNT}"))
    ch.root(service, "SET GLOBAL max_password_errors = 2")
    attempts = (
        ch.login(service, ch.WRONG),
        ch.login(service, ch.WRONG),
        ch.login(service, "Acme-Lock-pw2"),
    )
    unchanged = before == (priv(service), ch.root(service, f"SHOW CREATE USER {ACCOUNT}"))
    unlock = tool(service, f"ALTER USER {ACCOUNT} ACCOUNT UNLOCK")
    after = ch.login(service, "Acme-Lock-pw2")
    print(
        f"LK4 wrong, wrong, right: {attempts}; unchanged: {unchanged}; "
        f"unlock: {unlock}, then: {after}"
    )
    ch.check(
        "LK4",
        (attempts, unchanged, unlock, after),
        ((ch.REFUSED, ch.REFUSED, "4150 (HY000)"), True, ch.OK, ch.OK),
    )


def main() -> int:
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
