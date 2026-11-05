"""sopuli-dba : what PASSWORD EXPIRE does to a MariaDB rollover

#1271. MariaDB's rollover is `IDENTIFIED VIA <plugin> USING '<old>' OR <plugin>
USING '<new>'` (03, DP2): both passwords log in until the new value is sent
alone. MySQL keeps a retained password logging in, expired, after PASSWORD
EXPIRE, so its `account expire-password` discards it first (sql/mysql/04,
LE9). This measures the same on MariaDB, on each server, for
mysql_native_password and ed25519, as a tool account that holds only CREATE
USER, over PyMySQL from the host:

  RE1  the tool account sets the old and the new value with OR. Then a login
       with each password
  RE2  the tool account sends PASSWORD EXPIRE. Then the view's
       password_expired, as root, and a login with the old password, the new
       one and a wrong one
  RE3  on a second account, set up as RE1 and RE2: a session with the old
       password sends SET PASSWORD = PASSWORD('<its own>'). Then a login with
       the old, the new and its own password
  RE4  on the first account, the tool account sends the new value alone, as a
       rollover's finish does. Then password_expired, and a login with the old
       and the new password
  RE5  on the second account, the tool account sets the rollover with the new
       value first. Then a login with the new password, the old one and a
       wrong one

A login answers `ok` where the session runs `SELECT 1`, `1820` where the
session opens and `SELECT 1` is refused because the password has expired, or
the error's number at connect.

The probe checks each result against the one RESULTS below records. A
difference, or a step that fails, makes it exit 1.

It MEASURES and decides nothing.

STATUS: run on 10.11.19, 11.4.13, 11.8.9 and 12.3.3, the mariadb:10.11,
mariadb:11.4, mariadb:11.8 and mariadb:12.3 images of test/compose.yaml profile
mariadb-matrix, on 2026-11-05 (#1271), with PyMySQL 1.2.3 and PyNaCl 1.6.2, and
Python 3.13.12 on Windows 11 AMD64. Twice, exit 0, and the same result both
times.

RESULTS -- the same on every release

  RE1  the tool account sets both values. On mysql_native_password both
       passwords log in. On ed25519 the old one, the first method, logs in,
       and the new one fails inside PyMySQL: "received multiple auth switch
       requests", an OperationalError with no number. The server asks for a
       second authentication for the second method, and PyMySQL 1.2.3 takes
       only one. The mariadb client logs in with both (03, DP2)
  RE2  PASSWORD EXPIRE is accepted, and password_expired reads Y. **Both
       passwords still log in, expired**: each answers 1820. A wrong one is
       refused, 1045, on mysql_native_password; on ed25519 the second method
       and a wrong password both fail as in RE1
  RE3  the old password's expired session sets a password of its own. Then
       the old password is refused, 1045, and the new one and its own both log
       in, on mysql_native_password: SET PASSWORD replaced the method the
       session logged in with, and the other method stayed. On ed25519 its
       own logs in, and the others fail as in RE1
  RE4  the new value alone is accepted. password_expired reads N: setting a
       password ends the expiry. The old password is refused, 1045, and the
       new one logs in
  RE5  with the new value first, the new password logs in on both plugins.
       On mysql_native_password the old one logs in too, and a wrong one is
       refused, 1045. On ed25519 the old one and a wrong one fail as in RE1

  So PASSWORD EXPIRE does not end a rollover: both passwords keep logging
  in, expired. A new password ends both the rollover and the expiry. And
  PyMySQL can use only the first method of an ed25519 OR.

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mariadb/11_rollover_expiry_probe.py

It needs PyMySQL and PyNaCl in the environment that runs it, and 02 and 06
beside it, whose helpers and ports it uses.

THROWAWAY SERVERS ONLY. It installs the ed25519 plugin, creates the accounts
sopuli_probe_hash, sopuli_probe_tool and sopuli_probe_own, and drops them at
the end, also after a failed step. It uninstalls each plugin it installed, and
leaves one the server had before.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pymysql

# 06's name starts with a digit, so it is loaded by its path. It loads 02.
_SPEC = importlib.util.spec_from_file_location(
    "mariadb_pymysql_login_probe", Path(__file__).with_name("06_pymysql_login_probe.py")
)
assert _SPEC is not None
assert _SPEC.loader is not None
pl = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(pl)
ch = pl.ch

PLUGINS = ("mysql_native_password", "ed25519")
OWN = "sopuli_probe_own"
OLD, NEW, MINE = "Acme-Roll-old1", "Acme-Roll-new2", "Acme-Roll-mine3"


def connect(service: str, user: str, password: str) -> Any:
    """Without TLS, which neither plugin needs: it sends no password, and
    10.11.19 offers none (06, PL2)."""
    return pymysql.connect(
        host="127.0.0.1",
        port=pl.PORTS[service],
        user=user,
        password=password.encode("utf-8"),
        ssl_disabled=True,
        autocommit=True,
        connect_timeout=10,
    )


def login(service: str, user: str, password: str) -> str:
    """`ok`, `1820` after the session opens, or the number at connect."""
    try:
        connection = connect(service, user, password)
    except pymysql.err.MySQLError as exc:
        return pl.answer(exc)
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        return ch.OK
    except pymysql.err.MySQLError as exc:
        return pl.answer(exc)
    finally:
        connection.close()


def rollover(service: str, plugin: str, account: str, *, new_first: bool = False) -> str:
    """The tool account sets the old and the new value with OR, the old one
    first, or the new one first."""
    old, new = ch.COMPUTE[plugin](OLD), ch.COMPUTE[plugin](NEW)
    first, second = (new, old) if new_first else (old, new)
    answer = ch.as_tool(
        service,
        f"ALTER USER '{account}'@'%' IDENTIFIED VIA {plugin} USING '{first}' "
        f"OR {plugin} USING '{second}'",
    )
    return answer if answer == ch.OK else ch.code(answer)


def expired(service: str, account: str) -> str:
    return ch.root(
        service, f"SELECT password_expired FROM mysql.user WHERE User = '{account}' AND Host = '%'"
    )


def probe(service: str) -> None:
    had = ch.root(
        service,
        "SELECT GROUP_CONCAT(plugin_name) FROM information_schema.plugins "
        "WHERE plugin_name IN ('ed25519', 'parsec')",
    )
    # The accounts are dropped before the plugins they use are uninstalled.
    ch.cleaned(
        service,
        lambda: cases(service),
        lambda: ch.root(service, f"DROP USER IF EXISTS '{OWN}'@'%'"),
        lambda: ch.base.teardown(service),
        lambda: ch.uninstall_plugins(service, keep=had if had != "NULL" else ""),
    )


def cases(service: str) -> None:
    ch.base.setup(service, "Acme-Roll-pw0")
    ch.root(service, f"DROP USER IF EXISTS '{OWN}'@'%'")
    ch.root(service, f"CREATE USER '{OWN}'@'%' IDENTIFIED BY 'Acme-Roll-pw0'")
    ch.install_plugins(service)
    account = ch.ACCOUNT

    for plugin in PLUGINS:
        answer = rollover(service, plugin, account)
        both = (login(service, account, OLD), login(service, account, NEW))
        print(f"RE1 {plugin}: set {answer}; old {both[0]}; new {both[1]}")
        ch.check(f"RE1 {plugin}", (answer, *both), RECORDED_RE1[plugin])

        answer = ch.as_tool(service, f"ALTER USER '{account}'@'%' PASSWORD EXPIRE")
        after = (
            expired(service, account),
            login(service, account, OLD),
            login(service, account, NEW),
            login(service, account, ch.WRONG),
        )
        print(f"RE2 {plugin}: expire {answer}; password_expired {after[0]}; old {after[1]}; "
              f"new {after[2]}; wrong {after[3]}")  # fmt: skip
        ch.check(f"RE2 {plugin}", (answer, *after), RECORDED_RE2[plugin])

        rollover(service, plugin, OWN)
        ch.as_tool(service, f"ALTER USER '{OWN}'@'%' PASSWORD EXPIRE")
        own_set = _set_own(service)
        own = (
            own_set,
            login(service, OWN, OLD),
            login(service, OWN, NEW),
            login(service, OWN, MINE),
        )
        print(f"RE3 {plugin}: SET PASSWORD with the old {own[0]}; old {own[1]}; "
              f"new {own[2]}; its own {own[3]}")  # fmt: skip
        ch.check(f"RE3 {plugin}", own, RECORDED_RE3[plugin])

        answer = rollover(service, plugin, OWN, new_first=True)
        reversed_order = (
            answer,
            login(service, OWN, NEW),
            login(service, OWN, OLD),
            login(service, OWN, ch.WRONG),
        )
        print(f"RE5 {plugin}: set, new first, {reversed_order[0]}; new {reversed_order[1]}; "
              f"old {reversed_order[2]}; wrong {reversed_order[3]}")  # fmt: skip
        ch.check(f"RE5 {plugin}", reversed_order, RECORDED_RE5[plugin])

        new = ch.COMPUTE[plugin](NEW)
        answer = ch.as_tool(
            service, f"ALTER USER '{account}'@'%' IDENTIFIED VIA {plugin} USING '{new}'"
        )
        finish = (
            expired(service, account),
            login(service, account, OLD),
            login(service, account, NEW),
        )
        print(f"RE4 {plugin}: new alone {answer}; password_expired {finish[0]}; "
              f"old {finish[1]}; new {finish[2]}")  # fmt: skip
        ch.check(f"RE4 {plugin}", (answer, *finish), RECORDED_RE4)


def _set_own(service: str) -> str:
    """As the second account, logged in with the old password on an expired
    session: SET PASSWORD to a password of its own."""
    try:
        connection = connect(service, OWN, OLD)
    except pymysql.err.MySQLError as exc:
        return pl.answer(exc)
    try:
        with connection.cursor() as cursor:
            cursor.execute("SET PASSWORD = PASSWORD(%s)", (MINE,))
        return ch.OK
    except pymysql.err.MySQLError as exc:
        return pl.answer(exc)
    finally:
        connection.close()


#: PyMySQL 1.2.3's own error, with no number, where a login's password is not
#: the first method of an ed25519 OR: the server asks for a second auth switch.
SWITCH = "OperationalError: received multiple auth switch requests"
OK, EXPIRED, REFUSED = ch.OK, "1820", "1045"

RECORDED_RE1 = {
    "mysql_native_password": (OK, OK, OK),
    "ed25519": (OK, OK, SWITCH),
}
RECORDED_RE2 = {
    "mysql_native_password": (OK, "Y", EXPIRED, EXPIRED, REFUSED),
    "ed25519": (OK, "Y", EXPIRED, SWITCH, SWITCH),
}
RECORDED_RE3 = {
    "mysql_native_password": (OK, REFUSED, OK, OK),
    "ed25519": (OK, SWITCH, SWITCH, OK),
}
RECORDED_RE4 = (OK, "N", REFUSED, OK)
RECORDED_RE5 = {
    "mysql_native_password": (OK, OK, OK, REFUSED),
    "ed25519": (OK, OK, SWITCH, SWITCH),
}


def main() -> int:
    ch.base.SERVICES = tuple(pl.PORTS)
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
