"""sopuli-dba : what PASSWORD EXPIRE does to a MariaDB rollover

#1271. MariaDB's rollover is `IDENTIFIED VIA <plugin> USING '<old>' OR <plugin>
USING '<new>'` (03, DP2): both passwords log in until the new value is sent
alone. MySQL keeps a retained password logging in, expired, after PASSWORD
EXPIRE, so its `account expire-password` discards it first (sql/mysql/04,
LE9). This measures the same on MariaDB, on each server, for
mysql_native_password and ed25519, as a tool account that holds only CREATE
USER. Each login is made twice: over PyMySQL from the host, and with the
server's own mariadb client in its container, which takes a second
authentication where PyMySQL takes one:

  RE1  the tool account sets the old and the new value with OR. Then a login
       with each password
  RE2  the tool account sends PASSWORD EXPIRE. Then the view's
       password_expired, as root, and a login with the old password, the new
       one and a wrong one
  RE3  on a second account, twice: the tool account sets the rollover and
       expires it, and a client login with one of the two passwords confirms
       the expiry (1820). That session, first with the old password, then
       with the new one, sends SET PASSWORD = PASSWORD('<its own>'). Then a
       login with the old, the new and its own password
  RE4  on the first account, the tool account sends the new value alone, as a
       rollover's finish does. Then password_expired, and a login with the old
       and the new password
  RE5  on the second account, the tool account sets the rollover with the new
       value first. Then a login with the new password, the old one and a
       wrong one

A login is written `<PyMySQL> / <client>`. Each answers `ok` where the session
runs a statement, `1820` where the session opens and the statement is refused
because the password has expired, the error's number at connect, or for an
error PyMySQL raises itself, its class and the start of its message.

The probe checks each result against the one RESULTS below records. A
difference, or a step that fails, makes it exit 1.

It MEASURES and decides nothing.

STATUS: run on 10.11.19, 11.4.13, 11.8.9 and 12.3.3, the mariadb:10.11,
mariadb:11.4, mariadb:11.8 and mariadb:12.3 images of test/compose.yaml profile
mariadb-matrix, on 2026-11-05 (#1271), with PyMySQL 1.2.3 and PyNaCl 1.6.2, and
Python 3.13.12 on Windows 11 AMD64. Twice, exit 0, and the same result both
times.

RESULTS -- the same on every release; RECORDED below holds each value

  RE1  the tool account sets both values. With the client both passwords log
       in, on both plugins. Over PyMySQL both log in on
       mysql_native_password; on ed25519 the old one, the first method, logs
       in, and the new one fails inside PyMySQL: "received multiple auth
       switch requests", an OperationalError with no number. The server asks
       for a second authentication for the second method, and PyMySQL 1.2.3
       takes only one
  RE2  PASSWORD EXPIRE is accepted, and password_expired reads Y. **Both
       passwords still log in, expired**, and answer 1820, with the client on
       both plugins; a wrong one is refused, 1045. Over PyMySQL, ed25519's
       second method and a wrong password both fail as in RE1
  RE3  the expiry is confirmed, 1820, and the session sets a password of its
       own, from either side. **SET PASSWORD replaces the first method,
       whichever password the session logged in with**: the old password is
       then refused, 1045, and the new one and its own both log in
  RE4  the new value alone is accepted. password_expired reads N: setting a
       password ends the expiry. The old password is refused, 1045, and the
       new one logs in, over both clients
  RE5  with the new value first, the new password logs in over both clients.
       With the client the old one logs in too, and a wrong one is refused,
       1045; over PyMySQL, on ed25519, both fail as in RE1

  So PASSWORD EXPIRE does not end a rollover: both passwords keep logging
  in, expired. A new value alone ends both the rollover and the expiry.
  SET PASSWORD replaces the first method. And PyMySQL can use only the first
  method of an ed25519 OR, while the mariadb client uses either.

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mariadb/11_rollover_expiry_probe.py

It needs PyMySQL and PyNaCl in the environment that runs it, the docker CLI,
and 02 and 06 beside it, whose helpers and ports it uses. A password reaches
the client through the environment of `docker exec`, as MYSQL_PWD, never
through argv (02).

THROWAWAY SERVERS ONLY. It installs the ed25519 plugin, and parsec where the
image has it, creates the accounts sopuli_probe_hash, sopuli_probe_tool and
sopuli_probe_own, and drops them at the end, also after a failed step. It
uninstalls each plugin it installed, and leaves one the server had before.
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


def _py(service: str, user: str, password: str) -> str:
    """A PyMySQL login without TLS, which neither plugin needs: it sends no
    password, and 10.11.19 offers none (06, PL2)."""
    try:
        connection = pymysql.connect(
            host="127.0.0.1",
            port=pl.PORTS[service],
            user=user,
            password=password.encode("utf-8"),
            ssl_disabled=True,
            autocommit=True,
            connect_timeout=10,
        )
    except Exception as exc:  # noqa: BLE001 - the probe records whatever is raised
        return str(pl.answer(exc))
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        return ch.OK
    except Exception as exc:  # noqa: BLE001
        return str(pl.answer(exc))
    finally:
        connection.close()


def _client(service: str, user: str, password: str) -> str:
    """A login with the server's mariadb client: `ok`, or the number."""
    answer: str = ch.login(service, password, user)
    return answer.split(" ")[0]


def login(service: str, user: str, password: str) -> str:
    return f"{_py(service, user, password)} / {_client(service, user, password)}"


def rollover(service: str, plugin: str, account: str, *, new_first: bool = False) -> str:
    """The tool account sets the old and the new value with OR, the old one
    first, or the new one first."""
    old, new = ch.COMPUTE[plugin](OLD), ch.COMPUTE[plugin](NEW)
    first, second = (new, old) if new_first else (old, new)
    return _tool(
        service,
        f"ALTER USER '{account}'@'%' IDENTIFIED VIA {plugin} USING '{first}' "
        f"OR {plugin} USING '{second}'",
    )


def _tool(service: str, statement: str) -> str:
    answer: str = ch.as_tool(service, statement)
    return answer if answer == ch.OK else str(ch.code(answer))


def expired(service: str, account: str) -> str:
    value: str = ch.root(
        service, f"SELECT password_expired FROM mysql.user WHERE User = '{account}' AND Host = '%'"
    )
    return value


def set_own(service: str, password: str) -> str:
    """As the second account, on an expired session with ``password``: SET
    PASSWORD to one of its own, with the client, which logs in with either
    method."""
    ok, out = ch.mysql(service, OWN, password, f"SET PASSWORD = PASSWORD('{MINE}')")
    return ch.OK if ok else str(ch.code(out)).split(" ")[0]


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
        got: Any = (rollover(service, plugin, account), login(service, account, OLD),
                    login(service, account, NEW))  # fmt: skip
        print(f"RE1 {plugin}: set {got[0]}; old {got[1]}; new {got[2]}")
        ch.check(f"RE1 {plugin}", got, RECORDED.get(f"RE1 {plugin}"))

        got = (
            _tool(service, f"ALTER USER '{account}'@'%' PASSWORD EXPIRE"),
            expired(service, account),
            login(service, account, OLD),
            login(service, account, NEW),
            login(service, account, ch.WRONG),
        )
        print(f"RE2 {plugin}: expire {got[0]}; password_expired {got[1]}; old {got[2]}; "
              f"new {got[3]}; wrong {got[4]}")  # fmt: skip
        ch.check(f"RE2 {plugin}", got, RECORDED.get(f"RE2 {plugin}"))

        for side, password in (("old", OLD), ("new", NEW)):
            got = (
                rollover(service, plugin, OWN),
                _tool(service, f"ALTER USER '{OWN}'@'%' PASSWORD EXPIRE"),
                _client(service, OWN, password),
                set_own(service, password),
                login(service, OWN, OLD),
                login(service, OWN, NEW),
                login(service, OWN, MINE),
            )
            print(f"RE3 {plugin} by the {side}: set {got[0]}; expire {got[1]}; session "
                  f"{got[2]}; SET PASSWORD {got[3]}; old {got[4]}; new {got[5]}; "
                  f"its own {got[6]}")  # fmt: skip
            ch.check(f"RE3 {plugin} by the {side}", got, RECORDED.get(f"RE3 {plugin} {side}"))

        new = ch.COMPUTE[plugin](NEW)
        got = (
            _tool(service, f"ALTER USER '{account}'@'%' IDENTIFIED VIA {plugin} USING '{new}'"),
            expired(service, account),
            login(service, account, OLD),
            login(service, account, NEW),
        )
        print(f"RE4 {plugin}: new alone {got[0]}; password_expired {got[1]}; old {got[2]}; "
              f"new {got[3]}")  # fmt: skip
        ch.check(f"RE4 {plugin}", got, RECORDED.get(f"RE4 {plugin}"))

        got = (
            rollover(service, plugin, OWN, new_first=True),
            login(service, OWN, NEW),
            login(service, OWN, OLD),
            login(service, OWN, ch.WRONG),
        )
        print(f"RE5 {plugin}: set, new first, {got[0]}; new {got[1]}; old {got[2]}; "
              f"wrong {got[3]}")  # fmt: skip
        ch.check(f"RE5 {plugin}", got, RECORDED.get(f"RE5 {plugin}"))


#: PyMySQL 1.2.3's own error, with no number, where a login's password is not
#: the first method of an ed25519 OR: the server asks for a second auth switch.
SWITCH = "OperationalError: received multiple auth switch requests"

#: A login that logs in, or answers 1820 or 1045, over both clients.
OK, EXP, REF = "ok / ok", "1820 / 1820", "1045 / 1045"

#: Each case's results, the same on every release.
RECORDED: dict[str, tuple[str, ...]] = {
    "RE1 mysql_native_password": ("ok", OK, OK),
    "RE2 mysql_native_password": ("ok", "Y", EXP, EXP, REF),
    "RE3 mysql_native_password old": ("ok", "ok", "1820", "ok", REF, OK, OK),
    "RE3 mysql_native_password new": ("ok", "ok", "1820", "ok", REF, OK, OK),
    "RE4 mysql_native_password": ("ok", "N", REF, OK),
    "RE5 mysql_native_password": ("ok", OK, OK, REF),
    "RE1 ed25519": ("ok", OK, f"{SWITCH} / ok"),
    "RE2 ed25519": ("ok", "Y", EXP, f"{SWITCH} / 1820", f"{SWITCH} / 1045"),
    "RE3 ed25519 old": ("ok", "ok", "1820", "ok", f"{SWITCH} / 1045", f"{SWITCH} / ok", OK),
    "RE3 ed25519 new": ("ok", "ok", "1820", "ok", f"{SWITCH} / 1045", f"{SWITCH} / ok", OK),
    "RE4 ed25519": ("ok", "N", REF, OK),
    "RE5 ed25519": ("ok", OK, f"{SWITCH} / ok", f"{SWITCH} / 1045"),
}


def main() -> int:
    ch.base.SERVICES = tuple(pl.PORTS)
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
