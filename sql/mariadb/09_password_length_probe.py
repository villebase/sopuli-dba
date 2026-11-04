"""sopuli-dba : the passwords a MariaDB value computed by the client can carry

#1268. The MariaDB driver computes the value the server stores for a password
on the client (02) and logs in with PyMySQL (06). This measures, on each
server, whether a password's length or its characters limit that, with the
PyMySQL in the repo's .venv, from the host over TCP:

  PW1  for mysql_native_password and ed25519, and passwords of 1, 255, 256,
       257, 1024, 65,536 and 1,048,576 bytes of ASCII: the value 02 computes,
       set with IDENTIFIED VIA ... USING by a tool account that holds only
       CREATE USER. Then a PyMySQL login with the password, and one with the
       password less its last byte
  PW2  the same for `pässwörd-é` and `pass-€-word`, whose value is over the
       UTF-8 bytes. Then a login with the password given to PyMySQL as UTF-8
       bytes, and one given as a str
  PW3  the server's own values for three passwords, one of 300 bytes, from root's
       `IDENTIFIED VIA <plugin> USING PASSWORD(%s)` over PyMySQL with a utf8mb4
       connection. The values are recorded here, and
       tests/driver/test_mariadb_password.py checks the driver's against them

A login answers `ok`, or the error's number, or for an error PyMySQL raises
itself, its class.

The probe checks each result against the one RESULTS below records, as
02_client_hash_probe.py does. A difference, or a step that fails, makes it exit
1.

It MEASURES and decides nothing.

STATUS: run on 10.11.19, 11.4.13, 11.8.9 and 12.3.3, the mariadb:10.11,
mariadb:11.4, mariadb:11.8 and mariadb:12.3 images of test/compose.yaml profile
mariadb-matrix, on 2026-11-04 (#1268), with PyMySQL 1.2.3 and PyNaCl 1.6.2, and
Python 3.13.12 on Windows 11 AMD64. Twice, exit 0, and the same result both
times.

RESULTS -- the same on every release

  PW1  each value is set, `ok`. At every length the password logs in, and
       the password less its last byte is refused, 1045. There is no length
       limit: the server sees only the value
  PW2  each value is set. Given as UTF-8 bytes, each password logs in. Given
       as a str, PyMySQL 1.2.3 encodes it as latin-1: `pässwörd-é` is
       refused, 1045, and `pass-€-word` raises UnicodeEncodeError in PyMySQL
       (#1285)
  PW3  the values in SERVER_VALUES below

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mariadb/09_password_length_probe.py

It needs PyMySQL and PyNaCl in the environment that runs it, and 02 and 06
beside it. It reaches the servers on the ports 06 reads.

THROWAWAY SERVERS ONLY. It installs the ed25519 and parsec plugins, creates
the accounts sopuli_probe_hash and sopuli_probe_tool, as 02 does, and drops
them at the end. It uninstalls each plugin it installed, and leaves one the
server had before.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pymysql


def _load(name: str, file: str):  # type: ignore[no-untyped-def]
    # The probes' names start with a digit, so each is loaded by its path.
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pl = _load("mariadb_pymysql_login_probe", "06_pymysql_login_probe.py")
ch = pl.ch

PLUGINS = ("mysql_native_password", "ed25519")
LENGTHS = (1, 255, 256, 257, 1024, 65_536, 1_048_576)
#: PW2: each password, and what a login given it as a str answers. PyMySQL
#: encodes a str as latin-1, which has `é` and not `€`.
AS_STR = {"pässwörd-é": "1045", "pass-€-word": "UnicodeEncodeError"}

#: PW3: the server's values, as 11.8.9 stored them. The same on every release.
SERVER_VALUES = {
    ("mysql_native_password", "Acme-Vector-1"): "*BCF4821599FD729D65B1D7FD05E7F500E4353A95",
    ("mysql_native_password", "pässwörd-é"): "*90CD6D75F1B3F438B7F982777542A9E4479A252D",
    ("ed25519", "Acme-Vector-1"): "dqRDrLM3a3AWJrFD6+djW8n30QHqxVemmN5u/6RydE8",
    ("ed25519", "pässwörd-é"): "S7h7+pLYaV0vchpKE7ou3ooRNfyTTGxVuXj3CPd5rhM",
    # 300 bytes: longer than an Ed25519 seed, so a library that takes only a
    # seed cannot compute it.
    ("mysql_native_password", "Acme-Long-" * 30): "*028C62DD118198F89D80E6C42D1FEA2869F94C81",
    ("ed25519", "Acme-Long-" * 30): "TOe22qLnfsCgQIX4C0MkoHz7M5yy9/FVv40uu6jgQvU",
}


def connect(service: str, user: str, password: str | bytes) -> pymysql.Connection:  # type: ignore[type-arg]
    # Without TLS: neither plugin sends the password, and 10.11.19 offers no
    # TLS (06, PL2).
    return pymysql.connect(
        host="127.0.0.1",
        port=pl.PORTS[service],
        user=user,
        password=password,
        ssl_disabled=True,
        charset="utf8mb4",
        connect_timeout=10,
    )


def py_login(service: str, password: str | bytes) -> str:
    """`ok`, the error's number, or the class of what PyMySQL raised."""
    try:
        connect(service, ch.ACCOUNT, password).close()
    except pymysql.err.MySQLError as exc:
        return pl.answer(exc)
    except Exception as exc:  # noqa: BLE001 - the probe records whatever is raised
        return type(exc).__name__
    return ch.OK


def set_value(service: str, plugin: str, password: str) -> str:
    value = ch.COMPUTE[plugin](password)
    answer = ch.as_tool(
        service, f"ALTER USER '{ch.ACCOUNT}'@'%' IDENTIFIED VIA {plugin} USING '{value}'"
    )
    return answer if answer == ch.OK else ch.code(answer)


def server_value(service: str, plugin: str, password: str) -> str:
    connection = connect(service, "root", ch.ROOT_PASSWORD)
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                f"ALTER USER '{ch.ACCOUNT}'@'%%' IDENTIFIED VIA {plugin} USING PASSWORD(%s)",
                (password,),
            )
            cursor.execute(
                "SELECT authentication_string FROM mysql.user WHERE user = %s AND host = '%%'",
                (ch.ACCOUNT,),
            )
            row = cursor.fetchone()
    finally:
        connection.close()
    if row is None:
        raise ch.StepError(f"{service}: no row for {ch.ACCOUNT}")
    return str(row[0])


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
        lambda: ch.base.teardown(service),
        lambda: ch.uninstall_plugins(service, keep=had if had != "NULL" else ""),
    )


def cases(service: str) -> None:
    ch.base.setup(service, "Acme-Length-pw0")
    ch.install_plugins(service)

    for plugin in PLUGINS:
        for length in LENGTHS:
            password = ("Ab9-" * (length // 4 + 1))[:length]
            answer = set_value(service, plugin, password)
            good = py_login(service, password.encode("utf-8"))
            short = py_login(service, password[:-1].encode("utf-8"))
            print(f"PW1 {plugin} {length} bytes: set {answer}; password: {good}; less one: {short}")
            ch.check(f"PW1 {plugin} {length}", (answer, good, short), (ch.OK, ch.OK, "1045"))

        for password in AS_STR:
            answer = set_value(service, plugin, password)
            as_bytes = py_login(service, password.encode("utf-8"))
            as_str = py_login(service, password)
            print(f"PW2 {plugin} {password!a}: set {answer}; bytes: {as_bytes}; str: {as_str}")
            recorded = (ch.OK, ch.OK, AS_STR[password])
            ch.check(f"PW2 {plugin} {password!a}", (answer, as_bytes, as_str), recorded)

    for (plugin, password), recorded in SERVER_VALUES.items():
        value = server_value(service, plugin, password)
        print(f"PW3 {plugin} {password!a}: {value}")
        ch.check(f"PW3 {plugin} {password!a}", value, recorded)


def main() -> int:
    ch.base.SERVICES = tuple(pl.PORTS)
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
