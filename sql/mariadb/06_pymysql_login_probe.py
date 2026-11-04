"""sopuli-dba : PyMySQL logging in to MariaDB on each password plugin

#1267, M1. `creds check` logs in as the managed account, and the MySQL driver
does that with PyMySQL (#1202, decision 8). A MariaDB account may be on
mysql_native_password, ed25519 or parsec (02). This measures, on each server,
with the PyMySQL in the repo's .venv, from the host over TCP:

  PL1  for each plugin the server has after installing ed25519 and parsec: the
       account set by root with IDENTIFIED VIA <plugin> USING PASSWORD('...').
       Then a PyMySQL login with TLS turned off, with the password and with a
       wrong one
  PL2  the same two logins with TLS, given a context that checks neither the
       certificate nor the host name, and @@have_ssl. Where TLS is used, the
       session's Ssl_cipher is not empty
  PL3  the ed25519 login of PL1 in a child interpreter in which importing
       PyNaCl fails, as in an install without it

A login answers `ok`, or the error's number, or for an error PyMySQL raises
itself, its class and the start of its message.

The probe checks each result against the one RESULTS below records, as
02_client_hash_probe.py does. A difference, or a step that fails, makes it exit
1.

It MEASURES and decides nothing.

STATUS: run on 10.11.19, 11.4.13, 11.8.9 and 12.3.3, the mariadb:10.11,
mariadb:11.4, mariadb:11.8 and mariadb:12.3 images of test/compose.yaml profile
mariadb-matrix, on 2026-11-04 (#1267), with PyMySQL 1.2.3 and PyNaCl 1.6.2, and
Python 3.13.12 on Windows 11 AMD64. Twice, exit 0, and the same result both
times.

RESULTS -- the same on every release, except where noted

  PL1  mysql_native_password and ed25519: the password logs in, and a wrong
       one is refused, 1045. parsec, on 11.8.9 and 12.3.3: both are refused by
       PyMySQL itself, 2059, "Authentication plugin 'b'parsec'' not
       configured". PyMySQL has no parsec client
  PL2  11.4.13, 11.8.9 and 12.3.3 have TLS on, as the image starts them
       (@@have_ssl YES), and the logins are as in PL1, over TLS. 10.11.19 has
       it off (DISABLED), and PyMySQL refuses each login itself, 2026, "SSL is
       required but the server doesn't support it"
  PL3  RuntimeError, "'pynacl' package is required for ed25519_password auth
       method"

  So PyMySQL logs in on mysql_native_password, and on ed25519 only with
  PyNaCl installed. It cannot log in on parsec.

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mariadb/06_pymysql_login_probe.py

It needs PyMySQL and PyNaCl in the environment that runs it, and
02_client_hash_probe.py beside it. It reaches the servers on the ports
test/compose.yaml publishes, from SOPULI_TEST_MARIADB1011_PORT,
SOPULI_TEST_MARIADB114_PORT, SOPULI_TEST_MARIADB118_PORT and
SOPULI_TEST_MARIADB123_PORT, defaults 3311, 3314, 3318 and 3323.

THROWAWAY SERVERS ONLY. It installs the ed25519 and parsec plugins, creates
the accounts sopuli_probe_hash and sopuli_probe_tool, as 02 does, and drops
them at the end. It uninstalls each plugin it installed, and leaves one the
server had before.
"""

from __future__ import annotations

import importlib.util
import os
import ssl
import subprocess
import sys
from pathlib import Path

import pymysql

# 02's name starts with a digit, so it is loaded by its path.
_SPEC = importlib.util.spec_from_file_location(
    "mariadb_client_hash_probe", Path(__file__).with_name("02_client_hash_probe.py")
)
assert _SPEC is not None
assert _SPEC.loader is not None
ch = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ch)

#: Each service's published port, as test/compose.yaml names it.
PORTS = {
    service: int(os.environ.get(f"SOPULI_TEST_MARIADB{suffix}_PORT", default))
    for service, suffix, default in (
        ("mariadb-1011", "1011", "3311"),
        ("mariadb-114", "114", "3314"),
        ("mariadb-118", "118", "3318"),
        ("mariadb-123", "123", "3323"),
    )
}


def answer(exc: BaseException) -> str:
    """The error's number, or PyMySQL's own class and message start."""
    if isinstance(exc, pymysql.err.MySQLError) and exc.args and isinstance(exc.args[0], int):
        return str(exc.args[0])
    return f"{type(exc).__name__}: {str(exc)[:70]}"


def py_login(service: str, password: str, *, tls: bool) -> tuple[str, str]:
    """The login's answer, and the session's Ssl_cipher, empty without a session.

    A failure after the login is a failed step, not a result.
    """
    context = None
    if tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    try:
        connection = pymysql.connect(
            host="127.0.0.1",
            port=PORTS[service],
            user=ch.ACCOUNT,
            password=password,
            ssl=context,
            # Not redundant: with ssl=None alone, PyMySQL 1.2.3 still uses TLS
            # when the server offers it.
            ssl_disabled=not tls,
            connect_timeout=10,
        )
    except Exception as exc:  # noqa: BLE001 - the probe records whatever is raised
        return answer(exc), ""
    try:
        with connection.cursor() as cursor:
            cursor.execute("SHOW SESSION STATUS LIKE 'Ssl_cipher'")
            row = cursor.fetchone()
        return ch.OK, (row[1] if row else "")
    except pymysql.err.MySQLError as exc:
        raise ch.StepError(f"{service}: after the login: {exc}") from exc
    finally:
        connection.close()


#: The PL1 login in a child interpreter in which `import nacl` fails, as in an
#: install without PyNaCl. The password comes through the environment.
_WITHOUT_NACL = """
import os, sys
sys.modules["nacl"] = None
import pymysql
try:
    pymysql.connect(host="127.0.0.1", port=int(sys.argv[1]), user=sys.argv[2],
                    password=os.environ["SOPULI_PROBE_PASSWORD"], ssl_disabled=True,
                    connect_timeout=10).close()
    print("ok")
except Exception as exc:
    print(f"{type(exc).__name__}: {str(exc)[:70]}")
"""


def without_nacl(service: str, password: str) -> str:
    """The PL1 login with PyNaCl missing."""
    done = subprocess.run(
        [sys.executable, "-I", "-c", _WITHOUT_NACL, str(PORTS[service]), ch.ACCOUNT],
        env={**os.environ, "SOPULI_PROBE_PASSWORD": password},
        capture_output=True,
        text=True,
        check=False,
    )
    if done.returncode != 0:
        raise ch.StepError(f"{service}: the child interpreter: {done.stderr[-200:]}")
    return done.stdout.strip()


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
    release = ch.base.setup(service, "Acme-Login-pw0")
    parsec_install = ch.install_plugins(service)
    have = ch.plugins(service).split(",")
    have_ssl = ch.root(service, "SELECT @@have_ssl")
    print(f"plugins: {','.join(have)}; installing parsec: {parsec_install}; have_ssl: {have_ssl}")
    tls_offered = have_ssl == "YES"
    has_parsec = release.startswith(("11.8.", "12.3."))
    # As 02's CH4 records: the 10.11 and 11.4 images have no parsec library.
    ch.check("parsec install", parsec_install, ch.OK if has_parsec else "1126 (HY000)")

    for plugin in have:
        password = f"Acme-Login-{plugin[:6]}"
        ch.root(
            service,
            f"ALTER USER '{ch.ACCOUNT}'@'%' IDENTIFIED VIA {plugin} "
            f"USING PASSWORD({ch.quote(password)})",
        )
        plain = py_login(service, password, tls=False)
        wrong = py_login(service, ch.WRONG, tls=False)[0]
        print(f"PL1 {plugin}: password {plain}; wrong: {wrong}")
        recorded_plain = PARSEC_PL1 if plugin == "parsec" else ((ch.OK, ""), "1045")
        ch.check(f"PL1 {plugin}", (plain, wrong), recorded_plain)

        tls = py_login(service, password, tls=True)
        tls_wrong = py_login(service, ch.WRONG, tls=True)[0]
        print(f"PL2 {plugin}: password {tls}; wrong: {tls_wrong}")
        got = (tls[0], bool(tls[1]), tls_wrong)
        if not tls_offered:
            recorded = NO_TLS_PL2
        elif plugin == "parsec":
            recorded = PARSEC_PL2
        else:
            recorded = (ch.OK, True, "1045")
        ch.check(f"PL2 {plugin}", got, recorded)

        if plugin == "ed25519":
            hidden = without_nacl(service, password)
            print(f"PL3 ed25519 without PyNaCl: {hidden}")
            ch.check("PL3", hidden, NO_NACL)

    expected = ["ed25519", "mysql_native_password"] + (["parsec"] if has_parsec else [])
    ch.check("plugins", sorted(have), expected)
    ch.check("have_ssl", have_ssl, "DISABLED" if release.startswith("10.11.") else "YES")


#: PyMySQL has no parsec client: "Authentication plugin 'b'parsec'' not configured".
PARSEC_PL1 = (("2059", ""), "2059")
PARSEC_PL2 = ("2059", False, "2059")
#: Given a context, PyMySQL refuses a server that offers no TLS:
#: "SSL is required but the server doesn't support it".
NO_TLS_PL2 = ("2026", False, "2026")
NO_NACL = "RuntimeError: 'pynacl' package is required for ed25519_password auth method"


def main() -> int:
    ch.base.SERVICES = tuple(PORTS)
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
