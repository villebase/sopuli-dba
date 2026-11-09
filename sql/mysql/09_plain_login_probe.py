"""sopuli-dba : a caching_sha2_password login over a plain connection

#1407. Under `ssl_mode: DISABLED`, or `PREFERRED` against a server without
TLS, the MySQL driver logs in with PyMySQL over a plain connection. A login
the server has not cached needs caching_sha2_password's full exchange. This
measures, on each server, with the PyMySQL of the interpreter that runs it,
from the host over TCP with TLS turned off, what PyMySQL sends at each round
trip of the exchange and what the login answers:

  PL1  the server's cache emptied by FLUSH PRIVILEGES; a login with the
       password
  PL2  straight after PL1, the same login again, with nothing flushed
  PL3  the cache emptied; a login with a wrong password
  PL4  the cache emptied; a login with the password, PyMySQL given the
       server's public key as server_public_key, read by root from the status
       variable Caching_sha2_password_rsa_public_key
  PL5  the cache emptied; the PL1 login in a child interpreter in which
       importing `cryptography` fails, as in an install without it

A login answers `ok`, or the error's number, or for an error PyMySQL raises
itself, its class and the start of its message. What it sends is the list of
the packets PyMySQL's _auth._roundtrip carried after the handshake: `key
request`, `rsa password` (the password encrypted with the server's key, 256
bytes for its 2048-bit key) or `cleartext`. The scramble of the fast path
goes in the handshake, so a login the server has cached sends nothing here.

The probe checks each result against the one RESULTS below records for the
PyMySQL release it runs with, as 02_client_hash_probe.py does. A difference, a
release RESULTS does not record, or a step that fails, makes it exit 1.

It MEASURES and decides nothing.

STATUS: run on 8.0.46, 8.4.13 and 9.7.4, the mysql:8.0, mysql:8.4 and mysql:9
images of test/compose.yaml profile mysql-matrix, on 2026-11-09 (#1407), with
PyMySQL 1.2.4 and cryptography 50.0.0, and with PyMySQL 1.2.3 and cryptography
50.0.2, and Python 3.13.12 on Windows 11 AMD64. Twice with each PyMySQL
release, exit 0, and the same result each time.

RESULTS -- the same on all three releases

  PyMySQL 1.2.3
  PL1  sends a key request, then the password encrypted with the key the
       server sent; then fails itself, AttributeError, "'NoneType' object has
       no attribute 'is_auth_switch_request'"
  PL2  ok, sending nothing: the server accepted PL1's password and cached it
  PL3  sends the key request and the encrypted password; refused, 1045
  PL4  sends only the encrypted password; then fails as PL1
  PL5  sends the key request; then fails itself before the password,
       RuntimeError, "'cryptography' package is required for sha256_password
       or caching_sha2_password auth methods"

  PyMySQL 1.2.4
  PL1  sends the key request and the encrypted password; ok
  PL2  ok, sending nothing
  PL3  as on 1.2.3
  PL4  sends only the encrypted password; ok
  PL5  as on 1.2.3

  So both releases send the password over a plain connection, encrypted with
  a key the server sends unauthenticated, unless PyMySQL is given the key.
  1.2.3 then fails on the client side, after the server has accepted the
  login. Without `cryptography`, neither sends the password.

HOW TO RUN, against the matrix (test/README.md), from the repo root:

    .venv/Scripts/python sql/mysql/09_plain_login_probe.py

It needs PyMySQL and cryptography in the environment that runs it, and
02_client_hash_probe.py beside it. It reaches the servers on the ports
test/compose.yaml publishes, from SOPULI_TEST_MYSQL80_PORT,
SOPULI_TEST_MYSQL84_PORT and SOPULI_TEST_MYSQL9_PORT, defaults 3380, 3384 and
3390. The container names follow COMPOSE_PROJECT_NAME.

THROWAWAY SERVERS ONLY. On each server it creates the accounts
sopuli_probe_hash and sopuli_probe_tool, as 02 does, drops them at the end, and
runs FLUSH PRIVILEGES, which empties the server's login cache for every
account.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pymysql
import pymysql._auth

# 02's name starts with a digit, so it is loaded by its path.
_SPEC = importlib.util.spec_from_file_location(
    "client_hash_probe", Path(__file__).with_name("02_client_hash_probe.py")
)
assert _SPEC is not None
assert _SPEC.loader is not None
ch = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ch)

PORTS = {
    service: int(os.environ.get(f"SOPULI_TEST_MYSQL{suffix}_PORT", default))
    for service, suffix, default in (
        ("mysql-80", "80", "3380"),
        ("mysql-84", "84", "3384"),
        ("mysql-9", "9", "3390"),
    )
}
PASSWORD = "Acme-Plain-pw1"
RELEASE = ".".join(str(part) for part in pymysql.VERSION[:3])


def classify(data: bytes) -> str:
    """What the probe records of a packet the exchange sends. The PL5 child
    has its own copy, in _WITHOUT_CRYPTOGRAPHY. A cleartext password is
    recognised by its value: RSA ciphertext can end in a NUL byte too."""
    if data == b"\x02":
        return "key request"
    if data in (PASSWORD.encode() + b"\0", ch.WRONG.encode() + b"\0"):
        return "cleartext"
    return f"rsa password ({len(data)} bytes)"


SENT: list[str] = []
_ORIGINAL = pymysql._auth._roundtrip


def _recording(conn: Any, data: bytes) -> Any:
    SENT.append(classify(data))
    return _ORIGINAL(conn, data)


pymysql._auth._roundtrip = _recording


def answer(exc: BaseException) -> str:
    if isinstance(exc, pymysql.err.MySQLError) and exc.args and isinstance(exc.args[0], int):
        return str(exc.args[0])
    return f"{type(exc).__name__}: {str(exc)[:70]}"


def plain_login(service: str, password: str, **extra: Any) -> tuple[str, list[str]]:
    SENT.clear()
    try:
        connection = pymysql.connect(
            host="127.0.0.1",
            port=PORTS[service],
            user=ch.ACCOUNT,
            password=password,
            ssl_disabled=True,
            connect_timeout=10,
            **extra,
        )
    except Exception as exc:  # noqa: BLE001 - the probe records whatever is raised
        return answer(exc), list(SENT)
    try:
        with connection.cursor() as cursor:
            cursor.execute("SHOW SESSION STATUS LIKE 'Ssl_cipher'")
            row = cursor.fetchone()
        if row and row[1]:
            raise ch.StepError(f"{service}: the session is TLS: {row[1]}")
        return "ok", list(SENT)
    finally:
        connection.close()


#: The PL1 login in a child interpreter in which `import cryptography` fails.
#: The password comes through the environment.
_WITHOUT_CRYPTOGRAPHY = """
import json, os, sys
sys.modules["cryptography"] = None
import pymysql, pymysql._auth
def classify(data):
    if data == b"\\x02":
        return "key request"
    if data == os.environ["SOPULI_PROBE_PASSWORD"].encode() + b"\\0":
        return "cleartext"
    return f"rsa password ({len(data)} bytes)"
sent = []
original = pymysql._auth._roundtrip
def recording(conn, data):
    sent.append(classify(data))
    return original(conn, data)
pymysql._auth._roundtrip = recording
try:
    pymysql.connect(host="127.0.0.1", port=int(sys.argv[1]), user=sys.argv[2],
                    password=os.environ["SOPULI_PROBE_PASSWORD"], ssl_disabled=True,
                    connect_timeout=10).close()
    result = "ok"
except Exception as exc:
    result = f"{type(exc).__name__}: {str(exc)[:70]}"
print(json.dumps([result, sent]))
"""


def without_cryptography(service: str) -> tuple[str, list[str]]:
    done = subprocess.run(
        [sys.executable, "-I", "-c", _WITHOUT_CRYPTOGRAPHY, str(PORTS[service]), ch.ACCOUNT],
        env={**os.environ, "SOPULI_PROBE_PASSWORD": PASSWORD},
        capture_output=True,
        text=True,
        check=False,
    )
    if done.returncode != 0:
        raise ch.StepError(f"{service}: the child interpreter: {done.stderr[-200:]}")
    result, sent = json.loads(done.stdout)
    return result, sent


def flush(service: str) -> None:
    ch.root(service, "FLUSH PRIVILEGES")


def probe(service: str) -> None:
    ch.setup(service, PASSWORD)
    plugin = ch.root(
        service, f"SELECT plugin FROM mysql.user WHERE user = '{ch.ACCOUNT}' AND host = '%'"
    )
    ch.check("plugin", plugin, "caching_sha2_password")
    recorded = RESULTS[RELEASE]

    flush(service)
    results = {"PL1": plain_login(service, PASSWORD)}
    results["PL2"] = plain_login(service, PASSWORD)
    flush(service)
    results["PL3"] = plain_login(service, ch.WRONG)
    key = ch.root(service, "SHOW STATUS LIKE 'Caching_sha2_password_rsa_public_key'")
    pem = key.split("\t", 1)[1].replace("\\n", "\n").encode("ascii")
    flush(service)
    results["PL4"] = plain_login(service, PASSWORD, server_public_key=pem)
    flush(service)
    results["PL5"] = without_cryptography(service)

    for label, got in results.items():
        print(f"{label}: {got[0]}; sent: {', '.join(got[1]) or 'nothing'}")
        ch.check(f"{label} on {RELEASE}", (got[0], got[1]), recorded[label])


KEY = "key request"
RSA = "rsa password (256 bytes)"
FAILS_123 = "AttributeError: 'NoneType' object has no attribute 'is_auth_switch_request'"
#: Cut at 70 characters, as answer() cuts it.
NO_CRYPTOGRAPHY = (
    "RuntimeError: 'cryptography' package is required for sha256_password or caching_sha2"
)

#: Each case's (answer, sent), by PyMySQL release.
RESULTS: dict[str, dict[str, tuple[str, list[str]]]] = {
    "1.2.3": {
        "PL1": (FAILS_123, [KEY, RSA]),
        "PL2": ("ok", []),
        "PL3": ("1045", [KEY, RSA]),
        "PL4": (FAILS_123, [RSA]),
        "PL5": (NO_CRYPTOGRAPHY, [KEY]),
    },
    "1.2.4": {
        "PL1": ("ok", [KEY, RSA]),
        "PL2": ("ok", []),
        "PL3": ("1045", [KEY, RSA]),
        "PL4": ("ok", [RSA]),
        "PL5": (NO_CRYPTOGRAPHY, [KEY]),
    },
}


def main() -> int:
    if RELEASE not in RESULTS:
        print(f"PyMySQL {RELEASE}: no recorded results")
        return 1
    print(f"PyMySQL {RELEASE}")
    ch.SERVICES = tuple(PORTS)
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
