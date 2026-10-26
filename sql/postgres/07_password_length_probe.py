"""sopuli-dba : the longest password libpq and PostgreSQL accept, set as a verifier

#1057. The PostgreSQL driver is to send a SCRAM-SHA-256 verifier that it
computes on the client, so the server never sees the password. The password
policy sets no ceiling on `length:`. This measures, on each server and at each
length below:

  PL1  whether PGconn.encrypt_password computes a verifier
  PL2  that verifier set with ALTER ROLE, then a login with the password by
       psycopg, timed, and by psql. The same password without its last
       character must be refused, so a client that cut the password short is
       seen
  PL3  the password as plaintext in ALTER ROLE, which the server hashes under
       password_encryption = scram-sha-256, then a login by psycopg

The lengths are in bytes. Each ASCII password is drawn from the alnum_safe
charset. A second set ends with U+00E9, two bytes in UTF-8, so SASLprep has to
process it rather than pass it through as ASCII.

psycopg runs on the host running the probe. psql runs in the server's own
container and reaches the server by its compose service name, so over TCP and
not through the image's trust lines. A password reaches psql through the
environment of `docker exec`, never through argv. Windows limits one
environment variable to 32767 characters, so psql is not run above that.

It MEASURES and decides nothing.

STATUS: run on 13.23, 14.24, 15.19, 16.15, 17.11 and 18.6, the postgres:13 to
postgres:18 images of test/compose.yaml profile postgres-matrix, on 2026-10-26
(#1057). The host client was psycopg 3.3.6 with libpq 18.4, on Windows 11
AMD64; the container clients were psql with libpq 13.23, libpq 14.24,
libpq 15.19, libpq 16.15, libpq 17.11 and libpq 18.6. Three times, exit 0, the
same result each time but for the timings, which are the ranges below. Two
earlier versions are not counted. The first stopped at 65536 bytes and gave
the results below. The second added 1 MiB with a 10 s connect_timeout, and its
1 MiB logins timed out on 16.15 and 18.6 in one run and not in the other.

RESULTS

  PL1  a verifier of 133 bytes at every length, 12 bytes to 1 MiB
  PL2  the password logs in at every length, on all six servers, by psycopg
       and, up to 8192 bytes, by psql. One character short, it is refused at
       every length. A login takes 0.1 s or less up to 8192 bytes, 0.6 to 1 s
       at 65536, 2.5 to 3.4 s at 256 KiB and 10 to 15 s at 1 MiB: libpq's
       PBKDF2 hashes the password in each of 4096 iterations, so the time
       grows with the length
  PL3  13.23 refuses a plaintext password longer than 1024 bytes in ALTER
       ROLE: SQLSTATE 54000, "password too long", ASCII or not. 14.24 to 18.6
       accept every length, and the password logs in

  So with a verifier no length up to 1 MiB is refused anywhere. The ceiling
  that matters is the login time, which the client pays at each login.

HOW TO RUN, against the matrix (test/README.md), from the repo root, with the
repo's virtual environment:

    .venv/Scripts/python sql/postgres/07_password_length_probe.py

It needs psycopg and the docker CLI. The container names follow
COMPOSE_PROJECT_NAME, and the ports SOPULI_TEST_POSTGRES13_PORT to
SOPULI_TEST_POSTGRES18_PORT, so a second clone's matrix is the one it uses.

THROWAWAY SERVERS ONLY. On each server it creates the role sopuli_probe_len
and drops it at the end, and before it starts it drops one an interrupted run
left.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

import psycopg
from psycopg import pq, sql

#: The stack's project name, so a second clone's stack is the one probed.
PROJECT = os.environ.get("COMPOSE_PROJECT_NAME", "sopuli-test")
VERSIONS = (13, 14, 15, 16, 17, 18)
#: Tier 0's public test password, from test/compose.yaml.
SUPERUSER_PASSWORD = "sopuli-test"
ROLE = "sopuli_probe_len"
ASCII_LENGTHS = (12, 30, 64, 100, 128, 256, 512, 1000, 1023, 1024, 1025, 2048, 8192, 65536)
ASCII_LENGTHS += (1 << 18, 1 << 20)
#: Seconds a login may take. A 1 MiB password takes about ten.
LOGIN_TIMEOUT = 120
NON_ASCII_LENGTHS = (1024, 1025, 2048)
#: alnum_safe, from sopuli.config.charsets, in a fixed order.
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_#-.+=~"
#: The longest value Windows allows for one environment variable.
ENV_LIMIT = 32767
#: e with acute, written as a code point so the source stays ASCII.
E_ACUTE = chr(0xE9)


def _container(version: int) -> str:
    return f"{PROJECT}-postgres-{version}-1"


def _port(version: int) -> str:
    return os.environ.get(f"SOPULI_TEST_POSTGRES{version}_PORT", f"54{version}")


def _password(length: int, non_ascii: bool) -> str:
    """A test password of `length` bytes in UTF-8. Not a credential."""
    if non_ascii:
        return (ALPHABET * (length // len(ALPHABET) + 1))[: length - 2] + E_ACUTE
    return (ALPHABET * (length // len(ALPHABET) + 1))[:length]


def _superuser(version: int) -> psycopg.Connection:
    return psycopg.connect(
        host="127.0.0.1",
        port=_port(version),
        dbname="sopuli",
        user="postgres",
        password=SUPERUSER_PASSWORD,
        autocommit=True,
        connect_timeout=10,
    )


def _error(exc: psycopg.Error) -> str:
    return f"{exc.sqlstate} {type(exc).__name__}: {' '.join(str(exc).split())[:160]}"


def _alter(conn: psycopg.Connection, password: str) -> None:
    conn.execute(
        sql.SQL("ALTER ROLE {} PASSWORD {}").format(sql.Identifier(ROLE), sql.Literal(password))
    )


def _login_host(version: int, password: str) -> str:
    """Log in, and say what happened and how long it took.

    libpq's PBKDF2 hashes the whole password in each of its 4096 iterations,
    so a long password takes seconds. The timeout leaves room for that.
    """
    start = time.monotonic()
    try:
        with psycopg.connect(
            host="127.0.0.1",
            port=_port(version),
            dbname="sopuli",
            user=ROLE,
            password=password,
            connect_timeout=LOGIN_TIMEOUT,
        ):
            return f"ok in {time.monotonic() - start:.1f} s"
    except psycopg.Error as exc:
        if "password authentication failed" in str(exc):
            return "refused"
        return _error(exc)


def _login_psql(version: int, password: str) -> str:
    if len(password) > ENV_LIMIT:
        return "not run"
    argv = ["docker", "exec", "-e", "PGPASSWORD", _container(version)]
    argv += ["psql", f"host=postgres-{version} dbname=sopuli user={ROLE}"]
    argv += ["-X", "-At", "-c", "SELECT 'logged in'"]
    done = subprocess.run(
        argv, capture_output=True, env={**os.environ, "PGPASSWORD": password}, check=False
    )
    out = (done.stdout + done.stderr).decode("utf-8", "replace").strip()
    if done.returncode == 0 and out == "logged in":
        return "ok"
    if "password authentication failed" in out:
        return "refused"
    return f"error: {' '.join(out.split())[:160]}"


def _psql_version(version: int) -> str:
    argv = ["docker", "exec", _container(version), "psql", "--version"]
    done = subprocess.run(argv, capture_output=True, check=True)
    return done.stdout.decode().strip()


def _one(conn: psycopg.Connection, version: int, password: str) -> tuple[str, str]:
    try:
        verifier = conn.pgconn.encrypt_password(
            password.encode(), ROLE.encode(), b"scram-sha-256"
        ).decode()
        pl1 = f"verifier of {len(verifier)} bytes"
    except psycopg.Error as exc:
        return f"PL1 {_error(exc)}", ""
    try:
        _alter(conn, verifier)
        host, psql = _login_host(version, password), _login_psql(version, password)
        short = _login_host(version, password[:-1])
        pl2 = f"PL2 host {host}, psql {psql}, one character short {short}"
    except psycopg.Error as exc:
        pl2 = f"PL2 ALTER ROLE {_error(exc)}"
    try:
        conn.execute("SET password_encryption = 'scram-sha-256'")
        _alter(conn, password)
        pl3 = f"PL3 host {_login_host(version, password)}"
    except psycopg.Error as exc:
        pl3 = f"PL3 ALTER ROLE {_error(exc)}"
    finally:
        conn.execute("RESET password_encryption")
    return f"PL1 {pl1}; {pl2}", pl3


def _server(version: int) -> None:
    with _superuser(version) as conn:
        row = conn.execute("SELECT current_setting('server_version')").fetchone()
        assert row is not None
        print(f"=== server {row[0]}")
        print(f"host client: libpq {pq.version()}; container client: {_psql_version(version)}")
        conn.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(ROLE)))
        conn.execute(sql.SQL("CREATE ROLE {} LOGIN").format(sql.Identifier(ROLE)))
        try:
            cases = [(n, False) for n in ASCII_LENGTHS] + [(n, True) for n in NON_ASCII_LENGTHS]
            for length, non_ascii in cases:
                kind = "ending in U+00E9" if non_ascii else "ASCII"
                first, pl3 = _one(conn, version, _password(length, non_ascii))
                print(f"{length} bytes, {kind}: {first}; {pl3}")
        finally:
            conn.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(ROLE)))


def main() -> int:
    for version in VERSIONS:
        _server(version)
    return 0


if __name__ == "__main__":
    sys.exit(main())
