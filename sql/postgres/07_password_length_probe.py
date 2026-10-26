"""sopuli-dba : the longest password libpq and PostgreSQL accept, set as a verifier

#1057. The PostgreSQL driver is to send a SCRAM-SHA-256 verifier that it
computes on the client, so the server never sees the password. The password
policy sets no ceiling on `length:`. This measures, on each server and at each
length below:

  PL1  whether PGconn.encrypt_password computes a verifier
  PL2  that verifier set with ALTER ROLE, then a login with the password by
       psycopg, timed, and by psql. The same password without its last
       character must not log in with either, so a client that cut the
       password short is seen
  PL3  the password as plaintext in ALTER ROLE, which the server hashes under
       password_encryption = scram-sha-256, then a login by psycopg

The lengths are in bytes. Each ASCII password is drawn from the alnum_safe
charset. A second set ends with U+00E9, two bytes in UTF-8, so SASLprep has to
process it rather than pass it through as ASCII.

psycopg runs on the host running the probe. psql is the server's major
release, in a container the probe starts from the postgres:<major>-alpine
image on the compose network, because that image builds its own libpq. The
Debian images of the matrix do not: their psql loads the newest libpq5 of the
PostgreSQL apt repository, which is 18 in every one. A password reaches psql
through the environment of `docker exec`, never through argv. Windows limits
one environment entry, `PGPASSWORD=` and the value, to 32767 characters, so
psql is not run above that.

A password one character short that logs in, by either client, makes the
probe exit 1.

It MEASURES and decides nothing.

STATUS: run on 13.23, 14.24, 15.19, 16.15, 17.11 and 18.6, the postgres:13 to
postgres:18 images of test/compose.yaml profile postgres-matrix, on 2026-10-26
(#1057). The host client was psycopg 3.3.6 with libpq 18.4, on Windows 11
AMD64. The psql clients were the postgres:13-alpine to postgres:18-alpine
images, with libpq 13.23, libpq 14.24, libpq 15.19, libpq 16.15, libpq 17.11
and libpq 18.6. Four times, exit 0, the same result each time but for the
timings, which are the ranges below. The fourth ran after changes to the
probe's timeouts and clean-up. Earlier versions are not counted. They
ran psql in the matrix's own containers, which load libpq 18 whatever the
server's release, so they missed the libpq 13 limit below. One also timed out
at 1 MiB under a 10 s connect_timeout.

RESULTS

  PL1  a verifier of 133 bytes at every length, 12 bytes to 1 MiB
  PL2  psycopg logs in at every length, on all six servers. psql with libpq
       14 to 18 logs in at every length it was run with, up to 8192 bytes.
       psql with libpq 13 logs in up to 1024 bytes, and above that fails
       before it sends anything: "psql: error: out of memory", ASCII or not.
       No password one character short logs in. A psycopg login takes 0.1 s
       or less up to 8192 bytes, 0.6 to 0.7 s at 65536, 2.5 to 2.7 s at
       256 KiB and about 10 s at 1 MiB: libpq's PBKDF2 hashes the password in
       each of 4096 iterations, so the time grows with the length
  PL3  13.23 refuses a plaintext password longer than 1024 bytes in ALTER
       ROLE: SQLSTATE 54000, "password too long", ASCII or not. 14.24 to 18.6
       accept every length, and the password logs in

  So with a verifier the server sets no limit, up to 1 MiB. The client does:
  libpq 13 cannot log in with a password longer than 1024 bytes, and the
  login time grows with the length on every client.

HOW TO RUN, against the matrix (test/README.md), from the repo root, with the
repo's virtual environment:

    .venv/Scripts/python sql/postgres/07_password_length_probe.py

It needs psycopg and the docker CLI, and pulls postgres:13-alpine to
postgres:18-alpine. The container and network names follow
COMPOSE_PROJECT_NAME, and the ports SOPULI_TEST_POSTGRES13_PORT to
SOPULI_TEST_POSTGRES18_PORT, so a second clone's matrix is the one it uses.

THROWAWAY SERVERS ONLY. On each server it creates the role sopuli_probe_len
and drops it at the end, and before it starts it drops one an interrupted run
left. It removes each client container at the end, and one an interrupted
run left before it starts one.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

import psycopg
from psycopg import pq, sql

from sopuli.config import charsets

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
ALPHABET = charsets.ALPHABETS["alnum_safe"]
#: The longest entry Windows allows in a process's environment, counting the
#: terminating NUL.
ENV_LIMIT = 32767
#: e with acute, written as a code point so the source stays ASCII.
E_ACUTE = chr(0xE9)


def _client(version: int) -> str:
    """The client container's name. 06 uses its own, so the two can run at once."""
    return f"{PROJECT}-probe-len-client-{version}"


def _port(version: int) -> str:
    return os.environ.get(f"SOPULI_TEST_POSTGRES{version}_PORT", f"54{version}")


class StepError(Exception):
    """A step that is not a result failed, or a short password logged in."""


def _docker(*argv: str) -> str:
    done = subprocess.run(["docker", *argv], capture_output=True, check=False)
    out = (done.stdout + done.stderr).decode("utf-8", "replace").strip()
    if done.returncode != 0:
        raise StepError(f"docker {' '.join(argv[:3])} exited {done.returncode}: {out}")
    return out


def _remove_client(version: int) -> None:
    subprocess.run(["docker", "rm", "-f", _client(version)], capture_output=True, check=False)


def _start_client(version: int) -> str:
    """Start the psql container for this major release, and say which libpq it has."""
    _remove_client(version)
    _docker(
        "run", "-d", "--name", _client(version), "--network", f"{PROJECT}_default",
        "--entrypoint", "sleep", f"postgres:{version}-alpine", "infinity",
    )  # fmt: skip
    psql = _docker("exec", _client(version), "psql", "--version")
    libpq = _docker("exec", _client(version), "sh", "-c", "ls /usr/local/lib/libpq.so.5.*")
    return f"{psql}, {libpq}"


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
    if len("PGPASSWORD=") + len(password) + 1 > ENV_LIMIT:
        return "not run"
    argv = ["docker", "exec", "-e", "PGPASSWORD", _client(version)]
    argv += ["psql", f"host=postgres-{version} dbname=sopuli user={ROLE} connect_timeout=10"]
    argv += ["-X", "-At", "-c", "SELECT 'logged in'"]
    try:
        done = subprocess.run(
            argv,
            capture_output=True,
            env={**os.environ, "PGPASSWORD": password},
            check=False,
            timeout=LOGIN_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return f"error: no answer in {LOGIN_TIMEOUT} s"
    out = (done.stdout + done.stderr).decode("utf-8", "replace").strip()
    if done.returncode == 0 and out == "logged in":
        return "ok"
    if "password authentication failed" in out:
        return "refused"
    return f"error: {' '.join(out.split())[:160]}"


def _short(version: int, password: str) -> str:
    """Log in with the password one character short, which neither client may
    do. An error is a result, as it is for the whole password: a client that
    cannot send this length fails the same way at both."""
    host, psql = _login_host(version, password[:-1]), _login_psql(version, password[:-1])
    for client, result in (("psycopg", host), ("psql", psql)):
        if result.startswith("ok"):
            raise StepError(f"{client} logged in with the password one character short")
    return f"host {host}, psql {psql}"


def _one(conn: psycopg.Connection, version: int, password: str) -> tuple[str, str]:
    """PL1 and PL2, then PL3, which does not depend on them."""
    try:
        verifier = conn.pgconn.encrypt_password(
            password.encode(), ROLE.encode(), b"scram-sha-256"
        ).decode()
    except psycopg.Error as exc:
        first = f"PL1 {_error(exc)}; PL2 not run"
    else:
        try:
            _alter(conn, verifier)
            host, psql = _login_host(version, password), _login_psql(version, password)
            short = _short(version, password)
            pl2 = f"PL2 host {host}, psql {psql}, one character short {short}"
        except psycopg.Error as exc:
            pl2 = f"PL2 ALTER ROLE {_error(exc)}"
        first = f"PL1 verifier of {len(verifier)} bytes; {pl2}"
    try:
        conn.execute("SET password_encryption = 'scram-sha-256'")
        _alter(conn, password)
        pl3 = f"PL3 host {_login_host(version, password)}"
    except psycopg.Error as exc:
        pl3 = f"PL3 ALTER ROLE {_error(exc)}"
    finally:
        conn.execute("RESET password_encryption")
    return first, pl3


def _server(version: int) -> None:
    with _superuser(version) as conn:
        row = conn.execute("SELECT current_setting('server_version')").fetchone()
        assert row is not None
        print(f"=== server {row[0]}")
        try:
            container = _start_client(version)
            print(f"host client: libpq {pq.version()}; container client: {container}")
            conn.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(ROLE)))
            conn.execute(sql.SQL("CREATE ROLE {} LOGIN").format(sql.Identifier(ROLE)))
            cases = [(n, False) for n in ASCII_LENGTHS] + [(n, True) for n in NON_ASCII_LENGTHS]
            for length, non_ascii in cases:
                kind = "ending in U+00E9" if non_ascii else "ASCII"
                first, pl3 = _one(conn, version, _password(length, non_ascii))
                print(f"{length} bytes, {kind}: {first}; {pl3}", flush=True)
        finally:
            conn.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(ROLE)))
            _remove_client(version)


def main() -> int:
    try:
        for version in VERSIONS:
            _server(version)
    except StepError as exc:
        print(f"STOPPED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
