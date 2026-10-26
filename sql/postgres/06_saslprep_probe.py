"""sopuli-dba : whether a client's verifier and a server's SASLprep agree on a non-ASCII password

#1057. The PostgreSQL driver is to send a SCRAM-SHA-256 verifier that it
computes on the client. SCRAM normalises a password with SASLprep (RFC 4013)
before it hashes it: libpq does it when it computes a verifier and when it logs
in, and the server does it when it hashes a plaintext password. If two of them
normalise one password differently, the password set is not the one that logs
in. This records, on each server:

  SP0  whether every named charset of the password policy is ASCII. It reads
       sopuli.config.charsets, so it runs on the client only
  SP1  the server's encoding, and the libpq of each client
  SP2  for each group of passwords below, a password set two ways, then each
       password of its group used to log in, by two clients
  SP3  for each group, a verifier computed without SASLprep, as a client that
       skips it would, then each password of its group used to log in by
       psycopg. An ASCII password set this way first shows that the verifier
       is well formed

The groups. Each pair is two spellings that SASLprep makes one:

  composed     e with acute as U+00E9, and as e then U+0301
  ligature     U+FB01, the fi ligature, and the letters f i
  nbsp         U+00A0, the no-break space, and a space
  soft hyphen  U+00AD, which SASLprep removes, and nothing
  private use  U+E000, which SASLprep prohibits
  emoji        U+1F600, which is not in Unicode 3.2, so SASLprep prohibits it

The two ways to set it in SP2: a verifier computed by the client running the
probe with PGconn.encrypt_password, as the driver does, and a plaintext
password in ALTER ROLE, which the server hashes under password_encryption =
scram-sha-256. The two clients that log in: psycopg on the host running the
probe, and psql of the server's major release. The psql runs in a container
the probe starts from the postgres:<major>-alpine image on the compose network,
because that image builds its own libpq. The Debian images of the matrix do
not: their psql loads the newest libpq5 of the PostgreSQL apt repository,
which is 18 in every one. Each client also tries a wrong password, which must
be refused. A wrong password that logs in, or one that fails for another
reason, makes the probe exit 1.

It MEASURES and decides nothing.

STATUS: run on 13.23, 14.24, 15.19, 16.15, 17.11 and 18.6, the postgres:13 to
postgres:18 images of test/compose.yaml profile postgres-matrix, on 2026-10-26
(#1057). The host client was psycopg 3.3.6 with libpq 18.4, on Windows 11
AMD64. The psql clients were the postgres:13-alpine to postgres:18-alpine
images, with libpq 13.23, libpq 14.24, libpq 15.19, libpq 16.15, libpq 17.11
and libpq 18.6. Three times, exit 0, the same result each time. Four earlier
runs are not counted: they ran psql in the matrix's own containers, which
load libpq 18 whatever the server's release. They gave the same SP0 to SP3.

RESULTS -- the same on all six releases

  SP0  alnum, alnum_safe and printable_ascii are ASCII. `charset: custom` and
       --from-stdin are not limited to ASCII
  SP1  every server's encoding is UTF8. Each psql client loads the libpq of
       its own release
  SP2  every password logs in, set either way, by both clients, and so does the
       other spelling of its group: e with acute composed and decomposed, the
       ligature and f i, the no-break space and a space, the soft hyphen and
       nothing. The private-use character and U+1F600 log in too, set either
       way. Every wrong password is refused
  SP3  the ASCII password logs in. A verifier computed without SASLprep logs
       in with both spellings when it was computed from the spelling SASLprep
       gives: the composed e, f i, a space, nothing. Computed from the other
       spelling, it refuses both. The private-use character and U+1F600 log in,
       because libpq and the server use a password that SASLprep prohibits as
       it is

  So libpq 13 to 18 and the servers 13 to 18 agree, and a verifier from the
  driver's libpq logs in from a psql of each of those releases. A client that
  skips SASLprep agrees only where SASLprep would not change the password.

HOW TO RUN, against the matrix (test/README.md), from the repo root, with the
repo's virtual environment:

    .venv/Scripts/python sql/postgres/06_saslprep_probe.py

It needs psycopg and the docker CLI, and pulls postgres:13-alpine to
postgres:18-alpine. The container and network names follow
COMPOSE_PROJECT_NAME, and the ports SOPULI_TEST_POSTGRES13_PORT to
SOPULI_TEST_POSTGRES18_PORT, so a second clone's matrix is the one it uses.
A password reaches psql through the environment of `docker exec`, never
through argv.

THROWAWAY SERVERS ONLY. On each server it creates the role sopuli_probe_sasl
and drops it at the end, and before it starts it drops one an interrupted run
left. It removes each client container at the end, and one an interrupted
run left before it starts one.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import subprocess
import sys
from collections.abc import Callable

import psycopg
from psycopg import pq, sql

from sopuli.config import charsets

#: The stack's project name, so a second clone's stack is the one probed.
PROJECT = os.environ.get("COMPOSE_PROJECT_NAME", "sopuli-test")
VERSIONS = (13, 14, 15, 16, 17, 18)
#: Tier 0's public test password, from test/compose.yaml.
SUPERUSER_PASSWORD = "sopuli-test"
ROLE = "sopuli_probe_sasl"
#: Test passwords, not credentials. The ASCII part keeps each one long enough
#: for any policy floor, and different from the wrong one. The characters are
#: written as code points, because a no-break space or a soft hyphen typed into
#: the source cannot be seen. Each has a label, which is what the output
#: prints.
PREFIX = "PwSaslMarker6-"
GROUPS: dict[str, tuple[tuple[str, str], ...]] = {
    "composed": (("U+00E9", PREFIX + chr(0xE9)), ("e U+0301", PREFIX + "e" + chr(0x301))),
    "ligature": (("U+FB01", PREFIX + chr(0xFB01)), ("fi", PREFIX + "fi")),
    "nbsp": (("a U+00A0 b", PREFIX + "a" + chr(0xA0) + "b"), ("a space b", PREFIX + "a b")),
    "soft hyphen": (("a U+00AD b", PREFIX + "a" + chr(0xAD) + "b"), ("ab", PREFIX + "ab")),
    "private use": (("U+E000", PREFIX + chr(0xE000)),),
    "emoji": (("U+1F600", PREFIX + chr(0x1F600)),),
}
WRONG = PREFIX + "wrong"
ASCII_CONTROL = (("ascii", PREFIX + "ascii"),)


def _client(version: int) -> str:
    return f"{PROJECT}-probe-client-{version}"


def _port(version: int) -> str:
    return os.environ.get(f"SOPULI_TEST_POSTGRES{version}_PORT", f"54{version}")


class StepError(Exception):
    """A step that is not a result failed, so nothing after it is a result."""


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


def _alter(conn: psycopg.Connection, password: str) -> None:
    conn.execute(
        sql.SQL("ALTER ROLE {} PASSWORD {}").format(sql.Identifier(ROLE), sql.Literal(password))
    )


def _set_by_client(conn: psycopg.Connection, password: str) -> None:
    verifier = conn.pgconn.encrypt_password(password.encode(), ROLE.encode(), b"scram-sha-256")
    _alter(conn, verifier.decode())


def _set_by_server(conn: psycopg.Connection, password: str) -> None:
    conn.execute("SET password_encryption = 'scram-sha-256'")
    try:
        _alter(conn, password)
    finally:
        conn.execute("RESET password_encryption")


def _set_without_saslprep(conn: psycopg.Connection, password: str) -> None:
    """A SCRAM-SHA-256 verifier from RFC 5802, over the UTF-8 bytes as given."""
    salt, iterations = os.urandom(16), 4096
    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    stored = hashlib.sha256(hmac.digest(salted, b"Client Key", "sha256")).digest()
    server = hmac.digest(salted, b"Server Key", "sha256")

    def b64(data: bytes) -> str:
        return base64.b64encode(data).decode()

    _alter(conn, f"SCRAM-SHA-256${iterations}:{b64(salt)}${b64(stored)}:{b64(server)}")


def _login_host(version: int, password: str) -> str:
    try:
        with psycopg.connect(
            host="127.0.0.1",
            port=_port(version),
            dbname="sopuli",
            user=ROLE,
            password=password,
            connect_timeout=10,
        ):
            return "ok"
    except psycopg.OperationalError as exc:
        text = str(exc)
        return "refused" if "password authentication failed" in text else f"error: {text.strip()}"


def _login_psql(version: int, password: str) -> str:
    argv = ["docker", "exec", "-e", "PGPASSWORD", _client(version)]
    argv += ["psql", f"host=postgres-{version} dbname=sopuli user={ROLE}"]
    argv += ["-X", "-At", "-c", "SELECT 'logged in'"]
    done = subprocess.run(
        argv, capture_output=True, env={**os.environ, "PGPASSWORD": password}, check=False
    )
    out = (done.stdout + done.stderr).decode("utf-8", "replace").strip()
    if done.returncode == 0 and out == "logged in":
        return "ok"
    return "refused" if "password authentication failed" in out else f"error: {out}"


Login = Callable[[int, str], str]


def _logins(
    version: int, group: tuple[tuple[str, str], ...], clients: tuple[tuple[str, Login], ...]
) -> str:
    """Each password of the group, then a wrong one, by each client."""
    cells = []
    for client, login in clients:
        results = [f"{label}={login(version, form)}" for label, form in group]
        wrong = login(version, WRONG)
        if wrong == "ok":
            raise StepError(f"{client} logged in with the wrong password")
        if wrong != "refused":
            raise StepError(f"{client} could not try the wrong password: {wrong}")
        cells.append(f"{client} {' '.join(results)}")
    return " | ".join(cells)


def _server(version: int) -> None:
    both = (("host", _login_host), ("psql", _login_psql))
    with _superuser(version) as conn:
        row = conn.execute(
            "SELECT current_setting('server_version'), current_setting('server_encoding')"
        ).fetchone()
        assert row is not None
        print(f"=== server {row[0]}, encoding {row[1]}")
        container = _start_client(version)
        print(f"SP1 host client: libpq {pq.version()}; container client: {container}")
        conn.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(ROLE)))
        conn.execute(sql.SQL("CREATE ROLE {} LOGIN").format(sql.Identifier(ROLE)))
        try:
            for name, group in GROUPS.items():
                for how, setter in (("client", _set_by_client), ("server", _set_by_server)):
                    for label, form in group:
                        setter(conn, form)
                        result = _logins(version, group, both)
                        print(f"SP2 {name}, set by {how} from {label}: {result}")
            _set_without_saslprep(conn, ASCII_CONTROL[0][1])
            result = _logins(version, ASCII_CONTROL, both[:1])
            print(f"SP3 ascii, set without SASLprep: {result}")
            for name, group in GROUPS.items():
                for label, form in group:
                    _set_without_saslprep(conn, form)
                    result = _logins(version, group, both[:1])
                    print(f"SP3 {name}, set without SASLprep from {label}: {result}")
        finally:
            conn.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(ROLE)))
            _remove_client(version)


def main() -> int:
    for name, alphabet in charsets.ALPHABETS.items():
        print(f"SP0 charset {name}: {'ASCII' if alphabet.isascii() else 'not ASCII'}")
    try:
        for version in VERSIONS:
            _server(version)
    except StepError as exc:
        print(f"STOPPED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
