"""sopuli-dba : which libpq psycopg's binary wheels bundle, and require_auth

#1032. The PostgreSQL driver is to log in with require_auth=scram-sha-256,
which needs libpq 16 or later, and to compute verifiers with
PGconn.encrypt_password. psycopg's binary wheels bundle their own libpq. This
records, on the platform it runs on:

  LP1  the psycopg release, its implementation, and the libpq it loads
  LP2  a login with require_auth=scram-sha-256, to a server whose line asks
       for scram-sha-256
  LP3  a login to the same server with require_auth=md5
  LP4  PGconn.encrypt_password with the algorithm scram-sha-256

It MEASURES and decides nothing.

STATUS: run against 18.6, postgres-18 of test/compose.yaml profile
postgres-matrix, on 2026-10-25 (#1032), once on each platform:

  - Windows 11 AMD64, Python 3.13.12, psycopg 3.3.6, from the host;
  - Linux x86_64 glibc, the python:3.13-slim image, psycopg 3.3.6;
  - Linux x86_64 musl, the python:3.13-alpine image, psycopg 3.3.6;
  - Linux x86_64 glibc, earlier psycopg releases: 3.2.13 in python:3.12-slim,
    3.1.20 in python:3.12-slim, 3.1.12 in python:3.11-slim, and 3.1.4 and
    3.0.18 in python:3.10-slim. 3.2.0 and 3.1.0 did not install in those
    images, and were not tried further.

Not run on macOS or on Linux arm64.

RESULTS

  LP1  psycopg 3.3.6 is binary on each platform. On Windows it loads
       libpq 18.4, on Linux glibc and musl libpq 18.6. The earlier releases
       load libpq 17.6 (3.2.13), libpq 16.3 (3.1.20), libpq 16.0 (3.1.12),
       libpq 15.0 (3.1.4) and libpq 14.4 (3.0.18). Each loads the libpq it was
       built against
  LP2  logs in, with every psycopg release from 3.1.12 and on every platform.
       3.1.4 and 3.0.18 refuse it in the client: ProgrammingError 'invalid
       connection option "require_auth"'
  LP3  refused by the client, 'authentication method requirement "md5"
       failed: server requested SASL authentication', from 3.1.12. 3.1.4 and
       3.0.18 give the LP2 error
  LP4  a SCRAM-SHA-256 verifier of 133 bytes, on every one

  So which libpq a wheel bundles follows when it was built, not the platform
  alone. A wheel with libpq 15 or older does not know require_auth, and says
  so before it connects. psycopg.pq.version() reports the libpq a process
  loaded.

HOW TO RUN, against the matrix (test/README.md), in a virtual environment of
its own:

    python -m pip install "psycopg[binary]"
    python sql/postgres/05_psycopg_libpq_probe.py

In a container on the compose network, set SOPULI_TEST_PG_HOST=postgres-18 and
SOPULI_TEST_PG_PORT=5432. The password is tier 0's public test password.
"""

from __future__ import annotations

import os
import platform
import sys

import psycopg
from psycopg import pq

#: The server to log in to: postgres-18 of the matrix. In a container on the
#: compose network, set SOPULI_TEST_PG_HOST=postgres-18 and SOPULI_TEST_PG_PORT=5432.
HOST = os.environ.get("SOPULI_TEST_PG_HOST", "127.0.0.1")
PORT = os.environ.get("SOPULI_TEST_PG_PORT", os.environ.get("SOPULI_TEST_POSTGRES18_PORT", "5418"))
#: Tier 0's public test password, from test/compose.yaml. The server's
#: pg_hba.conf asks for scram-sha-256 on every TCP line.
PASSWORD = "sopuli-test"


def _login(require_auth: str) -> str:
    try:
        with psycopg.connect(
            host=HOST,
            port=PORT,
            dbname="sopuli",
            user="postgres",
            password=PASSWORD,
            require_auth=require_auth,
            connect_timeout=10,
        ) as conn:
            row = conn.execute("SELECT current_setting('server_version')").fetchone()
            return f"logged in, server {row[0] if row else '?'}"
    except psycopg.Error as exc:
        return f"{type(exc).__name__}: {str(exc).strip()}"


def main() -> int:
    print(f"platform: {platform.system()} {platform.release()} {platform.machine()}")
    print(f"python: {sys.version.split()[0]}")
    print(f"psycopg: {psycopg.__version__}, implementation {pq.__impl__}")
    print(f"libpq: runtime {pq.version()}, built against {pq.__build_version__}")
    for require_auth in ("scram-sha-256", "md5"):
        print(f"require_auth={require_auth}: {_login(require_auth)}")

    # The driver computes the verifier with PQencryptPasswordConn and names the
    # algorithm, so the server's password_encryption does not choose it.
    with psycopg.connect(
        host=HOST, port=PORT, dbname="sopuli", user="postgres", password=PASSWORD
    ) as conn:
        verifier = conn.pgconn.encrypt_password(b"PwProbeMarker5v", b"postgres", b"scram-sha-256")
    print(f"encrypt_password: {verifier.split(b'$', 1)[0].decode()}$..., {len(verifier)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
