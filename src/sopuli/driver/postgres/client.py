"""`doctor`'s lines about this machine's PostgreSQL client. Tier 0.

psycopg's binary wheels bundle libpq, and which one follows when the wheel was
built, not psycopg's own version (``docs/measurements.md``, #1032). So the
libpq a process loaded is read at run time, and the report says whether it
accepts ``require_auth``, which libpq 16 added.
"""

from __future__ import annotations

#: The first libpq major release that accepts ``require_auth``. An older one
#: refuses it in the client as an invalid connection option (measured, #1032).
REQUIRE_AUTH_FROM = 16


def libpq_release(version: int) -> tuple[int, int]:
    """``psycopg.pq.version()``'s number as ``(major, minor)``.

    libpq numbers a release from 10 on as ``major * 10000 + minor``, so 180004
    is 18.4. Before 10 the number had three parts; 90624 is 9.6.24, and the
    major is reported as 9.
    """
    if version >= 100000:
        return version // 10000, version % 10000
    return version // 10000, version // 100 % 100


def client_lines(*, psycopg_version: str, libpq_version: int) -> dict[str, str]:
    """The three client lines: psycopg, the libpq it loaded, and ``require_auth``."""
    major, minor = libpq_release(libpq_version)
    if major >= REQUIRE_AUTH_FROM:
        require_auth = "accepted"
    else:
        require_auth = f"not accepted: libpq {major} is older than {REQUIRE_AUTH_FROM}"
    return {
        "psycopg": psycopg_version,
        "libpq": f"{major}.{minor}",
        "require_auth": require_auth,
    }
