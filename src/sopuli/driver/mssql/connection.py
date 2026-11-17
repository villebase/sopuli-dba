"""The ODBC connection string for one SQL Server target. Tier 0.

The client is pyodbc with Microsoft ODBC Driver 18 (#1538, decision 6). It
takes one connection string, and the password is in it, so the string is
never logged, kept or shown: the session's debug line names the target, the
user, the code and the time, and nothing else (invariants 1 and 2).

Each value the config or the operator supplies is in braces, with each ``}``
doubled. A password of ``; { } =`` and a space logs in that way
(``06_client_library_probe.py``, CL3), and a value outside braces would end at
its first ``;``.

The ``mssql:`` block's ``encrypt`` maps to ODBC Driver 18's ``Encrypt``:
``optional`` to ``no``, ``mandatory`` to ``yes`` and ``strict`` to ``strict``.
Its other keys map one to one (``01-configuration.md`` §*`mssql:` on a
target*). The config refuses a key under a mode where it does nothing, so
this module writes what it is given.
"""

from __future__ import annotations

from sopuli.config.model import ExpandedTarget
from sopuli.config.targets import MSSQL_MANDATORY, MSSQL_OPTIONAL, MSSQL_STRICT
from sopuli.driver.address import host_and_port
from sopuli.driver.login import require_login, session_label
from sopuli.driver.protocol import Credential

#: The ODBC driver the connection names, as ``pyodbc.drivers()`` lists it.
ODBC_DRIVER = "ODBC Driver 18 for SQL Server"

#: ``encrypt`` as ODBC Driver 18's ``Encrypt`` keyword takes it.
ENCRYPT = {MSSQL_OPTIONAL: "no", MSSQL_MANDATORY: "yes", MSSQL_STRICT: "strict"}


def braced(value: str) -> str:
    """``value`` as an ODBC connection-string value: in braces, with each
    ``}`` doubled."""
    return "{" + value.replace("}", "}}") + "}"


def connection_string(
    target: ExpandedTarget, credential: Credential, *, correlation_id: str
) -> str:
    """The connection string for ``target`` as ``credential``. It holds the
    password, so the caller passes it to pyodbc and nowhere else.

    ``Database=master``: every login the tool makes names ``master``, so a
    contained user of the login's name in its default database does not
    answer it (``02-mssql-privileges.md`` §7). An IPv6 address is written
    without its brackets, as :func:`~sopuli.driver.address.host_and_port`
    gives it; whether ODBC Driver 18 takes that form is not measured. ``APP``
    carries the run's
    correlation id, which the server shows as ``APP_NAME()``. A credential
    with no username or no password is refused
    (:func:`~sopuli.driver.login.require_login`).
    """
    username, password = require_login(target, credential)
    host, port = host_and_port(target.target.dsn)
    settings = target.target.mssql_settings
    parts = [
        f"Driver={braced(ODBC_DRIVER)}",
        f"Server={braced(f'tcp:{host},{port}')}",
        "Database=master",
        f"APP={braced(session_label(correlation_id))}",
        f"Encrypt={ENCRYPT[settings.encrypt]}",
    ]
    if settings.trust_server_certificate:
        parts.append("TrustServerCertificate=yes")
    if settings.host_name_in_certificate is not None:
        parts.append(f"HostNameInCertificate={braced(settings.host_name_in_certificate)}")
    if settings.server_certificate is not None:
        parts.append(f"ServerCertificate={braced(settings.server_certificate)}")
    parts.append(f"UID={braced(username)}")
    parts.append(f"PWD={braced(password.reveal())}")
    return ";".join(parts) + ";"
