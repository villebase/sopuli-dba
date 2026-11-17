"""How a pyodbc exception from SQL Server is classified. Tier 0.

pyodbc raises an exception whose ``args`` are ``(sqlstate, message)``. The
message holds one or more ODBC diagnostic records, joined by ``"; "``. Each
record is the SQLSTATE in brackets, the components that raised it, the text,
and a number in parentheses, as ODBC Driver 18 18.7.1.1 writes them (measured
on 16.0.4325.4)::

    [28000] [Microsoft][ODBC Driver 18 for SQL Server][SQL Server]Login failed
    for user 'acme_app'. (18456) (SQLDriverConnect)

A record whose components end in ``[SQL Server]`` comes from the server, and
its number is the server's. Any other record is the client's own, such as a
``TCP Provider`` or ``SSL Provider`` failure, and its number is the operating
system's. Only pyodbc gives the server's number for each refusal of a login
(``06_client_library_probe.py``, CL2).

A server error keeps the server's number as its code. A failure with no
server record is the client's, and its code is the SQLSTATE: ``08001`` for a
connection that could not be made, ``HYT00`` for a timeout, ``IM002`` for an
ODBC driver that is not installed.

Nothing here raises; the caller decides.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from sopuli.driver import errors
from sopuli.driver.protocol import AuthenticationError
from sopuli.exit_codes import ExitCode

AUTHENTICATION = AuthenticationError.category

#: The login failed: a wrong password, a login that does not exist, or on
#: Windows a locked login, which answers its right password this way too
#: (``09_windows_policy_probe.py``, WP3).
LOGIN_FAILED = 18456
#: The login is disabled (``03_lockout_probe.py``, LK1).
LOGIN_DISABLED = 18470
#: The login must change its password (LK5).
MUST_CHANGE = 18488
#: ``ALTER LOGIN`` on a login that does not exist, or that the tool login
#: may not change, such as a member of ``sysadmin`` (GR1).
CANNOT_ALTER_LOGIN = 15151
#: ``CREATE LOGIN`` of a name a principal already has.
ALREADY_EXISTS = 15025
#: A ``HASHED`` value the server does not take: a ``0x0300`` value on 2019,
#: or a value of the wrong length (``11_hash_version_probe.py``).
INVALID_HASH = 15021
#: ``HASHED`` on a login whose ``CHECK_POLICY`` is on (CH4).
HASHED_NEEDS_POLICY_OFF = 33020
#: The login cannot open the database the statement names (RP4).
DATABASE_DENIED = 916
#: A write to a read-only database.
READ_ONLY_DATABASE = 3906
#: The server refused a permission the statement needs: on an object, or on
#: the server, as a read of ``sys.dm_exec_connections`` without ``VIEW SERVER
#: STATE`` is.
PERMISSION_DENIED = 229
SERVER_PERMISSION_DENIED = 300

#: The Windows socket error a server answers a ``strict`` connection with when
#: it does not take TDS 8: 2019 and 2022 reset it, from Windows and from Linux
#: (``10_client_tls_probe.py``, TL3).
CONNECTION_RESET = 10054

#: The SQLSTATE of an ODBC driver the driver manager cannot find.
DRIVER_NOT_FOUND = "IM002"

#: One diagnostic record: its SQLSTATE, its components, its text and number.
_RECORD = re.compile(
    r"\[(?P<state>[0-9A-Z]{5})\] (?P<source>(?:\[[^\]]*\])+)(?P<text>.*?) "
    r"\((?P<number>-?\d+)\)(?: \(\w+\))?\s*(?:; (?=\[[0-9A-Z]{5}\] \[)|$)",
    re.DOTALL,
)

#: The text of an ``SSL Provider`` record that rejects the server's
#: certificate: an untrusted chain (TL1) or a name it does not hold (TL4).
_CERTIFICATE = re.compile(r"certificate|does not match", re.IGNORECASE)


@dataclass(frozen=True)
class Rule:
    """What one server number means: its category, exit code and hint."""

    category: str
    exit_code: ExitCode = ExitCode.FAILURE
    hint: str | None = None


RULES: dict[int, Rule] = {
    LOGIN_FAILED: Rule(
        AUTHENTICATION,
        exit_code=ExitCode.AUTH_FAILURE,
        hint=(
            "the password this run used is not the one the server holds for this login, "
            "or no such login exists: the server gives both the same answer. On Windows "
            "a locked login answers its right password this way too"
        ),
    ),
    LOGIN_DISABLED: Rule(
        AUTHENTICATION,
        exit_code=ExitCode.AUTH_FAILURE,
        hint="the login is disabled; ALTER LOGIN … ENABLE ends it",
    ),
    MUST_CHANGE: Rule(
        AUTHENTICATION,
        exit_code=ExitCode.AUTH_FAILURE,
        hint="the login must change its password before it can log in",
    ),
    CANNOT_ALTER_LOGIN: Rule(
        "database",
        hint=(
            "the login does not exist, or the tool login may not change it: the server "
            "protects a member of sysadmin or securityadmin, and a login that holds "
            "CONTROL SERVER, ALTER ANY LOGIN or IMPERSONATE ANY LOGIN"
        ),
    ),
    ALREADY_EXISTS: Rule("database", hint="a login or server role already has this name"),
    INVALID_HASH: Rule(
        "database",
        hint="the server did not take the password value: its version or its length",
    ),
    HASHED_NEEDS_POLICY_OFF: Rule(
        "database",
        hint="the server takes a HASHED value only with CHECK_POLICY = OFF in the statement",
    ),
    DATABASE_DENIED: Rule(
        "authorization", hint="the tool login cannot open the database the statement names"
    ),
    READ_ONLY_DATABASE: Rule(
        "database",
        hint="the database is read-only, as on a secondary replica; point the target at one "
        "that takes writes",
    ),
    PERMISSION_DENIED: Rule(
        "authorization", hint="the tool login lacks the permission the message names"
    ),
    SERVER_PERMISSION_DENIED: Rule(
        "authorization", hint="the tool login lacks the server permission the message names"
    ),
}

#: A client failure while the session was being opened: nothing had run.
_FAILED_TO_CONNECT = (
    "the connection to the server failed while the session was being opened, before "
    "any statement ran"
)

#: A client failure on an open session: a statement in flight may have run.
LOST = (
    "the connection to the server was lost. A statement in flight may have run: if it "
    "set a password, the change is unknown until the login is checked"
)

CERTIFICATE_HINT = (
    "the server's certificate did not pass the check `mssql.encrypt` asks for. Put the "
    "CA that issued it in this machine's trust store, and connect by a name the "
    "certificate holds, or set `mssql.host_name_in_certificate`"
)

STRICT_HINT = (
    "the server reset a connection under `mssql.encrypt: strict`. SQL Server 2019 and "
    "2022 reset every strict connection in the measurements, and only 2025 took one: "
    "use `encrypt: mandatory` for this server"
)

DRIVER_HINT = (
    "install Microsoft ODBC Driver 18 for SQL Server, Microsoft's system package: "
    "pyodbc reaches the server through it. `sopuli doctor` lists the ODBC drivers "
    "pyodbc finds"
)


@dataclass(frozen=True)
class Record:
    """One ODBC diagnostic record."""

    sqlstate: str
    server: bool
    text: str
    number: int


@dataclass(frozen=True)
class Diagnosis(errors.Diagnosis):
    """One failure, classified. ``code`` is the server's number where a
    record came from the server, otherwise the SQLSTATE."""

    code: str
    category: str
    exit_code: ExitCode
    message: str
    hint: str | None = None


def records(message: str) -> tuple[Record, ...]:
    """The diagnostic records in a pyodbc message, in order."""
    return tuple(
        Record(
            sqlstate=match["state"],
            server=match["source"].endswith("[SQL Server]"),
            text=" ".join(match["text"].split()),
            number=int(match["number"]),
        )
        for match in _RECORD.finditer(message)
    )


def unchanged(message: str) -> str:
    """The scrub that changes nothing, for a statement that carries no hash."""
    return message


def from_error(
    exc: Any,
    *,
    connecting: bool = False,
    strict: bool = False,
    rules: Mapping[int, Rule] = RULES,
    scrub: Callable[[str], str] = unchanged,
) -> Diagnosis:
    """Classify a pyodbc exception, without importing pyodbc.

    The first server record decides: its number is the code, and :data:`RULES`
    gives its category, else ``database``. Without one, the failure is the
    client's: an ODBC driver that is not installed is a config error, and
    anything else a connection failure, with :data:`CERTIFICATE_HINT` for a
    rejected certificate and :data:`STRICT_HINT` for a reset under ``strict``.

    The message keeps each record's text, without the bracketed components,
    so the server's own words are kept (#785). ``scrub`` is applied to it
    first, as on the other drivers (#786): a statement that carries a
    password value is the caller's to know.

    ``connecting`` is true while the session is being opened, when nothing has
    run. ``strict`` is true when the target's ``encrypt`` is ``strict``.
    """
    args: tuple[Any, ...] = getattr(exc, "args", ())
    sqlstate = str(args[0]) if args else ""
    raw = scrub(str(args[1]) if len(args) > 1 else " ".join(str(arg) for arg in args))
    found = records(raw)
    message = " ".join(dict.fromkeys(record.text for record in found)) or raw.strip()

    server = next((record for record in found if record.server), None)
    if server is not None:
        rule = rules.get(server.number, Rule("database"))
        return Diagnosis(
            code=str(server.number),
            category=rule.category,
            exit_code=rule.exit_code,
            message=message,
            hint=rule.hint,
        )

    code = found[0].sqlstate if found else sqlstate or "HY000"
    if code == DRIVER_NOT_FOUND:
        return Diagnosis(
            code=code,
            category="config",
            exit_code=ExitCode.CONFIG_INVALID,
            message=message,
            hint=DRIVER_HINT,
        )
    hint = _FAILED_TO_CONNECT if connecting else LOST
    if any(_CERTIFICATE.search(record.text) for record in found):
        hint = CERTIFICATE_HINT
    elif strict and any(record.number == CONNECTION_RESET for record in found):
        hint = STRICT_HINT
    return Diagnosis(
        code=code, category="connectivity", exit_code=ExitCode.FAILURE, message=message, hint=hint
    )
