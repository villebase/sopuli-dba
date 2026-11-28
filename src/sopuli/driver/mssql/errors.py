"""How a pyodbc exception from SQL Server is classified. Tier 0.

pyodbc raises an exception whose ``args`` are ``(sqlstate, message)``, or
``(message, sqlstate)`` for an error of pyodbc's own, such as ``HY106`` for a
column type it cannot read (#1731). The message holds one or more ODBC
diagnostic records, joined by ``"; "``. Each record is the SQLSTATE in
brackets, the components that raised it, the text, and a number in
parentheses, as ODBC Driver 18 18.7.1.1 writes them (measured on
16.0.4325.4)::

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
#: ``CREATE LOGIN`` or ``ALTER LOGIN`` from a login without ``ALTER ANY
#: LOGIN``: "User does not have permission to perform this action" (measured
#: on 16.0.4325.4, #1550).
NO_LOGIN_PERMISSION = 15247

#: A clear-text password the host's policy refuses, under ``CHECK_POLICY =
#: ON``: too short, and not complex enough. Measured on 16.0.4325.4, the
#: Linux image, by UC-2's seen reset (#1599). A Windows host's numbers for
#: the same refusals are not measured.
PASSWORD_TOO_SHORT = 33062
PASSWORD_NOT_COMPLEX = 33064

#: The Windows socket error a server answers a ``strict`` connection with when
#: it does not take TDS 8: 2019 and 2022 reset it, from Windows and from Linux
#: (``10_client_tls_probe.py``, TL3).
CONNECTION_RESET = 10054

#: The SQLSTATE of an ODBC driver the driver manager cannot find: Windows's
#: driver manager answers ``IM002``.
DRIVER_NOT_FOUND = "IM002"

#: unixODBC's answer where the driver is registered and its library is not
#: there: ``01000``, "Can't open lib 'ODBC Driver 18 for SQL Server' : file not
#: found". Not measured: unixODBC's own wording.
_CANNOT_OPEN_LIB = re.compile(r"Can't open lib", re.IGNORECASE)

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
    PASSWORD_TOO_SHORT: Rule(
        "policy",
        hint="the host's password policy refused the new password; raise the policy's `length`",
    ),
    PASSWORD_NOT_COMPLEX: Rule(
        "policy",
        hint=(
            "the host's password policy refused the new password; give the policy "
            "uppercase, lowercase, digit and symbol classes"
        ),
    ),
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
    NO_LOGIN_PERMISSION: Rule(
        "authorization",
        hint=(
            "the tool login lacks the server permission the statement needs. For a change "
            "of a login that is ALTER ANY LOGIN (02-mssql-privileges.md §2.1)"
        ),
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

#: The capability a reset under ``strict`` reports missing (#1549): TDS 8,
#: which wraps the whole connection in TLS. ``error.target_capability``.
STRICT_ENCRYPTION = "strict_encryption"

STRICT_HINT = (
    "the connection was reset under `mssql.encrypt: strict`. SQL Server 2019 and 2022 "
    "reset every strict connection in the measurements, and only 2025 took one. If "
    "this server is 2019 or 2022, it does not take `strict`: set `encrypt: mandatory`. "
    "If it is 2025, something on the network reset the connection"
)

#: :class:`~sopuli.driver.protocol.UnsupportedCapabilityError`'s ``remedy``.
STRICT_REMEDY = "set `mssql.encrypt: mandatory` on the target"

#: A :class:`Diagnosis`'s category for a capability the server lacks: the
#: session raises it as :class:`~sopuli.driver.protocol.UnsupportedCapabilityError`.
CAPABILITY = "capability"

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


#: The SQLSTATE class of a warning or a message, such as a trigger's
#: ``PRINT``: the server sends it as a record, and it is not an error.
INFORMATIONAL = "01"


def server_error(found: tuple[Record, ...]) -> Record | None:
    """The first record the server sent as an error. A message before it,
    SQLSTATE ``01…``, is not the answer."""
    return next(
        (
            record
            for record in found
            if record.server and not record.sqlstate.startswith(INFORMATIONAL)
        ),
        None,
    )


#: A SQLSTATE: five digits or capital letters.
_SQLSTATE = re.compile(r"[0-9A-Z]{5}")


def _arguments(exc: Any) -> tuple[str, str]:
    """The pyodbc exception's SQLSTATE and text. pyodbc gives them in that
    order, except for an error of its own, such as ``HY106`` for a type it
    cannot read, where the text comes first (#1731)."""
    args: tuple[Any, ...] = getattr(exc, "args", ())
    if len(args) < 2:
        only = str(args[0]) if args else ""
        return (only if _SQLSTATE.fullmatch(only) else ""), only
    first, second = str(args[0]), str(args[1])
    if not _SQLSTATE.fullmatch(first) and _SQLSTATE.fullmatch(second):
        return second, first
    return first, second


def raw_message(exc: Any) -> str:
    """The pyodbc exception's text, where its records are."""
    return _arguments(exc)[1]


#: The SQLSTATE class of a connection that is gone.
CONNECTION_EXCEPTION = "08"
#: The server ended the session, as a ``KILL`` does: "Cannot continue the
#: execution because the session is in the kill state". It comes as
#: ``HY000``, and the next statement gets ``08S01`` (measured on
#: 16.0.4325.4, #1736).
SESSION_KILLED = 596


#: The ODBC driver's own record when the server ended the session: on
#: Windows it comes before the server's ``596``, and on Linux, in the tier-1
#: CI job, without it (#1736).
_TERMINATED = re.compile(r"Connection may have been terminated by the server", re.IGNORECASE)


def connection_gone(exc: Any) -> bool:
    """Whether the connection that raised ``exc`` can take nothing more: its
    SQLSTATE, or any record's, is class ``08``, the server ended the session
    (:data:`SESSION_KILLED`), or the driver says the server may have ended it
    (:data:`_TERMINATED`). A lock timeout, the query timeout and a cancel
    leave it usable (probe 17, S6)."""
    sqlstate, text = _arguments(exc)
    if sqlstate.startswith(CONNECTION_EXCEPTION) or _TERMINATED.search(text):
        return True
    return any(
        record.sqlstate.startswith(CONNECTION_EXCEPTION)
        or (record.server and record.number == SESSION_KILLED)
        for record in records(text)
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

    The first server error decides (:func:`server_error`, which passes over
    an informational record, as a trigger's ``PRINT`` before the refusal): its
    number is the code, and :data:`RULES`
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
    sqlstate, text = _arguments(exc)
    raw = scrub(text)
    found = records(raw)
    message = " ".join(dict.fromkeys(record.text for record in found)) or raw.strip()

    server = server_error(found)
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
    if code == DRIVER_NOT_FOUND or any(_CANNOT_OPEN_LIB.search(one.text) for one in found):
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
    elif strict and connecting and any(record.number == CONNECTION_RESET for record in found):
        # The server does not take TDS 8, as 2019 and 2022 do not (TL3). The
        # session raises it as the capability missing (STRICT_ENCRYPTION).
        return Diagnosis(
            code=code,
            category=CAPABILITY,
            exit_code=ExitCode.UNSUPPORTED_CAPABILITY,
            message=message,
            hint=STRICT_HINT,
        )
    return Diagnosis(
        code=code, category="connectivity", exit_code=ExitCode.FAILURE, message=message, hint=hint
    )
