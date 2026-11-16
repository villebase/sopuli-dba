"""sopuli-dba : what each Python client library does with a SQL Server login

#1538, M8. A SQL Server driver needs a client library that encrypts the
connection, tells one refused login from another, and passes any password the
policy allows. This measures four, on Windows and on Linux:

  CL1  encryption: what sys.dm_exec_connections.encrypt_option reads for a
       connection that asks for none, and for one that asks for it. The
       matrix's servers make their own certificates, so the ODBC libraries
       are told to trust the server's certificate. pymssql is asked for
       encryption="require", which checks no certificate at all. python-tds
       has no such setting: it encrypts only when given a CA file, and is
       given certifi's bundle
  CL2  refusals: what the library's exception carries for a wrong
       password, a disabled login and a login that must change its password,
       which the server tells apart as 18456, 18470 and 18488. A number
       counts only where the library gives it: an attribute, an argument,
       or the "(18470)" the ODBC driver puts after the server's message,
       before "(SQLDriverConnect)"
  CL3  a password with the characters a connection string treats as
       syntax, ; { } = and a space, and an apostrophe and é. The ODBC
       libraries take it in braces, a closing brace doubled

CL2 and CL3 connect as CL1 does when it encrypts, but for python-tds, which
connects unencrypted there: encrypted, it never reaches the login (CL1).

The libraries, as installed from PyPI: mssql-python 1.17.0, pyodbc 5.5.0
with Microsoft ODBC Driver 18 for SQL Server 18.7.1.1, pymssql 2.4.6, and
python-tds 1.17.1 with pyOpenSSL 26.4.0, cryptography 50.0.2 and certifi
2026.10.23. Strict encryption (TDS 8), and a certificate the server was given,
are measured for pyodbc by 10_client_tls_probe.py, which runs in this probe's
Linux image.

STATUS: run on 15.0.4510.2, 16.0.4325.4 and 17.0.5065.9, the
mcr.microsoft.com/mssql/server 2019-latest, 2022-latest and 2025-latest images
of test/compose.yaml profile mssql-matrix, as pulled on 2026-11-15, on
2026-11-15 (#1538). From Python 3.13.12 on Windows 11 AMD64, and from Python
3.13.18 on Debian 12 in the image, with msodbcsql18 18.7.1.1-1 and unixodbc
2.3.11. Twice, exit 0, and the same result every time.

RESULTS -- the same on every release and on both platforms

  CL1  mssql-python, pyodbc and pymssql encrypt when asked (TRUE), and not
       when not (FALSE). python-tds, given a CA file, verifies the server's
       certificate, and refuses the server's own one: OpenSSL.SSL.Error,
       "certificate verify failed". So it cannot encrypt to these servers
  CL2  **only pyodbc gives the server's number for all three**: 18456,
       18470 and 18488, as "(18470)" after the server's message and before
       "(SQLDriverConnect)". python-tds gives the number as an attribute
       for a wrong password (18456) and a must-change login (18488), and for
       a disabled login waits out its login timeout and raises
       TimeoutError. pymssql gives 18456 for all three, and its messages
       for the disabled and must-change logins hold only DB-Lib's own text,
       not the server's reason. mssql-python gives no number: the server's
       message, reason included, is in the text, and the exception class
       differs (ProgrammingError for a disabled login, OperationalError for
       the others)
  CL3  every library logs in with the password of ; { } = and a space. The
       ODBC libraries take it in braces, a closing brace doubled

HOW TO RUN, against the matrix (test/README.md), from the repo root, with the
four libraries installed in the Python that runs it and ODBC Driver 18 on the
machine:

    python sql/mssql/06_client_library_probe.py

It measures the libraries where it runs, and then on Linux: it builds the
image of 06_client_library.Dockerfile, sopuli-mssql-clients, and runs itself
in it on the matrix's network. It needs 02_client_hash_probe.py beside it.

THROWAWAY SERVERS ONLY. It creates the logins sopuli_probe_cl,
sopuli_probe_cl_off, sopuli_probe_cl_must and sopuli_probe_cl_syntax, and
drops them at the end.
"""

from __future__ import annotations

import importlib.util
import json
import os
import platform
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

HERE = Path(__file__).resolve().parent

# 02's name starts with a digit, so it is loaded by its path.
_SPEC = importlib.util.spec_from_file_location(
    "mssql_client_hash_probe", HERE / "02_client_hash_probe.py"
)
assert _SPEC is not None
assert _SPEC.loader is not None
ch = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ch)

IMAGE = "sopuli-mssql-clients"
PORTS = {"mssql-2019": 14319, "mssql-2022": 14322, "mssql-2025": 14325}
#: Test passwords, not credentials.
GOOD = "Acme-Client-pw1"
SYNTAX = "Acme;pw}{= 'x" + chr(0xE9) + "1"
#: The login CL1 uses, CL2's disabled and must-change logins, and CL3's.
ACCOUNT = "sopuli_probe_cl"
DISABLED = "sopuli_probe_cl_off"
MUST_CHANGE = "sopuli_probe_cl_must"
SYNTAX_ACCOUNT = "sopuli_probe_cl_syntax"
LOGINS = (ACCOUNT, DISABLED, MUST_CHANGE, SYNTAX_ACCOUNT)
REFUSALS = {
    "wrong password": (ACCOUNT, ch.WRONG),
    "disabled": (DISABLED, GOOD),
    "must change": (MUST_CHANGE, GOOD),
}
QUERY = (
    "SELECT SUSER_SNAME(), encrypt_option FROM sys.dm_exec_connections WHERE session_id = @@SPID"
)
#: The number the ODBC driver puts in parentheses after the server's message.
_ODBC_NUMBER = re.compile(r"\((\d{3,6})\) \(SQLDriverConnect\)")


def braced(value: str) -> str:
    """An ODBC connection-string value in braces, a closing brace doubled."""
    return "{" + value.replace("}", "}}") + "}"


def odbc_string(host: str, port: int, user: str, password: str, encrypt: bool) -> str:
    return (
        f"Server=tcp:{host},{port};Database=master;Uid={braced(user)};"
        f"Pwd={braced(password)};Encrypt={'yes' if encrypt else 'no'};"
        "TrustServerCertificate=yes;"
    )  # No timeout keyword: mssql-python refuses "Connection Timeout".


def connect_pyodbc(host: str, port: int, user: str, password: str, encrypt: bool) -> object:
    import pyodbc

    driver = "Driver={ODBC Driver 18 for SQL Server};"
    return pyodbc.connect(driver + odbc_string(host, port, user, password, encrypt))


def connect_mssql_python(host: str, port: int, user: str, password: str, encrypt: bool) -> object:
    import mssql_python

    return mssql_python.connect(odbc_string(host, port, user, password, encrypt))


def connect_pymssql(host: str, port: int, user: str, password: str, encrypt: bool) -> object:
    import pymssql

    return pymssql.connect(
        server=host, port=port, user=user, password=password, database="master",
        encryption="require" if encrypt else "off", login_timeout=15,
    )  # fmt: skip


def connect_pytds(host: str, port: int, user: str, password: str, encrypt: bool) -> object:
    # python-tds encrypts only with a CA file to verify the server against; it
    # has no setting that encrypts and trusts the server's certificate. So it
    # is asked to encrypt with certifi's bundle.
    import pytds

    cafile = {}
    if encrypt:
        import certifi

        cafile = {"cafile": certifi.where()}
    return pytds.connect(
        dsn=host, port=port, user=user, password=password, database="master",
        login_timeout=15, **cafile,
    )  # fmt: skip


LIBRARIES: dict[str, Callable[[str, int, str, str, bool], object]] = {
    "mssql-python": connect_mssql_python,
    "pyodbc": connect_pyodbc,
    "pymssql": connect_pymssql,
    "python-tds": connect_pytds,
}
#: CL2 and CL3 connect encrypted, but for python-tds, which cannot reach a
#: login encrypted to a server whose certificate it does not trust (CL1).
UNENCRYPTED = {"python-tds"}


def number(exc: BaseException) -> str:
    """The server's error number, where the exception gives it, or `none`."""
    for attribute in ("number", "msg_no"):
        value = getattr(exc, attribute, None)
        if isinstance(value, int):
            return str(value)
    first = exc.args[0] if exc.args else None
    if isinstance(first, tuple) and first and isinstance(first[0], int):
        return str(first[0])  # pymssql: ((number, message),)
    found = _ODBC_NUMBER.findall(str(exc))
    return found[0] if found else "none"


def query(connect: Callable[..., object], *args: object) -> list[str]:
    conn = connect(*args)
    try:
        cursor = conn.cursor()  # type: ignore[attr-defined]
        cursor.execute(QUERY)
        return [str(value) for value in cursor.fetchone()]
    finally:
        conn.close()  # type: ignore[attr-defined]


def measure(host: str, port: int) -> dict[str, str]:
    """CL1 to CL3 for each library, as label: result."""
    results: dict[str, str] = {}
    for name, connect in LIBRARIES.items():
        for encrypt in (False, True):
            try:
                _, option = query(connect, host, port, ACCOUNT, GOOD, encrypt)
                got = option
            except Exception as exc:  # noqa: BLE001 - the result is the failure
                kind = f"{type(exc).__module__}.{type(exc).__name__}"
                verify = ", certificate verify failed" * ("verify failed" in str(exc))
                got = f"refused, {kind}{verify}"
            results[f"CL1 {name} {'encrypt' if encrypt else 'plain'}"] = got
        encrypt = name not in UNENCRYPTED
        for case, (user, password) in REFUSALS.items():
            try:
                query(connect, host, port, user, password, encrypt)
                got = "logged in"
            except Exception as exc:  # noqa: BLE001 - the result is the failure
                got = f"{type(exc).__name__}, {number(exc)}"
            results[f"CL2 {name} {case}"] = got
        try:
            who, _ = query(connect, host, port, SYNTAX_ACCOUNT, SYNTAX, encrypt)
            got = "logged in" if who == SYNTAX_ACCOUNT else who
        except Exception as exc:  # noqa: BLE001 - the result is the failure
            got = f"refused, {number(exc)}"
        results[f"CL3 {name}"] = got
    return results


# ----------------------------------------------------------- the servers --


def setup(service: str) -> str:
    """Create the probe's logins; return the release."""
    teardown(service)
    q = ch.quote
    ch.sa(
        service,
        f"CREATE LOGIN [{ACCOUNT}] WITH PASSWORD = {q(GOOD)}, CHECK_POLICY = OFF; "
        f"CREATE LOGIN [{DISABLED}] WITH PASSWORD = {q(GOOD)}, CHECK_POLICY = OFF; "
        f"ALTER LOGIN [{DISABLED}] DISABLE; "
        f"CREATE LOGIN [{MUST_CHANGE}] WITH PASSWORD = {q(GOOD)} MUST_CHANGE, "
        "CHECK_POLICY = ON, CHECK_EXPIRATION = ON; "
        f"CREATE LOGIN [{SYNTAX_ACCOUNT}] WITH PASSWORD = {q(SYNTAX)}, CHECK_POLICY = OFF; "
        f"GRANT VIEW SERVER STATE TO [{ACCOUNT}]; GRANT VIEW SERVER STATE TO [{SYNTAX_ACCOUNT}]",
    )
    return ch.release(service)


def teardown(service: str) -> None:
    ch.sa(service, ";\n".join(ch.drop_login(name) for name in LOGINS))


def build() -> None:
    """Build the Linux image, once a run: it does not depend on the server."""
    built = subprocess.run(
        ["docker", "build", "-q", "-t", IMAGE, "-f",
         str(HERE / "06_client_library.Dockerfile"), str(HERE)],
        capture_output=True, check=False,
    )  # fmt: skip
    if built.returncode != 0:
        raise ch.StepError(f"building {IMAGE}: {built.stderr.decode()[-300:]}")


def on_linux(service: str) -> dict[str, str]:
    """`measure` in the Linux image, on the matrix's network."""
    done = subprocess.run(
        ["docker", "run", "--rm", "--network", f"{ch.PROJECT}_default",
         "-v", f"{HERE}:/probe:ro", IMAGE, "python", "-I",
         "/probe/06_client_library_probe.py", "--client", ch.container(service), "1433"],
        capture_output=True, check=False,
        env={**os.environ, "MSYS_NO_PATHCONV": "1"},
    )  # fmt: skip
    if done.returncode != 0:
        raise ch.StepError(f"{service} on Linux: {done.stderr.decode()[-300:]}")
    lines = done.stdout.decode("utf-8").strip().splitlines()
    if not lines:
        raise ch.StepError(f"{service} on Linux: no results: {done.stderr.decode()[-300:]}")
    return dict(json.loads(lines[-1]))


def here() -> str:
    return f"{platform.system()} {platform.machine()}, Python {platform.python_version()}"


def compare(service: str, where: str, results: dict[str, str]) -> None:
    # Every label of either side, so a case the run left out is a difference too.
    for label in [*RECORDED, *(label for label in results if label not in RECORDED)]:
        got = results.get(label)
        print(f"{label} [{where}]: {got}")
        ch.check(f"{service} {where} {label}", got, RECORDED.get(label))


def probe(service: str) -> None:
    def body() -> None:
        variable = f"SOPULI_TEST_{service.upper().replace('-', '')}_PORT"
        port = int(os.environ.get(variable, PORTS[service]))
        print(f"\n== {service} {setup(service)}")
        compare(service, here(), measure("127.0.0.1", port))
        compare(service, "Linux", on_linux(service))

    ch.cleaned(service, body, lambda: teardown(service))


#: What every library answered, on every release and on both platforms.
RECORDED: dict[str, str] = {
    "CL1 mssql-python plain": "FALSE",
    "CL1 mssql-python encrypt": "TRUE",
    "CL2 mssql-python wrong password": "OperationalError, none",
    "CL2 mssql-python disabled": "ProgrammingError, none",
    "CL2 mssql-python must change": "OperationalError, none",
    "CL3 mssql-python": "logged in",
    "CL1 pyodbc plain": "FALSE",
    "CL1 pyodbc encrypt": "TRUE",
    "CL2 pyodbc wrong password": "InterfaceError, 18456",
    "CL2 pyodbc disabled": "ProgrammingError, 18470",
    "CL2 pyodbc must change": "InterfaceError, 18488",
    "CL3 pyodbc": "logged in",
    "CL1 pymssql plain": "FALSE",
    "CL1 pymssql encrypt": "TRUE",
    "CL2 pymssql wrong password": "OperationalError, 18456",
    "CL2 pymssql disabled": "OperationalError, 18456",
    "CL2 pymssql must change": "OperationalError, 18456",
    "CL3 pymssql": "logged in",
    "CL1 python-tds plain": "FALSE",
    "CL1 python-tds encrypt": "refused, OpenSSL.SSL.Error, certificate verify failed",
    "CL2 python-tds wrong password": "OperationalError, 18456",
    "CL2 python-tds disabled": "TimeoutError, none",
    "CL2 python-tds must change": "OperationalError, 18488",
    "CL3 python-tds": "logged in",
}


def main() -> int:
    if sys.argv[1:2] == ["--client"]:
        # In the Linux image: measure, and print the results as one JSON line.
        print(json.dumps(measure(sys.argv[2], int(sys.argv[3]))))
        return 0
    print(here())
    try:
        build()
    except ch.StepError as exc:
        print(f"STEP FAILED: {exc}")
        return 1
    return ch.run(probe)


if __name__ == "__main__":
    sys.exit(main())
