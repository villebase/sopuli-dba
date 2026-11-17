"""`doctor`'s lines about this machine's SQL Server client. Tier 0.

pyodbc reaches the server through Microsoft's ODBC Driver 18, a system package
that ``pip`` does not install, as Oracle's Instant Client is not
(#1538, decision 6). So the report names pyodbc's release and whether the
ODBC driver manager lists ODBC Driver 18.
"""

from __future__ import annotations

from collections.abc import Iterable

from sopuli.driver.mssql.connection import ODBC_DRIVER


def client_lines(*, pyodbc_version: str, drivers: Iterable[str]) -> dict[str, str]:
    """The client lines: pyodbc's release, and ODBC Driver 18 or why it is
    missing, with the ODBC drivers the driver manager does list."""
    listed = tuple(drivers)
    if ODBC_DRIVER in listed:
        odbc = ODBC_DRIVER
    else:
        others = ", ".join(listed) if listed else "none"
        odbc = (
            f"not installed: install Microsoft {ODBC_DRIVER}, which pyodbc reaches the "
            f"server through. The ODBC drivers listed: {others}"
        )
    return {"pyodbc": pyodbc_version, "odbc_driver": odbc}
