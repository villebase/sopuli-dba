"""`doctor`'s line about this machine's MySQL client. Tier 0.

PyMySQL is pure Python and brings no client library, so its own release is the
whole answer. ``pymysql.__version__`` is not it: that is a MySQLdb-compatible
string (``2.2.8`` on PyMySQL 1.2.3), so the session reads ``pymysql.VERSION``
instead.
"""

from __future__ import annotations


def client_lines(*, pymysql_version: str) -> dict[str, str]:
    """The client line: PyMySQL's release."""
    return {"pymysql": pymysql_version}
