"""`doctor`'s MySQL client line. Tier 0: the version is an argument."""

from __future__ import annotations

from sopuli.driver.mysql.client import client_lines


def test_the_client_line_is_pymysqls_release() -> None:
    assert client_lines(pymysql_version="1.2.3") == {"pymysql": "1.2.3"}
