"""`expire_on_reset` is reported wherever `expire_password` is (#1554, Q8).
Tier 0, from each driver's fixed capability sets.

The seen reset asks for `expire_on_reset`. A product that can expire a
password a login has can also expire the one a reset sets, so a driver that
reports the first and not the second would refuse a seen reset it can do.
SQL Server's scope, which reports only `expire_on_reset`, is tested in
`test_mssql_tier0.py`; PostgreSQL's, which reports neither, in
`test_postgres_scope.py`.
"""

from __future__ import annotations

from sopuli.driver.mariadb.session import CAPABILITIES as MARIADB
from sopuli.driver.oracle.capabilities import STRUCTURAL as ORACLE
from sopuli.driver.protocol import EXPIRE_ON_RESET, EXPIRE_PASSWORD


def test_oracle_reports_both_on_every_release() -> None:
    assert {EXPIRE_PASSWORD, EXPIRE_ON_RESET} <= set(ORACLE)


def test_mariadb_reports_both_always() -> None:
    assert {EXPIRE_PASSWORD, EXPIRE_ON_RESET} <= MARIADB
