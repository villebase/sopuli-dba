"""What the three drivers' error maps share. Tier 0 (#1232).

Each driver classifies its own codes. What a diagnosis becomes when it is
raised is :mod:`sopuli.driver.errors`, so code that catches one driver's
:class:`~sopuli.driver.errors.MappedError` catches every driver's.
"""

from __future__ import annotations

import sopuli.driver.errors as errors
import sopuli.driver.mysql.errors as mysql
import sopuli.driver.oracle.errors as oracle
import sopuli.driver.postgres.errors as postgres


def test_every_driver_raises_the_shared_mapped_error() -> None:
    raised = [
        oracle.classify("ORA-00942", "ORA-00942: table or view does not exist").as_error(),
        postgres.classify("42P01", 'relation "t" does not exist').as_error(),
        mysql.classify(1146, "Table 'db.t' doesn't exist", sqlstate="42S02").as_error(),
    ]

    assert all(type(error) is errors.MappedError for error in raised)
    assert oracle.MappedError is postgres.MappedError is mysql.MappedError is errors.MappedError


def test_each_driver_writes_its_own_code_in_front_of_the_message() -> None:
    assert [
        str(oracle.classify("ORA-00942", "ORA-00942: table or view does not exist").as_error()),
        str(postgres.classify("42P01", 'relation "t" does not exist').as_error()),
        str(mysql.classify(1146, "Table 'db.t' doesn't exist", sqlstate="42S02").as_error()),
    ] == [
        "ORA-00942: table or view does not exist",
        '42P01: relation "t" does not exist',
        "1146 (42S02): Table 'db.t' doesn't exist",
    ]
