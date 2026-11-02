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
from sopuli.driver.protocol import AuthenticationError
from sopuli.exit_codes import ExitCode


def test_every_driver_raises_the_shared_mapped_error() -> None:
    raised = [
        oracle.classify("ORA-00942", "ORA-00942: table or view does not exist").as_error(),
        postgres.classify("42P01", 'relation "t" does not exist').as_error(),
        mysql.classify(1146, "Table 'db.t' doesn't exist", sqlstate="42S02").as_error(),
    ]

    assert all(type(error) is errors.MappedError for error in raised)
    assert oracle.MappedError is postgres.MappedError is mysql.MappedError is errors.MappedError


def test_every_driver_raises_a_wrong_password_as_an_authentication_error() -> None:
    diagnoses: list[errors.Diagnosis] = [
        oracle.classify("ORA-01017", "ORA-01017: invalid username/password; logon denied"),
        postgres.classify("28P01", 'password authentication failed for user "acme_app_user"'),
        mysql.classify(1045, "Access denied for user 'acme_app_user'", sqlstate="28000"),
    ]

    for diagnosis in diagnoses:
        raised = diagnosis.as_error()
        assert type(raised) is AuthenticationError
        assert raised.message == diagnosis.coded_message
        assert raised.code == diagnosis.code
        assert raised.retryable == diagnosis.retryable
        assert raised.exit_code == ExitCode.AUTH_FAILURE


def test_a_mapped_error_carries_the_diagnosis_regenerate() -> None:
    reused = oracle.classify("ORA-28007", "ORA-28007: the password cannot be reused")
    assert reused.regenerate
    assert reused.as_error().regenerate

    for diagnosis in [
        postgres.classify("42P01", 'relation "t" does not exist'),
        mysql.classify(1146, "Table 'db.t' doesn't exist", sqlstate="42S02"),
    ]:
        assert diagnosis.as_error().regenerate is False


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
