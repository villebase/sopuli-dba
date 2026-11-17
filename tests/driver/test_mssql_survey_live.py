"""Every login on a live SQL Server, as `report accounts` reads it (#1555).

Tier 1. `sa` makes each login; the tool login, with only `ALTER ANY LOGIN`
(`02-mssql-privileges.md` §2.1), surveys them. Every login this file makes
starts `w2_` and is dropped after. The matrix images run on Linux.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

pytest.importorskip("pyodbc")
session_module = pytest.importorskip("sopuli.driver.mssql.session")

from sopuli.config.model import ExpandedTarget, Target, TargetMssql  # noqa: E402
from sopuli.driver.mssql.accounts import LOCKED, OPEN  # noqa: E402
from sopuli.driver.mssql.survey import COUNT_ON_LINUX, LIFETIME_FROM_POLICY  # noqa: E402
from sopuli.driver.protocol import Credential  # noqa: E402
from sopuli.driver.survey import SurveyedAccount  # noqa: E402
from sopuli.secrets import Secret  # noqa: E402

LOGINS = ("w2_acme_app", "w2_acme_off", "w2_acme_exp", "w2_acme_cert")


def _sa(live_mssql: Any, *statements: str) -> None:
    connection = live_mssql.connect()
    try:
        cursor = connection.cursor()
        for statement in statements:
            cursor.execute(statement)
    finally:
        connection.close()


def _drop(live_mssql: Any) -> None:
    _sa(
        live_mssql,
        *(f"IF SUSER_ID(N'{name}') IS NOT NULL DROP LOGIN [{name}]" for name in LOGINS),
        "IF CERT_ID('w2_acme_cert_c') IS NOT NULL DROP CERTIFICATE [w2_acme_cert_c]",
    )


@pytest.fixture
def surveyed(live_mssql: Any) -> Iterator[dict[str, SurveyedAccount]]:
    """The survey as the tool login, by name, with the logins made, and
    dropped before and after."""
    _drop(live_mssql)
    try:
        _sa(
            live_mssql,
            "CREATE LOGIN [w2_acme_app] WITH PASSWORD = N'Acme-app-pw1', CHECK_POLICY = OFF",
            "CREATE LOGIN [w2_acme_off] WITH PASSWORD = N'Acme-off-pw1', CHECK_POLICY = OFF",
            "ALTER LOGIN [w2_acme_off] DISABLE",
            "CREATE LOGIN [w2_acme_exp] WITH PASSWORD = N'Acme-exp-pw1', CHECK_POLICY = ON, "
            "CHECK_EXPIRATION = ON",
            "CREATE CERTIFICATE [w2_acme_cert_c] ENCRYPTION BY PASSWORD = N'W2-cert-pw1' "
            "WITH SUBJECT = 'w2 survey'",
            "CREATE LOGIN [w2_acme_cert] FROM CERTIFICATE [w2_acme_cert_c]",
        )
        target = ExpandedTarget(
            target=Target(
                name="tier1-mssql",
                type="mssql",
                dsn=live_mssql.dsn,
                mssql=TargetMssql(trust_server_certificate=True),
            )
        )
        driver = session_module.MssqlDriver(correlation_id="tier1")
        session = driver.connect(
            target, Credential(live_mssql.tool_user, Secret(live_mssql.tool_password))
        )
        try:
            accounts, profiles = session.survey_with_profiles()
        finally:
            session.close()
        assert profiles == frozenset()
        yield {account.name: account for account in accounts}
    finally:
        _drop(live_mssql)


def test_every_login_is_read_with_the_narrow_grant(surveyed: dict[str, SurveyedAccount]) -> None:
    assert set(LOGINS) <= set(surveyed)
    assert "sa" in surveyed
    assert surveyed["sa"].vendor_maintained is False
    own = [name for name in surveyed if name.startswith("##MS_")]
    assert own, "the image has ##MS_ logins"
    assert all(surveyed[name].vendor_maintained for name in own)


def test_a_policy_off_login_is_open_with_no_limits(surveyed: dict[str, SurveyedAccount]) -> None:
    app = surveyed["w2_acme_app"]

    assert app.status == OPEN
    assert app.locked is False
    assert app.password_lifetime == "unlimited"
    assert app.failed_login_limit == "unlimited"
    # The matrix images run on Linux, where BadPasswordCount stops at 1 (LK2).
    assert app.failed_logins is None
    assert app.unreadable == (COUNT_ON_LINUX,)


def test_a_disabled_login_is_a_lock_somebody_set(surveyed: dict[str, SurveyedAccount]) -> None:
    off = surveyed["w2_acme_off"]

    assert off.status == LOCKED
    assert off.deliberately_locked is True


def test_expiration_on_leaves_the_lifetime_not_checked(
    surveyed: dict[str, SurveyedAccount],
) -> None:
    exp = surveyed["w2_acme_exp"]

    assert exp.password_lifetime is None
    # No login locks on a Linux host, so the policy sets no limit there (LK2).
    assert exp.failed_login_limit == "unlimited"
    assert exp.unreadable == (LIFETIME_FROM_POLICY, COUNT_ON_LINUX)


def test_a_certificate_login_has_no_password_values(
    surveyed: dict[str, SurveyedAccount],
) -> None:
    cert = surveyed["w2_acme_cert"]

    assert cert.status == OPEN
    assert cert.password_lifetime is None
    assert cert.failed_logins is None
    assert cert.unreadable == ("a login mapped to a certificate has no password",) * 3
