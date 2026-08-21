"""Connecting, against a real Oracle (#176). Tier 1.

The first test in this project that opens a socket to a database. Everything
about *what* to send is tier 0 (`test_oracle_client.py`); what is left is the
half only a real server can answer, and it is a short list:

* thick mode actually initialises against the installed Instant Client;
* the credential #175 resolved actually authenticates;
* `DBMS_SESSION.SET_IDENTIFIER` actually lands where §5 says it does. That one
  is the reason this file exists rather than being folded into a mock: the whole
  value of the call is that a *third party* — the audit trail — can see it, and
  nothing but the database can confirm that.
"""

from __future__ import annotations

import os

import pytest

from oracle_harness import Environment
from sopuli.config.model import AdminAuth, AdminCredential, ExpandedTarget, Target
from sopuli.driver.protocol import AuthenticationError, Credential
from sopuli.secrets import Secret

USER = os.environ.get("SOPULI_TEST_ORACLE_USER", "system")
PASSWORD = os.environ.get("SOPULI_TEST_ORACLE_PASSWORD", "sopuli-test")

#: A correlation id shaped like the real thing (a UUID), because that is what
#: goes into `CLIENT_ID` and the column is only 64 characters wide.
CORRELATION_ID = "9f1c2e7a-4d3b-4a51-9d2c-0b7f8e6a1234"


@pytest.fixture
def session_module() -> object:
    """`sopuli.driver.oracle.session`, imported only where there is a client.

    Imported inside the fixture rather than at module scope: this module is
    collected on the tier-0 matrix too, where `oracledb` is not installed, and a
    top-level import would turn every test here into a collection error instead
    of a skip with a reason.
    """
    return pytest.importorskip("sopuli.driver.oracle.session")


def target(environment: Environment) -> ExpandedTarget:
    return ExpandedTarget(
        target=Target(
            name="tier1-oracle",
            type="oracle",
            dsn=environment.dsn,
            admin=AdminCredential(username=USER, auth=AdminAuth(method="env")),
        ),
        index=0,
    )


def credential(password: str = PASSWORD) -> Credential:
    return Credential(username=USER, secret=Secret(password))


def test_a_connection_opens_and_closes(live_oracle: Environment, session_module: object) -> None:
    """The whole of D3 in one assertion: thick mode initialises against the
    installed client and the credential authenticates."""
    with session_module.connect(  # type: ignore[attr-defined]
        target(live_oracle),
        credential(),
        env=os.environ,
        correlation_id=CORRELATION_ID,
    ) as session:
        assert session.connection is not None
        assert session.correlation_id == CORRELATION_ID

        with session.connection.cursor() as cursor:
            [answer] = cursor.execute("select 1 from dual").fetchone()

    assert answer == 1
    assert session.connection is None, "the context manager closes it"


def test_the_correlation_id_is_on_the_session(
    live_oracle: Environment, session_module: object
) -> None:
    """§5's join, confirmed from the database's own side.

    `SYS_CONTEXT('USERENV','CLIENT_IDENTIFIER')` is what
    `UNIFIED_AUDIT_TRAIL.CLIENT_ID` is populated from, so asserting it here is
    asserting the property without needing an audit policy enabled on the test
    container -- which §5 requires of a production database and which a fresh
    Free image does not have.

    This is the property that replaced the rejected package's local audit table
    (ADR-001): the run's id in the tool's JSON, in the database's trail and
    against the vault's metadata is what makes the three line up afterwards.
    """
    session = session_module.connect(  # type: ignore[attr-defined]
        target(live_oracle),
        credential(),
        env=os.environ,
        correlation_id=CORRELATION_ID,
    )
    try:
        with session.connection.cursor() as cursor:
            [found] = cursor.execute(
                "select sys_context('userenv', 'client_identifier') from dual"
            ).fetchone()
    finally:
        session.close()

    assert found == CORRELATION_ID


def test_a_wrong_password_is_an_authentication_failure_and_not_a_traceback(
    live_oracle: Environment, session_module: object
) -> None:
    """ORA-01017, mapped by #172 rather than swallowed: the code survives, the
    server's own wording survives, and the exit code is 6 -- the same one the
    vault side uses, so a scheduler need not know which half of the run could
    not authenticate.
    """
    with pytest.raises(AuthenticationError) as refused:
        session_module.connect(  # type: ignore[attr-defined]
            target(live_oracle),
            credential("definitely-not-the-password"),
            env=os.environ,
            correlation_id=CORRELATION_ID,
        )

    assert refused.value.code == "ORA-01017"
    assert "ORA-01017" in str(refused.value) or "invalid" in str(refused.value).lower()


def test_the_client_version_is_available_without_a_database(
    live_oracle: Environment, session_module: object
) -> None:
    """What this issue owes #182 (P4): a 23.x client reaches 19c and later, so
    `doctor` can say a target is out of reach *before* anybody waits on a
    connection that cannot succeed.

    Initialises thick mode itself rather than relying on a test above having
    done it. That is the #174 lesson applied early: a test that passes because
    of what ran before it is a test that passes until somebody runs it alone,
    and `initialise` is idempotent by design, so asking costs nothing.

    Still connects to nothing -- which is the claim -- but takes `live_oracle`,
    because "there is an Instant Client here" and "there is a database here" are
    the same condition in every lane that runs this.
    """
    session_module.initialise(env=os.environ)  # type: ignore[attr-defined]

    version = session_module.client_version()  # type: ignore[attr-defined]

    assert version
    assert all(isinstance(part, int) for part in version)
