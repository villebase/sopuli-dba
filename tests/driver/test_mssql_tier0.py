"""The SQL Server driver's pure parts: the connection string, the error map,
the scope and `doctor`'s client lines. Tier 0 (#1549).

The error messages are pyodbc 5.5.0's with ODBC Driver 18 18.7.1.1, as it
raised them against 16.0.4325.4 from Windows (#1549).
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Target, TargetMssql
from sopuli.driver.mssql.client import client_lines
from sopuli.driver.mssql.connection import ODBC_DRIVER, braced, connection_string
from sopuli.driver.mssql.errors import (
    CERTIFICATE_HINT,
    DRIVER_HINT,
    STRICT_HINT,
    connection_gone,
    from_error,
    records,
)
from sopuli.driver.mssql.scope import NotAnInstanceError, observe
from sopuli.driver.protocol import (
    ENCRYPTION_TLS,
    EXPIRE_ON_RESET,
    SERVER,
    UNKNOWN,
    AuthenticationError,
    Credential,
)
from sopuli.exit_codes import ExitCode
from sopuli.secrets import Secret

PASSWORD = "p}a;ss {w=rd"


def target(**settings: Any) -> ExpandedTarget:
    return ExpandedTarget(
        target=Target(
            name="mssql-dev",
            type="mssql",
            dsn="mssql-dev.example.com:1433",
            mssql=TargetMssql(**settings) if settings else None,
        )
    )


def credential(password: str = PASSWORD) -> Credential:
    return Credential(username="sopuli_admin", secret=Secret(password))


def parts(text: str) -> list[str]:
    """The keywords of a connection string with no `;` inside braces."""
    return [part for part in text.split(";") if part]


# ------------------------------------------------------ connection string ---


def test_braced_doubles_a_closing_brace() -> None:
    assert braced("a}b{c") == "{a}}b{c}"


def test_the_default_encrypts_and_checks_the_server() -> None:
    text = connection_string(target(), credential(), correlation_id="run-1")
    head = text.split(";UID=")[0]
    assert parts(head) == [
        f"Driver={{{ODBC_DRIVER}}}",
        "Server={tcp:mssql-dev.example.com,1433}",
        "Database=master",
        "APP={sopuli run-1}",
        "Encrypt=yes",
    ]


def test_the_password_and_user_are_braced_and_last() -> None:
    text = connection_string(target(), credential(), correlation_id="run-1")
    assert text.endswith(";UID={sopuli_admin};PWD={p}}a;ss {w=rd};")


@pytest.mark.parametrize(
    ("settings", "expected"),
    [
        ({"encrypt": "optional"}, ["Encrypt=no"]),
        ({"encrypt": "strict"}, ["Encrypt=strict"]),
        (
            {"encrypt": "mandatory", "trust_server_certificate": True},
            ["Encrypt=yes", "TrustServerCertificate=yes"],
        ),
        (
            {"encrypt": "mandatory", "host_name_in_certificate": "db.example.com"},
            ["Encrypt=yes", "HostNameInCertificate={db.example.com}"],
        ),
        (
            {"encrypt": "strict", "server_certificate": "C:/certs/server}1.pem"},
            ["Encrypt=strict", "ServerCertificate={C:/certs/server}}1.pem}"],
        ),
    ],
)
def test_each_setting_becomes_its_keyword(settings: dict[str, Any], expected: list[str]) -> None:
    text = connection_string(target(**settings), credential(), correlation_id="run-1")
    head = text.split(";UID=")[0]
    found = head.split("APP={sopuli run-1};")[1]
    assert found.split(";") == expected


# ------------------------------------------------------------------ errors ---


class Raised(Exception):  # noqa: N818 -- a stand-in, named for what it holds
    """A stand-in for a pyodbc exception: `(sqlstate, message)`."""


WRONG_PASSWORD = Raised(
    "28000",
    "[28000] [Microsoft][ODBC Driver 18 for SQL Server][SQL Server]Login failed for user "
    "'sopuli_admin'. (18456) (SQLDriverConnect)",
)
UNTRUSTED = Raised(
    "08001",
    "[08001] [Microsoft][ODBC Driver 18 for SQL Server]SSL Provider: The certificate chain "
    "was issued by an authority that is not trusted.\r\n (-2146893019) (SQLDriverConnect); "
    "[08001] [Microsoft][ODBC Driver 18 for SQL Server]Client unable to establish "
    "connection. For solutions related to encryption errors, see "
    "https://go.microsoft.com/fwlink/?linkid=2226722 (-2146893019)",
)
RESET = Raised(
    "08001",
    "[08001] [Microsoft][ODBC Driver 18 for SQL Server]SSL Provider: An existing connection "
    "was forcibly closed by the remote host.\r\n (10054) (SQLDriverConnect); [08001] "
    "[Microsoft][ODBC Driver 18 for SQL Server]Client unable to establish connection (10054)",
)
UNREACHABLE = Raised(
    "08001",
    "[08001] [Microsoft][ODBC Driver 18 for SQL Server]TCP Provider: The wait operation "
    "timed out.\r\n (258) (SQLDriverConnect); [08001] [Microsoft][ODBC Driver 18 for SQL "
    "Server]Login timeout expired (0); [08001] [Microsoft][ODBC Driver 18 for SQL Server]A "
    "network-related or instance-specific error has occurred while establishing a "
    "connection to tcp:127.0.0.1,1. Server is not found or not accessible. (258)",
)
REFUSED_READ = Raised(
    "42000",
    "[42000] [Microsoft][ODBC Driver 18 for SQL Server][SQL Server]VIEW SERVER PERFORMANCE "
    "STATE permission was denied on object 'server', database 'master'. (300) "
    "(SQLExecDirectW); [42000] [Microsoft][ODBC Driver 18 for SQL Server][SQL Server]The "
    "user does not have permission to perform this action. (297)",
)
NO_DRIVER = Raised(
    "IM002",
    "[IM002] [Microsoft][ODBC Driver Manager] Data source name not found and no default "
    "driver specified (0) (SQLDriverConnect)",
)


def test_records_split_each_diagnostic() -> None:
    found = records(REFUSED_READ.args[1])
    assert [(one.sqlstate, one.server, one.number) for one in found] == [
        ("42000", True, 300),
        ("42000", True, 297),
    ]


def test_a_wrong_password_is_an_authentication_failure() -> None:
    diagnosis = from_error(WRONG_PASSWORD, connecting=True)
    assert diagnosis.code == "18456"
    assert diagnosis.message == "Login failed for user 'sopuli_admin'."
    error = diagnosis.as_error()
    assert isinstance(error, AuthenticationError)
    assert error.exit_code == ExitCode.AUTH_FAILURE
    assert str(error).startswith("18456: Login failed for user 'sopuli_admin'.")


@pytest.mark.parametrize(
    ("number", "category"),
    [
        (18470, "authentication"),
        (18488, "authentication"),
        (15151, "database"),
        (15025, "database"),
        (15021, "database"),
        (33020, "database"),
        (916, "authorization"),
        (3906, "database"),
        (99999, "database"),
    ],
)
def test_each_server_number_has_its_category(number: int, category: str) -> None:
    raised = Raised(
        "42000",
        f"[42000] [Microsoft][ODBC Driver 18 for SQL Server][SQL Server]Some text. ({number}) "
        "(SQLExecDirectW)",
    )
    diagnosis = from_error(raised)
    assert (diagnosis.code, diagnosis.category) == (str(number), category)


def test_the_first_server_record_decides() -> None:
    diagnosis = from_error(REFUSED_READ)
    assert (diagnosis.code, diagnosis.category) == ("300", "authorization")
    assert "The user does not have permission" in diagnosis.message


class _PyodbcOwnError(Exception):
    """pyodbc's own error, text first: as it raises for a sql_variant that
    holds an int, measured on 16.0.4325.4 with pyodbc 5.5.0 (#1731)."""


def test_an_error_of_pyodbcs_own_keeps_its_sqlstate_as_the_code() -> None:
    text = "ODBC SQL type -16 is not yet supported.  column-index=0  type=-16"

    diagnosis = from_error(_PyodbcOwnError(text, "HY106"))

    assert diagnosis.code == "HY106"
    assert diagnosis.message == text


def test_a_message_alone_is_not_taken_for_a_sqlstate() -> None:
    assert from_error(_PyodbcOwnError("some driver text")).code == "HY000"


#: What a session waiting on a lock gets when the server KILLs it, measured
#: on 16.0.4325.4 with pyodbc 5.5.0 (review of #1736), and what the next
#: statement gets.
KILLED = (
    "HY000",
    "[HY000] [Microsoft][ODBC Driver 18 for SQL Server]Unspecified error occurred on SQL "
    "Server. Connection may have been terminated by the server. (0) (SQLExecDirectW); "
    "[HY000] [Microsoft][ODBC Driver 18 for SQL Server][SQL Server]Cannot continue the "
    "execution because the session is in the kill state. (596)",
)
LINK_FAILURE = (
    "08S01",
    "[08S01] [Microsoft][ODBC Driver 18 for SQL Server]TCP Provider: An existing connection "
    "was forcibly closed by the remote host.\r\n (10054) (SQLExecDirectW); [08S01] "
    "[Microsoft][ODBC Driver 18 for SQL Server]Communication link failure (10054)",
)


@pytest.mark.parametrize(
    ("args", "gone"),
    [
        (KILLED, True),
        (LINK_FAILURE, True),
        (
            (
                "HYT00",
                "[HYT00] [Microsoft][ODBC Driver 18 for SQL Server]Query timeout expired (0)",
            ),
            False,
        ),
        (
            (
                "HY000",
                "[HY000] [Microsoft][ODBC Driver 18 for SQL Server][SQL Server]Lock request time "
                "out period exceeded. (1222) (SQLExecDirectW)",
            ),
            False,
        ),
    ],
    ids=["killed", "link-failure", "query-timeout", "lock-timeout"],
)
def test_connection_gone(args: tuple[str, str], gone: bool) -> None:
    assert connection_gone(_PyodbcOwnError(*args)) is gone


def test_an_untrusted_certificate_names_the_settings() -> None:
    diagnosis = from_error(UNTRUSTED, connecting=True)
    assert (diagnosis.code, diagnosis.category, diagnosis.hint) == (
        "08001",
        "connectivity",
        CERTIFICATE_HINT,
    )
    assert diagnosis.message.startswith("SSL Provider: The certificate chain was issued")


def test_a_reset_under_strict_is_the_capability_missing() -> None:
    refused = from_error(RESET, connecting=True, strict=True)
    assert (refused.category, refused.exit_code, refused.hint) == (
        "capability",
        ExitCode.UNSUPPORTED_CAPABILITY,
        STRICT_HINT,
    )


@pytest.mark.parametrize(
    ("connecting", "strict"),
    [(True, False), (False, True)],
    ids=["not strict", "on an open session"],
)
def test_a_reset_elsewhere_is_a_connection_failure(connecting: bool, strict: bool) -> None:
    diagnosis = from_error(RESET, connecting=connecting, strict=strict)
    assert (diagnosis.category, diagnosis.exit_code) == ("connectivity", ExitCode.FAILURE)
    assert diagnosis.hint != STRICT_HINT


def test_an_unreachable_server_is_a_connection_failure() -> None:
    diagnosis = from_error(UNREACHABLE, connecting=True)
    assert (diagnosis.code, diagnosis.category) == ("08001", "connectivity")
    assert "before any statement ran" in (diagnosis.hint or "")
    assert "statement in flight" in (from_error(UNREACHABLE).hint or "")


def test_a_missing_odbc_driver_is_a_config_error() -> None:
    diagnosis = from_error(NO_DRIVER, connecting=True)
    assert (diagnosis.code, diagnosis.category, diagnosis.exit_code, diagnosis.hint) == (
        "IM002",
        "config",
        ExitCode.CONFIG_INVALID,
        DRIVER_HINT,
    )


def test_unixodbc_without_the_driver_library_is_a_config_error() -> None:
    """unixODBC's wording where the driver is registered and its library is
    missing. Not measured: unixODBC's own text."""
    raised = Raised(
        "01000",
        "[01000] [unixODBC][Driver Manager]Can't open lib 'ODBC Driver 18 for SQL Server' : "
        "file not found (0) (SQLDriverConnect)",
    )
    diagnosis = from_error(raised, connecting=True)
    assert (diagnosis.code, diagnosis.category, diagnosis.hint) == ("01000", "config", DRIVER_HINT)


def test_the_scrub_runs_before_the_message_is_kept() -> None:
    diagnosis = from_error(WRONG_PASSWORD, scrub=lambda text: text.replace("sopuli_admin", "*"))
    assert diagnosis.message == "Login failed for user '*'."


def test_a_message_without_records_is_kept_whole() -> None:
    diagnosis = from_error(Raised("HY000", "something odd"))
    assert (diagnosis.code, diagnosis.message) == ("HY000", "something odd")


# ------------------------------------------------------------------- scope ---


class FakeCursor:
    def __init__(self, row: tuple[Any, ...]) -> None:
        self.row = row

    def execute(self, query: Any, args: Any = None, /) -> None:
        pass

    def fetchone(self) -> Any:
        return self.row

    def fetchall(self) -> Any:
        return [self.row]


def test_a_server_that_takes_writes() -> None:
    scope = observe(
        FakeCursor(("16.0.4325.4", 3, "READ_WRITE", "master")),
        target="mssql-dev",
        settings=TargetMssql(),
    )
    assert (scope.type, scope.db_release, scope.open_mode, scope.read_write) == (
        SERVER,
        "16.0.4325.4",
        "READ WRITE",
        True,
    )
    assert scope.encryption.method == ENCRYPTION_TLS


def test_the_scope_reports_expire_on_reset_and_not_expire_password() -> None:
    """`MUST_CHANGE` comes only with a new password: the seen reset can
    expire the password it sets, and `account expire-password` cannot
    expire the one a login has (#1554, Q8)."""
    scope = observe(
        FakeCursor(("16.0.4325.4", 3, "READ_WRITE", "master")),
        target="mssql-dev",
        settings=TargetMssql(),
    )
    assert scope.capabilities == frozenset({EXPIRE_ON_RESET})


def test_a_read_only_master() -> None:
    scope = observe(
        FakeCursor(("16.0.4325.4", 3, "READ_ONLY", "master")),
        target="mssql-dev",
        settings=TargetMssql(),
    )
    assert (scope.open_mode, scope.read_write) == ("READ ONLY", False)


def test_optional_encryption_is_unknown() -> None:
    scope = observe(
        FakeCursor(("16.0.4325.4", 3, "READ_WRITE", "master")),
        target="mssql-dev",
        settings=TargetMssql(encrypt="optional"),
    )
    assert scope.encryption.method == UNKNOWN
    assert "VIEW SERVER STATE" in (scope.encryption.hint or "")


def test_azure_sql_database_is_refused() -> None:
    with pytest.raises(NotAnInstanceError) as caught:
        observe(
            FakeCursor(("12.0.2000.8", 5, "READ_WRITE", "master")),
            target="az",
            settings=TargetMssql(),
        )
    assert caught.value.exit_code == ExitCode.CONFIG_INVALID
    assert 'target "az" is Azure SQL Database' in str(caught.value)


@pytest.mark.parametrize("edition", [6, 11])
def test_azure_synapse_is_refused(edition: int) -> None:
    with pytest.raises(NotAnInstanceError) as caught:
        observe(
            FakeCursor(("12.0.2000.8", edition, "READ_WRITE", "master")),
            target="az",
            settings=TargetMssql(),
        )
    assert 'target "az" is Azure Synapse' in str(caught.value)


# ------------------------------------------------------------------ client ---


def test_the_client_lines_name_odbc_driver_18() -> None:
    assert client_lines(pyodbc_version="5.5.0", drivers=["SQL Server", ODBC_DRIVER]) == {
        "pyodbc": "5.5.0",
        "odbc_driver": ODBC_DRIVER,
    }


def test_a_missing_odbc_driver_is_named_with_the_others() -> None:
    lines = client_lines(pyodbc_version="5.5.0", drivers=["SQL Server"])
    assert lines["odbc_driver"].startswith("not installed: install Microsoft ODBC Driver 18")
    assert lines["odbc_driver"].endswith("The ODBC drivers listed: SQL Server")
    assert client_lines(pyodbc_version="5.5.0", drivers=[])["odbc_driver"].endswith(": none")
