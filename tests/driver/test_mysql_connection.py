"""The MySQL connection arguments, built from a target. Tier 0 (#1221)."""

from __future__ import annotations

import ssl
from pathlib import Path

import pytest

from sopuli.config.errors import ConfigError
from sopuli.config.model import ExpandedTarget, Target, TargetMysql
from sopuli.driver.mysql.connection import connect_arguments, tls_arguments
from sopuli.driver.protocol import Credential, Timeouts
from sopuli.secrets import Secret

PASSWORD = "Tr0ub4dor-and-3"
RUN = "5b0d3f5e-2c0a-4c43-9d6c-0e6f1d2a7b11"


def _target(
    dsn: str = "mysql-dev.example.com:3306", block: TargetMysql | None = None
) -> ExpandedTarget:
    return ExpandedTarget(target=Target(name="mysql-dev", type="mysql", dsn=dsn, mysql=block))


def _arguments(target: ExpandedTarget, timeouts: Timeouts | None = None) -> dict[str, object]:
    return connect_arguments(
        target,
        Credential(username="sopuli_svc", secret=Secret(PASSWORD)),
        correlation_id=RUN,
        timeouts=timeouts or Timeouts(),
    )


def _context(mode: str, ca: str | None = None) -> ssl.SSLContext:
    context = tls_arguments(_target(block=TargetMysql(ssl_mode=mode, ssl_ca=ca)))["ssl"]
    assert isinstance(context, ssl.SSLContext)
    return context


def test_a_target_with_no_block_connects_verifying_the_server_and_its_name() -> None:
    arguments = _arguments(_target())
    context = arguments.pop("ssl")

    assert arguments == {
        "host": "mysql-dev.example.com",
        "port": 3306,
        "user": "sopuli_svc",
        "connect_timeout": Timeouts().connect_s,
        "program_name": f"sopuli {RUN}",
        "autocommit": True,
        "password": PASSWORD,
    }
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_disabled_turns_tls_off() -> None:
    assert tls_arguments(_target(block=TargetMysql(ssl_mode="DISABLED"))) == {"ssl_disabled": True}


def test_preferred_passes_nothing_so_pymysql_negotiates() -> None:
    """PyMySQL's own default is MySQL's PREFERRED: TLS where offered, clear
    where not, no certificate check."""
    assert tls_arguments(_target(block=TargetMysql(ssl_mode="PREFERRED"))) == {}


@pytest.mark.parametrize(
    ("mode", "verify_mode", "check_hostname"),
    [
        ("REQUIRED", ssl.CERT_NONE, False),
        ("VERIFY_CA", ssl.CERT_REQUIRED, False),
        ("VERIFY_IDENTITY", ssl.CERT_REQUIRED, True),
    ],
)
def test_each_mode_that_requires_tls_gets_a_context_of_its_own(
    mode: str, verify_mode: ssl.VerifyMode, check_hostname: bool
) -> None:
    """A context, because PyMySQL then refuses a server that offers no TLS, and
    because its own options check the host name only beside a CA file."""
    context = _context(mode)

    assert context.verify_mode == verify_mode
    assert context.check_hostname is check_hostname
    assert not context.verify_flags & ssl.VERIFY_X509_STRICT


def test_a_ca_file_is_the_one_the_context_trusts(tmp_path: Path) -> None:
    """Loaded, not merely accepted: the context holds exactly the file's
    certificates. A real bundle, copied, as in the HashiCorp transport's test,
    so the count is about this file and not the machine's trust store."""
    import certifi

    bundle = tmp_path / "acme-ca.pem"
    bundle.write_bytes(Path(certifi.where()).read_bytes())
    expected = ssl.create_default_context(cafile=str(bundle)).get_ca_certs()

    context = _context("VERIFY_CA", str(bundle))

    assert expected
    assert context.get_ca_certs() == expected


def test_a_ca_file_that_does_not_exist_is_a_config_error(tmp_path: Path) -> None:
    missing = tmp_path / "not-there.pem"

    with pytest.raises(ConfigError) as caught:
        _context("VERIFY_IDENTITY", str(missing))

    assert "target 'mysql-dev': `mysql.ssl_ca` could not be loaded" in str(caught.value)


def test_a_ca_file_that_is_not_a_certificate_is_a_config_error(tmp_path: Path) -> None:
    junk = tmp_path / "acme-ca.pem"
    junk.write_text("this is not a certificate", encoding="utf-8")

    with pytest.raises(ConfigError, match="mysql.ssl_ca"):
        _context("VERIFY_CA", str(junk))


def test_an_unknown_mode_is_a_fault_not_a_weaker_connection() -> None:
    with pytest.raises(ValueError, match="not a MySQL ssl_mode"):
        _context("verify-full")


def test_an_ipv6_dsn_loses_its_brackets() -> None:
    assert _arguments(_target(dsn="[2001:db8::20]:3306"))["host"] == "2001:db8::20"


def test_a_query_budget_becomes_socket_timeouts() -> None:
    arguments = _arguments(_target(), Timeouts(connect_s=5, query_s=30))

    assert arguments["connect_timeout"] == 5
    assert arguments["read_timeout"] == 30
    assert arguments["write_timeout"] == 30


def test_no_query_budget_sets_no_socket_timeout() -> None:
    arguments = _arguments(_target())

    assert "read_timeout" not in arguments
    assert "write_timeout" not in arguments


def test_the_password_is_only_in_its_own_argument() -> None:
    arguments = _arguments(_target())

    others = [value for key, value in arguments.items() if key != "password"]
    assert not any(PASSWORD in str(value) for value in others)


@pytest.mark.parametrize(
    ("credential", "message"),
    [
        (Credential(username=None, secret=Secret(PASSWORD)), "has no username"),
        (Credential(username="sopuli_svc", secret=None), "resolved no password"),
        (Credential(external=True), "has no username"),
    ],
)
def test_a_credential_with_a_part_missing_is_refused(credential: Credential, message: str) -> None:
    """PyMySQL would otherwise log in as the operating-system user, or with an
    empty password."""
    with pytest.raises(ConfigError, match=message):
        connect_arguments(_target(), credential, correlation_id=RUN, timeouts=Timeouts())
