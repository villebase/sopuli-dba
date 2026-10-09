"""Whether a connection is encrypted, read from what the session reports.

Tier 0. The banner rows below are copied from
``sql/oracle/12_connection_encryption_probe.sql``'s runs, one per release, so
the classifier is tested against what the server sent rather than against what
the documentation says it sends.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.driver.oracle.capabilities import (
    CONNECT_INFO,
    NETWORK_PROTOCOL,
    ProbeError,
    classify_encryption,
    encryption_of,
)
from sopuli.driver.protocol import (
    ENCRYPTION_NATIVE,
    ENCRYPTION_NONE,
    ENCRYPTION_TLS,
    UNKNOWN,
    Encryption,
)

PLAIN_23 = [
    "TCP/IP NT Protocol Adapter for Linux: Version 23.26.2.0.0 - Production",
    "Encryption service for Linux: Version 23.26.2.0.0 - Production",
    "Crypto-checksumming service for Linux: Version 23.26.2.0.0 - Production",
]
NNE_23 = [
    "TCP/IP NT Protocol Adapter for Linux: Version 23.26.2.0.0 - Production",
    "Encryption service for Linux: Version 23.26.2.0.0 - Production",
    "AES256 Encryption service adapter for Linux: Version 23.26.2.0.0 - Production",
    "Crypto-checksumming service for Linux: Version 23.26.2.0.0 - Production",
]
PLAIN_11 = [
    "TCP/IP NT Protocol Adapter for Linux: Version 11.2.0.2.0 - Production",
    "Oracle Advanced Security: encryption service for Linux: Version 11.2.0.2.0 - Production",
    "Oracle Advanced Security: crypto-checksumming service for Linux: "
    "Version 11.2.0.2.0 - Production",
]
NNE_11 = [
    "TCP/IP NT Protocol Adapter for Linux: Version 11.2.0.2.0 - Production",
    "Oracle Advanced Security: encryption service for Linux: Version 11.2.0.2.0 - Production",
    "Oracle Advanced Security: AES256 encryption service adapter for Linux: "
    "Version 11.2.0.2.0 - Production",
    "Oracle Advanced Security: crypto-checksumming service for Linux: "
    "Version 11.2.0.2.0 - Production",
]


@pytest.mark.parametrize("banners", [PLAIN_23, PLAIN_11], ids=["23.26", "11.2"])
def test_a_plain_tcp_connection_is_not_encrypted(banners: list[str]) -> None:
    """The ``Encryption service for Linux`` row is on every connection.

    It names the service, not an algorithm in use, so it must not be read as
    NNE. Matching on "encryption service" alone would call every connection
    encrypted.
    """
    found = classify_encryption("tcp", banners)
    assert found.method == ENCRYPTION_NONE
    assert found.algorithm is None
    assert found.hint is not None


@pytest.mark.parametrize("banners", [NNE_23, NNE_11], ids=["23.26", "11.2"])
def test_the_adapter_row_means_nne_and_names_the_algorithm(banners: list[str]) -> None:
    """11.2 writes the row in lower case after a prefix; later releases do not."""
    found = classify_encryption("tcp", banners)
    assert found == Encryption(method=ENCRYPTION_NATIVE, algorithm="AES256", protocol="tcp")


def test_tcps_is_tls_whatever_the_banners_say() -> None:
    assert classify_encryption("tcps", None).method == ENCRYPTION_TLS
    assert classify_encryption("TCPS", PLAIN_23).method == ENCRYPTION_TLS


def test_an_unreadable_view_is_unknown_not_unencrypted() -> None:
    """Could not look is not the same answer as looked and found nothing."""
    found = classify_encryption("tcp", None)
    assert found.method == UNKNOWN
    assert found.hint is not None
    assert "V_$SESSION_CONNECT_INFO" in found.hint


@pytest.mark.parametrize("protocol", ["ipc", "beq", None])
def test_an_unmeasured_transport_is_unknown(protocol: str | None) -> None:
    """Only TCP and TCPS were measured. Anything else is not guessed at."""
    found = classify_encryption(protocol, PLAIN_23)
    assert found.method == UNKNOWN
    assert found.protocol == protocol


class _Cursor:
    """Answers each statement with rows, or raises the exception it maps to."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.asked: list[str] = []
        self.sql = ""

    def execute(self, sql: str, parameters: Any = None, /) -> _Cursor:
        self.asked.append(sql)
        self.sql = sql
        answer = self.answers.get(sql, [(0,)])
        if isinstance(answer, Exception):
            raise answer
        return self

    def fetchone(self) -> Any:
        rows = self.answers.get(self.sql, [(0,)])
        return rows[0] if rows else None

    def fetchall(self) -> Any:
        return self.answers.get(self.sql, [(0,)])


def _ora(code: str) -> RuntimeError:
    return RuntimeError(f"{code}: something the server said")


def test_the_session_is_asked_for_its_protocol_and_its_banners() -> None:
    cursor = _Cursor({NETWORK_PROTOCOL: [("tcp",)], CONNECT_INFO: [(banner,) for banner in NNE_23]})
    assert encryption_of(cursor).method == ENCRYPTION_NATIVE
    assert cursor.asked == [NETWORK_PROTOCOL, CONNECT_INFO]


def test_a_tls_session_does_not_read_the_view() -> None:
    cursor = _Cursor({NETWORK_PROTOCOL: [("tcps",)]})
    assert encryption_of(cursor).method == ENCRYPTION_TLS
    assert cursor.asked == [NETWORK_PROTOCOL]


@pytest.mark.parametrize("code", ["ORA-00942", "ORA-41900"])
def test_a_revoked_view_reads_as_unknown(code: str) -> None:
    cursor = _Cursor({NETWORK_PROTOCOL: [("tcp",)], CONNECT_INFO: _ora(code)})
    assert encryption_of(cursor).method == UNKNOWN


def test_an_unexpected_failure_reading_the_view_is_not_an_answer() -> None:
    """The rule every probe follows: a code not in ``ABSENT_CODES`` raises."""
    cursor = _Cursor({NETWORK_PROTOCOL: [("tcp",)], CONNECT_INFO: _ora("ORA-03113")})
    with pytest.raises(ProbeError):
        encryption_of(cursor)


def test_the_statement_filters_on_the_session_s_own_sid() -> None:
    """On 21c, 19c and 12.2 the view shows other sessions, so a read without
    the filter would report somebody else's connection."""
    assert "sys_context('userenv','sid')" in CONNECT_INFO
