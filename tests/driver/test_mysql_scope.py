"""What a MySQL session reports about itself. Tier 0: a fake cursor answers
the two reads with rows in the shape MySQL 8.4.13 gave through PyMySQL 1.2.3."""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.driver.mysql.scope import (
    READ_ONLY,
    READ_WRITE,
    SESSION_FACTS,
    TLS_VERSION,
    UNENCRYPTED_HINT,
    NotMysqlError,
    ReadOnlyTargetError,
    observe,
    require_read_write,
)
from sopuli.driver.protocol import ENCRYPTION_NONE, ENCRYPTION_TLS, SERVER
from sopuli.exit_codes import ExitCode


class FakeCursor:
    def __init__(self, facts: tuple[Any, ...], tls: str | None) -> None:
        self.answers = {
            SESSION_FACTS: facts,
            TLS_VERSION: None if tls is None else ("Ssl_version", tls),
        }
        self.last: str | None = None

    def execute(self, query: Any, args: Any = None, /) -> None:
        self.last = query

    def fetchone(self) -> Any:
        assert self.last is not None
        return self.answers[self.last]


def _observe(
    version: str = "8.4.13",
    read_only: int = 0,
    super_read_only: int = 0,
    transaction_read_only: int = 0,
    tls: str | None = "TLSv1.3",
) -> Any:
    cursor = FakeCursor((version, read_only, super_read_only, transaction_read_only), tls)
    return observe(cursor, target="mysql-dev")


def test_a_writable_server_over_tls() -> None:
    scope = _observe()

    assert scope.type == SERVER
    assert scope.db_version == "8.4.13"
    assert scope.open_mode == READ_WRITE
    assert scope.read_write is True
    assert scope.encryption.method == ENCRYPTION_TLS
    assert scope.encryption.protocol == "tcp"
    assert scope.capabilities == frozenset()


def test_a_version_suffix_is_not_reported() -> None:
    assert _observe(version="8.0.46-log").db_version == "8.0.46"


@pytest.mark.parametrize("flags", [(1, 0, 0), (0, 1, 0), (0, 0, 1)])
def test_each_read_only_setting_makes_the_session_read_only(flags: tuple[int, int, int]) -> None:
    """`read_only`, `super_read_only` and the session's `transaction_read_only`."""
    read_only, super_read_only, transaction_read_only = flags
    scope = _observe(
        read_only=read_only,
        super_read_only=super_read_only,
        transaction_read_only=transaction_read_only,
    )

    assert scope.open_mode == READ_ONLY
    assert scope.read_write is False


@pytest.mark.parametrize("tls", ["", None])
def test_a_plain_connection_is_unencrypted_and_says_what_to_set(tls: str | None) -> None:
    """An empty `Ssl_version` is a plain connection."""
    encryption = _observe(tls=tls).encryption

    assert encryption.method == ENCRYPTION_NONE
    assert encryption.hint == UNENCRYPTED_HINT


def test_a_mariadb_server_is_refused_as_the_wrong_type() -> None:
    with pytest.raises(NotMysqlError) as caught:
        _observe(version="10.11.19-MariaDB-ubu2204")

    assert caught.value.category == "config"
    assert caught.value.exit_code == ExitCode.CONFIG_INVALID
    assert 'target "mysql-dev" declares type "mysql", and the server is MariaDB' in str(
        caught.value
    )


def test_a_write_on_a_read_only_session_is_refused_before_anything_is_sent() -> None:
    with pytest.raises(ReadOnlyTargetError, match="READ ONLY and cannot be written to"):
        require_read_write(_observe(super_read_only=1), target="mysql-dev")


def test_a_writable_session_passes() -> None:
    require_read_write(_observe(), target="mysql-dev")
