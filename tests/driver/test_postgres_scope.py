"""What a PostgreSQL session reports about itself. Tier 0, on a scripted cursor."""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.driver.postgres.scope import (
    IN_RECOVERY,
    READ_ONLY,
    READ_WRITE,
    SESSION_FACTS,
    SSL_ROW,
    SUPERUSER_REFUSED,
    ReadOnlyTargetError,
    SuperuserError,
    observe,
    require_read_write,
)
from sopuli.driver.protocol import CLUSTER, Scope
from sopuli.exit_codes import ExitCode


class _Cursor:
    """Answers each statement this module sends with one scripted row."""

    def __init__(self, facts: tuple[Any, ...], ssl: tuple[Any, ...] | None) -> None:
        self._rows = {SESSION_FACTS: facts, SSL_ROW: ssl}
        self._last: str | None = None
        self.sent: list[str] = []

    def execute(self, query: Any, params: Any = None, /) -> None:
        assert params is None, "the scope reads bind nothing"
        self.sent.append(query)
        self._last = query

    def fetchone(self) -> Any:
        assert self._last is not None
        return self._rows[self._last]


def _observe(
    *,
    recovery: bool = False,
    read_only: str = "off",
    ssl: tuple[Any, ...] | None = (True,),
    version: str = "16.15",
) -> Scope:
    facts = (version, recovery, read_only, "sopuli_admin", False, None)
    return observe(_Cursor(facts, ssl), target="pg-dev")


def test_a_member_of_a_superuser_role_is_refused_as_a_superuser_is() -> None:
    cursor = _Cursor(("16.15", False, "off", "sopuli_admin", False, "postgres"), (True,))

    with pytest.raises(SuperuserError) as refused:
        observe(cursor, target="pg-dev")

    assert refused.value.code == SUPERUSER_REFUSED
    assert refused.value.message == (
        'target "pg-dev" connects as "sopuli_admin", a member of the superuser role '
        '"postgres", and sopuli does not run as a superuser'
    )


def test_a_superuser_is_refused_before_the_second_read() -> None:
    cursor = _Cursor(("16.15", False, "off", "postgres", True, None), (True,))

    with pytest.raises(SuperuserError) as refused:
        observe(cursor, target="pg-dev")

    assert refused.value.code == SUPERUSER_REFUSED
    assert refused.value.exit_code == ExitCode.CONFIG_INVALID
    assert refused.value.category == "config"
    assert refused.value.message == (
        'target "pg-dev" connects as "postgres", a superuser, and sopuli does not run '
        "as a superuser"
    )
    assert "CREATEROLE" in str(refused.value.hint)
    assert cursor.sent == [SESSION_FACTS]


def test_a_primary_is_a_read_write_cluster() -> None:
    scope = _observe()

    assert scope.type == CLUSTER
    assert scope.container is None
    assert scope.db_version == "16.15"
    assert scope.open_mode == READ_WRITE
    assert scope.read_write is True


def test_a_packaged_builds_suffix_is_not_the_version() -> None:
    assert _observe(version="16.4 (Debian 16.4-1.pgdg120+1)").db_version == "16.4"


def test_no_capability_is_reported() -> None:
    assert _observe().capabilities == frozenset()


@pytest.mark.parametrize(
    ("recovery", "read_only", "open_mode"),
    [(True, "off", IN_RECOVERY), (True, "on", IN_RECOVERY), (False, "on", READ_ONLY)],
)
def test_a_standby_or_a_read_only_default_is_not_read_write(
    recovery: bool, read_only: str, open_mode: str
) -> None:
    scope = _observe(recovery=recovery, read_only=read_only)

    assert scope.open_mode == open_mode
    assert scope.read_write is False


def test_a_tls_session_is_tls() -> None:
    encryption = _observe().encryption

    assert (encryption.method, encryption.protocol, encryption.hint) == ("tls", "tcp", None)


def test_a_plain_session_is_none_with_a_hint() -> None:
    encryption = _observe(ssl=(False,)).encryption

    assert encryption.method == "none"
    assert "sslmode" in str(encryption.hint)


def test_a_missing_ssl_row_is_unknown_and_not_none() -> None:
    encryption = _observe(ssl=None).encryption

    assert encryption.method == "unknown"
    assert encryption.hint


def test_a_write_is_refused_on_a_standby() -> None:
    with pytest.raises(ReadOnlyTargetError) as refused:
        require_read_write(_observe(recovery=True), target="pg-dev")

    assert 'target "pg-dev" is IN RECOVERY' in refused.value.message
    assert "primary" in str(refused.value.hint)
    assert refused.value.category == "database"


def test_a_write_is_refused_under_a_read_only_default() -> None:
    with pytest.raises(ReadOnlyTargetError) as refused:
        require_read_write(_observe(read_only="on"), target="pg-dev")

    assert "default_transaction_read_only" in str(refused.value.hint)


def test_a_write_is_allowed_on_a_primary() -> None:
    require_read_write(_observe(), target="pg-dev")
