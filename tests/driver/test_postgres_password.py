"""Invariant 15 in tier 0: what `set_password` sends, and what it refuses first.

The verifier comes from libpq, which needs a connection, so here a scripted
connection returns one; the live test (`test_postgres_password_live.py`) has
libpq compute it, and reads the server's log back. What is checked here is that
the statement carries the verifier and never the password, and that every
refusal comes before anything is sent.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Target
from sopuli.driver.protocol import DriverError, Scope
from sopuli.secrets import Secret

session_module = pytest.importorskip("sopuli.driver.postgres.session")
password = pytest.importorskip("sopuli.driver.postgres.password")
roles = pytest.importorskip("sopuli.driver.postgres.roles")

ROLE = "acme_web_user"
PASSWORD = "Correct-Horse-Battery-9"
VERIFIER = "SCRAM-SHA-256$4096:c2FsdA==$c3RvcmVk:c2VydmVy"


class _PGconn:
    def __init__(self, answer: str = VERIFIER, fails: Exception | None = None) -> None:
        self.answer = answer
        self.fails = fails
        self.asked: list[tuple[bytes, bytes, bytes | None]] = []

    def encrypt_password(self, passwd: bytes, user: bytes, algorithm: bytes | None = None) -> bytes:
        self.asked.append((passwd, user, algorithm))
        if self.fails is not None:
            raise self.fails
        return self.answer.encode("ascii")


class _Cursor:
    def __init__(self, connection: _Connection) -> None:
        self.connection = connection

    def execute(self, query: Any, params: Any = None, /) -> None:
        if query == roles.ROLE_QUERY:
            return
        self.connection.sent.append(query)
        if self.connection.refuse is not None:
            raise self.connection.refuse

    def fetchall(self) -> Any:
        return self.connection.role_rows


class _Connection:
    def __init__(self) -> None:
        self.pgconn = _PGconn()
        self.sent: list[Any] = []
        self.refuse: Exception | None = None
        self.role_rows: list[tuple[Any, ...]] = [
            (ROLE, False, True, False, False, False, False, False, None, False, [])
        ]

    @contextmanager
    def cursor(self) -> Iterator[_Cursor]:
        yield _Cursor(self)


def _session(*, read_write: bool = True, version: str = "16.15") -> Any:
    target = ExpandedTarget(
        target=Target(name="pg-dev", type="postgresql", dsn="pg-dev.example.com:5432")
    )
    built = session_module.PostgresSession(connection=_Connection(), target=target)
    built._scope = Scope(
        type="cluster",
        open_mode="READ WRITE" if read_write else "READ ONLY",
        read_write=read_write,
        db_version=version,
    )
    return built


def _refused_before_sending(session: Any, secret: Secret) -> Any:
    with pytest.raises(DriverError) as refused:
        session.set_password(ROLE, secret)
    assert session.connection.sent == []
    assert refused.value.password_sent is False
    return refused.value


def _text(statement: Any) -> str:
    return repr(statement)


# ------------------------------------------------------------- what is sent ---


def test_the_statement_carries_the_verifier_and_never_the_password() -> None:
    session = _session()

    result = session.set_password(ROLE, Secret(PASSWORD))

    assert result.changed is True
    (statement,) = session.connection.sent
    text = _text(statement)
    assert VERIFIER in text
    assert PASSWORD not in text
    assert "ALTER ROLE" in text


def test_libpq_is_asked_for_scram_whatever_the_server_s_setting() -> None:
    session = _session()

    session.set_password(ROLE, Secret(PASSWORD))

    ((passwd, user, algorithm),) = session.connection.pgconn.asked
    assert algorithm == b"scram-sha-256"
    assert user == ROLE.encode()
    assert passwd == PASSWORD.encode()


def test_the_role_is_named_as_pg_roles_spells_it() -> None:
    session = _session()
    session.connection.role_rows = [
        ("Acme_Web_User", False, True, False, False, False, False, False, None, False, [])
    ]

    session.set_password(ROLE, Secret(PASSWORD))

    assert "Acme_Web_User" in _text(session.connection.sent[0])


def test_a_non_ascii_password_is_sent_to_libpq_as_utf8() -> None:
    session = _session()

    session.set_password(ROLE, Secret("Pässwörd-Ünïcode-1"))

    assert session.connection.pgconn.asked[0][0] == "Pässwörd-Ünïcode-1".encode()


# ------------------------------------------------- refused before sending ---


def test_a_read_only_cluster_is_refused_before_anything_is_sent() -> None:
    session = _session(read_write=False)

    with pytest.raises(DriverError) as refused:
        session.set_password(ROLE, Secret(PASSWORD))

    assert session.connection.sent == []
    assert session.connection.pgconn.asked == []
    assert refused.value.password_sent is False


def test_a_missing_role_is_refused_before_anything_is_sent() -> None:
    session = _session()
    session.connection.role_rows = []

    with pytest.raises(DriverError) as refused:
        session.set_password(ROLE, Secret(PASSWORD))

    assert "does not exist" in refused.value.message
    assert session.connection.sent == []
    assert refused.value.password_sent is False


def test_a_password_over_1024_bytes_is_refused_before_libpq_sees_it() -> None:
    """libpq 13 cannot log in with it (#1057), so the ceiling is the tool's.
    Counted in UTF-8 bytes: 342 three-byte characters are 1026 bytes."""
    session = _session()

    with pytest.raises(DriverError) as refused:
        session.set_password(ROLE, Secret("€" * 342))

    assert "1026 bytes" in refused.value.message
    assert "at most 1024" in refused.value.message
    assert session.connection.pgconn.asked == []
    assert session.connection.sent == []
    assert refused.value.password_sent is False


def test_exactly_1024_bytes_is_accepted() -> None:
    session = _session()

    session.set_password(ROLE, Secret("a" * 1024))

    assert len(session.connection.sent) == 1


def test_a_refused_statement_has_password_sent_set() -> None:
    """What crossed is a verifier, which still allows offline guessing, so the
    unencrypted-connection warnings apply to it."""
    session = _session()
    session.connection.refuse = DriverError("permission denied to alter role")

    with pytest.raises(DriverError) as refused:
        session.set_password(ROLE, Secret(PASSWORD))

    assert refused.value.password_sent is True


# --------------------------------------------------------------- the guards ---


def test_a_non_scram_answer_from_libpq_is_never_sent_and_never_quoted() -> None:
    session = _session()
    answer = "md5abcdef0123456789abcdef0123456789"
    session.connection.pgconn = _PGconn(answer=answer)

    refused = _refused_before_sending(session, Secret(PASSWORD))

    assert isinstance(refused, password.VerifierError)
    assert answer[:8] not in str(refused)


def test_a_libpq_failure_is_a_mapped_error_and_nothing_is_sent() -> None:
    import psycopg

    session = _session()
    session.connection.pgconn = _PGconn(fails=psycopg.OperationalError("out of memory"))

    refused = _refused_before_sending(session, Secret(PASSWORD))

    assert isinstance(refused, password.VerifierError)
    assert "could not compute a SCRAM verifier" in refused.message
    assert refused.hint


@pytest.mark.parametrize(
    ("value", "says"),
    [
        ("", "empty"),
        ("Before\x00After-1", "control characters"),
        ("Tab\there-1", "control characters"),
        ("Lone\ud800surrogate", "cannot be encoded"),
    ],
)
def test_a_password_libpq_would_mangle_is_refused_before_libpq_sees_it(
    value: str, says: str
) -> None:
    """A NUL would end libpq's C string early: the role would get the prefix's
    verifier, and the vault would keep the whole value."""
    session = _session()

    refused = _refused_before_sending(session, Secret(value))

    assert isinstance(refused, password.PasswordNotAdmissibleError)
    assert says in refused.message
    assert refused.category == "policy"
    assert session.connection.pgconn.asked == []


@pytest.mark.parametrize("version", ["9.6.24", "garbled"])
def test_a_server_that_cannot_store_a_verifier_is_refused_before_anything_is_sent(
    version: str,
) -> None:
    """Before 10 the server reads `SCRAM-SHA-256$…` as a plaintext password. A
    version that cannot be read refuses rather than guesses."""
    session = _session(version=version)

    refused = _refused_before_sending(session, Secret(PASSWORD))

    assert "cannot store a SCRAM verifier" in refused.message
    assert session.connection.pgconn.asked == []


def test_the_statement_builder_refuses_anything_but_a_verifier() -> None:
    with pytest.raises(ValueError, match="not a SCRAM-SHA-256 verifier"):
        password.alter_role(ROLE, PASSWORD)


def test_the_byte_limit_is_1024_bytes_of_utf8() -> None:
    limit = _session().byte_limit()

    assert limit.max_bytes == 1024
    assert limit.encoding == "utf-8"
