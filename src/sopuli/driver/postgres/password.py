"""Changing a PostgreSQL role's password without sending the password. Tier 0.

Invariant 15: the driver computes a SCRAM-SHA-256 verifier on the client and
sends ``ALTER ROLE … PASSWORD 'SCRAM-SHA-256$…'``. The password never reaches the
server. PostgreSQL keeps the text of that statement in its log,
``pg_stat_statements`` and ``pg_stat_activity``, even for a statement that fails
(``02-postgres-privileges.md`` §6), so what it keeps is a verifier: still worth an
offline guessing attack, which the policy's length protects against, and never a
password.

**libpq computes the verifier** (``PQencryptPasswordConn``, through psycopg's
``pgconn.encrypt_password``). It applies SASLprep, the normalisation the server
applies to a password at login, so the verifier is the one the server would
compute (``pg-saslprep`` in ``docs/README.md``). A verifier computed here in
Python would be a second implementation of that rule.

**The longest password is 1024 bytes, in UTF-8.** libpq 13 cannot log in with a
longer one (``pg-password-length``, #1057), and an application may still use it.
The server would accept any length behind a verifier, so the ceiling is the
tool's, decided on #1060.

The role's name is quoted as ``pg_roles`` spells it, and the verifier is a
literal: ``ALTER ROLE`` is a utility statement and takes no bind parameters.
"""

from __future__ import annotations

from typing import Any, Protocol

from psycopg import sql

from sopuli.passwords import ByteLimit
from sopuli.secrets import Secret

#: The longest password on a PostgreSQL target, decided on #1060.
MAX_PASSWORD_BYTES = 1024

#: The limit as the generator and `policy sample --max-bytes` read it. PostgreSQL
#: compares passwords as UTF-8 whatever the database's encoding: SCRAM hashes
#: the bytes the client sends, and libpq sends UTF-8.
LIMIT = ByteLimit(max_bytes=MAX_PASSWORD_BYTES, encoding="utf-8", charset="UTF8")

#: The algorithm libpq is asked for, named, so the server's
#: ``password_encryption`` setting cannot turn it into ``md5``.
ALGORITHM = b"scram-sha-256"

#: What every verifier starts with.
PREFIX = "SCRAM-SHA-256$"


class PasswordConnection(Protocol):
    """The part of psycopg's ``PGconn`` this module uses."""

    def encrypt_password(
        self, passwd: bytes, user: bytes, algorithm: bytes | None = None
    ) -> bytes: ...


def byte_width(secret: Secret) -> int:
    """How many bytes ``secret`` is in UTF-8, the width :data:`LIMIT` counts."""
    return LIMIT.width(secret.reveal())


def verifier(pgconn: PasswordConnection, role: str, secret: Secret) -> str:
    """The SCRAM-SHA-256 verifier for ``secret``, computed by libpq on this
    machine. ``role`` is the salt's only other input in old algorithms and is
    ignored by SCRAM, but libpq asks for it."""
    computed = pgconn.encrypt_password(
        secret.reveal().encode("utf-8"), role.encode("utf-8"), ALGORITHM
    ).decode("ascii")
    if not computed.startswith(PREFIX):
        raise ValueError(f"libpq returned a verifier that is not SCRAM-SHA-256: {computed[:16]}")
    return computed


def alter_role(role: str, computed: str) -> sql.Composed:
    """``ALTER ROLE "<role>" PASSWORD '<verifier>'``. ``computed`` must come from
    :func:`verifier`; anything else is refused, so a password cannot reach this
    statement by mistake."""
    if not computed.startswith(PREFIX):
        raise ValueError("refusing to send a password that is not a SCRAM-SHA-256 verifier")
    return sql.SQL("ALTER ROLE {} PASSWORD {}").format(sql.Identifier(role), sql.Literal(computed))


def as_text(statement: sql.Composed, context: Any) -> str:
    """The statement as the server would receive it, for tests and the debug log.
    It holds a verifier, never a password."""
    return statement.as_string(context)
