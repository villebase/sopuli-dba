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

The longest password, 1024 bytes of UTF-8, is in
:mod:`sopuli.driver.postgres.limits`, which does not import psycopg.

The role's name is quoted as ``pg_roles`` spells it, and the verifier is a
literal: ``ALTER ROLE`` is a utility statement and takes no bind parameters.

**psycopg is imported where it is used**, not at the top (ADR-006 rule 1). The
driver's registered module is :mod:`sopuli.driver.postgres.session`, and only
that module may load the client at import. So this one imports without psycopg
installed, and ``tests/store/test_install_shape.py`` can hold that no module
outside the session loads it (#1168).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from sopuli.config import charsets
from sopuli.driver.postgres.limits import LIMIT
from sopuli.driver.protocol import DriverError
from sopuli.secrets import Secret

if TYPE_CHECKING:
    from psycopg import sql

#: The algorithm libpq is asked for, named, so the server's
#: ``password_encryption`` setting cannot turn it into ``md5``.
ALGORITHM = b"scram-sha-256"

#: What every verifier starts with.
PREFIX = "SCRAM-SHA-256$"

#: The first major release whose server stores a SCRAM verifier it is sent.
#: An older server reads ``SCRAM-SHA-256$…`` as a plaintext password.
SCRAM_FROM = 10

#: The capability a server below :data:`SCRAM_FROM` lacks, as a refusal names it.
SCRAM_VERIFIER = "scram_verifier"


class PasswordConnection(Protocol):
    """The part of psycopg's ``PGconn`` this module uses."""

    def encrypt_password(
        self, passwd: bytes, user: bytes, algorithm: bytes | None = None
    ) -> bytes: ...


class PasswordNotAdmissibleError(DriverError):
    """The password cannot be sent to this target. ``policy``, and the exit
    code inherited, for the reason Oracle's class of the same name gives. The
    message names a class of problem and never a character of the password."""

    category = "policy"


class VerifierError(DriverError):
    """libpq could not compute a SCRAM verifier. Nothing was sent."""


def admit(secret: Secret) -> None:
    """Refuse a password this target cannot take, before libpq sees it.

    libpq takes the password as a C string, so a NUL would cut it short
    without an error, and the vault would hold a password the role does not
    have. Control characters are refused with it, as on Oracle. An empty
    password gets a verifier no login can use. A lone surrogate cannot be
    encoded as UTF-8. And the ceiling is
    :data:`~sopuli.driver.postgres.limits.MAX_PASSWORD_BYTES`. No I/O, so the
    caller asks it before anything else.
    """
    text = secret.reveal()
    if not text:
        raise PasswordNotAdmissibleError("the password is empty")
    if any(charsets.is_control(character) for character in text):
        raise PasswordNotAdmissibleError("the password contains control characters")
    if not LIMIT.encodable(text):
        raise PasswordNotAdmissibleError("the password cannot be encoded as UTF-8")
    width = LIMIT.width(text)
    if width > LIMIT.max_bytes:
        raise PasswordNotAdmissibleError(
            f"the password is {width} bytes, and a PostgreSQL target takes at most "
            f"{LIMIT.max_bytes}",
            hint=(
                "libpq 13 cannot log in with a longer password; lower the policy's "
                "`length`, or use a charset of one-byte characters"
            ),
        )


def verifier(pgconn: PasswordConnection, role: str, secret: Secret) -> str:
    """The SCRAM-SHA-256 verifier for ``secret``, computed by libpq on this
    machine. ``role`` is the salt's only other input in old algorithms and is
    ignored by SCRAM, but libpq asks for it.

    A failure is a :class:`VerifierError`. Its message keeps libpq's own
    error text, as every error keeps the server's (``CLAUDE.md``, *Style*):
    libpq's errors here are about the client, such as ``out of memory``, and
    never echo the password. What libpq returned on success is never quoted,
    because a malformed answer may be part of a verifier.
    """
    import psycopg

    try:
        answer = pgconn.encrypt_password(
            secret.reveal().encode("utf-8"), role.encode("utf-8"), ALGORITHM
        )
    except psycopg.Error as error:
        raise VerifierError(
            f"libpq could not compute a SCRAM verifier: {error}",
            hint="nothing was sent; this is the client library, not the server",
        ) from error
    try:
        computed = answer.decode("ascii")
    except UnicodeDecodeError:
        computed = ""
    if not computed.startswith(PREFIX):
        raise VerifierError(
            "libpq returned something other than a SCRAM-SHA-256 verifier",
            hint="nothing was sent; check which libpq psycopg loaded (`sopuli doctor`)",
        )
    return computed


def alter_role(role: str, computed: str) -> sql.Composed:
    """``ALTER ROLE "<role>" PASSWORD '<verifier>'``. ``computed`` must come from
    :func:`verifier`; anything else is refused, so a password cannot reach this
    statement by mistake."""
    if not computed.startswith(PREFIX):
        raise ValueError("refusing to send a password that is not a SCRAM-SHA-256 verifier")
    from psycopg import sql

    return sql.SQL("ALTER ROLE {} PASSWORD {}").format(sql.Identifier(role), sql.Literal(computed))
