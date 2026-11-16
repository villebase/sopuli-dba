"""The value a SQL Server password change sends instead of the password. Tier 0.

Decided on #1551 (``02-mssql-privileges.md`` §6.2): the driver computes the
value the server stores and sends it with ``ALTER LOGIN … WITH PASSWORD =
0x… HASHED``. The password never reaches the server. A statement that sends
the password in clear and then fails to parse is kept with the password in
Extended Events and in a server audit (``01_password_text_probe.py``, PT3). A
statement with a value keeps no password (PT5).

**A value is 70 bytes**: a 2-byte version, a 4-byte salt, and a 64-byte digest
of the password in UTF-16LE followed by the salt.

- ``0x0200``: SHA-512 of the password and the salt. Every supported release
  takes it.
- ``0x0300``: PBKDF2-HMAC-SHA512 of the password and the salt, 100,000
  rounds. 2022 and 2025 take it, and 2019 refuses it, ``15021``.

This module computes both as probe 02 computed them, and the server's own
value agreed for each password the probe tried, one that is not ASCII
included (``02_client_hash_probe.py``, CH1). Which version a target takes is
the session's to read; this module takes it as an argument.

**The server takes a wrong value.** It checks a value's length and version,
not that a password matches it (CH3). The login after the change is what
catches a fault here, not the server.

**A password is at most 128 UTF-16 code units** (:mod:`.limits`). The server
takes a value for a longer one (CH6), so :func:`password_value` admits the
password before it computes anything.

The statement that carries the value is built elsewhere: this module renders
the value as the hex literal it goes in.
"""

from __future__ import annotations

import hashlib

# `csprng`, not `random`: the salt must come from the system's random source,
# and a name that reads like the `random` module invites the wrong swap.
import secrets as csprng

from sopuli.config import charsets
from sopuli.driver.mssql.limits import LIMIT, MAX_PASSWORD_CHARACTERS
from sopuli.driver.protocol import DriverError
from sopuli.secrets import Secret

#: SHA-512 of the password and the salt.
SHA512 = 0x0200
#: PBKDF2-HMAC-SHA512 of the password and the salt, PBKDF2_ROUNDS rounds.
PBKDF2_SHA512 = 0x0300
VERSIONS = (SHA512, PBKDF2_SHA512)
PBKDF2_ROUNDS = 100_000

SALT_LENGTH = 4
DIGEST_LENGTH = 64
VALUE_LENGTH = 2 + SALT_LENGTH + DIGEST_LENGTH


class PasswordNotAdmissibleError(DriverError):
    """The password cannot be set on this target. ``policy``, as on the other
    drivers. The message names a class of problem and never a character of the
    password."""

    category = "policy"


def admit(secret: Secret) -> None:
    """Refuse a password the target cannot take, before anything is computed:
    an empty one, control characters (as on the other drivers), text that
    cannot be encoded as UTF-16, and more than
    :data:`MAX_PASSWORD_CHARACTERS`."""
    text = secret.reveal()
    if not text:
        raise PasswordNotAdmissibleError("the password is empty")
    if any(charsets.is_control(character) for character in text):
        raise PasswordNotAdmissibleError("the password contains control characters")
    # Checked without catching the codec's error: that error holds the whole
    # password, and would stay on the next exception's context.
    if not LIMIT.encodable(text):
        raise PasswordNotAdmissibleError("the password cannot be encoded as UTF-16")
    units = LIMIT.width(text) // 2
    if units > MAX_PASSWORD_CHARACTERS:
        raise PasswordNotAdmissibleError(
            f"the password is {units} UTF-16 code units, and a SQL Server target takes at "
            f"most {MAX_PASSWORD_CHARACTERS}",
            hint=(
                "the server refuses a longer one; lower the policy's `length`. A character "
                "outside the Basic Multilingual Plane is two code units"
            ),
        )


def draw_salt() -> bytes:
    """4 bytes from the system's random source."""
    return csprng.token_bytes(SALT_LENGTH)


def password_value(secret: Secret, version: int, *, salt: bytes | None = None) -> bytes:
    """The value SQL Server stores for ``secret``, in ``version``, with a new salt.

    ``salt`` is for tests, which compare a value with the server's own. The
    password is admitted first: the server stores a value for any password,
    one it would refuse in clear included (CH3, CH6).
    """
    if version not in VERSIONS:
        raise ValueError(f"not a password value version this driver computes: 0x{version:04x}")
    admit(secret)
    if salt is None:
        salt = draw_salt()
    elif len(salt) != SALT_LENGTH:
        raise ValueError(f"a salt is {SALT_LENGTH} bytes")
    encoded = secret.reveal().encode("utf-16-le")
    if version == PBKDF2_SHA512:
        digest = hashlib.pbkdf2_hmac("sha512", encoded, salt, PBKDF2_ROUNDS)
    else:
        digest = hashlib.sha512(encoded + salt).digest()
    return version.to_bytes(2, "big") + salt + digest


def hex_literal(value: bytes) -> str:
    """``value`` as the literal ``ALTER LOGIN … WITH PASSWORD = … HASHED`` takes.

    Refuses anything but a value of a version this driver computes: the server
    would take a wrong one (CH3).
    """
    if len(value) != VALUE_LENGTH or int.from_bytes(value[:2], "big") not in VERSIONS:
        raise ValueError(f"not a {VALUE_LENGTH}-byte password value of a known version")
    return "0x" + value.hex().upper()
