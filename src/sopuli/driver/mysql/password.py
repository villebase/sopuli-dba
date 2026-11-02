"""Changing a MySQL account's password without sending the password. Tier 0.

Invariant 15, carried over to MySQL (#1223, decided on #1202): the driver
computes the ``caching_sha2_password`` hash on the client and sends
``ALTER USER 'user'@'host' IDENTIFIED WITH caching_sha2_password AS 0x<hash>``.
The password never reaches the server. MySQL writes a password it parsed as
``<secret>`` in its logs, but a statement that fails to parse stays in
``performance_schema``'s statement history as it was sent, password included
(``01_password_text_probe.sql``). The hash goes as a hex literal, which
always parses, so that cannot happen here, and what the server could keep is a
hash: still worth an offline guessing attack, which the policy's length
protects against, and never a password.

**The hash is SHA-crypt with SHA-256** (``$A$`` + the rounds in thousands, as
three hex digits, + ``$`` + a 20-byte salt + the 43-character digest),
computed here in Python: no client library computes it. Probe 02 computed it
the same way, and the server's own hash agreed for each password it tried, up
to 100 bytes and with a character that is not ASCII (``02_client_hash_probe.py``,
CH1). An account with only ``CREATE USER`` sets it, and the password logs in
(CH2).

**The rounds are the server's**, from ``caching_sha2_password_digest_rounds``,
which any account reads: 5,000 on 8.0.46 and 8.4.13, and 10,000 on 9.7.4
(CH5). The server accepts either count, so this is to store what the server
would itself have stored.

**A password is at most 256 bytes.** Longer ones are accepted as a hash and then
refused at login, ``1045``, on every release measured (CH6).

The account is named as ``mysql.user`` spells it, each part a string literal:
``ALTER USER`` takes no bind parameters.
"""

from __future__ import annotations

import hashlib
import secrets as random

from sopuli.config import charsets
from sopuli.driver.protocol import DriverError
from sopuli.secrets import Secret

#: The plugin the hash is for (#1202, decision 5).
PLUGIN = "caching_sha2_password"

#: The rounds variable, which any account reads (CH5).
DIGEST_ROUNDS = "select @@global.caching_sha2_password_digest_rounds"

#: The longest password that logs in, in bytes of UTF-8 (CH6).
MAX_PASSWORD_BYTES = 256

#: crypt's base 64, which is also the salt's alphabet.
B64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
SALT_LENGTH = 20

#: SHA-crypt's order for writing the 32 digest bytes out as base 64.
_ORDER = (
    (0, 10, 20), (21, 1, 11), (12, 22, 2), (3, 13, 23), (24, 4, 14),
    (15, 25, 5), (6, 16, 26), (27, 7, 17), (18, 28, 8), (9, 19, 29),
)  # fmt: skip


class PasswordNotAdmissibleError(DriverError):
    """The password cannot be set on this target. ``policy``, as on the other
    drivers. The message names a class of problem and never a character of the
    password."""

    category = "policy"


def admit(secret: Secret) -> None:
    """Refuse a password the target cannot take, before anything is computed.

    An empty password, control characters (as on Oracle and PostgreSQL), text
    that cannot be encoded as UTF-8, and more than :data:`MAX_PASSWORD_BYTES`.
    """
    text = secret.reveal()
    if not text:
        raise PasswordNotAdmissibleError("the password is empty")
    if any(charsets.is_control(character) for character in text):
        raise PasswordNotAdmissibleError("the password contains control characters")
    try:
        width = len(text.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise PasswordNotAdmissibleError("the password cannot be encoded as UTF-8") from error
    if width > MAX_PASSWORD_BYTES:
        raise PasswordNotAdmissibleError(
            f"the password is {width} bytes, and a MySQL target takes at most {MAX_PASSWORD_BYTES}",
            hint=(
                "the server stores a longer one and then refuses it at login; lower the "
                "policy's `length`, or use a charset of one-byte characters"
            ),
        )


def _b64(b2: int, b1: int, b0: int, n: int) -> str:
    word = (b2 << 16) | (b1 << 8) | b0
    out = []
    for _ in range(n):
        out.append(B64[word & 0x3F])
        word >>= 6
    return "".join(out)


def sha256_crypt(password: bytes, salt: bytes, rounds: int) -> str:
    """SHA-crypt's digest, without glibc's 16-byte limit on the salt."""
    a = hashlib.sha256(password + salt)
    b = hashlib.sha256(password + salt + password).digest()
    n = len(password)
    while n > 32:
        a.update(b)
        n -= 32
    a.update(b[:n])
    n = len(password)
    while n:
        a.update(b if n & 1 else password)
        n >>= 1
    digest = a.digest()
    dp = hashlib.sha256(password * len(password)).digest()
    p = (dp * (len(password) // 32 + 1))[: len(password)]
    ds = hashlib.sha256(salt * (16 + digest[0])).digest()
    s = (ds * (len(salt) // 32 + 1))[: len(salt)]
    c = digest
    for i in range(rounds):
        h = hashlib.sha256()
        h.update(p if i & 1 else c)
        if i % 3:
            h.update(s)
        if i % 7:
            h.update(p)
        h.update(c if i & 1 else p)
        c = h.digest()
    return "".join(_b64(c[x], c[y], c[z], 4) for x, y, z in _ORDER) + _b64(0, c[31], c[30], 3)


def draw_salt() -> bytes:
    """20 characters of crypt's base 64, from the system's random source."""
    return "".join(random.choice(B64) for _ in range(SALT_LENGTH)).encode("ascii")


def caching_sha2_hash(secret: Secret, rounds: int, *, salt: bytes | None = None) -> bytes:
    """The value MySQL stores for ``secret``, with ``rounds`` and a new salt.

    ``rounds`` must be a multiple of 1,000, as the server's are: the stored
    form writes it in thousands.
    """
    if rounds <= 0 or rounds % 1000:
        raise ValueError(f"caching_sha2_password rounds must be a multiple of 1000: {rounds}")
    salt = salt or draw_salt()
    digest = sha256_crypt(secret.reveal().encode("utf-8"), salt, rounds)
    return b"$A$%03X$" % (rounds // 1000) + salt + digest.encode("ascii")


def quote(text: str) -> str:
    """``text`` as a MySQL string literal."""
    return "'" + text.replace("\\", "\\\\").replace("'", "''") + "'"


def alter_user(user: str, host: str, stored: bytes) -> str:
    """The one statement that sets the password: the account as the server
    spells it, and the hash as a hex literal."""
    return f"ALTER USER {quote(user)}@{quote(host)} IDENTIFIED WITH {PLUGIN} AS 0x{stored.hex()}"
