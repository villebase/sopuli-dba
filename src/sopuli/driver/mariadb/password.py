"""The values MariaDB stores for a password, computed on the client. Tier 0.

Invariant 15 on MariaDB (#1267, decided on #1220): MariaDB keeps the password
of ``IDENTIFIED BY '…'`` and ``USING PASSWORD('…')`` in clear in its logs and in
``performance_schema``, also when the statement fails
(``sql/mariadb/01_password_text_probe.py``). So the driver computes the value
the server stores and sends ``IDENTIFIED VIA <plugin> USING '<value>'``, which
lands everywhere with the value and no password
(``docs/design/02-mariadb-privileges.md`` §6). The value is never the password,
but it is returned as a :class:`~sopuli.secrets.Secret`: it allows an offline
guess, and a ``mysql_native_password`` value with one captured login handshake
is enough to log in (#1267, decision 4).

Two plugins take a value this module computes. Each is over the password's
UTF-8 bytes, which is what the server hashes for ``PASSWORD('…')`` on a
``utf8mb4`` connection:

- ``mysql_native_password``: ``*`` and the upper-case hex of
  SHA1(SHA1(password)). MySQL's driver does not use it; MariaDB loads this
  plugin by default.
- ``ed25519``: the Ed25519 public key of RFC 8032, derived from SHA-512 of the
  password, in base 64 without the trailing ``=``. The password is not a
  32-byte seed: it is hashed whatever its length, so a library call that takes
  only a seed does not compute it. PyNaCl does the curve arithmetic, as it does
  for PyMySQL's own ``ed25519`` login.

Both agree with the server's own ``PASSWORD()`` value, and an account with only
``CREATE USER`` sets each (``02_client_hash_probe.py``, CH1 and CH2).

**No length limit.** The server never sees the password, only the value, so it
has nothing to limit: a password of 1 byte to 1 MiB is set and logs in with
PyMySQL, on each plugin and on every release measured
(``09_password_length_probe.py``, PW1).
"""

from __future__ import annotations

import base64
import hashlib

# PyNaCl comes with the `mariadb` extra, for PyMySQL's own ed25519 login and for
# this value (#1267, decision 5). The registry lists `nacl` in the driver's
# `provides`, so an install without it is refused before this module loads.
from nacl.bindings import crypto_scalarmult_ed25519_base_noclamp

# Re-exported: the driver's callers and tests catch it from here.
from sopuli.driver.mysql_family.password import (
    PasswordNotAdmissibleError as PasswordNotAdmissibleError,
)
from sopuli.driver.mysql_family.password import refuse_unusable
from sopuli.secrets import Secret

#: The plugins this module computes a value for, by the server's name.
NATIVE = "mysql_native_password"
ED25519 = "ed25519"


def admit(secret: Secret) -> None:
    """Refuse a password the target cannot take, before anything is computed.

    What :func:`~sopuli.driver.mysql_family.password.refuse_unusable` refuses.
    There is no length limit (PW1).
    """
    refuse_unusable(secret.reveal())


def _utf8(secret: Secret) -> bytes:
    return secret.reveal().encode("utf-8")


def native_value(secret: Secret) -> Secret:
    """The value ``mysql_native_password`` stores for ``secret``."""
    inner = hashlib.sha1(_utf8(secret)).digest()
    return Secret("*" + hashlib.sha1(inner).hexdigest().upper())


def ed25519_value(secret: Secret) -> Secret:
    """The value ``ed25519`` stores for ``secret``: RFC 8032's public key.

    The scalar is the first half of SHA-512 of the password, clamped as RFC 8032
    §5.1.5 says: the low three bits and the top bit cleared, and bit 254 set.
    """
    scalar = bytearray(hashlib.sha512(_utf8(secret)).digest()[:32])
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    public = crypto_scalarmult_ed25519_base_noclamp(bytes(scalar))
    return Secret(base64.b64encode(public).decode("ascii").rstrip("="))


#: Each plugin's value, by the server's name for the plugin.
VALUES = {NATIVE: native_value, ED25519: ed25519_value}
