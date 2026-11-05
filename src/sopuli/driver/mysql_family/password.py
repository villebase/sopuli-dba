"""The passwords MySQL and MariaDB both refuse. Tier 0.

Each driver's ``admit`` reveals the password and passes its text here, with
its own product's limit: 256 bytes on MySQL, 1024 on MariaDB.
"""

from __future__ import annotations

from sopuli.config import charsets
from sopuli.driver.protocol import DriverError
from sopuli.passwords import ByteLimit


class PasswordNotAdmissibleError(DriverError):
    """The password cannot be set on this target. ``policy``, as on the other
    drivers. The message names a class of problem and never a character of the
    password."""

    category = "policy"


def refuse_unusable(text: str) -> None:
    """Refuse an empty password, control characters (as on Oracle and
    PostgreSQL), and text that cannot be encoded as UTF-8, which both servers
    hash the password in."""
    if not text:
        raise PasswordNotAdmissibleError("the password is empty")
    if any(charsets.is_control(character) for character in text):
        raise PasswordNotAdmissibleError("the password contains control characters")
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        raise PasswordNotAdmissibleError("the password cannot be encoded as UTF-8") from None


def refuse_longer(text: str, limit: ByteLimit, *, product: str, hint: str) -> None:
    """Refuse a password longer than ``limit``, counted as the limit counts it.
    ``product`` names the target in the message, and ``hint`` says why the
    limit is there."""
    width = limit.width(text)
    if width > limit.max_bytes:
        raise PasswordNotAdmissibleError(
            f"the password is {width} bytes, and {product} takes at most {limit.max_bytes}",
            hint=hint,
        )
