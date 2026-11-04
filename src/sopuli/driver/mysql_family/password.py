"""The passwords MySQL and MariaDB both refuse. Tier 0.

Each driver's ``admit`` reveals the password and passes its text here first,
then adds what its own product limits, such as MySQL's 256 bytes.
"""

from __future__ import annotations

from sopuli.config import charsets
from sopuli.driver.protocol import DriverError


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
