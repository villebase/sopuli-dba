"""Whether an address would send credentials over plain HTTP off the machine.

A vault address carries the token, an AppRole ``secret_id``, a userpass
password, and every password the tool writes. A chat webhook URL carries its own
token. Over ``http://`` all of it crosses the network in clear, so both are
refused unless the host is a loopback address, which never leaves the machine.
The tier-1 stack and a local Vault agent use one.

The host is compared as a whole, so ``localhost.example.com`` is not loopback.
There is no setting to waive the refusal (``01-configuration.md`` §3a).

Pure: no I/O, as the rest of config parsing (CLAUDE.md, *Keep pure layers pure*).
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

__all__ = ["LOOPBACK_HOSTS", "PLAIN_HTTP_HINT", "plain_http_scheme"]

#: The hosts that may be reached over ``http://``. ``urlsplit`` gives the host in
#: lower case and without the brackets of an IPv6 address.
LOOPBACK_HOSTS = ("127.0.0.1", "::1", "localhost")

#: What to do instead, for every message about the refusal.
PLAIN_HTTP_HINT = (
    "use https://. Plain http:// is allowed only to 127.0.0.1, ::1 or localhost, "
    "because anything else sends the credentials across the network in clear"
)

#: A scheme as RFC 3986 spells it, without the `.` it allows, so that a host
#: such as `chat.example.com:443/…` is not taken for one.
_SCHEME = re.compile(r"[a-z][a-z0-9+-]*://")


def plain_http_scheme(address: str) -> str | None:
    """What ``address`` is refused for, or ``None`` if it is allowed.

    ``https://`` is allowed anywhere, and ``http://`` only to a loopback host.
    Anything else is refused: another scheme, an ``http:`` or ``https:`` with no
    ``//``, or no scheme at all. The answer is ``http`` or a fixed phrase, never
    a piece of the address, because a webhook URL is a credential and its first
    characters may be part of the token.
    """
    text = address.strip()
    lowered = text.lower()
    if lowered.startswith("https://"):
        return None
    if lowered.startswith("http://"):
        try:
            host = urlsplit(text).hostname
        except ValueError:
            host = None
        return None if host in LOOPBACK_HOSTS else "http"
    if lowered.startswith(("http:", "https:")):
        return "a scheme with no //"
    return "another scheme" if _SCHEME.match(lowered) else "no scheme"
