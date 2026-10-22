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


def plain_http_scheme(address: str) -> str | None:
    """The scheme ``address`` would be refused for, or ``None`` if it is allowed.

    ``https`` is allowed anywhere, and ``http`` only to a loopback host. Any
    other scheme, or none, is refused too: it is not TLS. The return value is the
    scheme alone, for a message that must not quote the address, because a
    webhook URL is a credential.
    """
    if "://" not in address:
        # `urlsplit` would read `vault.example.com:8200` as the scheme
        # `vault.example.com`, and a message quoting that is no help.
        return "no scheme"
    parts = urlsplit(address.strip())
    scheme = parts.scheme.lower()
    if scheme == "https":
        return None
    if scheme == "http":
        try:
            host = parts.hostname
        except ValueError:
            host = None
        if host in LOOPBACK_HOSTS:
            return None
    return scheme or "no scheme"
