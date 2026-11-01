"""A ``host:port`` dsn, split. Tier 0.

PostgreSQL and MySQL targets both name their server this way
(``01-configuration.md`` §3a), and :mod:`sopuli.config.products` has already
refused any other shape, so this only splits.
"""

from __future__ import annotations


def host_and_port(dsn: str) -> tuple[str, int]:
    """Split a ``host:port`` dsn.

    An IPv6 address loses its brackets, because both clients take the bare
    address.
    """
    host, _, port = dsn.rpartition(":")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host, int(port)
