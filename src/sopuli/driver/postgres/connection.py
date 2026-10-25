"""The arguments a PostgreSQL connection is made with. Tier 0.

They are keyword arguments to ``psycopg.connect``, never a connection URI or a
keyword string. The password is one of them, so it is never in a string that a
log line or an error message could repeat, and never in ``argv`` (invariant 1).
"""

from __future__ import annotations

from typing import Any

from sopuli.config.model import ExpandedTarget
from sopuli.driver.protocol import Credential, Timeouts


def host_and_port(dsn: str) -> tuple[str, int]:
    """Split a ``host:port`` dsn. ``01-configuration.md`` §3a has the format,
    and :mod:`sopuli.config.products` has already refused any other.

    An IPv6 address loses its brackets, because libpq takes the bare address.
    """
    host, _, port = dsn.rpartition(":")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host, int(port)


def application_name(correlation_id: str) -> str:
    """What ``pg_stat_activity`` and the server log show for this run's sessions.

    The correlation id is the join between the tool's output, the server's own
    log and the vault, as ``DBMS_SESSION.SET_IDENTIFIER`` is on Oracle. 43
    characters, inside the 63 the server keeps.
    """
    return f"sopuli {correlation_id}"


def connect_arguments(
    target: ExpandedTarget,
    credential: Credential,
    *,
    correlation_id: str,
    timeouts: Timeouts,
) -> dict[str, Any]:
    """The keyword arguments for one connection to ``target`` as ``credential``.

    The settings are :attr:`~sopuli.config.model.Target.postgres_settings`: the
    ``postgres:`` block, or its defaults where the file wrote none.
    ``sslrootcert`` is left out where the file names none, and libpq then looks
    where it always does.

    A query budget of 0 sends no ``statement_timeout``, so the server's own
    setting applies. The tool imposes none by default, for the reason
    :data:`~sopuli.settings.registry.NO_QUERY_TIMEOUT` gives.
    """
    block = target.target.postgres_settings
    host, port = host_and_port(target.target.dsn)
    arguments: dict[str, Any] = {
        "host": host,
        "port": port,
        "dbname": block.database,
        "user": credential.username,
        "sslmode": block.sslmode,
        "application_name": application_name(correlation_id),
        "connect_timeout": timeouts.connect_s,
    }
    if block.sslrootcert is not None:
        arguments["sslrootcert"] = block.sslrootcert
    if timeouts.query_s:
        arguments["options"] = f"-c statement_timeout={timeouts.call_timeout_ms}"
    if credential.secret is not None:
        arguments["password"] = credential.secret.reveal()
    return arguments
