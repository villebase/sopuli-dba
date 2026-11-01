"""The arguments a PostgreSQL connection is made with. Tier 0.

They are keyword arguments to ``psycopg.connect``, never a connection URI that
the config or a log line holds. psycopg joins them into a conninfo string inside
the process to hand to libpq, as python-oracledb does with its own arguments.
The password is never in ``argv`` (invariant 1), and never in any other argument
here.
"""

from __future__ import annotations

from typing import Any

from sopuli.config.model import ExpandedTarget
from sopuli.driver.address import host_and_port
from sopuli.driver.login import require_login, session_label
from sopuli.driver.protocol import Credential, Timeouts


def application_name(correlation_id: str) -> str:
    """What ``pg_stat_activity`` and the server log show for this run's
    sessions: :func:`~sopuli.driver.login.session_label`."""
    return session_label(correlation_id)


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

    A query budget of 0 sends no ``statement_timeout``, so the server's setting
    applies, or ``PGOPTIONS`` where the shell sets it. The tool imposes none by
    default, for the reason :data:`~sopuli.settings.registry.NO_QUERY_TIMEOUT`
    gives. libpq reads its environment for any parameter left out here; the
    host, the port, the role, the password, ``sslmode`` and ``gssencmode`` are
    always sent.

    ``gssencmode`` is ``disable``. libpq's default, ``prefer``, uses GSSAPI
    encryption wherever a Kerberos ticket is at hand. That skips TLS, so the
    certificate check that ``sslmode`` asks for never runs, and the scope reads
    TLS only.

    A credential with no username or no password is refused
    (:func:`~sopuli.driver.login.require_login`).
    """
    username, password = require_login(target, credential)
    block = target.target.postgres_settings
    host, port = host_and_port(target.target.dsn)
    arguments: dict[str, Any] = {
        "host": host,
        "port": port,
        "dbname": block.database,
        "user": username,
        "sslmode": block.sslmode,
        "gssencmode": "disable",
        "application_name": application_name(correlation_id),
        "connect_timeout": timeouts.connect_s,
    }
    if block.sslrootcert is not None:
        arguments["sslrootcert"] = block.sslrootcert
    if timeouts.query_s:
        arguments["options"] = f"-c statement_timeout={timeouts.call_timeout_ms}"
    arguments["password"] = password.reveal()
    return arguments
