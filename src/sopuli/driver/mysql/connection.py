"""The arguments a MySQL connection is made with. Tier 0.

They are keyword arguments to ``pymysql.connect``, never a connection URI that
the config or a log line holds. The password is never in ``argv`` (invariant
1), and never in any other argument here.

**TLS is a context this module builds, not PyMySQL's TLS options.** Read from
PyMySQL 1.2.3's source (``Connection._create_ssl_ctx``):

- PyMySQL checks the host name only when a CA file is given, so its own
  options cannot express `VERIFY_IDENTITY` against the system's CAs.
- Given an ``ssl.SSLContext``, PyMySQL uses it as it is, and refuses a server
  that offers no TLS (``CR_SSL_CONNECTION_ERROR``, 2026) rather than carrying
  on in clear.
- Given no TLS option at all, it negotiates TLS where the server offers it and
  carries on in clear where it does not, without checking the certificate.
  That is MySQL's `PREFERRED`, so that mode passes nothing.

Whether a session is encrypted is still read from the session itself, after
the handshake (#1221, PR 3), so none of this is trusted alone.
"""

from __future__ import annotations

import ssl
from typing import Any

from sopuli.config.errors import ConfigError
from sopuli.config.model import ExpandedTarget
from sopuli.driver.address import host_and_port
from sopuli.driver.protocol import Credential, Timeouts


def program_name(correlation_id: str) -> str:
    """What ``performance_schema.session_connect_attrs`` shows for this run's
    sessions, as ``application_name`` does on PostgreSQL. The correlation id is
    the join between the tool's output, the server and the vault."""
    return f"sopuli {correlation_id}"


def tls_context(ssl_mode: str, ssl_ca: str | None) -> ssl.SSLContext | None:
    """The TLS context for a mode, or ``None`` where PyMySQL is to decide.

    ``DISABLED`` and ``PREFERRED`` return ``None``; :func:`connect_arguments`
    tells PyMySQL which of the two it is. The other modes require TLS:

    - ``REQUIRED`` encrypts and checks nothing about the server, as MySQL's own
      client does under that mode;
    - ``VERIFY_CA`` checks the certificate against ``ssl_ca``, or the system's
      CAs where none is named, and not the host name;
    - ``VERIFY_IDENTITY`` checks both.

    ``VERIFY_X509_STRICT`` is cleared, as PyMySQL clears it in its own context,
    because the certificates a MySQL server generates for itself fail it.
    """
    if ssl_mode in ("DISABLED", "PREFERRED"):
        return None
    context = ssl.create_default_context(cafile=ssl_ca)
    context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    if ssl_mode == "REQUIRED":
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    elif ssl_mode == "VERIFY_CA":
        context.check_hostname = False
        context.verify_mode = ssl.CERT_REQUIRED
    elif ssl_mode != "VERIFY_IDENTITY":
        raise ValueError(f"not a MySQL ssl_mode: {ssl_mode!r}")
    return context


def connect_arguments(
    target: ExpandedTarget,
    credential: Credential,
    *,
    correlation_id: str,
    timeouts: Timeouts,
) -> dict[str, Any]:
    """The keyword arguments for one connection to ``target`` as ``credential``.

    The settings are :attr:`~sopuli.config.model.Target.mysql_settings`: the
    ``mysql:`` block, or its defaults where the file wrote none.

    A query budget of 0 sets no read or write timeout on the socket, for the
    reason :data:`~sopuli.settings.registry.NO_QUERY_TIMEOUT` gives. MySQL's
    ``max_execution_time`` would not do instead: it bounds a ``SELECT`` only,
    and the statements that matter here are ``ALTER USER``.

    A credential with no username or no password is refused. Without one,
    PyMySQL would log in as the operating-system user, or with an empty
    password, and the run would log in as someone the config does not name.
    PyMySQL reads no option file unless asked to, so nothing else fills a gap.
    """
    if credential.username is None:
        raise ConfigError(
            f"target {target.name!r} has no username to connect as",
            hint="write `admin: { username: … }`, or set $SOPULI_DB_ADMIN_USER",
        )
    if credential.secret is None:
        raise ConfigError(f"target {target.name!r} resolved no password")
    block = target.target.mysql_settings
    host, port = host_and_port(target.target.dsn)
    arguments: dict[str, Any] = {
        "host": host,
        "port": port,
        "user": credential.username,
        "connect_timeout": timeouts.connect_s,
        "program_name": program_name(correlation_id),
        # Every statement stands alone. `ALTER USER` commits on its own anyway,
        # and a read must not hold a transaction open over a later change.
        "autocommit": True,
    }
    if block.ssl_mode == "DISABLED":
        arguments["ssl_disabled"] = True
    context = tls_context(block.ssl_mode, block.ssl_ca)
    if context is not None:
        arguments["ssl"] = context
    if timeouts.query_s:
        arguments["read_timeout"] = timeouts.query_s
        arguments["write_timeout"] = timeouts.query_s
    arguments["password"] = credential.secret.reveal()
    return arguments
