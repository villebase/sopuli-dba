"""The arguments a MySQL connection is made with. Tier 0.

They are keyword arguments to ``pymysql.connect``, never a connection URI that
the config or a log line holds. The password is never in ``argv`` (invariant
1), and never in any other argument here.

**TLS is a context this module builds, not PyMySQL's TLS options.** Read from
PyMySQL 1.2.3's source (``Connection.__init__`` and ``_create_ssl_ctx``):

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
from sopuli.driver.login import require_login, session_label
from sopuli.driver.protocol import Credential, Timeouts

#: The `ssl_mode` values that require TLS: :func:`tls_arguments` gives each a
#: context, and the session refuses one that is not TLS.
TLS_REQUIRED_MODES = ("REQUIRED", "VERIFY_CA", "VERIFY_IDENTITY")


def tls_arguments(target: ExpandedTarget) -> dict[str, Any]:
    """PyMySQL's TLS arguments for the target's ``ssl_mode``, all five modes
    in one place:

    - ``DISABLED`` turns TLS off;
    - ``PREFERRED`` passes nothing, which is PyMySQL's own negotiation;
    - ``REQUIRED`` encrypts and checks nothing about the server, as MySQL's own
      client does under that mode;
    - ``VERIFY_CA`` checks the certificate against ``ssl_ca``, or the system's
      CAs where none is named, and not the host name;
    - ``VERIFY_IDENTITY`` checks both.

    The last three pass a context, so PyMySQL refuses a server with no TLS.
    ``VERIFY_X509_STRICT`` is cleared, as PyMySQL clears it in its own context,
    because the certificates a MySQL server generates for itself fail it.

    A CA file that cannot be read, or holds no certificate, is refused here,
    naming the target and the key, before any socket opens. The run would
    otherwise end in a traceback with neither.

    A new context per connection. Building one reads the trust store, which
    costs far less than the connection it is for, and a context shared across
    connections would be shared mutable state.
    """
    block = target.target.mysql_settings
    if block.ssl_mode == "DISABLED":
        return {"ssl_disabled": True}
    if block.ssl_mode == "PREFERRED":
        return {}
    if block.ssl_mode not in TLS_REQUIRED_MODES:
        raise ValueError(f"not a MySQL ssl_mode: {block.ssl_mode!r}")
    try:
        context = ssl.create_default_context(cafile=block.ssl_ca)
    except OSError as error:
        # `ssl.SSLError` is an `OSError` too: a file that is not PEM.
        raise ConfigError(
            f"target {target.name!r}: `mysql.ssl_ca` could not be loaded: {error}",
            hint=(
                "point `mysql.ssl_ca` at the PEM file of the CA that issued the server certificate"
            ),
        ) from error
    context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    if block.ssl_mode == "REQUIRED":
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    elif block.ssl_mode == "VERIFY_CA":
        context.check_hostname = False
        context.verify_mode = ssl.CERT_REQUIRED
    elif block.ssl_mode != "VERIFY_IDENTITY":
        raise ValueError(f"not a MySQL ssl_mode: {block.ssl_mode!r}")
    return {"ssl": context}


def connect_arguments(
    target: ExpandedTarget,
    credential: Credential,
    *,
    correlation_id: str,
    timeouts: Timeouts,
) -> dict[str, Any]:
    """The keyword arguments for one connection to ``target`` as ``credential``.

    The settings are :attr:`~sopuli.config.model.Target.mysql_settings`: the
    ``mysql:`` block, or its defaults where the file wrote none. PyMySQL reads
    no option file unless asked to, so nothing on the machine fills a gap.

    **A query budget is a socket timeout, and a timed-out call's outcome is
    unknown.** MySQL has nothing like PostgreSQL's ``statement_timeout`` for
    ``ALTER USER``: ``max_execution_time`` bounds a ``SELECT`` only. So the
    budget becomes PyMySQL's read and write timeouts, which drop the connection
    and leave the statement running on the server. A call that times out may
    have changed the password, which is what
    :class:`~sopuli.driver.protocol.Timeouts` says of every call; the session
    reports such a change as unknown, never as not applied. A budget of 0 sets
    no timeout, for the reason
    :data:`~sopuli.settings.registry.NO_QUERY_TIMEOUT` gives.

    A credential with no username or no password is refused
    (:func:`~sopuli.driver.login.require_login`).
    """
    username, password = require_login(target, credential)
    host, port = host_and_port(target.target.dsn)
    arguments: dict[str, Any] = {
        "host": host,
        "port": port,
        "user": username,
        "connect_timeout": timeouts.connect_s,
        "program_name": session_label(correlation_id),
        # Every statement stands alone. `ALTER USER` commits on its own anyway,
        # and a read must not hold a transaction open over a later change.
        "autocommit": True,
        **tls_arguments(target),
    }
    if timeouts.query_s:
        arguments["read_timeout"] = timeouts.query_s
        arguments["write_timeout"] = timeouts.query_s
    arguments["password"] = password.reveal()
    return arguments
