"""Opening a connection, and putting the run's id on it (#176).

The first code in this project that opens a socket to a database, and the module
:data:`sopuli.driver.registry.DRIVERS` imports for ``type: oracle``. It imports
``oracledb`` at module scope on purpose: that is what makes
:func:`sopuli.driver.registry.resolve` able to answer "the driver is not
installed" as a structured error instead of a traceback (ADR-006 rule 1). The
package above it stays clean, so :mod:`.statements` and :mod:`.client` remain
importable -- and testable -- with no client on the machine.

Two decisions the issue asked for, made here and stated rather than implied.

**Thick-mode initialisation happens lazily, on the first connect.**
``init_oracle_client`` is process-global and effectively one-shot, so the choice
is between doing it at startup, where the failure is earliest and the message
best, and doing it when something actually connects. Lazy wins, because ADR-006
rule 3 says a base install opens no sockets and loads no vendor client: an
offline ``config validate`` that initialised Instant Client would be doing work
for a database it will never contact, and would *fail* on a machine where that
command is perfectly valid. The cost is that the error arrives a little later,
and it is a good error -- see :func:`sopuli.driver.oracle.client.missing_client`.

**One connection per target, never a shared session with ``SET CONTAINER``.**
A CDB root and its PDBs are separate services and are connected to separately.
The alternative needs ``ALTER SESSION SET CONTAINER``, which
``02-oracle-privileges.md`` §2 lists as optional and which the document's whole
position is to avoid needing: the grant set stays minimal, and a run that cannot
reach a PDB fails for that PDB rather than poisoning a session shared with
others.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import oracledb

from sopuli.config.model import ExpandedTarget
from sopuli.driver.oracle.client import (
    CLIENT_LIB_DIR_ENV,
    NO_CLIENT,
    Timeouts,
    connect_arguments,
    missing_client,
)
from sopuli.driver.oracle.errors import from_error
from sopuli.driver.protocol import Credential

#: Guards :func:`initialise`. ``init_oracle_client`` mutates process-global
#: state, and nothing in this codebase promises a connection is only ever opened
#: from one thread -- ``tests/lock/test_manager.py`` already runs a manager from
#: two. Cheap insurance against a failure that would be unreproducible.
_INITIALISING = threading.Lock()

#: Whether thick mode is up. python-oracledb tolerates a second
#: ``init_oracle_client`` with identical arguments and raises on a differing
#: one, so this is not merely an optimisation: it is what stops a second call
#: with a different ``lib_dir`` from turning a working process into a broken one.
_initialised = False


def initialise(*, env: Mapping[str, str], platform: str | None = None) -> None:
    """Start thick mode, once per process.

    ``lib_dir`` comes from :data:`~sopuli.driver.oracle.client.CLIENT_LIB_DIR_ENV`
    when it is set, and is otherwise left to the platform's loader -- P4's table
    is the specification for where that looks. An unset variable is not an
    error: the ordinary Linux install puts the client on ``LD_LIBRARY_PATH``
    and never needs one.
    """
    global _initialised
    with _INITIALISING:
        if _initialised:
            return
        lib_dir = env.get(CLIENT_LIB_DIR_ENV) or None
        try:
            oracledb.init_oracle_client(lib_dir=lib_dir)
        except oracledb.Error as error:
            if NO_CLIENT in str(error):
                raise missing_client(str(error), platform=platform) from error
            # Something else went wrong inside the client. Not ours to reword:
            # the driver's own message is the only description of it anybody has.
            raise
        _initialised = True


@dataclass
class OracleSession:
    """One open connection, and the target it belongs to.

    **Not yet a** :class:`sopuli.driver.protocol.Session`, and deliberately so.
    ``describe_user``, ``set_password`` and ``verify_password`` arrive with
    #178, #179 and #180; the protocol is structural, so this simply is not one
    until they do, and ``isinstance`` says so honestly rather than a stub
    claiming otherwise and returning nothing.

    What it has now is what connecting *is*: something open, something that
    knows which target it reached, and something that closes.
    """

    connection: Any
    target: ExpandedTarget
    correlation_id: str

    def close(self) -> None:
        """Let the connection go. Safe twice, because a caller unwinding from
        an error should not have to know whether it already did."""
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    def __enter__(self) -> OracleSession:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def connect(
    target: ExpandedTarget,
    credential: Credential,
    *,
    env: Mapping[str, str],
    correlation_id: str,
    timeouts: Timeouts | None = None,
) -> OracleSession:
    """Reach ``target`` as ``credential``, with the run's id on the session.

    Every failure comes back through :mod:`sopuli.driver.oracle.errors`, so an
    ``ORA-`` code keeps its number, its category and the server's own wording
    (#172) -- CLAUDE.md's rule that a vendor code is mapped and never swallowed.

    **The target is not added to the message here**, and that is #172's design
    rather than an omission: the server's wording is preserved rather than
    rewritten, and the command knows which target it asked for while this layer
    only knows the one it was handed. A caller reporting across an estate has
    the name already.
    """
    initialise(env=env)
    budget = timeouts or Timeouts()
    arguments = connect_arguments(target, credential, timeouts=budget)

    try:
        connection = oracledb.connect(**arguments)
    except oracledb.Error as error:
        raise from_error(error).as_error() from error

    try:
        # Set before anything else happens on this session, so there is no
        # window in which a statement could be audited without the id.
        connection.call_timeout = budget.call_timeout_ms
        set_identifier(connection, correlation_id)
    except oracledb.Error as error:
        # A session we cannot label is a session whose work cannot be traced
        # back to this run, which `02-oracle-privileges.md` §5 makes the
        # compensating control for having no audit table of our own. Closing it
        # is the honest outcome -- carrying on would silently give up the join
        # between the tool's output, the database trail and the vault.
        connection.close()
        raise from_error(error).as_error() from error

    return OracleSession(connection=connection, target=target, correlation_id=correlation_id)


def set_identifier(connection: Any, correlation_id: str) -> None:
    """``DBMS_SESSION.SET_IDENTIFIER`` -- the join, in one call (§5).

    The run's UUID lands in ``UNIFIED_AUDIT_TRAIL.CLIENT_ID``, which is what
    makes the tool's JSON output, the database's own trail and the vault's
    secret metadata line up afterwards. It is the property the rejected
    definer-rights package's local audit table would have provided (ADR-001),
    kept without the table -- and it is worth doing on *every* connection,
    including ones that turn out to read nothing, because a session that
    appears in the trail unlabelled is the one somebody has to explain.

    **Bound, not interpolated.** Invariant 14 forbids binding a *password*,
    because ``V$SQL_BIND_CAPTURE`` keeps bind values in clear -- which is exactly
    why a correlation id is safe to bind and a good thing to have captured. The
    inverse mistake is the dangerous one: building this string by concatenation
    would be the habit that later writes a password into SQL text.
    """
    with connection.cursor() as cursor:
        cursor.callproc("dbms_session.set_identifier", [correlation_id])


def client_version() -> tuple[int, ...]:
    """The Instant Client's version, for ``sopuli doctor`` (#182).

    Needs thick mode up but **not** a database, which is the property #182 wants:
    P4 requires the doctor report whether a target is out of the client's reach
    -- a 23.x client reaches 19c and later, so an 11.2 target cannot be reached
    from Apple Silicon at all -- and that is an answer worth giving before
    anybody waits on a connection that cannot succeed.
    """
    return tuple(oracledb.clientversion())
