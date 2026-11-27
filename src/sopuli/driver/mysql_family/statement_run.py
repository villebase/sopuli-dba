"""`sql run` on MySQL and MariaDB: one statement in a guarded transaction (UC-3).

:class:`StatementRunning` gives :class:`~sopuli.driver.mysql.session.MysqlSession`
and :class:`~sopuli.driver.mariadb.session.MariadbSession` the
:class:`~sopuli.driver.protocol.StatementRunner` methods. The two products differ
in how a statement is bounded in time and in how the server names itself, and
each session says which it is with two class attributes.

What the code relies on was measured by MySQL's probe 13 and MariaDB's probe
18, ``13_statement_run_probe.py`` and ``18_statement_run_probe.py`` (#1714),
on MySQL 8.0.46, 8.4.13 and 9.7.4 and MariaDB 10.11.19, 11.4.13, 11.8.9 and
12.3.3:

- ``START TRANSACTION READ ONLY`` refuses a write, ``1792``, but ``CREATE
  TABLE`` and ``TRUNCATE`` commit it and run. The keyword check is the only
  guard against DDL, as on Oracle.
- The text is sent with ``execute(text)`` and no parameters. PyMySQL formats a
  text it is given parameters for, even an empty tuple, and a ``%`` then fails.
  It does not set ``MULTI_STATEMENTS``, so the server refuses two statements in
  one text, ``1064``.
- On MySQL, ``max_execution_time`` bounds a ``SELECT`` alone, a locking
  ``SELECT``'s wait for a row lock included (``3024``), and
  ``innodb_lock_wait_timeout`` and ``lock_wait_timeout`` bound a write's lock
  wait (``1205``). Nothing on the server bounds a long write, so PyMySQL's read
  timeout does, which closes the connection. On MariaDB, ``max_statement_time``
  bounds every statement, ``COMMIT`` included (``1969``).
- After ``1205`` or ``1969`` the transaction is still open with its earlier
  writes, so every failure is followed by a rollback.
- On MySQL a ``COMMIT`` that the client lost to its read timeout still
  commits. So neither bound is left on the ``COMMIT``, and a lost one has
  ``commit_failed`` set.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, replace
from typing import Any, ClassVar, TypeVar

from sopuli.config.model import ExpandedTarget
from sopuli.driver.mysql_family.accounts import current_user
from sopuli.driver.mysql_family.errors import (
    COLUMN_ACCESS_DENIED,
    DATABASE_ACCESS_DENIED,
    SERVER_GONE,
    SERVER_LOST,
    TABLE_ACCESS_DENIED,
    UNKNOWN_CLIENT_ERROR,
    Diagnosis,
)
from sopuli.driver.protocol import DriverError, InternalFaultError, StatementResult
from sopuli.sql.guard import RowGuard
from sopuli.sql.statement import Statement, StatementKind
from sopuli.sql.values import JsonValue, to_json

T = TypeVar("T")

#: ``pymysql.constants.SERVER_STATUS.SERVER_STATUS_IN_TRANS``, written out so
#: that this module imports no vendor client at its top (ADR-006): the modules
#: beside the sessions are tier 0. PyMySQL itself is imported inside
#: :meth:`StatementRunning.run_statement`, which only a session reaches, and a
#: session's module has imported it already.
SERVER_STATUS_IN_TRANS = 1

#: ``ER_LOCK_WAIT_TIMEOUT``, for a row lock and a metadata lock alike.
LOCK_WAIT_TIMEOUT = 1205
#: ``ER_PARSE_ERROR``.
PARSE_ERROR = 1064
#: ``ER_OPTION_PREVENTS_STATEMENT``: ``read_only`` or ``super_read_only``.
OPTION_PREVENTS_STATEMENT = 1290
#: ``ER_CANT_EXECUTE_IN_READ_ONLY_TRANSACTION``.
READ_ONLY_TRANSACTION = 1792
#: ``ER_GTID_UNSAFE_NON_TRANSACTIONAL_TABLE``: a transaction that writes a
#: transactional and a non-transactional table, with
#: ``enforce_gtid_consistency`` on, as MySQL 9.7.4 has it by default.
GTID_UNSAFE = 1785
#: MySQL's ``ER_QUERY_TIMEOUT``: ``max_execution_time`` ended a ``SELECT``.
QUERY_TIMEOUT = 3024
#: MariaDB's ``ER_STATEMENT_TIMEOUT``: ``max_statement_time`` ended a statement.
STATEMENT_TIMEOUT = 1969

#: The numbers a lost connection has. Whatever was in flight may have run.
_LOST = (UNKNOWN_CLIENT_ERROR, SERVER_GONE, SERVER_LOST)

#: `sql run`'s hints, which replace the driver's: those speak of the tool
#: account and a password change, and here the run-as account runs a statement.
_STATEMENT_HINTS = {
    LOCK_WAIT_TIMEOUT: (
        "the statement waited longer than --timeout, or a lower lock timeout the account "
        "already has, for a lock another session holds. It was rolled back. Find what "
        "holds the lock, or raise the timeout"
    ),
    QUERY_TIMEOUT: (
        "the server stopped the SELECT after --timeout, or a lower max_execution_time the "
        "account already has. Raise the timeout, or make the query faster"
    ),
    STATEMENT_TIMEOUT: (
        "the server stopped the statement after --timeout, or a lower max_statement_time "
        "the account already has. The time counts a wait for a lock another session "
        "holds. It was rolled back. Raise the timeout, or find what makes it slow"
    ),
    PARSE_ERROR: (
        "the server could not parse the statement. Two statements in one text are "
        "refused this way too"
    ),
    DATABASE_ACCESS_DENIED: "the run-as account lacks a privilege this statement needs",
    TABLE_ACCESS_DENIED: "the run-as account lacks a privilege this statement needs",
    COLUMN_ACCESS_DENIED: "the run-as account lacks a privilege this statement needs",
    OPTION_PREVENTS_STATEMENT: (
        "the server's read_only or super_read_only refuses a write. Run it on the "
        "server that takes writes"
    ),
    GTID_UNSAFE: (
        "the server's enforce_gtid_consistency refuses a transaction that writes a "
        "table with transactions and one without, such as MyISAM. Nothing was changed"
    ),
    SERVER_LOST: (
        "the connection was lost. A statement that runs longer than --timeout ends this "
        "way on MySQL: the server finishes it and then rolls it back"
    ),
}

#: A read runs in ``START TRANSACTION READ ONLY``, so the shared hint is wrong
#: for what that refuses.
_READ_HINTS = {
    READ_ONLY_TRANSACTION: (
        "a SELECT or WITH runs in a read-only transaction, and `sql run` cannot run one "
        "that writes, such as SELECT ... FOR UPDATE, a WITH that writes, or a function "
        "that writes"
    ),
}


def for_statement(diagnosis: Diagnosis, *, read: bool) -> Diagnosis:
    """``diagnosis`` with `sql run`'s hint, where it has one. The number and
    the server's message are kept."""
    hint = _READ_HINTS.get(diagnosis.number) if read else None
    if hint is None:
        hint = _STATEMENT_HINTS.get(diagnosis.number)
    return diagnosis if hint is None else replace(diagnosis, hint=hint)


#: The longest text or binary value `sql run` returns, in characters or bytes,
#: as Oracle's LOB limit. A longer one is cut.
VALUE_LIMIT = 4000


def _cell(value: Any) -> tuple[JsonValue, bool]:
    """One fetched value in JSON form, and whether it was cut to get there.

    PyMySQL returns ``str`` for ``JSON``, ``ENUM``, ``SET``, the text types and
    a zero date; ``bytes`` for ``BIT``, the binary types and a geometry; and
    ``timedelta`` for ``TIME``, which becomes an ISO 8601 duration (probe item
    8). Bytes are cut before they become hex.
    """
    if isinstance(value, bytes | bytearray) and len(value) > VALUE_LIMIT:
        return to_json(bytes(value[:VALUE_LIMIT])), True
    converted = to_json(value)
    if isinstance(converted, str) and len(converted) > VALUE_LIMIT:
        return converted[:VALUE_LIMIT], True
    return converted, False


def read_result(cursor: Any, max_rows: int) -> StatementResult:
    """The rows of a query, at most ``max_rows`` of them."""
    columns = tuple(str(column[0]) for column in cursor.description)
    fetched = cursor.fetchmany(max_rows + 1)
    truncated = len(fetched) > max_rows
    rows: list[tuple[JsonValue, ...]] = []
    for row in fetched[:max_rows]:
        cells = [_cell(value) for value in row]
        truncated = truncated or any(cut for _, cut in cells)
        rows.append(tuple(value for value, _ in cells))
    return StatementResult(columns, tuple(rows), len(rows), truncated, False, None)


def _lower(requested: float, existing: float) -> float:
    """The lower of two bounds, where ``0`` means no bound."""
    if requested == 0 or existing == 0:
        return max(requested, existing)
    return min(requested, existing)


@dataclass
class _Bounds:
    """What :meth:`StatementRunning._bound` changed, to undo it."""

    #: ``SET SESSION`` assignments that put the session's own values back.
    restore: str | None = None
    #: The connection's read timeout before the statement, in seconds.
    read_timeout: float | None = None


class StatementRunning:
    """The :class:`~sopuli.driver.protocol.StatementRunner` methods, for a
    session that holds one PyMySQL connection.

    A session that takes these declares the fields below, and its
    ``_read``. It sets :attr:`bounds_every_statement` and
    :attr:`identity_query`.
    """

    #: MariaDB's ``max_statement_time`` bounds every statement. MySQL's
    #: ``max_execution_time`` bounds a ``SELECT`` alone.
    bounds_every_statement: ClassVar[bool]
    #: Reads the server's identity and ``DATABASE()``, for the plan fingerprint.
    identity_query: ClassVar[str]

    connection: Any
    target: ExpandedTarget
    _session_user: str | None
    _connection_lost: bool

    def _read(self, reader: Callable[[Any], T]) -> T:
        raise NotImplementedError

    def _diagnose(self, error: Any) -> Diagnosis:
        """The product's classification of a PyMySQL error."""
        raise NotImplementedError

    @property
    def connection_lost(self) -> bool:
        """A statement left the connection closed, as PyMySQL's read timeout
        does. A server-side timeout does not: the session stays usable."""
        return self._connection_lost

    def _account(self) -> str:
        """``CURRENT_USER()``, the account the server matched at login,
        ``user@host``, read once."""
        if self._session_user is None:
            self._session_user = self._read(current_user)
        return self._session_user

    def session_user(self) -> str:
        """The user name of the account the server matched at login, without
        its host. The service account is refused by name at any host (UC-3 §2).
        An anonymous account's user name is empty."""
        account = self._account()
        user, at, _host = account.rpartition("@")
        return user if at else account

    def current_user(self) -> str:
        """The account as ``user@host``. It is in the plan fingerprint, so a
        login that reaches another account of the same user changes it."""
        return self._account()

    def member_of(self, account: str) -> bool:
        """Whether the session's account holds ``account`` as a role. Not read
        yet: #1717 reads it on MySQL. A MariaDB role is never an account."""
        return False

    def database_identity(self) -> tuple[str, str]:
        """``(server identity, DATABASE())``. A session with no default
        database gives ``""``. MariaDB's ``@@server_uid`` changes at each
        restart, so a restart between the dry run and the real run changes the
        plan fingerprint, and the operator runs the dry run again."""

        def read(cursor: Any) -> tuple[str, str]:
            cursor.execute(self.identity_query)
            server, database = cursor.fetchone()
            return str(server), "" if database is None else str(database)

        return self._read(read)

    def run_statement(
        self,
        statement: Statement,
        *,
        guard: RowGuard | None,
        commit: bool,
        max_rows: int,
        timeout_ms: int,
    ) -> StatementResult:
        """Run one statement in a transaction that ends the way UC-3 says.

        A read runs in ``START TRANSACTION READ ONLY``, through an unbuffered
        cursor so that only the rows read cross into memory, and is rolled
        back. A write runs in ``START TRANSACTION READ WRITE`` and is committed
        only when ``commit`` is true, the guard passes and a row matched; any
        other outcome rolls back. Its row count is the rows it matched,
        because every MySQL-family session sets ``FOUND_ROWS``.

        ``timeout_ms`` bounds the statement, and ``0`` means no bound; a lower
        bound the account already has stays. The bounds are lifted before the
        ``COMMIT``, and the session's own values are put back after.

        A transaction an earlier caller left open is rolled back first, because
        ``START TRANSACTION`` would commit it.
        """
        if commit and guard is None:
            raise ValueError("run_statement commits only with a row guard")
        import pymysql
        import pymysql.cursors

        connection = self._open_connection()
        read = statement.kind is StatementKind.READ
        begun = committed = committing = False
        bounds = _Bounds(read_timeout=connection._read_timeout)
        try:
            if connection.server_status & SERVER_STATUS_IN_TRANS:
                connection.rollback()
            with connection.cursor() as control:
                bounds = self._bound(connection, control, timeout_ms)
                control.execute(
                    "START TRANSACTION READ ONLY" if read else "START TRANSACTION READ WRITE"
                )
                begun = True
            if read:
                with connection.cursor(pymysql.cursors.SSCursor) as rows:
                    rows.execute(statement.text)
                    return read_result(rows, max_rows)
            with connection.cursor() as cursor:
                cursor.execute(statement.text)
                count = int(cursor.rowcount)
            passed = None if guard is None else guard.passes(count)
            if commit and passed is not False and count > 0:
                committing = True
                self._lift(connection, bounds)
                connection.commit()
                committed = True
            return StatementResult((), (), count, False, committed, passed)
        except pymysql.err.MySQLError as error:
            self._connection_lost = not connection.open
            raised = for_statement(self._diagnose(error), read=read)
            failure = raised.as_error()
            # A COMMIT the server refused with a number was not applied. One
            # whose connection was lost may have been: on MySQL it still commits.
            failure.commit_failed = committing and (self._connection_lost or raised.number in _LOST)
            raise failure from error
        finally:
            connection._read_timeout = bounds.read_timeout
            if connection.open:
                if begun and not committed:
                    with suppress(pymysql.err.MySQLError):
                        connection.rollback()
                if bounds.restore is not None:
                    with suppress(pymysql.err.MySQLError), connection.cursor() as cursor:
                        cursor.execute(bounds.restore)

    def _open_connection(self) -> Any:
        """The connection, or a refusal to send on one that is closed."""
        if self.connection is None:
            raise InternalFaultError.closed_session(self.target.name)
        if self._connection_lost or not self.connection.open:
            raise DriverError(
                f"{SERVER_LOST}: the connection was closed under an earlier statement",
                hint="close this session and open another",
                code=str(SERVER_LOST),
            )
        return self.connection

    def _bound(self, connection: Any, cursor: Any, timeout_ms: int) -> _Bounds:
        """Bound the next statement by ``timeout_ms``, and say how to undo it.

        On MariaDB that is ``max_statement_time``, in seconds. On MySQL it is
        ``max_execution_time`` for a ``SELECT``, in milliseconds, the two lock
        timeouts, in whole seconds of at least 1, and PyMySQL's read timeout,
        one second past them, so that the server's own error comes first where
        it has one.
        """
        bounds = _Bounds(read_timeout=connection._read_timeout)
        if timeout_ms == 0:
            return bounds
        if self.bounds_every_statement:
            cursor.execute("SELECT @@session.max_statement_time")
            (existing,) = cursor.fetchone()
            limit = _lower(timeout_ms / 1000, float(existing))
            cursor.execute(f"SET SESSION max_statement_time = {limit:.3f}")
            bounds.restore = f"SET SESSION max_statement_time = {float(existing):.3f}"
            return bounds
        cursor.execute(
            "SELECT @@session.max_execution_time, @@session.innodb_lock_wait_timeout, "
            "@@session.lock_wait_timeout"
        )
        execution, row_lock, metadata = (int(value) for value in cursor.fetchone())
        seconds = max(1, math.ceil(timeout_ms / 1000))
        cursor.execute(
            f"SET SESSION max_execution_time = {int(_lower(timeout_ms, execution))}, "
            f"innodb_lock_wait_timeout = {int(_lower(seconds, row_lock))}, "
            f"lock_wait_timeout = {int(_lower(seconds, metadata))}"
        )
        bounds.restore = (
            f"SET SESSION max_execution_time = {execution}, "
            f"innodb_lock_wait_timeout = {row_lock}, lock_wait_timeout = {metadata}"
        )
        existing_read = bounds.read_timeout or 0
        connection._read_timeout = _lower(seconds + 1, existing_read) or None
        return bounds

    def _lift(self, connection: Any, bounds: _Bounds) -> None:
        """Take the statement's bounds off before the ``COMMIT``, which none of
        them may cut: the session's own read timeout comes back, and on MariaDB
        ``max_statement_time`` is 0 until :attr:`_Bounds.restore` runs."""
        connection._read_timeout = bounds.read_timeout
        if self.bounds_every_statement and bounds.restore is not None:
            with connection.cursor() as cursor:
                cursor.execute("SET SESSION max_statement_time = 0")
