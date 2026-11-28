"""`sql run` on SQL Server: one statement in a guarded transaction (UC-3).

:class:`StatementRunning` gives :class:`~sopuli.driver.mssql.session.MssqlSession`
the :class:`~sopuli.driver.protocol.StatementRunner` methods. It imports no
vendor client at its top (ADR-006): pyodbc's errors reach it through the
session's ``_diagnose`` and ``_is_client_error``.

What the code relies on was measured by ``17_statement_run_probe.py`` (#1729)
on 15.0.4510.2, 16.0.4325.4, 17.0.5065.9 and 16.0.1000.6, with pyodbc 5.5.0
and ODBC Driver 18:

- SQL Server has no read-only transaction. A read runs in ``BEGIN
  TRANSACTION`` with ``XACT_ABORT ON`` and is always rolled back (#1728, Q2).
  The rollback undoes DDL and a ``GRANT`` too. It does not undo a sequence's
  ``NEXT VALUE FOR``, an identity value, a table variable's rows or a
  session's ``sp_getapplock``.
- With ``XACT_ABORT ON``, ``LOCK_TIMEOUT``'s ``1222``, the query timeout's
  ``HYT00`` and a cancel's ``HY008`` each roll the transaction back and
  release its locks, and the connection stays usable. A deadlock victim,
  ``1205``, is rolled back too.
- pyodbc's ``rowcount`` is a trigger's count first where an ``AFTER`` trigger
  fires under ``NOCOUNT OFF``, and an ``INSTEAD OF`` trigger gives several.
  ``@@ROWCOUNT`` read next in the session is the statement's own count, so
  the guard reads that.
- pyodbc refuses ``datetimeoffset``, ``sql_variant``, ``hierarchyid`` and
  ``geography``, ``HY106``, unless the connection has an output converter
  for the type.
- After ``fetchmany``, ``cancel()`` and ``close()`` return at once, and the
  session has no request left, so a capped read leaves the session usable.
- The statement runs in ``master``, where every login the tool makes lands,
  and names other databases' objects by three-part names (#1728, Q3).
- A session the server ends, as a ``KILL`` does, gets ``596`` as ``HY000``,
  not ``08S01``; :func:`~sopuli.driver.mssql.errors.connection_gone` reads
  both as a lost connection (measured on 16.0.4325.4, #1736).
"""

from __future__ import annotations

import math
import struct
from collections.abc import Callable, Iterable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Any, TypeVar

from sopuli.config.model import ExpandedTarget
from sopuli.driver.mssql.capabilities import END_TRANSACTION
from sopuli.driver.mssql.errors import (
    DATABASE_DENIED,
    PERMISSION_DENIED,
    READ_ONLY_DATABASE,
    SERVER_PERMISSION_DENIED,
    Diagnosis,
    connection_gone,
)
from sopuli.driver.protocol import DriverError, InternalFaultError, StatementResult, Timeouts
from sopuli.output.debug import logger
from sopuli.sql.guard import RowGuard
from sopuli.sql.statement import Statement, StatementKind, StatementRefusedError
from sopuli.sql.values import JsonValue, to_json

LOG = logger("mssql")

T = TypeVar("T")

#: ``LOCK_TIMEOUT`` ended a wait for a lock.
LOCK_TIMEOUT = "1222"
#: The session was chosen as a deadlock's victim.
DEADLOCK = "1205"
#: The ODBC driver's query timeout fired: the connection's ``timeout``.
QUERY_TIMEOUT = "HYT00"
#: ``cursor.cancel()`` stopped the statement.
CANCELLED = "HY008"
#: A ``?`` outside a literal, which the driver reads as a parameter marker.
PARAMETER_COUNT = "07002"
#: An object the statement names does not exist, or the login cannot see it.
INVALID_OBJECT = "208"
#: The statement does not parse.
SYNTAX_ERROR = "102"
#: A statement that cannot run inside a transaction, such as ``ALTER DATABASE``.
NOT_IN_TRANSACTION = "226"
#: A linked server's statement inside a transaction.
TRANSACTION_CONTEXT_IN_USE = "3910"
#: The ODBC driver cannot read a column of this type.
TYPE_NOT_SUPPORTED = "HY106"

#: The client's own refusals and stops, which the driver classifies as a
#: connection failure because no server record came with them. The connection
#: is usable after each (probe 17, S6 and S8), so `sql run` reports them as
#: the statement's (review of #1736).
_STATEMENT_CODES = (QUERY_TIMEOUT, CANCELLED, PARAMETER_COUNT, TYPE_NOT_SUPPORTED)

#: `sql run`'s hints, which replace the driver's: those speak of the tool
#: login and a password change, and here the run-as login runs a statement.
_STATEMENT_HINTS = {
    LOCK_TIMEOUT: (
        "the statement waited longer than --timeout, or a lower LOCK_TIMEOUT the login "
        "already has, for a lock another session holds. It was rolled back. Find what "
        "holds the lock, or raise the timeout"
    ),
    QUERY_TIMEOUT: (
        "the statement ran longer than --timeout, and the client stopped it. It was "
        "rolled back. Raise the timeout, or make the statement faster"
    ),
    CANCELLED: "the statement was stopped before it finished. It was rolled back",
    DEADLOCK: (
        "the server chose this statement as a deadlock's victim and rolled it back. Run it again"
    ),
    PARAMETER_COUNT: (
        "the ODBC driver reads a ? outside a string as a parameter, and `sql run` sends "
        "none. Write the value in the statement"
    ),
    INVALID_OBJECT: (
        "the statement runs in master. Name another database's objects by three-part "
        "names, such as acme.dbo.orders. The run-as login may also lack a user in that "
        "database"
    ),
    SYNTAX_ERROR: (
        "the server could not parse the statement. A GO line, which sqlcmd and SSMS read, "
        "is not T-SQL"
    ),
    NOT_IN_TRANSACTION: "`sql run` runs every statement in a transaction, and this one cannot",
    TRANSACTION_CONTEXT_IN_USE: (
        "a statement on a linked server cannot run inside the transaction `sql run` "
        "opens. Run it on that server"
    ),
    TYPE_NOT_SUPPORTED: (
        "the ODBC driver cannot read a column of this type. CAST it to a type it reads, "
        "such as nvarchar"
    ),
    str(PERMISSION_DENIED): "the run-as login lacks a permission this statement needs",
    str(SERVER_PERMISSION_DENIED): "the run-as login lacks a permission this statement needs",
    str(DATABASE_DENIED): "the run-as login cannot open a database this statement names",
    str(READ_ONLY_DATABASE): (
        "the database is read-only, as on a secondary replica. Run the write on the "
        "replica that takes writes"
    ),
}

#: The hint for a ``COMMIT`` that failed: the change may have been made.
_FAILED_COMMIT = (
    "the COMMIT failed, so whether it took effect is unknown. Check the rows before running again"
)

#: The hint for the query timeout on one of the tool's own queries around the
#: statement, which the session's query budget bounds and ``--timeout`` does not.
_BUDGET_TIMEOUT = (
    "a query the tool sends around the statement ran past the session's query budget, "
    "db.query_timeout_s. Nothing was committed"
)


def for_statement(diagnosis: Diagnosis, *, in_statement: bool = True) -> Diagnosis:
    """``diagnosis`` with `sql run`'s hint, where it has one, and a client's
    own refusal or stop as a ``database`` failure, not a lost connection.
    ``in_statement`` is false for an error on one of the tool's own queries
    around the statement, where the query timeout is the session's budget and
    not ``--timeout`` (review of #1736). The code and the server's message are
    kept."""
    if diagnosis.code in _STATEMENT_CODES:
        diagnosis = replace(diagnosis, category="database")
    if diagnosis.code == QUERY_TIMEOUT and not in_statement:
        return replace(diagnosis, hint=_BUDGET_TIMEOUT)
    hint = _STATEMENT_HINTS.get(diagnosis.code)
    return diagnosis if hint is None else replace(diagnosis, hint=hint)


#: The longest text or binary value `sql run` returns, in characters or bytes,
#: as Oracle's LOB limit. A longer one is cut.
VALUE_LIMIT = 4000

#: The ODBC types pyodbc reads only through an output converter (probe 17, S8).
DATETIMEOFFSET = -155
#: ``hierarchyid``, ``geography``, ``geometry`` and a CLR type.
USER_DEFINED_TYPE = -151


def _datetimeoffset(raw: bytes | None) -> datetime | None:
    """A ``datetimeoffset`` as the ODBC driver sends it: ``SQL_SS_TIMESTAMPOFFSET``,
    six shorts, the fraction in nanoseconds, and the offset's hours and
    minutes. The fraction keeps the microseconds a ``datetime`` holds."""
    if raw is None:
        return None
    year, month, day, hour, minute, second, fraction, hours, minutes = struct.unpack("<6hI2h", raw)
    offset = timezone(timedelta(hours=hours, minutes=minutes))
    return datetime(year, month, day, hour, minute, second, fraction // 1000, tzinfo=offset)


def _raw(raw: bytes | None) -> bytes | None:
    """A ``hierarchyid`` or a spatial value as its bytes, which become hex."""
    return raw


#: The converters a UC-3 session adds, by ODBC type.
OUTPUT_CONVERTERS: dict[int, Callable[[bytes | None], Any]] = {
    DATETIMEOFFSET: _datetimeoffset,
    USER_DEFINED_TYPE: _raw,
}


def _cell(value: Any) -> tuple[JsonValue, bool]:
    """One fetched value in JSON form, and whether it was cut to get there.
    Bytes are cut before they become hex, which is twice as long."""
    if isinstance(value, bytes | bytearray):
        return to_json(bytes(value[:VALUE_LIMIT])), len(value) > VALUE_LIMIT
    converted = to_json(value)
    if isinstance(converted, str) and len(converted) > VALUE_LIMIT:
        return converted[:VALUE_LIMIT], True
    return converted, False


def read_result(cursor: Any, max_rows: int) -> tuple[StatementResult, bool]:
    """The rows of a query, at most ``max_rows`` of them, and whether the
    server has more to send. A batch whose first answer is a row count and
    not rows, such as ``SELECT … INTO``, is refused: there are no rows to
    show."""
    if cursor.description is None:
        raise DriverError(
            "the SELECT returned no rows to show",
            hint=(
                "a SELECT ... INTO stores its rows in a table, which `sql run` does not "
                "show. Leave out the INTO"
            ),
        )
    columns = tuple(str(column[0]) for column in cursor.description)
    fetched = cursor.fetchmany(max_rows + 1)
    more = len(fetched) > max_rows
    truncated = more
    rows: list[tuple[JsonValue, ...]] = []
    for row in fetched[:max_rows]:
        cells = [_cell(value) for value in row]
        truncated = truncated or any(cut for _, cut in cells)
        rows.append(tuple(value for value, _ in cells))
    return StatementResult(columns, tuple(rows), len(rows), truncated, False, None), more


#: ``@@OPTIONS`` bits: ``XACT_ABORT`` and ``NOCOUNT``.
XACT_ABORT_BIT = 16384
NOCOUNT_BIT = 512
#: ``@@LOCK_TIMEOUT`` with no bound.
NO_LOCK_TIMEOUT = -1


@dataclass(frozen=True)
class _Settings:
    """The session's own settings, read before the statement and put back
    after it."""

    lock_timeout: int
    xact_abort: bool
    nocount: bool

    def restore(self) -> str:
        return (
            f"SET XACT_ABORT {'ON' if self.xact_abort else 'OFF'}; "
            f"SET NOCOUNT {'ON' if self.nocount else 'OFF'}; "
            f"SET LOCK_TIMEOUT {self.lock_timeout}"
        )


def lock_timeout(timeout_ms: int, existing: int) -> int:
    """The ``LOCK_TIMEOUT`` for the statement, in milliseconds: the lower of
    ``timeout_ms`` and the session's own, where ``0`` and ``-1`` respectively
    mean no bound. A lower bound the login already has stays."""
    if timeout_ms == 0:
        return existing
    if existing == NO_LOCK_TIMEOUT:
        return timeout_ms
    return min(timeout_ms, existing)


#: The server compiles a batch, runs none of it, and lists its statements.
#: Each ``SET SHOWPLAN`` must be a batch of its own.
SHOWPLAN_ON = "SET SHOWPLAN_ALL ON"
SHOWPLAN_OFF = "SET SHOWPLAN_ALL OFF"
#: ``SHOWPLAN permission denied in database '…'``.
NO_SHOWPLAN = "262"
_NO_SHOWPLAN_HINT = (
    "`sql run` asks the server to list the statement's parts before it runs anything, "
    "and the run-as login needs the SHOWPLAN permission for that in each database the "
    "statement names, the one this message names among them: GRANT SHOWPLAN TO the "
    "login's user there (02-mssql-privileges.md §8)"
)

#: The ``SHOWPLAN_ALL`` types a read and a write may be (probe 17, S1).
#: ``SELECT 1`` is ``SELECT WITHOUT QUERY``; ``SELECT … INTO`` is ``SELECT
#: INTO``, which makes a table, and passes as neither. A ``WITH`` has its main
#: statement's type.
READ_TYPES = ("SELECT", "SELECT WITHOUT QUERY")
WRITE_TYPES = ("UPDATE", "INSERT", "DELETE", "MERGE")


def batch_statements(columns: Sequence[str], rows: Iterable[Sequence[Any]]) -> list[str]:
    """The type of each statement of the batch, in order, from
    ``SHOWPLAN_ALL``'s one row set.

    A statement of the batch has a row of its own whose ``Type`` is not
    ``PLAN_ROW`` and whose ``Parent`` is ``0``. A module the statement calls
    adds rows too: a multi-statement function a ``TEXT`` row with the same
    ``StmtId`` and its body under it, and a procedure its body under the
    ``EXECUTE PROC`` row, with a ``Parent`` that is not ``0``. So the rows
    with ``Parent`` ``0`` count, one per ``StmtId`` (measured on 16.0.4325.4,
    #1732).

    Every second statement after an ``UPDATE`` that was tried has a row of
    its own: ``COMMIT``, ``ROLLBACK``, ``BEGIN TRAN``, ``SAVE TRANSACTION``,
    ``EXECUTE AS``, ``REVERT``, each ``SET``, ``IF``, ``WHILE``, ``GOTO``,
    ``RETURN``, ``RAISERROR``, ``PRINT``, ``WAITFOR``, ``USE``, ``KILL``,
    ``DBCC``, ``CHECKPOINT``, ``RECONFIGURE``, DDL, ``GRANT``, ``DENY``,
    ``REVOKE``, ``EXEC`` of a procedure or a string, ``BACKUP``, ``BEGIN …
    END``, ``TRY … CATCH``, cursors, ``SETUSER`` and ``SHUTDOWN``. Only a
    ``DECLARE`` of a variable or a table variable with no value has none; it
    ends with the batch, and changes nothing (measured on 16.0.4325.4, review
    of #1737).
    """
    type_at, statement_at, parent_at = (
        columns.index(name) for name in ("Type", "StmtId", "Parent")
    )
    found: dict[int, str] = {}
    for row in rows:
        kind = str(row[type_at]).strip().upper()
        if kind == "PLAN_ROW" or int(row[parent_at]) != 0:
            continue
        found.setdefault(int(row[statement_at]), kind)
    return list(found.values())


def _refuse_batch(target: str, statements: Sequence[str], *, read: bool) -> None:
    """Refuse a batch that is not one statement of the run's kind."""
    if len(statements) != 1:
        listed = ", ".join(statements) or "none"
        raise StatementRefusedError(
            f"target {target!r}: the server reads the text as {len(statements)} statements "
            f"({listed}), and `sql run` runs one",
            hint="T-SQL needs no ';' between two statements, so a text that reads as one "
            "statement to the eye can hold two. Give one SELECT, UPDATE, INSERT, DELETE or "
            "MERGE",
        )
    (kind,) = statements
    if kind in (READ_TYPES if read else WRITE_TYPES):
        return
    if read:
        hint = (
            "a read is one SELECT that returns rows. A SELECT ... INTO makes a table: "
            "leave out the INTO"
            if kind == "SELECT INTO"
            else "a read is one SELECT, or a WITH that leads to one"
        )
    else:
        hint = "a write is one UPDATE, INSERT, DELETE or MERGE"
    raise StatementRefusedError(
        f"target {target!r}: the server reads the statement as {kind}, which "
        f"`sql run` does not run as a {'read' if read else 'write'}",
        hint=hint,
    )


def query_timeout(timeout_ms: int) -> int:
    """The client's bound on the statement, in whole seconds, one past
    ``LOCK_TIMEOUT``, so the server's ``1222`` comes first for a lock wait.
    ``0`` sets none. ``--timeout`` replaces the session's own query budget
    for the statement."""
    return 0 if timeout_ms == 0 else math.ceil(timeout_ms / 1000) + 1


class StatementRunning:
    """The :class:`~sopuli.driver.protocol.StatementRunner` methods, for a
    session that holds one pyodbc connection.

    A session that takes these declares the fields below, its ``_read``, and
    its ``_diagnose`` and ``_is_client_error``, which classify a pyodbc error
    without this module importing pyodbc.
    """

    connection: Any
    target: ExpandedTarget
    timeouts: Timeouts
    _logins: tuple[str, str] | None
    _connection_lost: bool

    def _read(self, reader: Callable[[Any], T]) -> T:
        raise NotImplementedError

    def _is_client_error(self, error: BaseException) -> bool:
        """Whether ``error`` is ``pyodbc.Error``."""
        raise NotImplementedError

    def _diagnose(self, error: BaseException) -> Diagnosis:
        """The classification of a pyodbc error."""
        raise NotImplementedError

    @property
    def connection_lost(self) -> bool:
        """A statement left the connection unusable. A lock timeout, the
        query timeout and a cancel do not (probe 17, S6)."""
        return self._connection_lost

    def _both_logins(self) -> tuple[str, str]:
        """``ORIGINAL_LOGIN()`` and ``SUSER_SNAME()``, read once."""
        if self._logins is None:

            def read(cursor: Any) -> tuple[str, str]:
                cursor.execute("SELECT ORIGINAL_LOGIN(), SUSER_SNAME()")
                original, current = cursor.fetchone()
                return str(original), str(current)

            self._logins = self._session_read(read)
        return self._logins

    def _session_read(self, reader: Callable[[Any], T]) -> T:
        """:meth:`_read`, on a connection that is not lost, and marking it
        lost where the read finds it gone (review of #1736)."""
        self._open_connection()
        try:
            return self._read(reader)
        except DriverError as error:
            self._connection_lost = connection_gone(error.__cause__)
            raise

    def session_user(self) -> str:
        """``ORIGINAL_LOGIN()``, the login the session logged in as. Login
        names compare without case (``05_identity_probe.py``), as
        ``upper()`` compares them."""
        return self._both_logins()[0]

    def current_user(self) -> str:
        """``SUSER_SNAME()``, the login the statement runs as. It differs from
        :meth:`session_user` only inside ``EXECUTE AS LOGIN`` (probe 17, S9),
        which the statement check refuses as a first word, and
        :meth:`check_statement` as a second statement."""
        return self._both_logins()[1]

    def member_of(self, account: str) -> bool:
        """``False``: a login is never granted to another login. The way to
        act as one is ``EXECUTE AS LOGIN``, which `sql run` refuses, and
        every ``sysadmin`` holds ``IMPERSONATE`` on every login, so reading
        it would refuse the usual DBA login (#1728, Q4)."""
        return False

    def database_identity(self) -> tuple[str, str]:
        """``(SERVERPROPERTY('ServerName'), DB_NAME())``. The database is
        ``master`` (#1728, Q3). An Availability Group failover changes the
        server's name, so the plan fingerprint changes, and the operator runs
        the dry run again."""

        def read(cursor: Any) -> tuple[str, str]:
            cursor.execute("SELECT CAST(SERVERPROPERTY('ServerName') AS nvarchar(256)), DB_NAME()")
            server, database = cursor.fetchone()
            return "" if server is None else str(server), "" if database is None else str(database)

        return self._session_read(read)

    def check_statement(self, statement: Statement, *, timeout_ms: int) -> None:
        """Refuse a text the server reads as anything but one statement of
        the run's kind, before any statement runs on any target (#1728, Q1).

        T-SQL needs no ``;`` between two statements, so the statement check
        cannot see where one ends. The server can: under ``SET SHOWPLAN_ALL
        ON`` it compiles the batch, runs none of it, and lists each statement
        with its type (probe 17, S1). A read passes as one ``SELECT``, not
        ``SELECT INTO``, and a write as one ``UPDATE``, ``INSERT``, ``DELETE``
        or ``MERGE`` (:func:`batch_statements`).

        The run-as login needs ``SHOWPLAN`` in each database the statement
        names, and none in ``master``; without it the server refuses with
        ``262``. ``timeout_ms`` bounds the check as it bounds the statement,
        and ``0`` leaves the session's own query budget.
        """
        connection = self._open_connection()
        statements: list[str] = []
        planning = False
        connection.timeout = query_timeout(timeout_ms) or self.timeouts.query_s
        try:
            with _cursor(connection) as cursor:
                cursor.execute(SHOWPLAN_ON)
                planning = True
                cursor.execute(statement.text)
                # The columns come from the first row set that has any, so a
                # first answer without them cannot leave the rows unread
                # (review of #1737). With none at all, there is no statement.
                columns: list[str] = []
                rows: list[Sequence[Any]] = []
                while True:
                    if cursor.description is not None:
                        columns = columns or [str(column[0]) for column in cursor.description]
                        rows.extend(cursor.fetchall())
                    if not cursor.nextset():
                        break
            statements = batch_statements(columns, rows) if columns else []
        except Exception as error:
            if not self._is_client_error(error):
                raise
            self._connection_lost = connection_gone(error)
            diagnosis = self._diagnose(error)
            if diagnosis.code == NO_SHOWPLAN:
                diagnosis = replace(diagnosis, hint=_NO_SHOWPLAN_HINT)
            else:
                diagnosis = for_statement(diagnosis)
            raise diagnosis.as_error() from error
        finally:
            connection.timeout = self.timeouts.query_s
            planned_off = not planning or (
                not self._connection_lost and self._quietly(connection, SHOWPLAN_OFF)
            )
        if not planned_off:
            # The session may still be under SHOWPLAN, where a statement
            # compiles and runs nothing. It is marked lost, and the check
            # fails here, so no target runs the statement (review of #1737).
            raise DriverError(
                f"target {self.target.name!r}: SET SHOWPLAN_ALL OFF failed after the check",
                hint="close this session and open another",
            )
        _refuse_batch(self.target.name, statements, read=statement.kind is StatementKind.READ)

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

        Both a read and a write run in ``BEGIN TRANSACTION`` with ``XACT_ABORT
        ON`` and ``NOCOUNT OFF``. A read is always rolled back. A write is
        committed only when ``commit`` is true, the guard passes and a row
        matched, counted by ``@@ROWCOUNT``; any other outcome rolls back.

        ``timeout_ms`` is ``LOCK_TIMEOUT`` for the statement, where the
        login's own is not lower, and the client's query timeout one second
        past it; ``0`` sets neither. No bound is left on the ``COMMIT``. The
        session's own settings and query budget are put back after.

        A read that stops at ``max_rows`` cancels the rest, and the session
        stays usable. A transaction an earlier caller left open is rolled
        back first.
        """
        if commit and guard is None:
            raise ValueError("run_statement commits only with a row guard")
        connection = self._open_connection()
        read = statement.kind is StatementKind.READ
        settings: _Settings | None = None
        committed = committing = in_statement = False
        converting: list[int] = []
        try:
            with _cursor(connection) as control:
                control.execute("SELECT @@LOCK_TIMEOUT, @@OPTIONS")
                existing, options = (int(value) for value in control.fetchone())
                settings = _Settings(
                    existing, bool(options & XACT_ABORT_BIT), bool(options & NOCOUNT_BIT)
                )
                control.execute(
                    "SET XACT_ABORT ON; SET NOCOUNT OFF; "
                    f"SET LOCK_TIMEOUT {lock_timeout(timeout_ms, existing)}"
                )
                control.execute(f"{END_TRANSACTION}; BEGIN TRANSACTION")
            for sqltype, convert in OUTPUT_CONVERTERS.items():
                connection.add_output_converter(sqltype, convert)
                converting.append(sqltype)
            # pyodbc gives a cursor the connection's timeout when it is made.
            connection.timeout = query_timeout(timeout_ms)
            with _cursor(connection) as cursor:
                connection.timeout = self.timeouts.query_s
                in_statement = True
                cursor.execute(statement.text)
                if read:
                    result, more = read_result(cursor, max_rows)
                    if more:
                        cursor.cancel()
                    return result
                # An error in a trigger, or an OUTPUT clause's rows, come
                # after the first answer.
                while cursor.nextset():
                    pass
                in_statement = False
            with _cursor(connection) as control:
                control.execute("SELECT @@ROWCOUNT")
                (found,) = control.fetchone()
            count = int(found)
            passed = None if guard is None else guard.passes(count)
            if commit and passed is not False and count > 0:
                # No bound on the COMMIT: the cursor takes the timeout when
                # it is made.
                connection.timeout = 0
                committing = True
                with _cursor(connection) as control:
                    control.execute("COMMIT TRANSACTION")
                committed = True
            return StatementResult((), (), count, False, committed, passed)
        except Exception as error:
            if not self._is_client_error(error):
                raise
            raised = for_statement(self._diagnose(error), in_statement=in_statement)
            self._connection_lost = connection_gone(error)
            if committing:
                raised = replace(raised, hint=_FAILED_COMMIT)
            failure = raised.as_error()
            # Any COMMIT that failed has an unknown outcome. A fatal server
            # error can end the session with a number other than KILL's 596,
            # so the error cannot always tell a COMMIT that was applied from
            # one that was not (review of #1736).
            failure.commit_failed = committing
            raise failure from error
        finally:
            for sqltype in converting:
                connection.remove_output_converter(sqltype)
            connection.timeout = self.timeouts.query_s
            # END_TRANSACTION reads @@TRANCOUNT, so it is sent even where the
            # BEGIN's batch failed after BEGIN ran (review of #1736).
            undo = [] if committed else [END_TRANSACTION]
            if settings is not None:
                undo.append(settings.restore())
            for sql in undo:
                if self._connection_lost or not self._quietly(connection, sql):
                    break

    def _quietly(self, connection: Any, sql: str) -> bool:
        """Send ``sql``, and say whether it ran. A failure is not raised: the
        error being raised, or the result being returned, is the answer. But
        the session is then marked lost, so nothing more is sent on it: a
        rollback that failed may have left the transaction and its locks
        open, and a restore that failed the statement's settings in place
        (review of #1736). `sql run` closes the session, and the server ends
        the transaction with it."""
        try:
            with _cursor(connection) as cursor:
                cursor.execute(sql)
        except Exception as error:
            if not self._is_client_error(error):
                raise
            LOG.debug("%s: %s failed: %s", self.target.name, sql, self._diagnose(error).code)
            self._connection_lost = True
            return False
        return True

    def _open_connection(self) -> Any:
        """The connection, or a refusal to send on one that is lost."""
        if self._connection_lost:
            raise DriverError(
                "the connection was lost under an earlier statement",
                hint="close this session and open another",
            )
        if self.connection is None:
            raise InternalFaultError.closed_session(self.target.name)
        return self.connection


@contextmanager
def _cursor(connection: Any) -> Iterator[Any]:
    """A cursor of ``connection``, closed after."""
    cursor = connection.cursor()
    try:
        yield cursor
    finally:
        cursor.close()
