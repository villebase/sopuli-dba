"""`sql run`: connect to the selected targets and run one statement (UC-3).

The order is UC-3 §2 and §4's. Every check that needs no connection runs
first, then every selected target is connected and its session user checked,
and only then does any statement run. A target that cannot be reached, or
whose statement fails, is reported with its error, and a read goes on with
the others (§5).

The command line, the credential and the text live elsewhere: `sopuli.cli`
opens a session with the run-as credential, and `sopuli.output.sql_view`
renders the outcomes.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass

from sopuli.admin import refuse_service_account, refuse_session_user, run_as_user
from sopuli.apply import SKIPPED
from sopuli.check import ERROR
from sopuli.config.model import Config, ExpandedTarget
from sopuli.driver.protocol import Session, StatementResult, StatementRunner
from sopuli.driver.registry import DriverNotImplementedError, require_command
from sopuli.exit_codes import ExitCode
from sopuli.output.document import Error
from sopuli.safety import ServiceAccountRefusedError
from sopuli.sql.statement import Statement

#: The run document's name for the command, as `require_command` checks it.
COMMAND = "sql.run"

#: The rows a read returns per target unless `--max-result-rows` says otherwise.
DEFAULT_MAX_ROWS = 100
#: The seconds one statement may take unless `--timeout` says otherwise.
DEFAULT_TIMEOUT = 30

#: A read that answered.
READ = "READ"
#: A write that was committed.
COMMITTED = "COMMITTED"
#: A write that was rolled back: a dry run, or no row changed.
ROLLED_BACK = "ROLLED_BACK"
#: A write that was rolled back because its row count failed the guard.
GUARD_FAILED = "GUARD_FAILED"
#: A real write stopped at an earlier target and never ran here.
NOT_ATTEMPTED = "NOT_ATTEMPTED"

#: The ``run_as`` of a target refused before its account was asked for.
ABSENT = "-"

#: Opens one session as the run-as account: the target and ``--as``.
Opener = Callable[[ExpandedTarget, str | None], Session]
#: Turns an exception into the target's ``error``, keeping the vendor code.
Finding = Callable[[Exception], Error]


@dataclass(frozen=True)
class Connection:
    """One selected target after the connect step: a session, or why there is none."""

    target: ExpandedTarget
    #: The user name the session logs in as, ``external``, or :data:`ABSENT`.
    run_as: str
    session: Session | None = None
    error: Error | None = None
    #: ``(DB_UNIQUE_NAME, CON_NAME)``, read when the session opened.
    identity: tuple[str, str] | None = None
    #: The target's product is not written for `sql run` (``SOPULI-20006``).
    unsupported: bool = False


@dataclass(frozen=True)
class TargetOutcome:
    """What one target did with the statement."""

    target: str
    run_as: str
    state: str
    result: StatementResult | None = None
    error: Error | None = None


def connect_all(
    config: Config,
    as_user: str | None,
    *,
    open_session: Opener,
    finding: Finding,
    env: Mapping[str, str] | None = None,
) -> list[Connection]:
    """Connect every selected target, in the config's order, before any statement runs.

    A target of a product `sql run` is not written for is refused here, with
    ``SOPULI-20006``, and never connected. For the others, the plan-time checks
    of UC-3 §2 run first: no run-as account is exit 9, and the service account
    is ``SOPULI-20010``. Either refuses the whole run before a socket opens.

    Then each target is connected. One that cannot be reached carries its
    error, and the others go on. Each session's user is checked against the
    service account, and one match refuses the whole run with
    ``SOPULI-20010``, with every session closed. Last, the database identity
    is read, for a write's fingerprint.
    """
    env = os.environ if env is None else env
    targets = config.expanded_targets
    refused: dict[str, Error] = {}
    for target in targets:
        try:
            require_command(target.target, COMMAND)
        except DriverNotImplementedError as error:
            refused[target.name] = finding(error)
            continue
        refuse_service_account(target, as_user, env=env)

    connections: list[Connection] = []
    try:
        for target in targets:
            if target.name in refused:
                connections.append(
                    Connection(target, ABSENT, error=refused[target.name], unsupported=True)
                )
                continue
            connections.append(
                _connect(target, as_user, open_session=open_session, finding=finding, env=env)
            )
    except BaseException:
        close_all(connections)
        raise
    return connections


def _connect(
    target: ExpandedTarget,
    as_user: str | None,
    *,
    open_session: Opener,
    finding: Finding,
    env: Mapping[str, str],
) -> Connection:
    """One target's connection, its session user checked and its identity read."""
    who = run_as_user(target, as_user)
    try:
        session = open_session(target, as_user)
    except Exception as error:  # noqa: BLE001 -- a per-target finding
        return Connection(target, who, error=finding(error))
    try:
        if not isinstance(session, StatementRunner):
            # The registry lets only a runner's product through. One that is
            # not anyway is refused here rather than sent a statement.
            raise DriverNotImplementedError(
                f"target {target.name!r}: this driver cannot run a statement"
            )
        refuse_session_user(target, session.session_user(), as_user, env=env)
        identity = session.database_identity()
    except DriverNotImplementedError as error:
        with suppress(Exception):
            session.close()
        return Connection(target, who, error=finding(error), unsupported=True)
    except ServiceAccountRefusedError:
        # The whole run is refused; the caller closes the other sessions.
        with suppress(Exception):
            session.close()
        raise
    except Exception as error:  # noqa: BLE001 -- a per-target finding
        with suppress(Exception):
            session.close()
        return Connection(target, who, error=finding(error))
    except BaseException:
        with suppress(Exception):
            session.close()
        raise
    return Connection(target, who, session=session, identity=identity)


def run_read(
    connections: Sequence[Connection],
    statement: Statement,
    *,
    max_rows: int,
    timeout_ms: int,
    finding: Finding,
) -> list[TargetOutcome]:
    """Run a read on every connected target, and close every session.

    A read never stops: a target whose statement fails carries its error, and
    the next target runs (UC-3 §5). Each read is rolled back by the runner.
    """
    outcomes: list[TargetOutcome] = []
    try:
        for one in connections:
            outcomes.append(_read_one(one, statement, max_rows, timeout_ms, finding))
    finally:
        close_all(connections)
    return outcomes


def _read_one(
    one: Connection, statement: Statement, max_rows: int, timeout_ms: int, finding: Finding
) -> TargetOutcome:
    name = one.target.name
    if one.session is None:
        state = SKIPPED if one.unsupported else ERROR
        return TargetOutcome(name, one.run_as, state, error=one.error)
    session = one.session
    assert isinstance(session, StatementRunner)  # checked by _connect
    try:
        result = session.run_statement(
            statement, guard=None, commit=False, max_rows=max_rows, timeout_ms=timeout_ms
        )
    except Exception as error:  # noqa: BLE001 -- a per-target finding
        return TargetOutcome(name, one.run_as, ERROR, error=finding(error))
    finally:
        with suppress(Exception):
            session.close()
    return TargetOutcome(name, one.run_as, READ, result=result)


def close_all(connections: Sequence[Connection]) -> None:
    """Close every open session. Closing one twice is harmless."""
    for one in connections:
        if one.session is not None:
            with suppress(Exception):
                one.session.close()


def exit_code(outcomes: Sequence[TargetOutcome]) -> int:
    """0 when every target answered; 5 when every target is of a product
    `sql run` is not written for; 1 when none answered; else 4."""
    if not outcomes:
        return int(ExitCode.SUCCESS)
    if all(outcome.state == SKIPPED for outcome in outcomes):
        return int(ExitCode.UNSUPPORTED_CAPABILITY)
    answered = sum(1 for outcome in outcomes if outcome.state == READ)
    if answered == 0:
        return int(ExitCode.FAILURE)
    if answered < len(outcomes):
        return int(ExitCode.PARTIAL)
    return int(ExitCode.SUCCESS)
