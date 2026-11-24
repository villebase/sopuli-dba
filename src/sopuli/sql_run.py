"""`sql run`: connect to the selected targets and run one statement (UC-3).

The order is UC-3 §2 and §4's. Every check that needs no connection runs
first, then every selected target is connected and its session user checked,
and only then does any statement run. A target that cannot be reached, or
whose statement fails, is reported with its error. A read goes on with the
others (§5). A write computes its plan fingerprint from the connected
targets, and a real write stops at the first target that fails (§4, §5).

The command line, the credential and the text live elsewhere: `sopuli.cli`
opens a session with the run-as credential, and `sopuli.output.sql_view`
renders the outcomes.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, replace

from sopuli.admin import (
    refuse_service_account,
    refuse_session_user,
    run_as_prompts,
    run_as_user,
)
from sopuli.apply import SKIPPED
from sopuli.check import ERROR
from sopuli.config.model import Config, ExpandedTarget
from sopuli.driver.protocol import AuthenticationError, Session, StatementResult, StatementRunner
from sopuli.driver.registry import DriverNotImplementedError, require_command
from sopuli.exit_codes import ExitCode
from sopuli.output.document import Error
from sopuli.safety import RefusedError, ServiceAccountRefusedError, refuse_run_as_unattended
from sopuli.sql.fingerprint import PlannedTarget, fingerprint
from sopuli.sql.guard import RowGuard
from sopuli.sql.statement import Statement

#: The run document's name for the command, as `require_command` checks it.
COMMAND = "sql.run"

#: ``error.code`` for a real write whose ``--plan`` is not its fingerprint
#: (`03-json-output.md` §3).
PLAN_CHANGED = "SOPULI-20011"


class PlanChangedError(RefusedError):
    """A real write's ``--plan`` differs from the fingerprint it computed. Nothing ran."""

    code = PLAN_CHANGED


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
    #: A typed password was refused on an earlier target, so this one was not
    #: tried (UC-3 §2). ``error`` says where.
    not_attempted: bool = False
    #: The database refused the login itself, such as ``ORA-01017``.
    login_refused: bool = False


@dataclass(frozen=True)
class TargetOutcome:
    """What one target did with the statement."""

    target: str
    run_as: str
    state: str
    result: StatementResult | None = None
    error: Error | None = None
    #: A write whose commit was sent and then failed or was interrupted: it may
    #: have taken effect. Its state is ``ERROR``, and the exit code counts it as
    #: possibly committed.
    outcome_unknown: bool = False


def connect_all(
    config: Config,
    as_user: str | None,
    *,
    open_session: Opener,
    finding: Finding,
    attended: bool,
    need_identity: bool = False,
    env: Mapping[str, str] | None = None,
) -> list[Connection]:
    """Connect every selected target, in the config's order, before any statement runs.

    A target of a product `sql run` is not written for is refused here, with
    ``SOPULI-20006``, and never connected. For the others, the plan-time checks
    of UC-3 §2 run first: no run-as account is exit 9, the service account is
    ``SOPULI-20010``, and a run-as password that nobody can type (``attended``
    is false) or that is in a keyring this install cannot read is refused too.
    Each refuses the whole run before a socket opens.

    Then each target is connected. One that cannot be reached carries its
    error, and the others go on. When a target refuses a typed password, no
    later target that would use a typed password for the same user, by
    ``upper()``, is connected: those are :data:`NOT_ATTEMPTED`, so a mistyped
    password cannot lock the account across the fleet. Another user's typed
    password was never refused, and is asked for and tried as usual. Each
    session's user is checked against the service account, and one match
    refuses the whole run with ``SOPULI-20010``, with every session closed.
    The database identity is read only where
    ``need_identity`` asks for it, for a write's fingerprint.
    """
    env = os.environ if env is None else env
    targets = config.expanded_targets
    refused: dict[str, Error] = {}
    supported: list[ExpandedTarget] = []
    for target in targets:
        try:
            require_command(target.target, COMMAND)
        except DriverNotImplementedError as error:
            refused[target.name] = finding(error)
            continue
        refuse_service_account(target, as_user, env=env)
        supported.append(target)
    refuse_run_as_unattended(supported, as_user, attended=attended)

    connections: list[Connection] = []
    # Each user whose typed password a target refused, by upper(), with the
    # name as typed and the target that refused it.
    refused_typed: dict[str, tuple[str, str]] = {}
    try:
        for target in targets:
            if target.name in refused:
                connections.append(
                    Connection(target, ABSENT, error=refused[target.name], unsupported=True)
                )
                continue
            typed = run_as_prompts(target, as_user)
            who = run_as_user(target, as_user)
            if typed and who.upper() in refused_typed:
                user, refused_on = refused_typed[who.upper()]
                connections.append(_not_attempted(target, who, user, refused_on))
                continue
            one = _connect(
                target,
                as_user,
                open_session=open_session,
                finding=finding,
                env=env,
                need_identity=need_identity,
            )
            if typed and one.login_refused:
                refused_typed[who.upper()] = (who, target.name)
            connections.append(one)
    except BaseException:
        close_all(connections)
        raise
    return connections


def _not_attempted(target: ExpandedTarget, who: str, user: str, refused_on: str) -> Connection:
    """A target left alone because ``refused_on`` refused the password typed for
    ``user``, the same account by ``upper()`` as this target's ``who``."""
    return Connection(
        target,
        who,
        error=Error(
            category="policy",
            message=(
                f"the password typed for {user} was refused on {refused_on}, so it was "
                f"not tried here, where another failed login could lock {user}"
            ),
            hint="check the password and run it again",
        ),
        not_attempted=True,
    )


def _connect(
    target: ExpandedTarget,
    as_user: str | None,
    *,
    open_session: Opener,
    finding: Finding,
    env: Mapping[str, str],
    need_identity: bool,
) -> Connection:
    """One target's connection, its session user checked, and its identity
    read where ``need_identity`` asks."""
    who = run_as_user(target, as_user)
    try:
        session = open_session(target, as_user)
    except AuthenticationError as error:
        return Connection(target, who, error=finding(error), login_refused=True)
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
        identity = session.database_identity() if need_identity else None
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
        state = SKIPPED if one.unsupported else NOT_ATTEMPTED if one.not_attempted else ERROR
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


def planned_accounts(config: Config, as_user: str | None) -> list[tuple[str, str]]:
    """(run-as user, target) for each selected target, in sorted order, for the plan.

    A target of a product `sql run` is not written for is left out: nothing
    runs there, so it counts for neither ``max_targets`` nor
    ``confirm_environments``. Its result is still reported, as ``SKIPPED``.
    Pure: the config and ``--as`` decide it.
    """
    pairs: list[tuple[str, str]] = []
    for target in sorted(config.expanded_targets, key=lambda one: one.name):
        try:
            require_command(target.target, COMMAND)
        except DriverNotImplementedError:
            continue
        pairs.append((run_as_user(target, as_user), target.name))
    return pairs


def plan_fingerprint(
    connections: Sequence[Connection], statement: Statement, guard: RowGuard
) -> str:
    """The write's plan fingerprint (UC-3 §4), from what the connect step found.

    Every selected target counts, so a target that is added, or one that could
    not be reached in the dry run and can now, changes it. A target with no
    session has :data:`ABSENT` for its database identity.
    """
    return fingerprint(
        statement,
        guard,
        [
            PlannedTarget(
                one.target.name,
                one.target.target.dsn,
                one.run_as,
                *(one.identity or (ABSENT, ABSENT)),
            )
            for one in connections
        ],
    )


def refuse_unconnected(connections: Sequence[Connection]) -> None:
    """Refuse a real write where a selected target of a product `sql run` runs
    on did not connect (UC-3 §5).

    The write could not finish on that target, and the tool knows it before
    any statement runs, so it commits nowhere rather than on the targets
    before it. Every unconnected target is named, with its reason.
    """
    missing = [one for one in connections if one.session is None and not one.unsupported]
    if not missing:
        return
    reasons = "; ".join(
        f"{one.target.name} ({one.error.message if one.error is not None else 'no session'})"
        for one in missing
    )
    raise RefusedError(
        f"a real write needs every selected target connected, and these did not: {reasons}",
        hint="nothing was run; fix the connection, or leave the target out with a selector, "
        "and dry-run again",
    )


def plan_note(given: str, computed: str) -> str:
    """What a dry run says about a ``--plan`` it was given. It changes nothing."""
    said = "matches" if given.strip().lower() == computed else "does not match"
    return f"--plan {given} {said} this dry run's fingerprint"


def refuse_another_plan(given: str, computed: str) -> None:
    """Refuse a real write whose ``--plan`` is not this run's fingerprint (``SOPULI-20011``)."""
    if given.strip().lower() == computed:
        return
    raise PlanChangedError(
        f"--plan {given} is not this run's plan fingerprint, which is {computed}: the "
        "statement, the row guard or a target changed since the dry run",
        hint="nothing was run; run it again with --dry-run, check the targets and the row "
        "counts, and give the fingerprint it prints to --plan",
    )


def run_write(
    connections: Sequence[Connection],
    statement: Statement,
    guard: RowGuard,
    *,
    commit: bool,
    timeout_ms: int,
    finding: Finding,
    into: list[TargetOutcome] | None = None,
) -> list[TargetOutcome]:
    """Run a write on each target in sorted order (UC-3 §4, §5).

    Each outcome is appended to ``into`` as it is known, so a caller keeps
    the record when an interrupt, such as Ctrl-C, stops the run. Then the
    target in flight is :data:`ERROR`, because whether it committed is
    unknown, the rest are :data:`NOT_ATTEMPTED`, and the interrupt is raised
    again.

    A real run (``commit``) stops at the first target that does not end
    :data:`COMMITTED` or :data:`ROLLED_BACK`, whether its guard failed or its
    statement failed or timed out. The caller has already refused a real run
    with a target that did not connect (:func:`refuse_unconnected`), and the
    check here covers it too. The targets after it are
    :data:`NOT_ATTEMPTED`. A target of another product is :data:`SKIPPED` and
    does not stop it. A dry run never stops, so it reports every count. The
    caller closes the sessions.
    """
    outcomes: list[TargetOutcome] = [] if into is None else into
    ordered = sorted(connections, key=lambda each: each.target.name)
    stopped_at: str | None = None
    # The target whose statement is running, between its start and the
    # outcome being recorded.
    in_flight: str | None = None
    try:
        for one in ordered:
            if stopped_at is not None:
                stopped = _stopped(stopped_at)
                name = one.target.name
                outcomes.append(TargetOutcome(name, one.run_as, NOT_ATTEMPTED, error=stopped))
                continue
            in_flight = one.target.name
            outcome = _write_one(one, statement, guard, commit, timeout_ms, finding)
            outcomes.append(outcome)
            in_flight = None
            if commit and outcome.state not in (COMMITTED, ROLLED_BACK, SKIPPED):
                stopped_at = one.target.name
    except BaseException:
        # _write_one keeps every Exception, so this is Ctrl-C or an exit. The
        # targets already recorded stay as they are.
        at = in_flight or (ordered[len(outcomes) - 1].target.name if outcomes else "")
        for rest in ordered[len(outcomes) :]:
            if rest.target.name == in_flight:
                outcomes.append(_interrupted(rest, commit=commit))
            else:
                stopped = _stopped_by_interrupt(at)
                outcomes.append(
                    TargetOutcome(rest.target.name, rest.run_as, NOT_ATTEMPTED, error=stopped)
                )
        raise
    return outcomes


def _interrupted(one: Connection, *, commit: bool) -> TargetOutcome:
    said = "whether it committed is unknown" if commit else "a dry run commits nothing"
    return TargetOutcome(
        one.target.name,
        one.run_as,
        ERROR,
        error=Error(
            category="policy",
            message=f"interrupted while the statement ran here; {said}",
            hint="check the rows on this target before you run it again",
        ),
        outcome_unknown=commit,
    )


def _stopped_by_interrupt(at: str) -> Error:
    return Error(
        category="policy",
        message=f"not run: the run was interrupted at {at}",
        hint="dry-run the remaining targets again, and run again",
    )


def _write_one(
    one: Connection,
    statement: Statement,
    guard: RowGuard,
    commit: bool,
    timeout_ms: int,
    finding: Finding,
) -> TargetOutcome:
    name = one.target.name
    if one.session is None:
        state = SKIPPED if one.unsupported else NOT_ATTEMPTED if one.not_attempted else ERROR
        return TargetOutcome(name, one.run_as, state, error=one.error)
    session = one.session
    assert isinstance(session, StatementRunner)  # checked by _connect
    try:
        result = session.run_statement(
            statement, guard=guard, commit=commit, max_rows=0, timeout_ms=timeout_ms
        )
    except Exception as error:  # noqa: BLE001 -- a per-target finding
        found = finding(error)
        if not getattr(error, "commit_failed", False):
            return TargetOutcome(name, one.run_as, ERROR, error=found)
        # The commit was sent and raised: it may have taken effect.
        unknown = replace(
            found,
            message="the commit failed; whether it took effect is unknown, so check the "
            f"rows before running again: {found.message}",
        )
        return TargetOutcome(name, one.run_as, ERROR, error=unknown, outcome_unknown=True)
    if result.guard_passed is False:
        changed = "1 row" if result.row_count == 1 else f"{result.row_count} rows"
        return TargetOutcome(
            name,
            one.run_as,
            GUARD_FAILED,
            result=result,
            error=Error(
                category="policy",
                message=f"the statement changed {changed}, and the guard allows "
                f"{guard.describe()}; it was rolled back",
                hint="check the rows on this target, then dry-run again",
            ),
        )
    return TargetOutcome(name, one.run_as, COMMITTED if result.committed else ROLLED_BACK, result)


def _stopped(at: str) -> Error:
    return Error(
        category="policy",
        message=f"not run: the write stopped at {at}, which did not succeed",
        hint=f"fix the cause on {at}, dry-run the remaining targets again, and run again",
    )


def write_exit_code(outcomes: Sequence[TargetOutcome], *, dry_run: bool) -> int:
    """5 when every target is of a product `sql run` is not written for. The
    others decide the rest, and a skipped target is left out: 0 when each
    committed or rolled back a write that changed no row (on a dry run, passed
    its guard); otherwise 4 when some target committed, or may have, because
    its commit failed (on a dry run, passed), and 1 when none did."""
    if not outcomes:
        return int(ExitCode.SUCCESS)
    counted = [outcome for outcome in outcomes if outcome.state != SKIPPED]
    if not counted:
        return int(ExitCode.UNSUPPORTED_CAPABILITY)
    passed = sum(1 for outcome in counted if outcome.state in (COMMITTED, ROLLED_BACK))
    if passed == len(counted):
        return int(ExitCode.SUCCESS)
    # A commit whose outcome is unknown may have taken effect, so it counts.
    progressed = (
        passed
        if dry_run
        else sum(1 for one in counted if one.state == COMMITTED or one.outcome_unknown)
    )
    return int(ExitCode.PARTIAL if progressed else ExitCode.FAILURE)


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
