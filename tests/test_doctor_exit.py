"""`doctor`'s exit code when a target answers and is then refused (#1062).

Tier 0: the rule reads the entry `doctor` builds and the exception it caught,
so no database is needed. The live refusals are in
`tests/driver/test_postgres_doctor.py` (`SOPULI-20007`, `SOPULI-20008`) and
`tests/driver/test_oracle_doctor.py` (a scope the target asserts and is not).
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.cli import _doctor_exit, _refused_for_setup
from sopuli.driver.protocol import DriverError
from sopuli.exit_codes import ExitCode


class _RefusedError(DriverError):
    """A refusal that asks for exit 9, as `SOPULI-20007` does."""

    category = "config"
    exit_code = ExitCode.CONFIG_INVALID


class _ConfigWithAnotherExitError(DriverError):
    """A `config` error whose own exit is not 9: the category alone does not decide."""

    category = "config"
    exit_code = ExitCode.USAGE


class _UnreadableError(DriverError):
    """A dictionary view the account cannot read: a finding about grants."""

    category = "database"


def _entry(*, reachable: bool) -> dict[str, Any]:
    return {"target": "pg-dev", "reachable": reachable}


@pytest.mark.parametrize(
    ("reachable", "error", "refused"),
    [
        (True, _RefusedError("refused"), True),
        (True, _ConfigWithAnotherExitError("refused"), False),
        (True, _UnreadableError("ORA-00942"), False),
        (True, None, False),
        (False, _RefusedError("an admin password that is not set"), False),
        (False, _UnreadableError("ORA-12541"), False),
    ],
)
def test_only_an_error_that_exits_9_on_a_reached_target_is_a_refusal(
    reachable: bool, error: Exception | None, refused: bool
) -> None:
    """The exception's own `exit_code` decides, not the serialised category. A
    target that was not reached is exit 1's case whatever its error asks for:
    the exception cannot tell a server's refusal at login from a failure before
    the server was asked."""
    assert _refused_for_setup(_entry(reachable=reachable), error) is refused


def test_an_assertion_that_fails_before_an_audit_error_is_still_a_refusal() -> None:
    """`doctor --check-privileges` whose audit fails after the scope was read:
    the entry carries no scope, so the assertion's answer is passed in."""
    entry = _entry(reachable=True)
    assert _refused_for_setup(entry, _UnreadableError("ORA-00942"), holds=False) is True
    assert _refused_for_setup(entry, _UnreadableError("ORA-00942"), holds=True) is False


@pytest.mark.parametrize(("matches", "refused"), [(False, True), (True, False)])
def test_a_scope_the_target_asserts_and_is_not_is_a_refusal(matches: bool, refused: bool) -> None:
    """`doctor` reports an assertion that does not match as `asserted` rather
    than raising it. A mutating verb refuses that target at exit 9."""
    entry = _entry(reachable=True)
    entry["asserted"] = {"scope": "pdb", "container": "ORDERS", "matches": matches}
    assert _refused_for_setup(entry) is refused


def test_a_refused_target_is_exit_9() -> None:
    assert _doctor_exit((), unreachable=0, refused=1) == ExitCode.CONFIG_INVALID


def test_a_refusal_wins_over_an_unreachable_target_and_vault() -> None:
    """Both are reported in the document. The exit names the one a person
    fixes in the configuration."""
    assert _doctor_exit((), unreachable=2, vaults_down=1, refused=1) == ExitCode.CONFIG_INVALID


def test_with_no_refusal_the_exit_is_as_before() -> None:
    assert _doctor_exit((), unreachable=0) == ExitCode.SUCCESS
    assert _doctor_exit((), unreachable=1) == ExitCode.FAILURE
    assert _doctor_exit((), unreachable=0, vaults_down=1) == ExitCode.FAILURE
