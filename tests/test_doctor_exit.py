"""`doctor`'s exit code when a target answers and is then refused (#1062).

Tier 0: the rule reads the entries `doctor` builds, so no database is needed.
The live refusals, `SOPULI-20007` and `SOPULI-20008`, are in
`tests/driver/test_postgres_doctor.py`.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.cli import _doctor_exit, _refused_for_setup
from sopuli.exit_codes import ExitCode


def _entry(*, reachable: bool, category: str | None = None) -> dict[str, Any]:
    entry: dict[str, Any] = {"target": "pg-dev", "reachable": reachable}
    if category is not None:
        entry["error"] = {"category": category, "message": "refused", "code": "SOPULI-20007"}
    return entry


@pytest.mark.parametrize(
    ("entry", "refused"),
    [
        (_entry(reachable=True, category="config"), True),
        (_entry(reachable=True, category="database"), False),
        (_entry(reachable=True), False),
        (_entry(reachable=False, category="config"), False),
        (_entry(reachable=False, category="connectivity"), False),
    ],
)
def test_only_a_config_error_on_a_reached_target_is_a_refusal(
    entry: dict[str, Any], refused: bool
) -> None:
    """A `database` error on a target that answered, such as a view the account
    cannot read, is a finding about grants. A target that never answered is
    exit 1's case, whatever its error says."""
    assert _refused_for_setup(entry) is refused


@pytest.mark.parametrize(("matches", "refused"), [(False, True), (True, False)])
def test_a_scope_the_target_asserts_and_is_not_is_a_refusal(matches: bool, refused: bool) -> None:
    """`doctor` reports an assertion that does not match as `asserted` rather
    than raising it. Every other verb refuses that target at exit 9."""
    entry = _entry(reachable=True)
    entry["asserted"] = {"scope": "pdb", "container": "ORDERS", "matches": matches}
    assert _refused_for_setup(entry) is refused


def test_a_refused_target_is_exit_9() -> None:
    assert _doctor_exit((), failed=0, refused=1) == ExitCode.CONFIG_INVALID


def test_a_refusal_wins_over_an_unreachable_target_and_vault() -> None:
    """Both are reported in the document. The exit names the one a person
    fixes in the configuration."""
    assert _doctor_exit((), failed=2, vaults_down=1, refused=1) == ExitCode.CONFIG_INVALID


def test_with_no_refusal_the_exit_is_as_before() -> None:
    assert _doctor_exit((), failed=0) == ExitCode.SUCCESS
    assert _doctor_exit((), failed=1) == ExitCode.FAILURE
    assert _doctor_exit((), failed=0, vaults_down=1) == ExitCode.FAILURE
