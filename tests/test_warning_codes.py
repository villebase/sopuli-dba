"""The `SOPULI-` codes are one series each, with no number used twice.

Tier 0: reads `src/` and `docs/design/03-json-output.md`, and opens no socket.

J3 (`03-json-output.md` §3) makes the warning codes one flat series,
`SOPULI-W001` upwards, and the tool's own error codes another, from
`SOPULI-20001`. A pull request takes the next free number. Two pull requests
written at the same time often take the same one, and nothing at merge time
says so: the second constant shadows nothing, and a dict literal with a repeated
key keeps the last value without a word. So this checks, for each series:

* no two constants in `src/` hold one code;
* the numbers run from the first with no gap;
* the document's table has each code once, and the same codes as `src/`;
* every code written anywhere in `src/` is in the table.

The pull request that merges second then fails on its rebase, and takes the next
free number before it merges.

It is in `ci.yml`'s `docs` job as well as the main lanes, because
`03-json-output.md` is on the prose list: a pull request that changes only the
table would otherwise run no test that reads it.
"""

from __future__ import annotations

import ast
import re
from collections import defaultdict
from pathlib import Path

import pytest

from repo_files import requires_repo
from sopuli.diagnostics import WARNINGS

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "sopuli"
DOC = ROOT / "docs" / "design" / "03-json-output.md"

#: Each series: its pattern, its first number, and the heading of its table.
SERIES = {
    "warning": (re.compile(r"SOPULI-W(\d{3})"), 1, "### Diagnostic codes"),
    "error": (re.compile(r"SOPULI-(2\d{4})"), 20001, "### Error codes"),
}


def _constants(pattern: re.Pattern[str]) -> dict[str, list[str]]:
    """Each code assigned to a name in `src/`, and every name it is assigned to.

    Assignments only, so an import that re-exports a code, as `diagnostics.py`
    does for `SOPULI-W004`, is not counted as a second constant.
    """
    found: dict[str, list[str]] = defaultdict(list)
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                targets, value = node.targets, node.value
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                targets, value = [node.target], node.value
            else:
                continue
            if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
                continue
            if not pattern.fullmatch(value.value):
                continue
            for target in targets:
                if isinstance(target, ast.Name):
                    where = f"{path.relative_to(ROOT).as_posix()}:{node.lineno}"
                    found[value.value].append(f"{target.id} ({where})")
    return found


def _written(pattern: re.Pattern[str]) -> dict[str, str]:
    """Every code written anywhere in `src/`, with the first place it appears."""
    found: dict[str, str] = {}
    for path in sorted(SRC.rglob("*.py")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for match in pattern.finditer(line):
                found.setdefault(match.group(0), f"{path.relative_to(ROOT).as_posix()}:{number}")
    return found


def _table(heading: str, pattern: re.Pattern[str]) -> list[str]:
    """The codes in the first column of the table under ``heading``, in order."""
    requires_repo(DOC)
    lines = DOC.read_text(encoding="utf-8").splitlines()
    start = lines.index(heading)
    codes = []
    for line in lines[start + 1 :]:
        if line.startswith("#"):
            break
        cell = line.split("|")[1].strip() if line.startswith("|") else ""
        match = pattern.fullmatch(cell.strip("`"))
        if match:
            codes.append(match.group(0))
    return codes


def _number(code: str, pattern: re.Pattern[str]) -> int:
    match = pattern.fullmatch(code)
    assert match is not None, code
    return int(match.group(1))


@pytest.mark.parametrize("series", sorted(SERIES))
def test_no_two_constants_hold_one_code(series: str) -> None:
    pattern, _, _ = SERIES[series]
    shared = {code: names for code, names in _constants(pattern).items() if len(names) > 1}
    assert not shared, (
        "two constants hold one code; the pull request that merged second takes the "
        f"next free number: {shared}"
    )


@pytest.mark.parametrize("series", sorted(SERIES))
def test_the_numbers_have_no_gap(series: str) -> None:
    pattern, first, heading = SERIES[series]
    numbers = sorted(_number(code, pattern) for code in _table(heading, pattern))
    assert numbers == list(range(first, first + len(numbers))), numbers


@pytest.mark.parametrize("series", sorted(SERIES))
def test_the_table_lists_each_code_once(series: str) -> None:
    pattern, _, heading = SERIES[series]
    codes = _table(heading, pattern)
    repeated = sorted({code for code in codes if codes.count(code) > 1})
    assert not repeated, f"rows repeated under {heading!r}: {repeated}"


@pytest.mark.parametrize("series", sorted(SERIES))
def test_the_table_and_the_source_hold_the_same_codes(series: str) -> None:
    pattern, _, heading = SERIES[series]
    table = set(_table(heading, pattern))
    defined = set(_constants(pattern))
    assert table - defined == set(), f"in the table, with no constant in src/: {table - defined}"
    assert defined - table == set(), f"a constant in src/, not in the table: {defined - table}"


@pytest.mark.parametrize("series", sorted(SERIES))
def test_every_code_in_the_source_is_in_the_table(series: str) -> None:
    """A code in a message or a comment is as visible to a reader as a constant."""
    pattern, _, heading = SERIES[series]
    table = set(_table(heading, pattern))
    unknown = {code: where for code, where in _written(pattern).items() if code not in table}
    assert not unknown, f"codes in src/ that the table does not have: {unknown}"


def test_the_registry_describes_every_warning_in_the_table() -> None:
    """`WARNINGS` is what a run uses to describe a code; the table is what a reader sees."""
    pattern, _, heading = SERIES["warning"]
    assert set(WARNINGS) == set(_table(heading, pattern))
