"""The measurement matrix agrees with the headers of the scripts in `sql/oracle/`.

Tier 0: reads Markdown, SQL comments and Python docstrings.

`docs/measurements.md` is the one place that says which script ran on which
Oracle release. Each script's header records the same runs in more detail. This
module checks that the two name the same releases, so a run recorded in one and
not the other fails here.

A release is written in full, five numbers: `19.32.0.0.0`, not `19c`. A SQL
script's header is the comment block at the top, up to its first line that is
not a comment. A Python probe's header is its module docstring, read with `ast`
so that the probe, which imports `oracledb`, is not imported. A release that the
*Releases* table marks "Not a database", such as an Instant Client, is not
compared.

A Python probe with rows of its own is checked like a SQL script. A probe with
no rows whose header names the SQL script of the same name reads that script's
output, as `06_verifier_reproduce.py` does, so it may name only releases that
the script's rows list.
"""

from __future__ import annotations

import ast
import functools
import re
from pathlib import Path

import pytest

from repo_files import requires_repo

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "docs" / "measurements.md"
SCRIPTS = ROOT / "sql" / "oracle"

#: A full Oracle release, such as `19.32.0.0.0` or `11.2.0.2.0`.
RELEASE = re.compile(r"\b\d{2}\.\d{1,2}\.\d\.\d\.\d\b")
#: The marker on the line before the *Scripts* table.
MARKER = "<!-- measurements: scripts -->"
#: What the *Releases* table says of a release that is a client.
NOT_A_DATABASE = "Not a database"
#: Every script and probe whose header is checked.
PROBES = sorted([*SCRIPTS.glob("*.sql"), *SCRIPTS.glob("*.py")])


def _header(script: Path) -> str:
    """A SQL script's top comment block, or a Python probe's docstring."""
    # `utf-8-sig`, so that a byte order mark an editor added is not read as text.
    text = script.read_text(encoding="utf-8-sig")
    if script.suffix == ".py":
        return ast.get_docstring(ast.parse(text)) or ""
    lines = []
    for line in text.splitlines():
        if not line.startswith("--"):
            break
        lines.append(line)
    return "\n".join(lines)


@functools.cache
def _rows() -> tuple[tuple[str, ...], ...]:
    """The cells of each body row of the *Scripts* table."""
    lines = MATRIX.read_text(encoding="utf-8").splitlines()
    start = lines.index(MARKER) + 1
    rows = []
    for line in lines[start + 2 :]:
        if not line.startswith("|"):
            break
        rows.append(tuple(cell.strip() for cell in line.strip("|").split("|")))
    return tuple(rows)


@functools.cache
def _clients() -> frozenset[str]:
    """The releases the *Releases* table marks as a client, not a database."""
    _, rest = MATRIX.read_text(encoding="utf-8").split("## Releases\n", 1)
    releases = rest.split("\n## ", 1)[0]
    return frozenset(
        match.group(1)
        for match in re.finditer(r"^\| `([^`]+)` \|(.*)$", releases, re.MULTILINE)
        if NOT_A_DATABASE in match.group(2)
    )


def _released(text: str) -> set[str]:
    return set(RELEASE.findall(text))


def _matrix() -> dict[str, set[str]]:
    """Each script in the *Scripts* table, with the releases it lists."""
    found: dict[str, set[str]] = {}
    for script, release, *_ in _rows():
        found.setdefault(script.strip("`"), set()).update(_released(release))
    return found


def _disagreement(
    name: str, header: str, matrix: dict[str, set[str]], clients: frozenset[str]
) -> str | None:
    """How a script's header and the matrix disagree, or ``None`` if they agree.

    A Python probe with no rows of its own, whose header names a SQL script with
    the same name, reads that script's output. It may name only releases that the
    script's rows list. Every other script must name the same releases as its
    rows.
    """
    in_header = _released(header) - clients
    companion = name.removesuffix(".py") + ".sql"
    if name.endswith(".py") and name not in matrix and companion in header:
        ran = matrix.get(companion, set())
        if in_header <= ran:
            return None
        return (
            f"{name} reads the output of {companion}, and names "
            f"{sorted(in_header - ran)} that {MATRIX.name} does not list for it."
        )
    in_matrix = matrix.get(name, set())
    if in_header == in_matrix:
        return None
    return (
        f"{name}: the header names {sorted(in_header - in_matrix)} that "
        f"{MATRIX.name} does not, and {MATRIX.name} names {sorted(in_matrix - in_header)} "
        "that the header does not. Record a run in both."
    )


def test_the_scripts_table_is_found() -> None:
    requires_repo(MATRIX)
    assert len(_rows()) > 0, f"no rows after {MARKER} in {MATRIX.name}"


def test_every_row_names_one_release_and_a_date() -> None:
    requires_repo(MATRIX)
    for row in _rows():
        assert len(row) == 5, f"expected 5 cells: {row}"
        script, release, date, _issue, result = row
        assert len(_released(release)) == 1, f"{script}: one release per row, got {release!r}"
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", date), f"{script} {release}: date {date!r}"
        assert result, f"{script} {release}: empty result"


@pytest.mark.parametrize("script", PROBES, ids=lambda p: p.name)
def test_a_script_header_and_the_matrix_name_the_same_releases(script: Path) -> None:
    requires_repo(MATRIX)
    problem = _disagreement(script.name, _header(script), _matrix(), _clients())
    assert problem is None, problem


def test_the_releases_table_marks_the_instant_client() -> None:
    requires_repo(MATRIX)
    assert "23.26.3.0.0" in _clients()
    assert "23.26.2.0.0" not in _clients()


MATRIX_06 = {"06_x.sql": {"19.3.0.0.0", "21.3.0.0.0"}}
CLIENTS = frozenset({"23.26.3.0.0"})


@pytest.mark.parametrize(
    ("name", "header", "agrees"),
    [
        ("14_x.py", "run on 19.3.0.0.0, Instant Client 23.26.3.0.0", False),
        ("06_x.sql", "run on 19.3.0.0.0 and 21.3.0.0.0", True),
        ("06_x.sql", "run on 19.3.0.0.0", False),
        ("06_x.py", "reads 06_x.sql's output, from 19.3.0.0.0", True),
        ("06_x.py", "reads 06_x.sql's output", True),
        ("06_x.py", "reads 06_x.sql's output, from 18.4.0.0.0", False),
        ("06_x.py", "its own run on 19.3.0.0.0, with Instant Client `23.26.3.0.0`", False),
        ("06_x.py", "names no script and no release", True),
    ],
    ids=[
        "own-rows-missing",
        "sql-agrees",
        "sql-row-unrecorded",
        "companion-subset",
        "companion-names-none",
        "companion-names-another",
        "same-name-but-not-a-companion",
        "no-rows-no-releases",
    ],
)
def test_the_comparison(name: str, header: str, agrees: bool) -> None:
    """Each rule, on made-up headers, so a rule that always passes fails here.

    An Instant Client release is never compared, however it is written."""
    assert (_disagreement(name, header, MATRIX_06, CLIENTS) is None) is agrees


def test_a_byte_order_mark_is_not_part_of_the_header(tmp_path: Path) -> None:
    probe = tmp_path / "15_x.py"
    probe.write_bytes('﻿"""Run on 19.3.0.0.0."""\n'.encode())
    script = tmp_path / "15_x.sql"
    script.write_bytes("﻿-- Run on 19.3.0.0.0.\nSELECT 1 FROM dual;\n".encode())

    assert _header(probe) == "Run on 19.3.0.0.0."
    assert _header(script) == "-- Run on 19.3.0.0.0."


def test_the_matrix_names_only_scripts_that_exist() -> None:
    requires_repo(MATRIX)
    requires_repo(SCRIPTS)
    missing = sorted(name for name in _matrix() if not (SCRIPTS / name).is_file())
    assert not missing, f"{MATRIX.name} lists scripts that are not in sql/oracle/: {missing}"


def test_every_release_used_is_in_the_releases_table() -> None:
    requires_repo(MATRIX)
    text = MATRIX.read_text(encoding="utf-8")
    _, rest = text.split("## Releases\n", 1)
    releases, below = rest.split("\n## ", 1)
    listed = {m.group(1) for m in re.finditer(r"^\| `([^`]+)` \|", releases, re.MULTILINE)}
    used = _released(below)
    assert used <= listed, f"releases with no row in ## Releases: {sorted(used - listed)}"
