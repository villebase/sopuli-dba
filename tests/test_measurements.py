"""The measurement matrix agrees with the headers of the scripts in `sql/oracle/`.

Tier 0: reads Markdown, SQL comments and Python docstrings.

`docs/measurements.md` is the one place that says which script ran on which
Oracle release. Each script's header records the same runs in more detail. This
module checks that the two name the same releases, so a run recorded in one and
not the other fails here.

A release is written in full, five numbers: `19.32.0.0.0`, not `19c`. A SQL
script's header is the comment block at the top, up to its first line that is
not a comment. A Python probe's header is its module docstring, read with `ast`
so that the probe, which imports `oracledb`, is not imported. An Instant Client
release in a header is the client's, not a database's, so it is not compared.

A Python probe with rows of its own is checked like a SQL script. A probe with
no rows that has a SQL script of the same name reads that script's output, as
`06_verifier_reproduce.py` does, so it may name only releases that the script's
rows list.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from repo_files import requires_repo

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "docs" / "measurements.md"
SCRIPTS = ROOT / "sql" / "oracle"

#: A full Oracle release, such as `19.32.0.0.0` or `11.2.0.2.0`.
RELEASE = re.compile(r"\b\d{2}\.\d{1,2}\.\d\.\d\.\d\b")
#: The client a probe ran with, such as `Instant Client 23.26.3.0.0`.
CLIENT = re.compile(r"Instant\s+Client\s+" + RELEASE.pattern)
#: The marker on the line before the *Scripts* table.
MARKER = "<!-- measurements: scripts -->"
#: Every script and probe whose header is checked.
PROBES = sorted([*SCRIPTS.glob("*.sql"), *SCRIPTS.glob("*.py")])


def _header(script: Path) -> str:
    """A SQL script's top comment block, or a Python probe's docstring."""
    text = script.read_text(encoding="utf-8")
    if script.suffix == ".py":
        header = ast.get_docstring(ast.parse(text)) or ""
    else:
        lines = []
        for line in text.splitlines():
            if not line.startswith("--"):
                break
            lines.append(line)
        header = "\n".join(lines)
    return CLIENT.sub("", header)


def _rows() -> list[list[str]]:
    """The cells of each body row of the *Scripts* table."""
    lines = MATRIX.read_text(encoding="utf-8").splitlines()
    start = lines.index(MARKER) + 1
    rows = []
    for line in lines[start + 2 :]:
        if not line.startswith("|"):
            break
        rows.append([cell.strip() for cell in line.strip("|").split("|")])
    return rows


def _released(text: str) -> set[str]:
    return set(RELEASE.findall(text))


def _matrix() -> dict[str, set[str]]:
    """Each script in the *Scripts* table, with the releases it lists."""
    found: dict[str, set[str]] = {}
    for script, release, *_ in _rows():
        found.setdefault(script.strip("`"), set()).update(_released(release))
    return found


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
    in_header = _released(_header(script))
    matrix = _matrix()
    companion = script.with_suffix(".sql")
    if script.suffix == ".py" and script.name not in matrix and companion.is_file():
        ran = matrix.get(companion.name, set())
        assert in_header <= ran, (
            f"{script.name} reads the output of {companion.name}, and names "
            f"{sorted(in_header - ran)} that {MATRIX.name} does not list for it."
        )
        return
    in_matrix = matrix.get(script.name, set())
    assert in_header == in_matrix, (
        f"{script.name}: the header names {sorted(in_header - in_matrix)} that "
        f"{MATRIX.name} does not, and {MATRIX.name} names {sorted(in_matrix - in_header)} "
        "that the header does not. Record a run in both."
    )


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
