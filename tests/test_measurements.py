"""The measurement matrix agrees with the headers of the scripts in `sql/`.

Tier 0: reads Markdown, SQL comments and Python docstrings.

`docs/measurements.md` is the one place that says which script ran on which
release. It has one part for Oracle, for the scripts in `sql/oracle/`, and one
for PostgreSQL, for the scripts in `sql/postgres/`. Each script's header records
the same runs in more detail. This module checks that the two name the same
releases, so a run recorded in one and not the other fails here.

An Oracle release is written in full, five numbers: `19.32.0.0.0`, not `19c`. A
PostgreSQL release is two numbers: `16.15`, not `16`. A SQL script's header is
the comment block at the top, up to its first line that is not a comment. A
Python probe's header is its module docstring, read with `ast` so that the
probe, which imports a vendor client, is not imported. A release a header writes
after "Instant Client" or "libpq" is the client the probe ran with, and is not
compared. The same number may be a database elsewhere: Oracle Free 23.26.3.0.0
and Instant Client 23.26.3.0.0 are two products, and so are PostgreSQL 18.6 and
libpq 18.6.

A Python probe with rows of its own is checked like a SQL script. A probe with
no rows whose header names the SQL script of the same name reads that script's
output, as `06_verifier_reproduce.py` does, so it may name only releases that
the script's rows list.
"""

from __future__ import annotations

import ast
import functools
import re
from dataclasses import dataclass
from pathlib import Path

import pytest

from repo_files import requires_repo

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "docs" / "measurements.md"


@dataclass(frozen=True)
class Product:
    """One product's part of the matrix, and how its releases are written."""

    name: str
    scripts: Path
    #: The heading of the product's *Releases* table.
    releases_heading: str
    #: The marker on the line before the product's *Scripts* table.
    marker: str
    release: re.Pattern[str]
    #: A client release in a header. The words may wrap onto a new line, behind
    #: a SQL comment's `--`.
    client: re.Pattern[str]


#: A full Oracle release, such as `19.32.0.0.0` or `11.2.0.2.0`.
_ORACLE_RELEASE = r"\b\d{2}\.\d{1,2}\.\d\.\d\.\d\b"
#: A PostgreSQL release, such as `16.15` or `18.6`. Not part of a longer number,
#: so `3.13.12` and `19.3.0.0.0` hold none. A full stop after it ends a sentence.
_POSTGRES_RELEASE = r"(?<![\d.])\d{2}\.\d{1,2}(?!\d|\.\d)"

ORACLE = Product(
    name="oracle",
    scripts=ROOT / "sql" / "oracle",
    releases_heading="## Releases",
    marker="<!-- measurements: scripts -->",
    release=re.compile(_ORACLE_RELEASE),
    client=re.compile(r"Instant(?:\s|--)+Client(?:\s|--)+`?" + _ORACLE_RELEASE + "`?"),
)
POSTGRES = Product(
    name="postgres",
    scripts=ROOT / "sql" / "postgres",
    releases_heading="## PostgreSQL releases",
    marker="<!-- measurements: postgres scripts -->",
    release=re.compile(_POSTGRES_RELEASE),
    client=re.compile(r"libpq(?:\s|--)+`?" + _POSTGRES_RELEASE + "`?"),
)
PRODUCTS = (ORACLE, POSTGRES)

#: Every script and probe whose header is checked, with its product.
PROBES = [
    (product, script)
    for product in PRODUCTS
    for script in sorted([*product.scripts.glob("*.sql"), *product.scripts.glob("*.py")])
]


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
def _rows(product: Product) -> tuple[tuple[str, ...], ...]:
    """The cells of each body row of the product's *Scripts* table."""
    lines = MATRIX.read_text(encoding="utf-8").splitlines()
    start = lines.index(product.marker) + 1
    rows = []
    for line in lines[start + 2 :]:
        if not line.startswith("|"):
            break
        rows.append(tuple(cell.strip() for cell in line.strip("|").split("|")))
    return tuple(rows)


def _releases_section(product: Product, text: str) -> tuple[set[str], str]:
    """The releases the product's *Releases* table lists, and the text below it."""
    _, rest = text.split(product.releases_heading + "\n", 1)
    table, below = rest.split("\n## ", 1)
    # Up to the next product's part, so one product's text is not read as the
    # other's.
    for other in PRODUCTS:
        if other is not product:
            below = below.split(other.releases_heading + "\n", 1)[0]
    return set(re.findall(r"^\| `([^`]+)` \|", table, re.MULTILINE)), below


def _released(product: Product, text: str) -> set[str]:
    return set(product.release.findall(text))


def _databases(product: Product, header: str) -> set[str]:
    """The releases a header names, without the client it ran with."""
    return _released(product, product.client.sub("", header))


def _matrix(product: Product) -> dict[str, set[str]]:
    """Each script in the product's *Scripts* table, with the releases it lists."""
    found: dict[str, set[str]] = {}
    for script, release, *_ in _rows(product):
        found.setdefault(script.strip("`"), set()).update(_released(product, release))
    return found


def _disagreement(
    product: Product, name: str, header: str, matrix: dict[str, set[str]]
) -> str | None:
    """How a script's header and the matrix disagree, or ``None`` if they agree.

    A Python probe with no rows of its own, whose header names a SQL script with
    the same name, reads that script's output. It may name only releases that the
    script's rows list. Every other script must name the same releases as its
    rows.
    """
    in_header = _databases(product, header)
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


@pytest.mark.parametrize("product", PRODUCTS, ids=lambda p: p.name)
def test_the_scripts_table_is_found(product: Product) -> None:
    requires_repo(MATRIX)
    assert len(_rows(product)) > 0, f"no rows after {product.marker} in {MATRIX.name}"


@pytest.mark.parametrize("product", PRODUCTS, ids=lambda p: p.name)
def test_every_row_names_one_release_and_a_date(product: Product) -> None:
    requires_repo(MATRIX)
    for row in _rows(product):
        assert len(row) == 5, f"expected 5 cells: {row}"
        script, release, date, _issue, result = row
        released = _released(product, release)
        assert len(released) == 1, f"{script}: one release per row, got {release!r}"
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", date), f"{script} {release}: date {date!r}"
        assert result, f"{script} {release}: empty result"


@pytest.mark.parametrize(
    ("product", "script"), PROBES, ids=[f"{p.name}/{s.name}" for p, s in PROBES]
)
def test_a_script_header_and_the_matrix_name_the_same_releases(
    product: Product, script: Path
) -> None:
    requires_repo(MATRIX)
    problem = _disagreement(product, script.name, _header(script), _matrix(product))
    assert problem is None, problem


@pytest.mark.parametrize(
    ("product", "header", "databases"),
    [
        (ORACLE, "run on 23.26.2.0.0, with Instant Client 23.26.3.0.0", {"23.26.2.0.0"}),
        (ORACLE, "with Instant\nClient 23.26.3.0.0 for Windows", set()),
        (ORACLE, "-- with Instant\n-- Client `23.26.3.0.0`", set()),
        (ORACLE, "run on 23.26.3.0.0, with Instant Client 23.26.3.0.0", {"23.26.3.0.0"}),
        (POSTGRES, "run on 18.6, with libpq 18.4", {"18.6"}),
        (POSTGRES, "-- psql and\n-- libpq `18.6`, on 18.6", {"18.6"}),
        (POSTGRES, "Python 3.13.12, psycopg 3.3.6, on 2026-10-25", set()),
        (POSTGRES, "Oracle 19.3.0.0.0 is not a PostgreSQL release", set()),
        (POSTGRES, "As on 13.23. Run on 17.11.", {"13.23", "17.11"}),
    ],
    ids=[
        "client-dropped",
        "wrapped",
        "sql-comment-and-backticks",
        "database-at-the-same-number",
        "libpq-dropped",
        "libpq-wrapped-at-the-same-number",
        "longer-numbers-are-not-releases",
        "an-oracle-release-is-not-one",
        "a-release-that-ends-a-sentence",
    ],
)
def test_a_client_is_told_from_a_database_by_its_words(
    product: Product, header: str, databases: set[str]
) -> None:
    assert _databases(product, header) == databases


MATRIX_06 = {"06_x.sql": {"19.3.0.0.0", "21.3.0.0.0"}, "07_x.sql": {"23.26.3.0.0"}}


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
        ("07_x.sql", "run on Free 23.26.3.0.0, with Instant Client 23.26.3.0.0", True),
        ("07_x.sql", "with Instant Client 23.26.3.0.0 only", False),
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
        "a-database-at-a-clients-number",
        "only-the-client-named",
    ],
)
def test_the_comparison(name: str, header: str, agrees: bool) -> None:
    """Each rule, on made-up headers, so a rule that always passes fails here.

    A release written after "Instant Client" is never compared."""
    assert (_disagreement(ORACLE, name, header, MATRIX_06) is None) is agrees


def test_a_byte_order_mark_is_not_part_of_the_header(tmp_path: Path) -> None:
    bom = chr(0xFEFF)
    probe = tmp_path / "15_x.py"
    probe.write_bytes(f'{bom}"""Run on 19.3.0.0.0."""\n'.encode())
    script = tmp_path / "15_x.sql"
    script.write_bytes(f"{bom}-- Run on 19.3.0.0.0.\nSELECT 1 FROM dual;\n".encode())

    assert _header(probe) == "Run on 19.3.0.0.0."
    assert _header(script) == "-- Run on 19.3.0.0.0."


@pytest.mark.parametrize("product", PRODUCTS, ids=lambda p: p.name)
def test_the_matrix_names_only_scripts_that_exist(product: Product) -> None:
    requires_repo(MATRIX)
    requires_repo(product.scripts)
    missing = sorted(name for name in _matrix(product) if not (product.scripts / name).is_file())
    folder = product.scripts.relative_to(ROOT).as_posix()
    assert not missing, f"{MATRIX.name} lists scripts that are not in {folder}/: {missing}"


@pytest.mark.parametrize("product", PRODUCTS, ids=lambda p: p.name)
def test_every_release_used_is_in_the_releases_table(product: Product) -> None:
    requires_repo(MATRIX)
    listed, below = _releases_section(product, MATRIX.read_text(encoding="utf-8"))
    # Clients too: a release written after "Instant Client" or "libpq" needs its
    # own row, which says what product it is.
    used = _released(product, below)
    missing = sorted(used - listed)
    assert not missing, f"releases with no row in {product.releases_heading}: {missing}"
