"""The statement check's T-SQL dialect, for SQL Server targets (#1730). Tier 0, pure."""

from __future__ import annotations

import pytest

from sopuli.sql.statement import (
    Dialect,
    StatementKind,
    StatementRefusedError,
    classify,
    classify_for,
)

MS = Dialect.MSSQL
ORA = Dialect.ORACLE
PG = Dialect.POSTGRESQL
MY = Dialect.MYSQL


@pytest.mark.parametrize(
    ("raw", "keyword", "kind"),
    [
        ("SELECT name FROM sys.databases;", "SELECT", StatementKind.READ),
        ("WITH c AS (SELECT 1 AS a) SELECT a FROM c", "WITH", StatementKind.READ),
        ("UPDATE acme.dbo.settings SET v = N'Y' WHERE k = 'x';", "UPDATE", StatementKind.WRITE),
        ("INSERT INTO acme.dbo.t VALUES (1)", "INSERT", StatementKind.WRITE),
        ("DELETE FROM acme.dbo.t WHERE k = 1", "DELETE", StatementKind.WRITE),
        (
            "MERGE acme.dbo.t AS t USING acme.dbo.s AS s ON t.k = s.k "
            "WHEN MATCHED THEN UPDATE SET v = s.v;",
            "MERGE",
            StatementKind.WRITE,
        ),
    ],
)
def test_the_tsql_dialect_accepts(raw: str, keyword: str, kind: StatementKind) -> None:
    statement = classify(raw, dialect=MS)
    assert (statement.keyword, statement.kind) == (keyword, kind)


@pytest.mark.parametrize(
    "raw",
    [
        "EXEC sp_who",
        "EXECUTE AS LOGIN = 'acme_owner'",
        "DECLARE @x int",
        "SET XACT_ABORT OFF",
        "USE acme",
        "BEGIN TRANSACTION",
        "TRUNCATE TABLE acme.dbo.t",
        "GRANT CONTROL SERVER TO dba_alpha",
        "UPDATE acme.dbo.t SET a = 1; DELETE FROM acme.dbo.u",
    ],
)
def test_the_tsql_dialect_refuses(raw: str) -> None:
    with pytest.raises(StatementRefusedError):
        classify(raw, dialect=MS)


def test_block_comments_nest() -> None:
    """The comment ends at its own `*/`, so the DELETE inside is not read."""
    raw = "/* /* */ DELETE FROM t */ SELECT 1"
    assert classify(raw, dialect=MS).keyword == "SELECT"
    assert classify(raw, dialect=ORA).keyword == "DELETE"


def test_a_nested_comment_hides_a_select_the_oracle_way() -> None:
    raw = "/* /* */ SELECT 1 */ DELETE FROM t"
    assert classify(raw, dialect=MS).kind is StatementKind.WRITE
    assert classify(raw, dialect=ORA).kind is StatementKind.READ
    _refused_as_read_differently(raw, [ORA, MS], "Oracle")


def _refused_as_read_differently(raw: str, dialects: list[Dialect], other: str) -> None:
    with pytest.raises(StatementRefusedError, match="reads differently on") as refused:
        classify_for(raw, dialects)
    assert other in refused.value.message
    assert "SQL Server" in refused.value.message


@pytest.mark.parametrize(
    ("raw", "text"),
    [
        ("SELECT [a--b] FROM t;", "SELECT [a--b] FROM t"),
        ("SELECT [a]]--] FROM t; -- note", "SELECT [a]]--] FROM t"),
        ("SELECT [a/*b] FROM t;", "SELECT [a/*b] FROM t"),
        ("SELECT 'it''s -- not' FROM t;", "SELECT 'it''s -- not' FROM t"),
        ("SELECT N'x -- y' FROM t;", "SELECT N'x -- y' FROM t"),
        ("SELECT 'a\\' FROM t;", "SELECT 'a\\' FROM t"),
        ('SELECT "a--b" FROM t;', 'SELECT "a--b" FROM t'),
        ("SELECT a FROM #t;", "SELECT a FROM #t"),
        ("SELECT 1 /* a /* b */ c */;", "SELECT 1 /* a /* b */ c */"),
    ],
)
def test_literals_and_names_are_read_whole(raw: str, text: str) -> None:
    """A `--` or a `/*` inside a name or a literal is not a comment, so the
    terminator after it is seen and removed."""
    assert classify(raw, dialect=MS).text == text


def test_a_bracketed_name_reads_differently_the_oracle_way() -> None:
    """Oracle reads `--b] FROM t; -- note` as one comment, sees no terminator,
    and so keeps the `;`, which it refuses."""
    with pytest.raises(StatementRefusedError, match="read the Oracle way"):
        classify_for("SELECT [a--b] FROM t; -- note", [ORA, MS])


def test_a_hash_is_not_a_comment() -> None:
    assert classify("SELECT a FROM #t -- x", dialect=MS).text == "SELECT a FROM #t -- x"
    with pytest.raises(StatementRefusedError, match="read the MySQL way"):
        classify_for("SELECT a FROM #t; -- x", [MY, MS])


def test_an_unclosed_bracket_keeps_the_semicolon_and_is_refused() -> None:
    with pytest.raises(StatementRefusedError, match="';' before its end"):
        classify("SELECT [a FROM t; -- x", dialect=MS)


@pytest.mark.parametrize(
    "raw",
    [
        "SELECT 1\nGO",
        "SELECT 1\nGO\nSELECT 2",
        "UPDATE t SET a = 1\n  go 5\n",
        "SELECT 1\nGO -- end of batch",
        "SELECT 1\r\nGo\r\n",
    ],
)
def test_a_go_line_is_refused(raw: str) -> None:
    with pytest.raises(StatementRefusedError, match="GO line"):
        classify(raw, dialect=MS)


def test_a_statement_that_starts_with_go_is_refused_by_its_first_word() -> None:
    with pytest.raises(StatementRefusedError, match="starts with GO"):
        classify("GO\nSELECT 1", dialect=MS)


@pytest.mark.parametrize(
    "raw",
    [
        "SELECT go FROM t",
        "SELECT a,\ngo FROM t",
        "SELECT 1 AS go",
        "SELECT 'x\nGO\n' FROM t",
        "SELECT [x\nGO\n] FROM t",
        "/*\nGO\n*/ SELECT 1",
        "SELECT 1 -- then\n-- GO\n",
        "SELECT gone FROM t",
    ],
)
def test_go_elsewhere_is_not_a_batch_separator(raw: str) -> None:
    assert classify(raw, dialect=MS).kind is StatementKind.READ


def test_go_is_refused_only_the_sql_server_way() -> None:
    assert classify("SELECT 1\nGO", dialect=ORA).keyword == "SELECT"
    with pytest.raises(StatementRefusedError, match="read the SQL Server way"):
        classify_for("SELECT 1\nGO", [ORA, MS])


@pytest.mark.parametrize(
    "raw",
    [
        "WITH c AS (SELECT id FROM t) DELETE FROM c",
        "WITH c AS (SELECT id FROM t) UPDATE c SET v = 1",
        "WITH c AS (SELECT id FROM t) INSERT INTO u SELECT id FROM c",
        "WITH c AS (SELECT k FROM s) MERGE t USING c ON t.k = c.k WHEN MATCHED THEN DELETE;",
        "WITH c (a) AS (SELECT ')' AS p) DELETE FROM c",
        "WITH c AS (SELECT 1 AS [)]) UPDATE c SET x = 1",
        "WITH a AS (SELECT 1 AS x), b AS (SELECT x FROM a) DELETE FROM b",
        "WITH c AS (SELECT 1 /* ) */ AS x) DELETE FROM c",
    ],
)
def test_a_with_that_writes_is_a_write(raw: str) -> None:
    statement = classify(raw, dialect=MS)
    assert (statement.keyword, statement.kind) == ("WITH", StatementKind.WRITE)


@pytest.mark.parametrize(
    "raw",
    [
        "WITH c AS (SELECT 1 AS x) SELECT * FROM c WHERE x IN (SELECT 1)",
        "WITH c AS (SELECT 'DELETE' AS v) SELECT v FROM c",
        "WITH XMLNAMESPACES ('urn:acme' AS ns) SELECT 1 AS a",
        "WITH c AS (SELECT 1 AS [delete]) SELECT * FROM c",
    ],
)
def test_a_with_that_reads_is_a_read(raw: str) -> None:
    assert classify(raw, dialect=MS).kind is StatementKind.READ


def test_a_with_that_writes_reads_differently_on_postgresql() -> None:
    raw = "WITH c AS (SELECT 1 AS x) DELETE FROM c"
    assert classify(raw, dialect=PG).kind is StatementKind.READ
    _refused_as_read_differently(raw, [PG, MS], "PostgreSQL")


def test_a_second_statement_with_no_semicolon_is_left_to_the_server() -> None:
    """T-SQL needs no `;`. The scan cannot tell where a statement ends, so the
    server's list of the statements refuses this one (#1728, Q1)."""
    statement = classify("UPDATE t SET a = 1 DELETE FROM u", dialect=MS)
    assert statement.kind is StatementKind.WRITE
