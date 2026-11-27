"""The statement check for `sql run`. Tier 0, pure."""

from __future__ import annotations

import pytest

from sopuli.safety import RefusedError
from sopuli.sql.statement import (
    Dialect,
    StatementKind,
    StatementRefusedError,
    classify,
    classify_for,
    table_references,
)

PG = Dialect.POSTGRESQL
ORA = Dialect.ORACLE
MY = Dialect.MYSQL
MARIA = Dialect.MARIADB
MYSQL_FAMILY = pytest.mark.parametrize("dialect", [MY, MARIA], ids=["mysql", "mariadb"])


@pytest.mark.parametrize(
    ("raw", "keyword", "kind"),
    [
        ("select 1 from dual", "SELECT", StatementKind.READ),
        ("\n\n  WITH x AS (SELECT 1 a FROM dual) SELECT a FROM x", "WITH", StatementKind.READ),
        ("-- check\nSELECT 1 FROM dual;", "SELECT", StatementKind.READ),
        ("/* c */ /*+ index(t) */ select * from t", "SELECT", StatementKind.READ),
        ("update acme.settings set v = 'Y' where k = 'x';\n/\n", "UPDATE", StatementKind.WRITE),
        ("INSERT INTO t VALUES (1)", "INSERT", StatementKind.WRITE),
        (
            "merge into t using s on (t.k = s.k) when matched then update set v = s.v",
            "MERGE",
            StatementKind.WRITE,
        ),
        ("delete from t where k = 1", "DELETE", StatementKind.WRITE),
    ],
)
def test_classify_accepts(raw: str, keyword: str, kind: StatementKind) -> None:
    statement = classify(raw)
    assert statement.keyword == keyword
    assert statement.kind == kind


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   \n",
        "-- only a comment\n",
        "/* x */",
        "drop table t",
        "alter system set processes = 300",
        "truncate table t",
        "begin null; end;",
        "declare x number; begin null; end;",
        "call p()",
        "exec p",
        "commit",
        "rollback",
        "lock table t in exclusive mode",
        "grant select on t to x",
        "select 1 from dual; delete from t",
    ],
)
def test_classify_refuses(raw: str) -> None:
    with pytest.raises(StatementRefusedError):
        classify(raw)


def test_refusal_names_the_keyword() -> None:
    with pytest.raises(StatementRefusedError, match="DROP"):
        classify("drop table t")


def test_refusal_of_an_empty_statement_says_so() -> None:
    with pytest.raises(StatementRefusedError, match="empty"):
        classify("-- nothing\n")


@pytest.mark.parametrize("raw", ["(select 1 from dual)", ";;", "'x'"])
def test_text_with_no_leading_word_is_not_called_empty(raw: str) -> None:
    with pytest.raises(StatementRefusedError, match="does not start with a keyword"):
        classify(raw)


def test_an_unclosed_comment_is_named() -> None:
    with pytest.raises(StatementRefusedError, match="not closed"):
        classify("/* select 1 from dual")


def test_refusal_is_a_refused_error_with_code_and_exit_8() -> None:
    with pytest.raises(StatementRefusedError) as raised:
        classify("drop table t")
    assert isinstance(raised.value, RefusedError)
    assert raised.value.code == "SOPULI-20009"
    assert int(raised.value.exit_code) == 8


def test_a_slash_left_after_the_terminators_is_refused() -> None:
    with pytest.raises(StatementRefusedError, match="'/'"):
        classify("select 1 from dual\n/\n;")


@pytest.mark.parametrize("raw", ["ſelect 1 from dual", "ınsert into t values (1)"])
def test_a_non_ascii_first_word_is_refused(raw: str) -> None:
    # upper() would turn these into SELECT and INSERT.
    with pytest.raises(StatementRefusedError, match="does not start with a keyword"):
        classify(raw)


def test_whitespace_before_the_semicolon_does_not_matter() -> None:
    assert classify("select 1 ;").text == classify("select 1;").text == "select 1"


def test_only_ascii_whitespace_is_stripped() -> None:
    # U+00A0 is not ASCII whitespace, so it stays in the text.
    assert classify("select 1 ").text == "select 1 "


def test_classify_strips_terminators() -> None:
    assert classify("SELECT 1 FROM dual;\r\n/\r\n").text == "SELECT 1 FROM dual"


def test_classify_keeps_the_text_inside_unchanged() -> None:
    raw = "update t set v = 'On'\n  where k = 2"
    assert classify(raw).text == raw


@pytest.mark.parametrize(
    ("raw", "text"),
    [
        ("SELECT 1 FROM dual; -- note", "SELECT 1 FROM dual"),
        ("SELECT 1 FROM dual;-- note\n", "SELECT 1 FROM dual"),
        ("SELECT 1 FROM dual; /* note */", "SELECT 1 FROM dual"),
        ("SELECT 1 FROM dual;\n-- one\n/* two\nlines */\n-- three\n", "SELECT 1 FROM dual"),
        ("SELECT 1 FROM dual\n/\n-- note", "SELECT 1 FROM dual"),
        ("UPDATE t SET v = 'a--b' WHERE k = 1; -- note", "UPDATE t SET v = 'a--b' WHERE k = 1"),
        ("SELECT '/*' FROM dual; /* x */", "SELECT '/*' FROM dual"),
        ('SELECT "a--b" FROM dual; -- x', 'SELECT "a--b" FROM dual'),
        ("SELECT 1 FROM dual; -- note\n/", "SELECT 1 FROM dual"),
        ("SELECT 1 FROM dual;\n/* a */\n/\n-- b\n", "SELECT 1 FROM dual"),
        ("SELECT q'[it's]' FROM dual; -- note", "SELECT q'[it's]' FROM dual"),
        ("SELECT Q'{a -- b}' FROM dual; /* c */", "SELECT Q'{a -- b}' FROM dual"),
        ("SELECT nq'!it's /* x!' FROM dual; -- note", "SELECT nq'!it's /* x!' FROM dual"),
        ("SELECT q'[a]' || q'(b)' FROM dual; -- n", "SELECT q'[a]' || q'(b)' FROM dual"),
    ],
)
def test_a_comment_after_the_terminator_is_dropped_with_it(raw: str, text: str) -> None:
    assert classify(raw).text == text


@pytest.mark.parametrize(
    "raw",
    [
        "SELECT 1 FROM dual; -- note\nDELETE FROM t",
        "SELECT 1 FROM dual; /* a */ DELETE FROM t",
        "SELECT 1 FROM dual; /* a */ -- b\nDELETE FROM t -- c",
        "SELECT 1 FROM dual; /* never closed",
        "SELECT 'it' FROM dual; -- a\n; DELETE FROM t",
    ],
)
def test_a_second_statement_after_a_comment_is_still_refused(raw: str) -> None:
    with pytest.raises(StatementRefusedError):
        classify(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "SELECT 1 FROM dual; /* never closed",
        "SELECT 1 FROM dual\n/\n/* never closed",
        "SELECT 1 FROM dual; -- a\n/* never closed",
    ],
)
def test_an_unclosed_comment_after_the_terminator_is_named(raw: str) -> None:
    with pytest.raises(StatementRefusedError, match="not closed"):
        classify(raw)


def test_a_comment_with_no_terminator_before_it_stays_in_the_text() -> None:
    raw = "SELECT 1 FROM dual -- note"
    assert classify(raw).text == raw


def test_a_semicolon_inside_a_literal_is_refused() -> None:
    # A known false refusal, accepted by the spec.
    with pytest.raises(StatementRefusedError):
        classify("select 'a;b' from dual")


# PostgreSQL's rules (#1692).


def test_postgresql_comments_nest_in_the_keyword_check() -> None:
    # Oracle's first `*/` ends the comment, so it reads SELECT. PostgreSQL
    # reads the whole first line as one comment and runs the DELETE.
    raw = "/* /* */ SELECT */ DELETE FROM t"
    assert classify(raw, dialect=ORA).keyword == "SELECT"
    statement = classify(raw, dialect=PG)
    assert (statement.keyword, statement.kind) == ("DELETE", StatementKind.WRITE)


@pytest.mark.parametrize(
    ("raw", "text"),
    [
        ("SELECT $$a -- b$$ FROM t; -- note", "SELECT $$a -- b$$ FROM t"),
        ("SELECT $fn$it's /* x$fn$; /* c */", "SELECT $fn$it's /* x$fn$"),
        ("SELECT $a$ $$ -- $a$ FROM t; -- n", "SELECT $a$ $$ -- $a$ FROM t"),
        ("SELECT E'it\\'s -- x' FROM t; -- n", "SELECT E'it\\'s -- x' FROM t"),
        ("SELECT e'a\\\\' FROM t; -- n", "SELECT e'a\\\\' FROM t"),
        ("SELECT E'it''s -- x' FROM t; -- n", "SELECT E'it''s -- x' FROM t"),
        ("SELECT 'a\\' FROM t; -- n", "SELECT 'a\\' FROM t"),
        ("SELECT a$b$c FROM t; -- n", "SELECT a$b$c FROM t"),
        ("SELECT 1; /* a /* b */ c */", "SELECT 1"),
        ("SELECT 1 FROM t\n/\n-- note", "SELECT 1 FROM t"),
        ('SELECT "a--b" FROM t; -- x', 'SELECT "a--b" FROM t'),
    ],
)
def test_postgresql_literals_and_comments_after_the_terminator(raw: str, text: str) -> None:
    assert classify(raw, dialect=PG).text == text


@pytest.mark.parametrize(
    "raw",
    [
        # Oracle reads `--` in the dollar quote as a comment, and the `;` stays.
        "SELECT $$a -- b$$ FROM t; -- note",
        # Oracle ends the literal at `\'`, and the `;` stays.
        "SELECT E'it\\'s -- x' FROM t; -- n",
        # Oracle's comment ends at the first `*/`.
        "SELECT 1; /* a /* b */ c */",
    ],
)
def test_the_postgresql_forms_are_refused_the_oracle_way(raw: str) -> None:
    with pytest.raises(StatementRefusedError):
        classify(raw, dialect=ORA)


@pytest.mark.parametrize(
    "raw",
    [
        "SELECT $$a;b$$ FROM t",
        "SELECT E'a\\';b' FROM t",
        "SELECT $$a; -- never closed",
        # `q'` is no quote on PostgreSQL, so the `'` after `it` opens a literal.
        "SELECT q'[it's]' FROM t; -- n",
        "SELECT 1 FROM t; $$ -- $$ DELETE FROM t",
    ],
)
def test_postgresql_refuses_a_semicolon_left_in_the_text(raw: str) -> None:
    with pytest.raises(StatementRefusedError, match="';'"):
        classify(raw, dialect=PG)


@pytest.mark.parametrize(
    "raw", ["SELECT 1; /* a /* b */", "/* /* */ SELECT 1", "SELECT 1\n/\n/* a /* b */"]
)
def test_postgresql_names_an_unclosed_nested_comment(raw: str) -> None:
    with pytest.raises(StatementRefusedError, match="not closed"):
        classify(raw, dialect=PG)


@pytest.mark.parametrize(
    ("raw", "text"),
    [
        # The continued part keeps the E string's escapes.
        ("SELECT E'a'\n'b\\' -- x' FROM t; -- n", "SELECT E'a'\n'b\\' -- x' FROM t"),
        ("SELECT E'a' \n  'b\\' -- x' FROM t; -- n", "SELECT E'a' \n  'b\\' -- x' FROM t"),
        ("SELECT E'a''b'\n'c\\'d' FROM t; -- n", "SELECT E'a''b'\n'c\\'d' FROM t"),
    ],
)
def test_an_escape_string_continued_on_a_later_line(raw: str, text: str) -> None:
    assert classify(raw, dialect=PG).text == text


@pytest.mark.parametrize(
    "gap",
    ["\n-- c\n", " -- c\n", "\n  -- c\n-- d\n  "],
    ids=["after the break", "before the break", "two comments"],
)
def test_an_escape_string_continues_across_line_comments(gap: str) -> None:
    # PostgreSQL's lexer allows `--` comments between the parts (`whitespace_with_newline`).
    raw = f"SELECT E'a'{gap}'b\\'' FROM t; -- n"
    assert classify(raw, dialect=PG).text == f"SELECT E'a'{gap}'b\\'' FROM t"


def test_an_escape_string_is_not_continued_on_the_same_line() -> None:
    # Without a line break between them, the second literal stands alone,
    # and its `\` escapes nothing, so `'b\'` ends there.
    raw = "SELECT E'a' 'b\\' FROM t; -- n"
    assert classify(raw, dialect=PG).text == "SELECT E'a' 'b\\' FROM t"


@pytest.mark.parametrize("tag", ["t€", "€", "é1", "_x"])
def test_a_dollar_quote_tag_may_hold_any_non_ascii_character(tag: str) -> None:
    raw = f"SELECT ${tag}$a -- b${tag}$ FROM t; -- n"
    assert classify(raw, dialect=PG).text == f"SELECT ${tag}$a -- b${tag}$ FROM t"


def test_a_parameter_is_not_a_dollar_quote() -> None:
    raw = "SELECT $1, '$2$' FROM t"
    assert classify(raw, dialect=PG).text == raw


@pytest.mark.parametrize(
    "dialects", [[], [ORA], [ORA, PG], [PG, ORA, PG]], ids=["none", "oracle", "both", "repeated"]
)
def test_classify_for_returns_the_one_reading(dialects: list[Dialect]) -> None:
    raw = "UPDATE t SET v = 'a--b' WHERE k = 1; -- note"
    assert classify_for(raw, dialects) == classify(raw)


def test_classify_for_refuses_two_readings() -> None:
    with pytest.raises(StatementRefusedError, match="reads differently on Oracle and PostgreSQL"):
        classify_for("/* /* */ SELECT */ DELETE FROM t", [PG, ORA])


def test_classify_for_keeps_a_text_nothing_was_cut_from() -> None:
    # The servers parse it differently, but the tool sends the same text to both.
    raw = "SELECT 1 /* a /* b */ c */ FROM t"
    assert classify_for(raw, [PG, ORA]).text == raw


def test_classify_for_names_the_product_whose_reading_refused() -> None:
    with pytest.raises(StatementRefusedError) as raised:
        classify_for("SELECT $$a -- b$$ FROM t; -- note", [ORA, PG])
    assert raised.value.message == "read the Oracle way, the statement holds a ';' before its end"
    assert raised.value.hint is not None
    assert raised.value.hint.endswith("Or select one product's targets at a time")


@pytest.mark.parametrize("raw", ["drop table t", "", "select 1; select 2"])
def test_classify_for_does_not_name_a_product_when_every_product_refuses(raw: str) -> None:
    with pytest.raises(StatementRefusedError) as raised:
        classify_for(raw, [ORA, PG])
    with pytest.raises(StatementRefusedError) as alone:
        classify(raw)
    assert raised.value.message == alone.value.message
    assert raised.value.hint == alone.value.hint


def test_classify_for_with_one_dialect_does_not_name_it() -> None:
    with pytest.raises(StatementRefusedError) as raised:
        classify_for("drop table t", [PG])
    assert raised.value.message.startswith("the statement starts with DROP")


# MySQL and MariaDB (#1715).


@MYSQL_FAMILY
@pytest.mark.parametrize(
    ("raw", "text"),
    [
        ("# note\nSELECT 1", "# note\nSELECT 1"),
        ("SELECT 1; # note", "SELECT 1"),
        ("SELECT 1; -- note", "SELECT 1"),
        ("SELECT 1;\t--\tnote", "SELECT 1"),
        ("SELECT 1;--", "SELECT 1"),
        ("SELECT 1--1;", "SELECT 1--1"),
        ("SELECT `a``b` FROM t; # c", "SELECT `a``b` FROM t"),
        ("SELECT 'it''s', \"a\"\"b\" FROM t;", "SELECT 'it''s', \"a\"\"b\" FROM t"),
        (
            "SELECT 'a -- b', \"c # d\", `e /* f` FROM t; -- g",
            "SELECT 'a -- b', \"c # d\", `e /* f` FROM t",
        ),
        ("SELECT /*+ MAX_EXECUTION_TIME(1000) */ 1;", "SELECT /*+ MAX_EXECUTION_TIME(1000) */ 1"),
        ("UPDATE t SET v = 'Y' WHERE k = 'x';\n/\n", "UPDATE t SET v = 'Y' WHERE k = 'x'"),
    ],
)
def test_mysql_comments_and_literals(dialect: Dialect, raw: str, text: str) -> None:
    assert classify(raw, dialect=dialect).text == text


@MYSQL_FAMILY
@pytest.mark.parametrize("raw", ["--DELETE FROM t\nSELECT 1", "#\n--x\nSELECT 1"])
def test_a_double_dash_before_a_letter_is_not_a_mysql_comment(dialect: Dialect, raw: str) -> None:
    with pytest.raises(StatementRefusedError, match="does not start with a keyword"):
        classify(raw, dialect=dialect)


@MYSQL_FAMILY
def test_a_double_dash_before_a_letter_after_the_terminator_is_code(dialect: Dialect) -> None:
    assert classify("SELECT 1; --x").text == "SELECT 1"
    with pytest.raises(StatementRefusedError, match="';' before its end"):
        classify("SELECT 1; --x", dialect=dialect)


@MYSQL_FAMILY
def test_mysql_block_comments_do_not_nest(dialect: Dialect) -> None:
    assert classify("/* /* */ SELECT */ DELETE FROM t", dialect=dialect).keyword == "SELECT"


@MYSQL_FAMILY
@pytest.mark.parametrize(
    "raw",
    [
        "/*!50000 DELETE FROM t */ SELECT 1",
        "/*! DELETE FROM t */",
        "SELECT /*! 1 */ FROM t",
        "/*M!100100 SELECT 1 */",
        "select /*m! 1 */ 1",
        "SELECT 1; /*! note */",
        "SELECT 1 /*!",
    ],
)
def test_an_executable_comment_is_refused(dialect: Dialect, raw: str) -> None:
    with pytest.raises(StatementRefusedError, match="executable comment"):
        classify(raw, dialect=dialect)


@MYSQL_FAMILY
@pytest.mark.parametrize(
    "raw",
    ["SELECT '/*! x */' FROM t", "# /*! x */\nSELECT 1", "-- /*! x */\nSELECT 1", "SELECT `/*!`"],
)
def test_an_executable_comment_marker_in_a_literal_or_comment_is_not_refused(
    dialect: Dialect, raw: str
) -> None:
    assert classify(raw, dialect=dialect).text == raw


def test_an_executable_comment_is_an_ordinary_comment_elsewhere() -> None:
    assert classify("/*! x */ SELECT 1 FROM dual").keyword == "SELECT"
    assert classify("/*! x */ SELECT 1", dialect=PG).keyword == "SELECT"


@MYSQL_FAMILY
@pytest.mark.parametrize(
    "raw",
    [
        "SELECT * FROM t INTO OUTFILE '/tmp/x'",
        "select a into dumpfile '/tmp/x' from t",
        "SELECT * INTO /* c */ OUTFILE '/x' FROM t",
        "SELECT * INTO # c\n OutFile '/x' FROM t",
        "UPDATE t SET v = 1 WHERE k IN (SELECT k FROM s INTO OUTFILE '/x')",
    ],
)
def test_a_file_write_is_refused(dialect: Dialect, raw: str) -> None:
    with pytest.raises(StatementRefusedError, match="writes a file on the server"):
        classify(raw, dialect=dialect)


@MYSQL_FAMILY
@pytest.mark.parametrize(
    "raw",
    [
        "SELECT 'into outfile' FROM t",
        "SELECT a INTO @v FROM t",
        "SELECT outfile FROM t",
        "SELECT 1 # into outfile",
        "SELECT `into` outfile FROM t",
        "INSERT INTO outfiles VALUES (1)",
    ],
)
def test_into_outfile_in_a_literal_comment_or_name_is_not_refused(
    dialect: Dialect, raw: str
) -> None:
    assert classify(raw, dialect=dialect).text == raw


def test_a_file_write_is_refused_only_on_mysql_and_mariadb() -> None:
    raw = "SELECT * FROM t INTO OUTFILE '/tmp/x'"
    assert classify(raw).text == raw
    assert classify(raw, dialect=PG).text == raw


@MYSQL_FAMILY
@pytest.mark.parametrize(
    "raw",
    [r"SELECT 'it\'s' FROM t", r'SELECT "a\"b" FROM t', r"SELECT 'a\\' FROM t; -- c"],
)
def test_a_backslash_escape_both_readings_agree_on(dialect: Dialect, raw: str) -> None:
    assert classify(raw, dialect=dialect).keyword == "SELECT"


@MYSQL_FAMILY
def test_a_backslash_that_hides_a_terminator_is_refused(dialect: Dialect) -> None:
    # Without backslash escapes, `-- '` is a comment after the terminator. With
    # them, the `;` is in a literal that never closes.
    with pytest.raises(StatementRefusedError, match="';' before its end"):
        classify(r"SELECT 'a\' FROM t; -- '", dialect=dialect)


@MYSQL_FAMILY
def test_an_escaped_quote_before_a_comment_after_the_terminator_is_refused(
    dialect: Dialect,
) -> None:
    # A false refusal: without backslash escapes, the `;` and the comment are in
    # a literal that never closes. With no comment, both readings cut the `;`.
    # A doubled quote reads the same way in both.
    escaped = r"UPDATE t SET v = 'O\'Brien' WHERE k = 1;"
    assert classify(escaped, dialect=dialect).text == escaped[:-1]
    with pytest.raises(StatementRefusedError, match="';' before its end"):
        classify(escaped + " # note", dialect=dialect)
    doubled = "UPDATE t SET v = 'O''Brien' WHERE k = 1; # note"
    assert classify(doubled, dialect=dialect).keyword == "UPDATE"


@MYSQL_FAMILY
def test_a_backslash_that_hides_a_comment_is_refused(dialect: Dialect) -> None:
    # Without backslash escapes, the `/` line ends the statement, and the rest is
    # a comment the tool would cut. With them, the whole text is one literal.
    with pytest.raises(StatementRefusedError, match="with and without backslash escapes"):
        classify("SELECT 'a\\'\n/\n-- '", dialect=dialect)


@MYSQL_FAMILY
def test_an_executable_comment_one_reading_sees_is_refused(dialect: Dialect) -> None:
    # Under NO_BACKSLASH_ESCAPES the server ends the literal at `\'` and runs
    # the comment's text.
    with pytest.raises(StatementRefusedError, match="executable comment"):
        classify(r"SELECT 'a\' /*! , 1 */ '' FROM t", dialect=dialect)


@MYSQL_FAMILY
def test_a_file_write_one_reading_sees_is_refused(dialect: Dialect) -> None:
    with pytest.raises(StatementRefusedError, match="writes a file on the server"):
        classify(r"SELECT 'a\' INTO OUTFILE '/x' -- '", dialect=dialect)


@MYSQL_FAMILY
@pytest.mark.parametrize(
    ("raw", "match"),
    [
        (r"""SELECT "\" '\' "' INTO OUTFILE '/x' FROM t""", "writes a file on the server"),
        (r"""SELECT "\" '\' "' /*! INTO OUTFILE '/x' */ FROM t""", "executable comment"),
    ],
)
def test_what_only_the_ansi_quotes_reading_sees_is_refused(
    dialect: Dialect, raw: str, match: str
) -> None:
    # With ANSI_QUOTES alone, `"\"` is a name with no escapes and `'\' "'` is a
    # string, so the server sees what follows it as code (review of #1719).
    with pytest.raises(StatementRefusedError, match=match):
        classify(raw, dialect=dialect)


def test_classify_for_reads_mysql_and_mariadb_alike() -> None:
    raw = r"UPDATE t SET v = 'a\\b' WHERE k = 1; # note"
    assert classify_for(raw, [MY, MARIA]) == classify(raw, dialect=MY)


def test_classify_for_names_mysql_when_its_reading_refuses() -> None:
    with pytest.raises(StatementRefusedError) as raised:
        classify_for("SELECT 1 FROM t; --x", [ORA, MY])
    assert raised.value.message == "read the MySQL way, the statement holds a ';' before its end"


def test_classify_for_refuses_postgresql_and_mysql_readings_that_differ() -> None:
    with pytest.raises(
        StatementRefusedError, match="reads differently on MySQL and PostgreSQL"
    ) as raised:
        classify_for("/* /* */ SELECT */ DELETE FROM t", [PG, MY])
    assert raised.value.hint is not None
    assert "backslash escapes" in raised.value.hint


def test_classify_for_names_oracle_when_a_hash_comment_is_not_one_there() -> None:
    with pytest.raises(StatementRefusedError, match="read the Oracle way"):
        classify_for("# note\nSELECT 1 FROM t", [ORA, MARIA])


# The table names a MySQL or MariaDB write gives (#1717, #1713 Q3 A′).


def _references(text: str, dialect: Dialect = MY) -> frozenset[tuple[str | None, str]]:
    return table_references(classify(text, dialect=dialect), dialect)


@MYSQL_FAMILY
@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("UPDATE acme.settings SET v = 1", {("ACME", "SETTINGS"), (None, "SETTINGS")}),
        ("UPDATE acme . settings SET v = 1", {("ACME", "SETTINGS")}),
        ("UPDATE `acme`.`set``tings` SET v = 1", {("ACME", "SET`TINGS")}),
        ('UPDATE "acme"."settings" SET v = 1', {("ACME", "SETTINGS")}),
        ("DELETE x FROM acme.ti x JOIN acme.tm y ON x.id = y.id", {("ACME", "TM"), (None, "X")}),
        ("INSERT INTO acme.tm SELECT * FROM acme.ti", {("ACME", "TM"), ("ACME", "TI")}),
    ],
)
def test_table_references_holds_every_name(
    dialect: Dialect, text: str, expected: set[tuple[str | None, str]]
) -> None:
    assert expected <= _references(text, dialect)


@MYSQL_FAMILY
@pytest.mark.parametrize(
    "text",
    [
        "UPDATE acme.ti SET note = 'acme.tm' WHERE id = 1",
        "UPDATE acme.ti SET v = 1 -- acme.tm\n",
        "UPDATE acme.ti SET v = 1 # acme.tm\n",
        "UPDATE acme.ti /* acme.tm */ SET v = 1",
    ],
)
def test_table_references_skips_literals_and_comments(dialect: Dialect, text: str) -> None:
    found = _references(text, dialect)
    assert ("ACME", "TM") not in found
    assert ("ACME", "TI") in found


def test_table_references_reads_only_mysql_and_mariadb() -> None:
    with pytest.raises(ValueError, match="MySQL and MariaDB"):
        table_references(classify("UPDATE t SET v = 1"), ORA)
