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
)

PG = Dialect.POSTGRESQL
ORA = Dialect.ORACLE


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
