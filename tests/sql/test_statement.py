"""The statement check for `sql run`. Tier 0, pure."""

from __future__ import annotations

import pytest

from sopuli.safety import RefusedError
from sopuli.sql.statement import StatementKind, StatementRefusedError, classify


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


def test_a_semicolon_inside_a_literal_is_refused() -> None:
    # A known false refusal, accepted by the spec.
    with pytest.raises(StatementRefusedError):
        classify("select 'a;b' from dual")
