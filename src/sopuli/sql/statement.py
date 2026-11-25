"""Check one SQL statement before `sql run` connects (UC-3).

The check is by keyword. It lets a read or a plain data change through and
refuses everything else. It scans comments and literals by the rules of one
product, its :class:`Dialect`. It does no I/O.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from sopuli.safety import RefusedError

#: ``error.code`` for a statement the check refuses (`03-json-output.md` §3).
STATEMENT_REFUSED = "SOPULI-20009"

READ_KEYWORDS = ("SELECT", "WITH")
WRITE_KEYWORDS = ("UPDATE", "INSERT", "MERGE", "DELETE")


class StatementKind(StrEnum):
    READ = "read"
    WRITE = "write"


class Dialect(StrEnum):
    """Whose rules for comments and literals the scan follows.

    Oracle's block comments end at the first ``*/``, and it has ``q'[...]'``
    literals. PostgreSQL's block comments nest, and it has dollar quotes and
    ``E'...'`` strings with backslash escapes. The value is the target's
    ``type:``.
    """

    ORACLE = "oracle"
    POSTGRESQL = "postgresql"


class StatementRefusedError(RefusedError):
    """The statement is not one `sql run` accepts. Nothing was sent."""

    code = STATEMENT_REFUSED


@dataclass(frozen=True)
class Statement:
    """A statement that passed the check."""

    #: The text sent to the server, with the line ends and terminator removed.
    text: str
    kind: StatementKind
    #: The first word, in upper case.
    keyword: str


#: ASCII whitespace only. `str.strip` would also remove Unicode spaces.
_SPACE = " \t\n\r\f\v"

#: What :func:`_literal_end` returns for a literal that never closes.
_UNCLOSED = -1


def _comment_end(text: str, i: int, dialect: Dialect) -> int | None:
    """Where the block comment that opens at ``text[i]`` ends, or ``None``
    when it never closes.

    On Oracle the first ``*/`` closes it. On PostgreSQL a ``/*`` inside opens
    a nested comment, and each needs its own ``*/``.
    """
    if dialect is Dialect.ORACLE:
        found = text.find("*/", i + 2)
        return None if found == -1 else found + 2
    depth, j, n = 1, i + 2, len(text)
    while j < n:
        if text.startswith("/*", j):
            depth += 1
            j += 2
        elif text.startswith("*/", j):
            depth -= 1
            j += 2
            if depth == 0:
                return j
        else:
            j += 1
    return None


def _first_word(text: str, dialect: Dialect) -> tuple[str, str]:
    """The first word after any whitespace and comments, and why there is none.

    The reason is ``""`` when there is a word, ``"empty"`` when only whitespace
    and closed comments remain, ``"unclosed"`` for a ``/*`` with no end, and
    ``"other"`` when the next character starts no word.
    """
    i, n = 0, len(text)
    while i < n:
        if text[i] in _SPACE:
            i += 1
        elif text.startswith("--", i):
            end = text.find("\n", i)
            i = n if end == -1 else end + 1
        elif text.startswith("/*", i):
            closed = _comment_end(text, i, dialect)
            if closed is None:
                return "", "unclosed"
            i = closed
        else:
            break
    start = i
    while i < n and text[i].isascii() and (text[i].isalnum() or text[i] == "_"):
        i += 1
    if i > start:
        return text[start:i], ""
    return "", "empty" if start >= n else "other"


#: The character that closes a q-quoted literal, by the one that opens it. Any
#: other character closes with itself.
_Q_CLOSERS = {"[": "]", "(": ")", "{": "}", "<": ">"}


def _is_word_char(char: str) -> bool:
    return char.isascii() and (char.isalnum() or char in "_$#")


def _q_quote_start(text: str, i: int) -> bool:
    """Whether ``text[i]`` is the ``q`` of ``q'...'`` or ``nq'...'``, Oracle's
    alternative quoting, and not the end of a longer word."""
    if text[i] not in "qQ" or text[i + 1 : i + 2] != "'":
        return False
    before = i - 1
    if before >= 0 and text[before] in "nN":
        before -= 1
    return before < 0 or not _is_word_char(text[before])


def _is_postgres_word_char(char: str) -> bool:
    """A character that can be part of a PostgreSQL name. Non-ASCII letters
    can, and so can ``$`` after the first character."""
    return char.isalnum() or char in "_$" or not char.isascii()


def _after_word(text: str, i: int) -> bool:
    return i > 0 and _is_postgres_word_char(text[i - 1])


#: A PostgreSQL dollar-quote tag: ``$$``, or ``$name$``, where the name follows
#: the rules for a name but holds no ``$``. As in a name, any character outside
#: ASCII may appear, not only a letter.
_DOLLAR_TAG = re.compile(r"\$(?:[A-Za-z_\x80-\U0010ffff][A-Za-z0-9_\x80-\U0010ffff]*)?\$")


def _dollar_tag(text: str, i: int) -> str | None:
    """The tag of a dollar quote that opens at ``text[i]``, or ``None``.

    A ``$`` after a name character is part of the name, as in ``a$b``, and
    ``$1`` is a parameter, so neither opens a quote.
    """
    if text[i] != "$" or _after_word(text, i):
        return None
    found = _DOLLAR_TAG.match(text, i)
    return None if found is None else found.group()


def _continued_at(text: str, i: int) -> int | None:
    """Where a string continues after the quote that ended before ``text[i]``.

    PostgreSQL joins two string literals separated only by whitespace that
    holds a line break. The position of the next part's opening ``'`` comes
    back, or ``None`` when no part follows.
    """
    j, n = i, len(text)
    while j < n and text[j] in _SPACE:
        j += 1
    if j < n and text[j] == "'" and "\n" in text[i:j]:
        return j
    return None


def _escape_string_end(text: str, i: int) -> int:
    """Where an ``E'...'`` string ends, for the ``'`` at ``text[i]``, or
    :data:`_UNCLOSED`. A backslash escapes the next character, so ``\\'``
    does not end it. ``''`` does not either. A part that continues it on a
    later line keeps its escapes."""
    j, n = i + 1, len(text)
    while j < n:
        if text[j] == "\\":
            j += 2
        elif text[j] == "'":
            if text.startswith("''", j):
                j += 2
                continue
            continued = _continued_at(text, j + 1)
            if continued is None:
                return j + 1
            j = continued + 1
        else:
            j += 1
    return _UNCLOSED


def _literal_end(text: str, i: int, dialect: Dialect) -> int | None:
    """Where the literal or quoted name that opens at ``text[i]`` ends,
    :data:`_UNCLOSED` when it never closes, or ``None`` when none opens there."""
    char = text[i]
    if dialect is Dialect.ORACLE and _q_quote_start(text, i):
        if i + 2 >= len(text):
            return _UNCLOSED
        closer = _Q_CLOSERS.get(text[i + 2], text[i + 2]) + "'"
        found = text.find(closer, i + 3)
        return _UNCLOSED if found == -1 else found + 2
    if dialect is Dialect.POSTGRESQL:
        if char in "eE" and text[i + 1 : i + 2] == "'" and not _after_word(text, i):
            return _escape_string_end(text, i + 1)
        tag = _dollar_tag(text, i)
        if tag is not None:
            found = text.find(tag, i + len(tag))
            return _UNCLOSED if found == -1 else found + len(tag)
    if char in "'\"":
        found = text.find(char, i + 1)
        return _UNCLOSED if found == -1 else found + 1
    return None


def _code_end(text: str, dialect: Dialect) -> tuple[int, int | None]:
    """Where the code of ``text`` ends, and where an unclosed comment starts.

    The first is the length of ``text`` up to its last character that is not
    whitespace and not in a comment, so what follows is whitespace and comments
    only. String literals, quoted names, and Oracle's q-quoted literals or
    PostgreSQL's dollar quotes and ``E'...'`` strings, are skipped whole, so a
    ``--`` or a ``/*`` in one is not a comment.

    The second is ``None``, or the position of a ``/*`` that never closes, with
    the code end before it. An unclosed literal makes the rest of the text code:
    its length comes back and nothing is cut.
    """
    i, n, end = 0, len(text), 0
    while i < n:
        char = text[i]
        if char in _SPACE:
            i += 1
        elif text.startswith("--", i):
            found = text.find("\n", i)
            i = n if found == -1 else found + 1
        elif text.startswith("/*", i):
            closed = _comment_end(text, i, dialect)
            if closed is None:
                return end, i
            i = closed
        elif (literal := _literal_end(text, i, dialect)) is not None:
            if literal == _UNCLOSED:
                return n, None
            i = end = literal
        else:
            i += 1
            end = i
    return end, None


def _is_terminated(code: str) -> bool:
    return code.endswith(";") or code.rsplit("\n", 1)[-1].strip(_SPACE) == "/"


def _without_trailing_comments(text: str, dialect: Dialect) -> str:
    """``text`` without the comments after its terminator.

    Only a comment that follows a ``;`` or a line holding only ``/`` goes, with
    that terminator left for :func:`_strip_terminators`. A comment after a
    statement with no terminator stays where the operator wrote it. A comment
    that never closes after a terminator is refused by name.
    """
    end, unclosed = _code_end(text, dialect)
    code = text[:end].rstrip(_SPACE)
    if not _is_terminated(code):
        return text
    if unclosed is not None:
        raise StatementRefusedError(
            "the statement has a comment that is not closed",
            hint="close the /* comment, or remove it",
        )
    return code


def _strip_terminators(raw: str, dialect: Dialect) -> str:
    text = raw.replace("\r\n", "\n").replace("\r", "\n")
    text = _without_trailing_comments(text, dialect).rstrip(_SPACE)
    lines = text.split("\n")
    if lines[-1].strip(_SPACE) == "/":
        # A comment may sit between the `;` and the `/`, and so after the `/`.
        before = "\n".join(lines[:-1]).rstrip(_SPACE)
        text = _without_trailing_comments(before, dialect).rstrip(_SPACE)
    if text.endswith(";"):
        text = text[:-1].rstrip(_SPACE)
    return text


def classify(raw: str, *, dialect: Dialect = Dialect.ORACLE) -> Statement:
    """Check ``raw`` and return the statement, or raise :class:`StatementRefusedError`.

    ``dialect`` says how comments and literals are read. The trailing ``/``
    line is SQL*Plus's terminator, and it is stripped in every dialect, so
    one statement reads the same way on a run of more than one product.

    A ``;`` left after the one terminator is refused, so a second statement
    cannot ride along. A ``;`` inside a string literal is refused too. That is a
    false refusal, and UC-3 accepts it.
    """
    text = _strip_terminators(raw, dialect)
    word, reason = _first_word(text, dialect)
    if not word:
        message = {
            "empty": "the statement is empty",
            "unclosed": "the statement has a comment that is not closed",
        }.get(reason, "the statement does not start with a keyword")
        raise StatementRefusedError(
            message,
            hint="give one SELECT, WITH, UPDATE, INSERT, MERGE or DELETE statement",
        )
    keyword = word.upper()
    if keyword in READ_KEYWORDS:
        kind = StatementKind.READ
    elif keyword in WRITE_KEYWORDS:
        kind = StatementKind.WRITE
    else:
        raise StatementRefusedError(
            f"the statement starts with {keyword}, which `sql run` does not run",
            hint="it runs SELECT, WITH, UPDATE, INSERT, MERGE and DELETE only",
        )
    if text.rsplit("\n", 1)[-1].strip(_SPACE) == "/":
        raise StatementRefusedError(
            "the statement has a '/' alone on its last line",
            hint="give one statement, with at most one ';' or one '/' line at its end",
        )
    if ";" in text:
        raise StatementRefusedError(
            "the statement holds a ';' before its end",
            hint="give one statement. A ';' inside a string literal is refused too",
        )
    return Statement(text=text, kind=kind, keyword=keyword)


#: How a refusal names each dialect.
_PRODUCT_NAMES = {Dialect.ORACLE: "Oracle", Dialect.POSTGRESQL: "PostgreSQL"}


def classify_for(raw: str, dialects: Iterable[Dialect]) -> Statement:
    """Check ``raw`` once for each dialect a run covers.

    One refusal refuses the statement. Where two dialects give a different
    text or keyword, the statement is refused too, and neither reading is
    picked: the plan fingerprint and every target need one text. With no
    dialect, Oracle's is used. Where more than one dialect is checked, a
    refusal names the product whose reading refused it.
    """
    covered = sorted(set(dialects))
    if len(covered) <= 1:
        return classify(raw, dialect=covered[0] if covered else Dialect.ORACLE)
    found: dict[Dialect, Statement] = {}
    for dialect in covered:
        try:
            found[dialect] = classify(raw, dialect=dialect)
        except StatementRefusedError as refused:
            advice = "select one product's targets at a time"
            hint = f"{refused.hint}. Or {advice}" if refused.hint else advice
            raise StatementRefusedError(
                f"read the {_PRODUCT_NAMES[dialect]} way, {refused.message}",
                hint=hint,
            ) from refused
    readings = set(found.values())
    if len(readings) > 1:
        names = " and ".join(_PRODUCT_NAMES[dialect] for dialect in found)
        raise StatementRefusedError(
            f"the statement reads differently on {names}",
            hint=(
                "write it so that every product reads it the same way, without nested "
                "comments, dollar quotes or E'...' strings, or select one product's "
                "targets at a time"
            ),
        )
    return next(iter(found.values()))
