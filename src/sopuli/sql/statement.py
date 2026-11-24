"""Check one SQL statement before `sql run` connects (UC-3).

The check is by keyword. It lets a read or a plain data change through and
refuses everything else. It does no I/O.
"""

from __future__ import annotations

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


def _first_word(text: str) -> tuple[str, str]:
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
            end = text.find("*/", i + 2)
            if end == -1:
                return "", "unclosed"
            i = end + 2
        else:
            break
    start = i
    while i < n and text[i].isascii() and (text[i].isalnum() or text[i] == "_"):
        i += 1
    if i > start:
        return text[start:i], ""
    return "", "empty" if start >= n else "other"


def _code_end(text: str) -> int:
    """The length of ``text`` up to its last character that is not whitespace and
    not in a comment, so what follows is whitespace and comments only.

    String literals and quoted names are skipped whole, so a ``--`` or a ``/*`` in
    one is not a comment. Text this cannot read, an unclosed comment or literal,
    is all code: its length comes back and nothing is cut.
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
            found = text.find("*/", i + 2)
            if found == -1:
                return n
            i = found + 2
        elif char in "'\"":
            found = text.find(char, i + 1)
            if found == -1:
                return n
            i = end = found + 1
        else:
            i += 1
            end = i
    return end


def _without_trailing_comments(text: str) -> str:
    """``text`` without the comments after its terminator.

    Only a comment that follows a ``;`` or a line holding only ``/`` goes, with
    that terminator left for :func:`_strip_terminators`. A comment after a
    statement with no terminator stays where the operator wrote it.
    """
    code = text[: _code_end(text)].rstrip(_SPACE)
    if code.endswith(";") or code.rsplit("\n", 1)[-1].strip(_SPACE) == "/":
        return code
    return text


def _strip_terminators(raw: str) -> str:
    text = _without_trailing_comments(raw.replace("\r\n", "\n").replace("\r", "\n")).rstrip(_SPACE)
    lines = text.split("\n")
    if lines[-1].strip(_SPACE) == "/":
        text = "\n".join(lines[:-1]).rstrip(_SPACE)
    if text.endswith(";"):
        text = text[:-1].rstrip(_SPACE)
    return text


def classify(raw: str) -> Statement:
    """Check ``raw`` and return the statement, or raise :class:`StatementRefusedError`.

    A ``;`` left after the one terminator is refused, so a second statement
    cannot ride along. A ``;`` inside a string literal is refused too. That is a
    false refusal, and UC-3 accepts it.
    """
    text = _strip_terminators(raw)
    word, reason = _first_word(text)
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
