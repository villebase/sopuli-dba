"""Text from outside the tool, made safe to put on a terminal (#859).

ORA- messages, vault error bodies, lock holders and anything else the tool did
not write can carry control characters, and a terminal acts on them: an OSC
sequence (``ESC ] 0;title BEL``) sets the window title, a lone ``\\r`` returns
to the start of the line so the next text overwrites it, ``\\b`` deletes what
was printed, and a colour sequence such as conceal (``ESC [ 8 m``) hides what
follows.

Every one is shown rather than sent: ``\\x1b``, ``\\x07``, ``\\r``. The
operator sees that the text had one, and nothing is acted on. The only escape
sequences written as escapes are the ones the tool's own palette produces
(:data:`OURS`), and only when colour is on. With colour off they are removed,
which is what colour off means.

Also shown, as ``\\uXXXX``: the Unicode line and paragraph separators, which
``str.splitlines`` splits on; the bidirectional overrides and isolates, which
reorder what is displayed; and the zero-width characters, which make two names
look alike.

Pure, and tier 0. JSON output does not pass through here: the encoder escapes
control characters itself, and the document carries the server's text exactly.
"""

from __future__ import annotations

import re

from sopuli.output.palette import Role, paint

__all__ = ["OURS", "printable", "printable_cell"]

#: A colour sequence (SGR, ``ESC [ ... m``).
_SGR = r"\x1b\[[0-9;]*m"

#: The Unicode characters shown as well as the control ones: zero-width
#: (U+200B-U+200D, U+FEFF), line and paragraph separators (U+2028, U+2029),
#: bidirectional embeddings, overrides and isolates (U+202A-U+202E,
#: U+2066-U+2069).
_UNICODE = "​-‍  ‪-‮⁦-⁩﻿"

#: C0 except the line break and the tab, DEL, C1 (which includes the
#: single-byte CSI ``\x9b`` and OSC ``\x9d``), and :data:`_UNICODE`.
_TEXT = re.compile(rf"{_SGR}|\r\n|[\x00-\x08\x0b-\x1f\x7f-\x9f{_UNICODE}]")

#: The same for a table cell, where the line break and the tab are shown too.
_CELL = re.compile(rf"[\x00-\x1f\x7f-\x9f{_UNICODE}]")

#: Every escape sequence the tool's own palette writes. Computed from the
#: palette rather than listed, so a new role cannot be shown as an escape.
OURS = frozenset(re.findall(_SGR, "".join(paint("x", role) for role in Role)))

_NAMED = {"\r": "\\r", "\n": "\\n", "\t": "\\t"}


def _shown(character: str) -> str:
    if character in _NAMED:
        return _NAMED[character]
    if ord(character) > 0xFF:
        return f"\\u{ord(character):04x}"
    return f"\\x{ord(character):02x}"


def printable(text: str, *, colour: bool) -> str:
    """``text`` with every control character shown and line breaks kept.

    ``colour`` is whether the stream may carry colour. The palette's own
    sequences (:data:`OURS`) are kept where it may and removed where it may not;
    any other colour sequence, from outside the tool, is shown either way.
    A ``\\r\\n`` line end becomes ``\\n``, so text from a Windows host or an
    HTTP body does not show a ``\\r`` on every line.
    """

    def replace(match: re.Match[str]) -> str:
        token = match.group()
        if token == "\r\n":
            return "\n"
        if len(token) > 1:
            if token in OURS:
                return token if colour else ""
            return "\\x1b" + token[1:]
        return _shown(token)

    return _TEXT.sub(replace, text)


def printable_cell(text: str) -> str:
    """``text`` for one table cell: every control character shown, line breaks too.

    A line break or a ``\\r`` in a cell would start a row the table never laid
    out, so a server message could print a row that reads ``ok``. A cell is
    painted after this, so no escape in it is the tool's own.
    """
    return _CELL.sub(lambda match: _shown(match.group()), text)
