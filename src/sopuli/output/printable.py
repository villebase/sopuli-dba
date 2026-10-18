"""Text from outside the tool, made safe to put on a terminal (#859).

ORA- messages, vault error bodies, lock holder fields and anything else the
tool did not write can carry control characters. A terminal acts on them: an
OSC sequence (``ESC ] 0;title BEL``) sets the window title, a lone ``\\r``
returns to the start of the line so the next text overwrites a table row, and
``\\b`` deletes what was printed. ``click.unstyle`` removes only CSI sequences,
and only where colour is off.

Every control character is shown rather than dropped: ``\\x1b``, ``\\x07``,
``\\r``. The operator sees that the text had one, and nothing is acted on. Pure
and dependency-free, so it is tier 0.

JSON output is not touched here. The JSON encoder escapes control characters
itself, and the document carries the server's text exactly.
"""

from __future__ import annotations

import re

__all__ = ["printable", "printable_cell"]

#: A colour sequence (SGR, ``ESC [ ... m``), the only escape sequence the tool
#: itself writes, through :mod:`sopuli.output.palette`.
_SGR = re.compile(r"\x1b\[[0-9;]*m")

#: C0 (except the line break and the tab), DEL, and C1. C1 includes the
#: single-byte forms of CSI (``\x9b``) and OSC (``\x9d``).
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

#: The same, with the line break and the tab as well, for a table cell.
_CELL_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")

_NAMED = {"\r": "\\r", "\n": "\\n", "\t": "\\t"}


def _shown(match: re.Match[str]) -> str:
    character = match.group()
    return _NAMED.get(character, f"\\x{ord(character):02x}")


def printable(text: str, *, keep_colour: bool = False) -> str:
    """``text`` with every control character shown, line breaks and tabs kept.

    ``keep_colour`` keeps colour sequences (SGR) whole, for text the tool has
    already painted and is about to print with colour on. Every other escape
    sequence, an OSC title or a cursor movement, is still shown. A colour
    sequence from outside is kept as well: it changes how text looks, not where
    it goes, and telling it apart from the tool's own would mean filtering every
    external string before it is painted.
    """
    if not keep_colour:
        return _CONTROL.sub(_shown, text)
    kept = _SGR.split(text)
    colours = _SGR.findall(text)
    parts = [_CONTROL.sub(_shown, kept[0])]
    for colour, rest in zip(colours, kept[1:], strict=True):
        parts.append(colour)
        parts.append(_CONTROL.sub(_shown, rest))
    return "".join(parts)


def printable_cell(text: str) -> str:
    """``text`` for one table cell: every control character shown, line breaks too.

    A line break or a ``\\r`` in a cell would start a new row that the table
    never laid out, so a server message could print a row that reads ``ok``.
    """
    return _CELL_CONTROL.sub(_shown, text)
