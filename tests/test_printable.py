"""Text from outside the tool, made safe to put on a terminal (#859).

Server messages, vault error bodies and lock holders can carry control
characters, and a terminal acts on them. These are the shapes that matter: an
OSC sequence that sets the window title, a lone carriage return that lets the
next text overwrite a row, and the C1 forms of both.
"""

from __future__ import annotations

import io
import json
from typing import TextIO, cast

import click
import pytest

from sopuli.output.color import ColorChoice
from sopuli.output.emit import Emitter, OutputMode
from sopuli.output.palette import Role, paint
from sopuli.output.printable import printable, printable_cell
from sopuli.output.table import Column, render_table

#: An ORA-20000 from a site-written verify function, carrying an OSC title
#: sequence and a carriage return that would overwrite the line with "ok".
HOSTILE = "ORA-20000: rejected\x1b]0;owned\x07\rSTATE ok"


def test_osc_and_carriage_return_are_shown_not_sent() -> None:
    shown = printable(HOSTILE)

    assert "\x1b" not in shown
    assert "\x07" not in shown
    assert "\r" not in shown
    assert shown == "ORA-20000: rejected\\x1b]0;owned\\x07\\rSTATE ok"


@pytest.mark.parametrize(
    ("character", "shown"),
    [("\x08", "\\x08"), ("\x7f", "\\x7f"), ("\x9b", "\\x9b"), ("\x9d", "\\x9d"), ("\x00", "\\x00")],
    ids=["backspace", "delete", "c1-csi", "c1-osc", "nul"],
)
def test_every_other_control_character_is_shown(character: str, shown: str) -> None:
    assert printable(f"a{character}b") == f"a{shown}b"


def test_line_breaks_and_tabs_are_kept_in_free_text() -> None:
    """A multi-line hint or a traceback is still multi-line."""
    assert printable("first\n\tsecond") == "first\n\tsecond"


def test_a_table_cell_shows_line_breaks_too() -> None:
    """A line break in a cell would start a row the table never laid out."""
    assert printable_cell("a\nb\rc\td") == "a\\nb\\rc\\td"


def test_colour_is_kept_only_when_asked() -> None:
    painted = paint("DRIFT", Role.BAD)

    assert printable(painted, keep_colour=True) == painted
    assert "\x1b" not in printable(painted)


def test_keeping_colour_still_shows_every_other_escape_sequence() -> None:
    painted = paint("DRIFT", Role.BAD) + HOSTILE

    kept = printable(painted, keep_colour=True)

    assert kept.startswith(paint("DRIFT", Role.BAD))
    assert "\x1b]" not in kept
    assert "\r" not in kept


def test_a_hostile_cell_cannot_forge_a_row() -> None:
    lines = render_table([Column("ACCOUNT"), Column("DETAIL")], [["acme_web_user", HOSTILE]])

    assert len(lines) == 2
    assert "\r" not in click.unstyle(lines[1])
    assert "\x1b]" not in lines[1]


@pytest.mark.parametrize("choice", [ColorChoice.NEVER, ColorChoice.ALWAYS])
def test_the_emitter_shows_control_characters_with_colour_on_or_off(
    choice: ColorChoice, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("sopuli.output.color.enable_virtual_terminal", lambda _: True)
    written = io.StringIO()
    emitter = Emitter(mode=OutputMode.TEXT, stream=cast("TextIO", written), color_choice=choice)

    emitter.emit_text(HOSTILE)

    assert written.getvalue().strip() == "ORA-20000: rejected\\x1b]0;owned\\x07\\rSTATE ok"


def test_main_shows_the_control_characters_in_an_error_it_prints(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The run-level error line carries the exception's message, which is the
    server's or the vault's text, and it goes to stderr outside the emitter."""
    import sopuli.cli as cli_module

    def failing(**_: object) -> None:
        raise RuntimeError(HOSTILE)

    monkeypatch.setattr(cli_module, "configure_streams", lambda: None)
    monkeypatch.setattr(cli_module.cli, "main", failing)

    with pytest.raises(SystemExit):
        cli_module.main()

    printed = capsys.readouterr().err
    assert "\x1b" not in printed
    assert "\r" not in printed
    assert "\\x1b]0;owned\\x07\\rSTATE ok" in printed


def test_the_debug_formatter_shows_control_characters() -> None:
    import logging

    from sopuli.output.debug import DebugFormatter

    record = logging.LogRecord("sopuli.driver", logging.DEBUG, __file__, 1, HOSTILE, None, None)

    formatted = DebugFormatter(started=0.0).format(record)

    assert "\x1b" not in formatted
    assert "\r" not in formatted


def test_json_keeps_the_servers_text_exactly() -> None:
    """The JSON encoder escapes control characters itself, so the document
    carries the message as the server sent it."""
    assert json.loads(json.dumps({"message": HOSTILE}))["message"] == HOSTILE
