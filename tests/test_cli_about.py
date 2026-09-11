"""``sopuli about`` -- the one command that is not a run (#413).

Tier 0 (``04-testing.md`` §4): ``CliRunner`` in-process, no containers, no I/O.
Trivially so here, because the command has no I/O to stub -- everything it
prints is compiled in.

Three things are worth holding, and only one of them is the output itself:

**That it stays outside the machinery.** Its whole justification is that it
resolves no settings and has no machine-readable half, so a later change that
gave it ``--output`` would be a change to what the command *is*.
``tests/test_cli_precedence.py`` holds the structural end of that (``NOT_A_RUN``);
this holds the end a user meets -- the options it refuses.

**That ``--version`` did not change.** The reason `about` exists at all is that
``--version`` has to stay one greppable line, so the test that says so belongs
next to the thing that was tempted to grow.

**That the colour gate is the tool's, not click's.** ``click.secho`` was the
obvious way to write this command and it is the wrong one: click strips ANSI
only when the stream is not a terminal, so a coloured banner written with
``secho`` reaches an interactive terminal with ``NO_COLOR=1`` set (verified
against click 8.4.2). P4 promises otherwise, and
:func:`~sopuli.output.color.resolve_color` is what keeps the promise.
"""

from __future__ import annotations

import io
from typing import TextIO, cast

import click
import pytest
from click.testing import CliRunner

from sopuli.cli import cli
from sopuli.exit_codes import ExitCode
from sopuli.output.about_view import (
    BANNER,
    MAINTAINER,
    REPO_URL,
    SUPPORT_URL,
    TAGLINE,
    render,
)
from sopuli.output.color import ColorChoice
from sopuli.output.emit import Emitter
from sopuli.version import get_version


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


class FakeStream(io.StringIO):
    """A stream that also knows whether it is a terminal."""

    def __init__(self, *, tty: bool) -> None:
        super().__init__()
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


@pytest.fixture
def vt_available(monkeypatch: pytest.MonkeyPatch) -> None:
    """Take the Windows console API out of the picture (see ``test_color.py``)."""
    monkeypatch.setattr("sopuli.output.color.enable_virtual_terminal", lambda _: True)


def written(
    choice: ColorChoice = ColorChoice.AUTO,
    *,
    tty: bool,
    env: dict[str, str] | None = None,
) -> str:
    """``about``'s text through the real emitter, onto a stream we can inspect."""
    stream = FakeStream(tty=tty)
    Emitter(stream=cast("TextIO", stream), color_choice=choice, env=env or {}).emit_text(render())
    return stream.getvalue()


# --------------------------------------------------------------- the output ---


def test_about_succeeds(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["about"])

    assert result.exit_code == ExitCode.SUCCESS


@pytest.mark.parametrize(
    "expected",
    [BANNER, TAGLINE, REPO_URL, MAINTAINER, SUPPORT_URL],
    ids=["banner", "tagline", "repo", "maintainer", "support"],
)
def test_about_prints_every_part(runner: CliRunner, expected: str) -> None:
    result = runner.invoke(cli, ["about"])

    assert expected in result.output


def test_about_prints_the_installed_version(runner: CliRunner) -> None:
    """The same string ``--version`` reports, from the same function.

    Two places naming a version is how they come to disagree, so this asserts
    they agree rather than asserting a literal.
    """
    result = runner.invoke(cli, ["about"])

    assert f"version {get_version()}" in result.output


def test_about_says_the_same_thing_twice(runner: CliRunner) -> None:
    """No I/O behind it, so there is nothing for a second run to differ about.

    Not idempotency in invariant 9's sense -- nothing mutates -- but the
    property the command is *for*: identical bytes on every machine and every
    invocation is what makes it quotable in a bug report.
    """
    first = runner.invoke(cli, ["about"]).output
    second = runner.invoke(cli, ["about"]).output

    assert first == second


def test_about_output_is_ascii(runner: CliRunner) -> None:
    """The tool's own prose stays ASCII (``tests/test_cli_smoke.py``).

    It binds hardest here: a banner is exactly where somebody reaches for box
    drawing, and it renders beautifully on the terminals that have the font and
    as a row of boxes on the ones that do not.
    """
    runner.invoke(cli, ["about"]).output.encode("ascii")


# ------------------------------------------------------ outside the machinery ---


def test_about_declares_no_parameters_at_all() -> None:
    """The command's own parser, not a list somebody maintains.

    Empty rather than ``{"--help"}``: click adds the help option when it builds
    a context, so what a command *declares* is the whole of what was written
    here. That is the assertion worth making -- one declared option is how the
    second one arrives.
    """
    assert cli.commands["about"].params == []


def test_about_still_has_help(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["about", "--help"])

    assert result.exit_code == ExitCode.SUCCESS
    assert "about [OPTIONS]" in result.output


@pytest.mark.parametrize(
    "flag",
    [["--output", "json"], ["--dry-run"], ["--config", "sopuli.yaml"], ["--color", "never"]],
    ids=["output", "dry-run", "config", "color"],
)
def test_about_refuses_a_global_option_after_the_verb(runner: CliRunner, flag: list[str]) -> None:
    """Exit 2, because it is not an option this command has.

    Including ``--color``, which the command *does* honour from the position
    before the verb. Accepting it in both places would mean declaring it, and a
    command that declares one global option is a command somebody will add the
    next one to.
    """
    result = runner.invoke(cli, ["about", *flag])

    assert result.exit_code == ExitCode.USAGE


def test_about_emits_no_json(runner: CliRunner) -> None:
    """There is no machine half, so asking the group for one must not produce a
    run document describing a command that acted on nothing."""
    result = runner.invoke(cli, ["--output", "json", "about"])

    assert result.exit_code == ExitCode.SUCCESS
    assert TAGLINE in result.output


def test_version_is_still_one_plain_line(runner: CliRunner) -> None:
    """The reason `about` exists. ``--version`` is parsed by scripts and CI."""
    result = runner.invoke(cli, ["--version"])

    assert result.exit_code == ExitCode.SUCCESS
    assert len(result.output.strip().splitlines()) == 1
    assert get_version() in result.output
    assert BANNER.splitlines()[0] not in result.output
    assert click.unstyle(result.output) == result.output


# ------------------------------------------------------------- the colour gate ---


@pytest.mark.usefixtures("vt_available")
def test_the_banner_is_coloured_on_a_terminal() -> None:
    assert "\x1b[" in written(tty=True)


def test_the_banner_is_plain_down_a_pipe() -> None:
    """`sopuli about > BANNER.txt`, or any `| grep`."""
    assert "\x1b[" not in written(tty=False)


@pytest.mark.usefixtures("vt_available")
@pytest.mark.parametrize("variable", ["NO_COLOR", "SOPULI_NO_COLOR"])
def test_no_colour_reaches_the_banner_on_a_terminal(variable: str) -> None:
    """What ``click.secho`` would have got wrong.

    click strips ANSI on a non-terminal and consults neither variable, so the
    obvious one-line implementation passes the pipe test above and fails this
    one -- on the only stream a banner is ever actually read from.
    """
    assert "\x1b[" not in written(tty=True, env={variable: "1"})


@pytest.mark.usefixtures("vt_available")
def test_colour_never_is_honoured_before_the_verb(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["--color", "never", "about"])

    assert "\x1b[" not in result.output


def test_colour_always_is_honoured_before_the_verb(runner: CliRunner) -> None:
    """``CliRunner``'s stream is not a terminal, so this is also the proof that
    the group's flag reaches a command that declares none of its own."""
    result = runner.invoke(cli, ["--color", "always", "about"])

    assert "\x1b[" in result.output


@pytest.mark.usefixtures("vt_available")
def test_the_colour_carries_no_meaning() -> None:
    """`palette.py`'s first rule, and it is free here: strip the escapes and the
    screen is the plain screen, byte for byte."""
    assert click.unstyle(written(tty=True)) == written(tty=False)
