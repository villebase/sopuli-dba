"""What ``keyring set`` and ``keyring delete`` do (#1417, decision 3).

The verbs write and remove the entries that a ``{ keyring: NAME }`` source or a
``method: keyring`` admin credential reads: service ``sopuli``, user name
``NAME``. Writing through the library that reads them gives each entry the name
the reader looks for.

**No config is needed** (decision 1 of the verbs). The entry is how a new
machine gets the credential its config authenticates with, so the verb runs
before the config can. When a config is loaded and names no such entry, the run
says so, because that is usually a typo in one or the other.

**Convergent** (invariant 9): ``set`` reads the entry first and compares it in
the process, so writing the value it already holds is ``unchanged``, and
deleting an entry that is not there is ``absent``. Neither changes anything, and
neither is an error. Replacing a different value needs ``--replace``: a mistyped
vault token stops every scheduled run on the machine, as
``--overwrite-current`` guards a ``current`` in the vault.

**No audit event.** The verbs change nothing in a database or a vault; the run
document is their whole report.
"""

from __future__ import annotations

import hmac
from collections.abc import Callable
from dataclasses import dataclass
from typing import BinaryIO

from sopuli import os_keyring
from sopuli.config.errors import ArgumentError
from sopuli.config.model import Config
from sopuli.diagnostics import KEYRING_REPLACE_NEEDS_FLAG
from sopuli.keyring_survey import EntryReport, KeyringReport, named_anywhere, sources
from sopuli.material import strip_one_newline
from sopuli.output.document import Diagnostic
from sopuli.safety import RefusedError
from sopuli.secrets import Secret

#: Asks for a value without echoing it: :func:`getpass.getpass` in a real run.
Asker = Callable[[str], str]


@dataclass(frozen=True)
class Change:
    """What one run of a `keyring` verb did, or would do."""

    report: KeyringReport
    #: Whether the keyring was written to: ``changed`` in the summary.
    changed: bool
    diagnostics: tuple[Diagnostic, ...] = ()


def check_name(entry: str) -> str:
    """The entry name, or a refusal of one nothing could read back.

    The config takes any non-empty string, so this refuses only what no config
    line could name: an empty name, or one that starts or ends with a space,
    which YAML would have stripped.
    """
    if not entry or entry != entry.strip():
        raise ArgumentError(
            f"{entry!r} is not an entry name a config can refer to",
            hint="give the name as the config writes it, such as vault-dev",
        )
    return entry


def read_value(entry: str, *, stdin: BinaryIO, terminal: bool, ask: Asker) -> Secret:
    """The value to store, never from an option (invariant 1).

    From a pipe or a redirect when stdin is not a terminal, with one trailing
    ``\\n`` or ``\\r\\n`` removed: a pipe adds one, and PowerShell's adds ``\\r\\n``.
    At a terminal, asked twice without echo, and refused when the two differ.
    An empty value is refused either way, because a reader treats an empty
    entry as a missing one.
    """
    if terminal:
        first = ask(f"Value for {os_keyring.describe(entry)}: ")
        if first:
            again = ask("Type it again: ")
            if not hmac.compare_digest(first.encode("utf-8"), again.encode("utf-8")):
                raise ArgumentError(
                    "the two values did not match",
                    hint="nothing was written; run the command again",
                )
        text = first
    else:
        try:
            text = strip_one_newline(stdin.read().decode("utf-8"))
        except UnicodeDecodeError as error:
            raise ArgumentError(
                "stdin is not UTF-8 text", hint="pipe the value in as UTF-8 text"
            ) from error
    if not text:
        raise ArgumentError(
            "the value is empty",
            hint=(
                "nothing was written: a reader treats an empty entry as a missing one. "
                "Pipe the value in, or run the command at a terminal to be asked for it"
            ),
        )
    return Secret(text)


def set_entry(
    entry: str, value: Secret, *, config: Config | None, replace: bool, dry_run: bool
) -> Change:
    """Write ``value`` as the entry, unless it is already there."""
    found = os_keyring.compare(entry, value, where=WHERE_SET)
    action = {
        os_keyring.ABSENT: "add",
        os_keyring.SAME: "unchanged",
        os_keyring.DIFFERENT: "replace",
    }[found]
    notes = list(_unnamed(entry, config))
    if action == "replace" and not replace:
        if not dry_run:
            raise RefusedError(
                f"{os_keyring.describe(entry)} holds a different value, and replacing "
                f"it was not authorised (--replace)",
                hint=(
                    "pass --replace to replace it. Every run that reads this entry "
                    "will use the new value"
                ),
            )
        notes.append(
            Diagnostic(
                level="warning",
                message=f"replacing {os_keyring.describe(entry)} needs --replace",
                code=KEYRING_REPLACE_NEEDS_FLAG,
            )
        )
    write = action in ("add", "replace") and not dry_run
    if write:
        os_keyring.write(entry, value, where=WHERE_SET)
    return _change(
        entry,
        config,
        present=found != os_keyring.ABSENT,
        action=action,
        applied=not dry_run,
        changed=write,
        notes=notes,
    )


def delete_entry(entry: str, *, config: Config | None, dry_run: bool) -> Change:
    """Remove the entry, if it is there."""
    there = os_keyring.present(entry, where=WHERE_DELETE)
    write = there and not dry_run
    if write:
        os_keyring.remove(entry, where=WHERE_DELETE)
    return _change(
        entry,
        config,
        present=there,
        action="delete" if there else "absent",
        applied=not dry_run,
        changed=write,
        notes=[],
    )


#: The positions the refusals of :mod:`sopuli.os_keyring` name.
WHERE_SET = "keyring set"
WHERE_DELETE = "keyring delete"


def _change(
    entry: str,
    config: Config | None,
    *,
    present: bool,
    action: str,
    applied: bool,
    changed: bool,
    notes: list[Diagnostic],
) -> Change:
    chosen = os_keyring.backend(where=WHERE_SET)
    required_by = tuple(sources(config).get(entry, ())) if config is not None else ()
    one = EntryReport(
        entry=entry,
        required_by=required_by,
        present=present,
        action=action,
        applied=applied,
    )
    report = KeyringReport(backend=os_keyring.name_of(chosen), problem=None, entries=(one,))
    return Change(report=report, changed=changed, diagnostics=tuple(notes))


def _unnamed(entry: str, config: Config | None) -> tuple[Diagnostic, ...]:
    if config is None or named_anywhere(config, entry):
        return ()
    return (
        Diagnostic(
            level="info",
            message=(
                f"the loaded config names no keyring entry {entry!r}: check the "
                f"spelling here and in the config"
            ),
        ),
    )
