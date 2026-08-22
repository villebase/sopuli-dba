"""How long a password may be here, and in what character set (#179).

`#171 <https://github.com/futville/sopuli-dba/issues/171>`_ made a
:class:`~sopuli.passwords.ByteLimit` a required argument to
:func:`~sopuli.driver.oracle.statements.alter_user_password`, precisely so a
statement cannot be built by somebody who never found out. This is where the
answer comes from.

**The maximum is derived from the probed version, and that is not a violation of
invariant 3.** The rule is that the tool never branches on a version *from
config*; no dictionary view states the password limit, so the only place it can
come from is the version the database itself reported when the session opened.
The distinction matters: `04-testing.md` §3 makes the same point about the
harness, and the version here is :attr:`Scope.db_version`, read on connect.

**The character set needs no grant.** ``NLS_DATABASE_PARAMETERS`` answered
``AL32UTF8`` to a service account holding exactly `02-oracle-privileges.md` §2's
grants and nothing else -- measured, because a probe requiring a grant nobody
made is the failure #178 already found once. It is the *database* character set
rather than the session's, which is what §8 specifies: the limit is counted in
the character set the server stores the password in, not the one this client
happens to be speaking.

**An unmapped character set falls back to ASCII, deliberately.** Oracle has a
long tail of character sets and this table will never be complete. The fallback
is not a guess about byte widths -- it is a refusal to make one: under ``ascii``
every generated password (§8's alphabets are ASCII) measures exactly, and
anything outside ASCII is refused by
:func:`~sopuli.driver.oracle.statements.admissible` with a message naming the
database's own word for the character set. The alternative, assuming UTF-8,
silently *under*-counts on Oracle's ``UTF8`` (CESU-8) for supplementary
characters, which would build a statement the server rejects.
"""

from __future__ import annotations

from sopuli.driver.oracle.capabilities import Cursor, read
from sopuli.passwords import ByteLimit

#: The *database* character set (§8), not the session's.
CHARSET_QUERY = "select value from nls_database_parameters where parameter = 'NLS_CHARACTERSET'"

#: 128 bytes from 12.2, 30 below it.
MODERN_MAX_BYTES = 128
LEGACY_MAX_BYTES = 30
LONG_IDENTIFIER_FLOOR = (12, 2)

#: Oracle's character sets, as Python codecs. Deliberately short: these are the
#: ones a supported release is actually installed with, and an entry is cheap to
#: add for a site that needs it. Anything absent lands on :data:`FALLBACK`.
CODECS: dict[str, str] = {
    "AL32UTF8": "utf-8",
    "UTF8": "utf-8",
    "US7ASCII": "ascii",
    "WE8MSWIN1252": "cp1252",
    "WE8ISO8859P1": "latin-1",
    "WE8ISO8859P15": "iso8859-15",
    "EE8MSWIN1250": "cp1250",
    "CL8MSWIN1251": "cp1251",
}

#: What an unmapped character set gets. See the module docstring: this refuses to
#: guess rather than guessing conservatively.
FALLBACK = "ascii"


def max_bytes(db_version: str | None) -> int:
    """Oracle's maximum password length for this release.

    Unknown reads as **modern**, not as legacy. A tool that could not read the
    version and therefore capped every password at 30 bytes would be silently
    weakening passwords on a database that accepts 128 -- and the server refuses
    an over-long one anyway, so the cost of being wrong the other way is an
    error rather than a weaker credential.
    """
    return LEGACY_MAX_BYTES if _below(db_version, LONG_IDENTIFIER_FLOOR) else MODERN_MAX_BYTES


def _below(version: str | None, floor: tuple[int, int]) -> bool:
    if not version:
        return False
    parts = version.split(".")
    try:
        return (int(parts[0]), int(parts[1])) < floor
    except (IndexError, ValueError):
        return False


def character_set(cursor: Cursor) -> str | None:
    """The database character set, or ``None`` where it could not be read."""
    row = read(cursor, CHARSET_QUERY)
    return str(row[0]).upper() if row and row[0] else None


def resolve(cursor: Cursor, db_version: str | None) -> ByteLimit:
    """This target's password limit, counted in its own character set."""
    charset = character_set(cursor)
    return ByteLimit(
        max_bytes=max_bytes(db_version),
        encoding=CODECS.get(charset or "", FALLBACK),
        charset=charset,
    )
