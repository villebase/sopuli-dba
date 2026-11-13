"""How an optional DBA-created view is checked and its refusals read (#1457). Tier 0.

A DBA may create a read-only view with ``SQL SECURITY DEFINER`` over the keys
the tool needs and nothing else, and grant the tool account ``SELECT`` on it.
The tool never trusts its shape: it reads the view's column names from
``information_schema.COLUMNS`` before any row, every session, and does not
read a view with a column outside the expected set (invariant 2, P2). Under a
column grant only the granted columns are listed, and the others cannot be
read either.

MySQL and MariaDB answer alike (``12_definer_view_probe.py``,
``16_definer_view_probe.py``):

- no row in ``COLUMNS``, or ``1142`` on the read: the view is absent, its
  schema is absent, or the tool account has no grant on it. The server tells
  none of these apart. ``1146`` is a view dropped while the grant is left;
- ``1045`` on the read, in a session already logged in: its definer is gone;
- ``1356``: its definer cannot read what the view selects.

The server's message is never repeated, as it could carry a stored value.
"""

from __future__ import annotations

from collections.abc import Collection

from sopuli.driver.mysql_family.accounts import text
from sopuli.driver.mysql_family.errors import error_number
from sopuli.driver.protocol import Cursor

#: ``ER_ACCESS_DENIED_ERROR``: the view's definer is gone.
DEFINER_GONE = 1045
#: ``ER_VIEW_INVALID``: the definer cannot read what the view selects.
VIEW_INVALID = 1356
#: ``ER_TABLEACCESS_DENIED_ERROR``: no grant on the view, or no view.
NO_GRANT = 1142
#: ``ER_NO_SUCH_TABLE``: the view was dropped after its columns were read,
#: with the grant left, as the install script's own re-run can do. Absent,
#: as MariaDB's ``sopuli.global_privileges`` reader takes it.
NO_SUCH_TABLE = 1146
#: The client's own error numbers (CR_*), such as a lost connection: not the
#: server's answer about the view.
CLIENT_ERRORS = range(2000, 3000)


def columns_query(schema: str, name: str) -> str:
    """The view's column names, as the tool account may see them."""
    return (
        "select COLUMN_NAME from information_schema.COLUMNS "
        f"where TABLE_SCHEMA = '{schema}' and TABLE_NAME = '{name}'"
    )


def shape_problem(
    cursor: Cursor, schema: str, name: str, *, expected: Collection[str], read: Collection[str]
) -> tuple[bool, str | None]:
    """Whether the view is listed at all, and what is wrong with its columns.

    ``(False, None)`` for a view the tool account cannot see. ``(True, what)``
    for one with a column outside ``expected``, or without one of ``read``.
    Names are compared without case: the server does too.
    """
    cursor.execute(columns_query(schema, name))
    columns = {text(row[0]).lower() for row in cursor.fetchall()}
    if not columns:
        return False, None
    extra = tuple(sorted(columns - {column.lower() for column in expected}))
    if extra:
        return True, f"it has columns the tool does not expect ({', '.join(extra)})"
    missing = [column for column in read if column.lower() not in columns]
    if missing:
        return True, f"the tool account cannot read its columns {', '.join(missing)}"
    return True, None


def refusal(error: Exception, *, source: str) -> str | None:
    """What a refused read of the view says: ``None`` where the view is
    absent or not granted, else what is wrong with it. ``source`` is what its
    definer reads, such as ``mysql.user``.

    Raises ``error`` again where it is not the server's answer, such as a lost
    connection: that is the target's, as any read's would be.
    """
    number = error_number(error)
    if number is None or CLIENT_ERRORS.start <= number < CLIENT_ERRORS.stop:
        raise error
    if number in (NO_GRANT, NO_SUCH_TABLE):
        return None
    if number == DEFINER_GONE:
        return f"its definer no longer exists ({DEFINER_GONE})"
    if number == VIEW_INVALID:
        return f"its definer cannot read {source} ({VIEW_INVALID})"
    # Any other refusal of an optional view: not read, never the target's
    # failure (#1376). Only the number.
    return f"the server refused to read it ({number})"


def integer(value: object) -> int | None:
    """An integer the view gave, as text or a number. Raises ``ValueError``
    for anything else; the caller never repeats the value."""
    if value is None:
        return None
    found = text(value)
    if not found.lstrip("-").isdigit():
        raise ValueError("not an integer")
    return int(found)
