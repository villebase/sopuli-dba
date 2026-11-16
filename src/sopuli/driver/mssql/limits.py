"""The longest password on a SQL Server target. Tier 0.

A module of its own, as on MySQL, so that the registry can read the limit
without importing the module that computes a password value.

**128 characters, as UTF-16 code units.** The server refuses 129 in clear,
``15156``, and takes a value for a longer one (``02_client_hash_probe.py``,
CH6). The server counts ``nvarchar`` characters, which are UTF-16 code units,
so a character outside the Basic Multilingual Plane counts as two. Only ASCII
was measured at the limit; counting code units can refuse a password the
server would take, never the other way round.
"""

from __future__ import annotations

from sopuli.passwords import ByteLimit

MAX_PASSWORD_CHARACTERS = 128

#: The same limit in bytes: UTF-16LE takes 2 bytes for each code unit.
LIMIT = ByteLimit(max_bytes=2 * MAX_PASSWORD_CHARACTERS, encoding="utf-16-le", charset="UTF-16")
