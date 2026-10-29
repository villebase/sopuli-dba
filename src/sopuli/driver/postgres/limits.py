"""The longest password on a PostgreSQL target. Tier 0, and free of psycopg.

A module of its own, holding the one fact the registry's literal is pinned to,
so a test can compare the two without importing anything that computes or sends
a password.

**1024 bytes, in UTF-8.** libpq 13 cannot log in with a longer password
(``pg-password-length``, #1057), and an application may still use it. The
server would accept any length behind a verifier, so the ceiling is the tool's,
decided on #1060. PostgreSQL compares passwords as UTF-8 whatever the
database's encoding: SCRAM hashes the bytes the client sends, and libpq sends
UTF-8.
"""

from __future__ import annotations

from sopuli.passwords import ByteLimit

MAX_PASSWORD_BYTES = 1024

#: The limit as the generator and `policy sample --max-bytes` read it.
LIMIT = ByteLimit(max_bytes=MAX_PASSWORD_BYTES, encoding="utf-8", charset="UTF8")
