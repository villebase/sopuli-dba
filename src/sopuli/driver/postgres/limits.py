"""The longest password on a PostgreSQL target. Tier 0, and free of psycopg.

Kept apart from :mod:`sopuli.driver.postgres.password`, which imports psycopg,
so a test can pin the registry's literal to this constant on a machine without
the ``postgres`` extra.

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
