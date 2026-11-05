"""The longest password on a MariaDB target. Tier 0, and free of PyMySQL and
PyNaCl.

A module of its own, holding the one fact the registry's literal is pinned to,
so a test can compare the two without importing anything that computes or sends
a password.

**1024 bytes, in UTF-8**, as decided on #1270. The
server sees only the value the driver computes, so it sets and logs in a
password of 1 byte to 1 MiB on both plugins (``09_password_length_probe.py``,
PW1). The limit is for the application's client, which may not handle what
PyMySQL handles. It is the PostgreSQL limit (#1060). Both values are computed
over the password's UTF-8 bytes, whatever the server's character set.
"""

from __future__ import annotations

from sopuli.passwords import ByteLimit

MAX_PASSWORD_BYTES = 1024

#: The limit as the generator and `policy sample --max-bytes` read it.
LIMIT = ByteLimit(max_bytes=MAX_PASSWORD_BYTES, encoding="utf-8", charset="utf8mb4")
