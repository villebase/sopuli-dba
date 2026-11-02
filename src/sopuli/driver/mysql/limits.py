"""The longest password on a MySQL target. Tier 0, and free of PyMySQL.

A module of its own, holding the one fact the registry's literal is pinned to,
so a test can compare the two without importing anything that computes or sends
a password.

**256 bytes, in UTF-8.** The server stores the hash of a longer password and
then refuses it at login with ``1045``, on 8.0.46, 8.4.13 and 9.7.4
(``02_client_hash_probe.py``, CH6). The hash is computed over the password's
UTF-8 bytes, whatever the server's character set.
"""

from __future__ import annotations

from sopuli.passwords import ByteLimit

MAX_PASSWORD_BYTES = 256

#: The limit as the generator and `policy sample --max-bytes` read it.
LIMIT = ByteLimit(max_bytes=MAX_PASSWORD_BYTES, encoding="utf-8", charset="utf8mb4")
