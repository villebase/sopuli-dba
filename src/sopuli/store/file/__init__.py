"""The ``file`` store: one age-encrypted file per store (#1372, #1415).

For local development and CI, not for production: every run that opens one
warns with ``SOPULI-W069``. The registry names :mod:`.store`, whose
``connect`` opens :class:`._store.FileStore`. The document format
(:mod:`._document`), the encryption (:mod:`._crypto`) and the file on disk
(:mod:`._disk`) are the store's parts.

Nothing in this package imports a vendor client at import time (ADR-006
rule 1), so a base install can import every module here. ``pyrage`` is
imported inside the functions that use it, and the registry says to install
``sopuli-dba[file]`` where it is missing.
"""
