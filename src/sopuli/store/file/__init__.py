"""The ``file`` store: one age-encrypted file per store (#1372, #1415).

For local development and CI, not for production: every run that opens one
warns with ``SOPULI-W070``. The registry names :mod:`.store`, whose
``connect`` opens :class:`._store.FileStore`. The document format
(:mod:`._document`), the encryption (:mod:`._crypto`) and the file on disk
(:mod:`._disk`) are the store's parts.

ADR-006 rule 1: :mod:`.store`, the module the registry names, imports
``pyrage`` at module level, so a machine without it fails there and the
registry says to install ``sopuli-dba[file]``. Every other module here
imports it inside the functions that use it, so a base install can import
them.

What ``doctor`` and the diagnostics use is exported here, so they depend on
this package and not on its parts: :func:`leftovers`, which finds the
temporary files a write left behind (#1430), and what it returns.
"""

from sopuli.store.file._disk import Leftover
from sopuli.store.file._store import Leftovers, leftovers

__all__ = ["Leftover", "Leftovers", "leftovers"]
