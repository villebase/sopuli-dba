"""The ``file`` store: one age-encrypted file per store (#1372, #1415).

Not built yet. The document format (:mod:`._document`) and the encryption
(:mod:`._crypto`) are here. The registry names ``sopuli.store.file.store``,
which the next part of #1372 adds; until it exists, a run that reaches a
``file`` store is refused with ``SOPULI-20005``, and ``config validate`` and
``doctor`` say this build cannot serve it.

Nothing in this package imports a vendor client at import time (ADR-006
rule 1), so a base install can import every module here.
"""
