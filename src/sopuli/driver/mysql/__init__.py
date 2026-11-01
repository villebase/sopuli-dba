"""The MySQL driver (P1). The target is a server (#1221).

The modules here are tier 0: they build what is sent and read what comes back,
with no client on the machine. Nothing imports them yet, so a ``mysql`` target
still refuses with ``SOPULI-20006``.
"""
