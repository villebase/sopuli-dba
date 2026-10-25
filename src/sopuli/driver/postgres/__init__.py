"""The PostgreSQL driver (P1), for UC-1. The target is a cluster.

The modules here are tier 0: they build what is sent and read what comes back,
with no client on the machine. Nothing imports them yet, so a ``postgresql``
target still refuses with ``SOPULI-20006``.
"""
