"""The PostgreSQL driver (P1), for UC-1. The target is a cluster.

:mod:`.session` is the module :data:`sopuli.driver.registry.DRIVERS` imports for
``type: postgresql``, and the only one that imports ``psycopg`` (ADR-006). The
others are tier 0: they build what is sent and read what comes back, with no
client on the machine.

This build connects and reports what it found. Every operation past that
refuses with ``SOPULI-20006``, as the whole driver did before it had a module.
"""
