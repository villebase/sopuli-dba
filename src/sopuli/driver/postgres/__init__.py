"""The PostgreSQL driver (P1), for UC-1. The target is a cluster.

:mod:`.session` is the module :data:`sopuli.driver.registry.DRIVERS` imports for
``type: postgresql``, and the one module that imports ``psycopg`` when it is
imported (ADR-006). :mod:`.password`, which only it imports, needs libpq to
compute a verifier and psycopg's ``sql`` to quote the statement, and imports
them inside the functions that use them (#1168). The others are tier 0: they
build what is sent and read what comes back, with no client on the machine.

This build connects, reports what it found, describes a role, checks its
password by logging in as it, and sets it: UC-1's commands. UC-2's operations
refuse with ``SOPULI-20006``.
"""
