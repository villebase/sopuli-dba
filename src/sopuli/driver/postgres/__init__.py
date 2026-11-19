"""The PostgreSQL driver (P1), for UC-1. The target is a cluster.

:mod:`.session` is the module :data:`sopuli.driver.registry.DRIVERS` imports for
``type: postgresql``, and the one module that imports ``psycopg`` when it is
imported (ADR-006). :mod:`.password`, which only it imports, needs libpq to
compute a verifier and psycopg's ``sql`` to quote the statement, and imports
them inside the functions that use them (#1168). The others are tier 0: they
build what is sent and read what comes back, with no client on the machine.

The driver serves the commands the registry lists for PostgreSQL. It applies
no role attributes and does not expire a password: a capability refuses each
before the call, and the call raises ``SOPULI-20006`` if a run gets there
anyway.
"""
