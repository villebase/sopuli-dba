"""The SQL Server driver (P1). The target is a server (#1538).

``password``, ``limits`` and ``statements`` are tier 0: they compute the value
a password change sends and build the statements that send it, with no client
on the machine. ``docs/design/02-mssql-privileges.md`` is the spec.
"""
