"""The SQL Server driver (P1). The target is a server (#1538).

``session`` imports pyodbc and is the one module that needs the ``mssql``
extra. The others are tier 0: ``password``, ``limits`` and ``statements``
compute the value a password change sends and build the statements that send
it; ``connection``, ``errors``, ``scope`` and ``client`` build the connection
string, classify a failure and read what the session is, with no client on
the machine. ``docs/design/02-mssql-privileges.md`` is the spec.
"""
