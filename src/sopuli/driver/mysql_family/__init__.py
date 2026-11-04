"""The code the MySQL driver shares with the MariaDB driver to come. Tier 0.

MariaDB is a driver of its own (``docs/README.md``, ``mariadb-driver-shape``),
and the two share what this package holds (#1267, decision D7):

- ``connection``: the arguments a PyMySQL connection is made with, TLS
  included;
- ``client``: `doctor`'s line about PyMySQL;
- ``accounts``: an account as a user name and a host, and how the server
  compares and names one;
- ``errors``: the error numbers both servers send, and PyMySQL's own, with
  their categories and hints;
- ``password``: the passwords both refuse, before a value is computed.

What the products do differently stays in each driver: on MySQL, the
``caching_sha2_password`` hash, ``RETAIN`` and ``DISCARD``, ``SYSTEM_USER``,
and every read of a ``mysql.user`` column. Nothing here imports PyMySQL.
"""
