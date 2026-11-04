"""The MariaDB driver (#1268).

:mod:`~sopuli.driver.mariadb.session` connects and serves `doctor`; the modules
beside it are tier 0. MariaDB gets a driver of its own, not a variant of
MySQL's (#1202, decision 2), and shares :mod:`sopuli.driver.mysql_family` with
it (#1267, decision 7).
"""
