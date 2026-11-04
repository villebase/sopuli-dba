"""The MariaDB driver (#1268).

Not written yet: there is no ``session`` module, so a MariaDB target resolves to
:class:`~sopuli.driver.registry.DriverNotImplementedError`, ``SOPULI-20006``. The
package exists so that the registry's lookup of ``sopuli.driver.mariadb.session``
finds no module, rather than failing on a missing parent.
"""
