"""The MySQL driver (P1). The target is a server (#1221).

``session`` imports PyMySQL, and the registry imports ``session``. The other
modules are tier 0: they build what is sent and read what comes back, with no
client on the machine. The driver connects and reports the server for `doctor`;
every other command refuses a ``mysql`` target with ``SOPULI-20006``.
"""
