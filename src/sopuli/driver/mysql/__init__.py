"""The MySQL driver (P1). The target is a server (#1221).

``session`` imports PyMySQL, and the registry imports ``session``. The other
modules are tier 0: they build what is sent and read what comes back, with no
client on the machine. The driver serves the commands the registry lists for
MySQL. It applies no account attributes: a capability refuses them at plan
time, and the call raises ``SOPULI-20006`` if a run gets there anyway.
"""
