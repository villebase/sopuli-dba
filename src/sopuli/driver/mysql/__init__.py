"""The MySQL driver (P1). The target is a server (#1221).

``session`` imports PyMySQL, and the registry imports ``session``. The other
modules are tier 0: they build what is sent and read what comes back, with no
client on the machine. The driver runs `doctor`, the `creds` commands and the
`account` commands. It applies no account attributes: that call raises
``SOPULI-20006``.
"""
