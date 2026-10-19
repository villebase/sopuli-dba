"""``python -m sopuli``: the same entry point as the ``sopuli`` command.

It works when the ``sopuli`` command is not on ``PATH``, which is the usual state
after a pip user install on Windows. ``docs/getting-started.md`` §2 points a user
here when the shell does not recognise ``sopuli``.

The guard keeps an import harmless. ``tests/store/test_install_shape.py`` imports
every module in the package, and an unguarded call would run the CLI there.
"""

from sopuli.cli import main

if __name__ == "__main__":
    main()
