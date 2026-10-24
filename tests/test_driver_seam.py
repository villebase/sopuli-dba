"""Where Oracle still reaches past the driver interface, pinned so it only shrinks.

P1 says no command contains vendor code and Oracle's shape must not leak into
the interface. Planning the PostgreSQL driver found where it does. This file
holds the line while those places are removed:

- no module outside the Oracle driver names `OracleDriver`. A command gets a
  driver from `sopuli.driver.registry.driver_for` (#1030);
- `sopuli.cli` has no `resolve_driver` left. A test that still patched it would
  patch nothing and then dial a real database;
- every import of a `sopuli.driver.oracle` module from outside that package is
  listed in :data:`KNOWN_ORACLE_IMPORTS`.

**A tripwire, not a proof**, like `tests/test_reveal_sites.py`: it parses the
tree, so it sees ordinary imports and names, and not an `importlib` call with a
string.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "sopuli"
ORACLE_PACKAGE = "sopuli.driver.oracle"

#: Each entry is a module outside the Oracle driver that still imports from it,
#: and so a leak to remove before or while a second driver is written. Removing
#: an import fails this test until its entry goes too, so the set can only
#: shrink. Adding one is a new leak, and needs a reason in review.
KNOWN_ORACLE_IMPORTS = {
    ("cli.py", "sopuli.driver.oracle.client"),
    ("cli.py", "sopuli.driver.oracle.limits"),
    ("cli.py", "sopuli.driver.oracle.verification"),
    ("cli.py", "sopuli.driver.oracle.wallet"),
    ("diagnostics.py", "sopuli.driver.oracle.wallet"),
    ("output/status_view.py", "sopuli.driver.oracle.rollover"),
    ("output/wallet_view.py", "sopuli.driver.oracle.wallet"),
    ("preflight.py", "sopuli.driver.oracle.errors"),
    ("reset.py", "sopuli.driver.oracle.accounts"),
}


def _outside_the_oracle_driver() -> dict[str, ast.Module]:
    oracle = SRC / "driver" / "oracle"
    return {
        path.relative_to(SRC).as_posix(): ast.parse(path.read_text(encoding="utf-8"))
        for path in sorted(SRC.rglob("*.py"))
        if oracle not in path.parents
    }


def _names(identifier: str) -> set[str]:
    """The modules that use ``identifier`` as a name or an attribute."""
    found = set()
    for module, tree in _outside_the_oracle_driver().items():
        for node in ast.walk(tree):
            if (isinstance(node, ast.Name) and node.id == identifier) or (
                isinstance(node, ast.Attribute) and node.attr == identifier
            ):
                found.add(module)
    return found


def _oracle_imports() -> set[tuple[str, str]]:
    found = set()
    for module, tree in _outside_the_oracle_driver().items():
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module is not None:
                imported = [node.module]
            elif isinstance(node, ast.Import):
                imported = [alias.name for alias in node.names]
            else:
                continue
            for name in imported:
                if name == ORACLE_PACKAGE or name.startswith(ORACLE_PACKAGE + "."):
                    found.add((module, name))
    return found


def test_no_module_outside_the_driver_names_the_oracle_driver_class() -> None:
    assert _names("OracleDriver") == set()


def test_the_cli_has_no_resolve_driver_left_to_patch() -> None:
    import sopuli.cli

    assert not hasattr(sopuli.cli, "resolve_driver")


def test_oracle_imports_outside_the_driver_only_shrink() -> None:
    assert _oracle_imports() == KNOWN_ORACLE_IMPORTS
