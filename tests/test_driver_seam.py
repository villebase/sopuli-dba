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

import pytest

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


def _in_oracle(name: str) -> bool:
    return name == ORACLE_PACKAGE or name.startswith(ORACLE_PACKAGE + ".")


def _base(module: str, node: ast.ImportFrom) -> str:
    """The absolute module an ``ImportFrom`` names, a relative one resolved
    against ``module``'s own package."""
    if node.level == 0:
        return node.module or ""
    package = ["sopuli", *module.removesuffix(".py").split("/")][:-1]
    if module.endswith("__init__.py"):
        package = ["sopuli", *module.split("/")[:-1]]
    package = package[: len(package) - (node.level - 1)]
    return ".".join([*package, *([node.module] if node.module else [])])


def _oracle_imports_in(module: str, tree: ast.Module) -> set[str]:
    """The Oracle modules ``tree`` imports, each named as the module it reads
    from: ``from sopuli.driver.oracle.errors import X`` counts as
    ``sopuli.driver.oracle.errors``, and ``from sopuli.driver import oracle`` as
    ``sopuli.driver.oracle``."""
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found |= {alias.name for alias in node.names if _in_oracle(alias.name)}
        elif isinstance(node, ast.ImportFrom):
            base = _base(module, node)
            if _in_oracle(base):
                found.add(base)
            else:
                found |= {
                    f"{base}.{alias.name}"
                    for alias in node.names
                    if _in_oracle(f"{base}.{alias.name}")
                }
    return found


def _oracle_imports() -> set[tuple[str, str]]:
    return {
        (module, name)
        for module, tree in _outside_the_oracle_driver().items()
        for name in _oracle_imports_in(module, tree)
    }


def test_no_module_outside_the_driver_names_the_oracle_driver_class() -> None:
    assert _names("OracleDriver") == set()


def test_the_cli_has_no_resolve_driver_left_to_patch() -> None:
    import sopuli.cli

    assert not hasattr(sopuli.cli, "resolve_driver")


def test_oracle_imports_outside_the_driver_only_shrink() -> None:
    assert _oracle_imports() == KNOWN_ORACLE_IMPORTS


@pytest.mark.parametrize(
    ("module", "source", "found"),
    [
        ("apply.py", "from sopuli.driver import oracle", "sopuli.driver.oracle"),
        ("output/view.py", "from ..driver.oracle import errors", "sopuli.driver.oracle"),
        ("driver/registry.py", "from .oracle.session import x", "sopuli.driver.oracle.session"),
        ("driver/registry.py", "from . import oracle", "sopuli.driver.oracle"),
    ],
)
def test_an_import_spelled_another_way_still_counts(module: str, source: str, found: str) -> None:
    """The import forms a refactor is likely to write: the package imported from
    its parent, and a relative import."""
    assert _oracle_imports_in(module, ast.parse(source)) == {found}


def test_an_import_of_something_else_does_not_count() -> None:
    tree = ast.parse("from sopuli.driver import protocol\nfrom . import registry")

    assert _oracle_imports_in("driver/x.py", tree) == set()
