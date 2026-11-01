"""Names are compared by ``upper()``, never by ``casefold()`` (#1218).

Invariant 5 compares account, role and profile names by ``upper()``, because
that is how the drivers look a name up. The two folds give different answers
for some names: the dotless ``ı`` and ``i`` are one name by ``upper()`` (both
become ``I``) and two names by ``casefold()``. A selector or a guardrail that
folded by ``casefold()`` could then match an account the driver treats as
another one, or miss one it treats as the same. #1208 moved every such
comparison to ``upper()``. This file keeps a new one from moving back.

**A tripwire, not a proof**, like ``tests/test_reveal_sites.py``. It parses
the tree, so a ``casefold()`` in a comment or a docstring does not count, and
``getattr(name, "casefold")()`` would get past it. Every real call so far is an
ordinary method call.

A module that needs ``casefold()`` for something that is not a database name
goes in :data:`PERMITTED`, with the reason.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "sopuli"

#: The modules that may call ``casefold()``, by path, and why each one may.
PERMITTED = {
    "config/notify.py": (
        "a notify template's placeholder, compared with `NAMED_SECRETS`. It is a "
        "template field name, not a database name, so invariant 5's fold does not apply"
    ),
}


def _casefold_calls() -> dict[str, list[int]]:
    """Every ``.casefold()`` call in ``src/``, by module path."""
    found: dict[str, list[int]] = {}
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "casefold"
            ):
                found.setdefault(path.relative_to(SRC).as_posix(), []).append(node.lineno)
    return found


def test_no_module_outside_the_list_calls_casefold() -> None:
    unexpected = {
        where: lines for where, lines in _casefold_calls().items() if where not in PERMITTED
    }

    assert not unexpected, (
        f"casefold() is called where names may be compared: {unexpected}. Compare "
        f"account, role and profile names by upper(), invariant 5's comparison and the "
        f"drivers' lookup. If the value is not a database name, add the module to "
        f"PERMITTED here, with the reason."
    )


def test_the_permitted_list_has_not_gone_stale() -> None:
    """A listed module that no longer calls ``casefold()`` would hide the next call
    added to it, so its entry is deleted."""
    calls = _casefold_calls()
    stale = sorted(where for where in PERMITTED if where not in calls)

    assert not stale, f"listed in PERMITTED and calling no casefold(): {stale}. Delete the entry."


def test_the_two_folds_disagree_on_a_name() -> None:
    """The reason the test exists, checked rather than only stated."""
    assert "ı".upper() == "i".upper()
    assert "ı".casefold() != "i".casefold()


def test_the_sweep_finds_a_call_it_should() -> None:
    """A sweep that found nothing anywhere would make the first test pass for ever.
    The permitted call in ``notify.py`` is the one it must see."""
    assert _casefold_calls().get("config/notify.py")
