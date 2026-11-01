"""Names are compared by ``upper()``, never by ``casefold()`` (#1218).

Invariant 5 compares account, role and profile names by ``upper()``, because
that is how the drivers look a name up. The two folds give different answers
for some names: the dotless ``ı`` and ``i`` are one name by ``upper()`` (both
become ``I``) and two names by ``casefold()``. A selector or a guardrail that
folded by ``casefold()`` could then match an account the driver treats as
another one, or miss one it treats as the same. #1208 moved every such
comparison to ``upper()``. This file keeps a new one from moving back.

**A tripwire, not a proof**, like ``tests/test_reveal_sites.py``. It parses
the tree and finds every use of the ``casefold`` attribute, called or not, so
``name.casefold()`` and ``key=str.casefold`` are both found, and a mention in a
comment or a docstring is not. ``getattr(name, "casefold")`` would get past it.

**``lower()`` is not checked**, though it breaks the rule in the same way:
``"ı".lower()`` stays ``ı``. The code calls ``lower()`` in many places that
have nothing to do with names, such as messages and the reset record path,
which is ``upper().lower()`` on purpose. A list of those would be long and
would not help a reviewer. Review is what catches a name compared by
``lower()``.

A module that needs ``casefold()`` for something that is not a database name
goes in :data:`PERMITTED`, with the number of uses and the reason.
"""

from __future__ import annotations

import ast
from functools import cache
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "sopuli"

#: The modules that may use ``casefold``, by path: how many uses, and why.
#:
#: The count is pinned, so a second use added to a listed module fails here
#: until somebody argues for it too.
PERMITTED: dict[str, tuple[int, str]] = {
    "config/notify.py": (
        1,
        "a notify template's placeholder, compared with `NAMED_SECRETS`. It is a "
        "template field name, not a database name, so invariant 5's fold does not apply",
    ),
}


def _uses(tree: ast.AST) -> list[int]:
    """The line of every use of the ``casefold`` attribute in ``tree``."""
    return [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr == "casefold"
    ]


@cache
def _casefold_uses() -> dict[str, tuple[int, ...]]:
    """Every use of ``casefold`` in ``src/``, by module path."""
    found: dict[str, tuple[int, ...]] = {}
    for path in sorted(SRC.rglob("*.py")):
        lines = _uses(ast.parse(path.read_text(encoding="utf-8")))
        if lines:
            found[path.relative_to(SRC).as_posix()] = tuple(lines)
    return found


def test_casefold_is_used_only_where_the_list_allows() -> None:
    unexpected = {
        where: lines
        for where, lines in _casefold_uses().items()
        if where not in PERMITTED or len(lines) != PERMITTED[where][0]
    }

    assert not unexpected, (
        f"casefold is used where names may be compared: {unexpected}. Compare "
        f"account, role and profile names by upper(), invariant 5's comparison and the "
        f"drivers' lookup. If the value is not a database name, add the use to "
        f"PERMITTED here, with the reason."
    )


def test_the_permitted_list_has_not_gone_stale() -> None:
    """A listed module that no longer uses ``casefold`` would hide the next use
    added to it, so its entry is deleted."""
    uses = _casefold_uses()
    stale = sorted(where for where in PERMITTED if where not in uses)

    assert not stale, f"listed in PERMITTED and using no casefold: {stale}. Delete the entry."


def test_the_sweep_finds_a_call_and_a_reference() -> None:
    """A sweep that found nothing would make the first test pass for ever. This
    checks it on fixed source, so it does not depend on what ``src/`` holds."""
    source = "a = name.casefold()\nb = sorted(names, key=str.casefold)\n# x.casefold()\n"

    assert _uses(ast.parse(source)) == [1, 2]


def test_the_two_folds_disagree_on_a_name() -> None:
    """The reason the test exists, checked rather than only stated."""
    assert "ı".upper() == "i".upper()
    assert "ı".casefold() != "i".casefold()
