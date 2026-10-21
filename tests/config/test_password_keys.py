"""One key for "the same password" (#847).

Tier 0 (04-testing.md §4): pure, no I/O. The loader's two checks and
``creds generate`` all key on :func:`sopuli.config.password_keys.password_key`,
so what makes two bindings one password is decided here.
"""

from __future__ import annotations

import pytest

from sopuli.config.model import Binding
from sopuli.config.password_keys import PasswordKey, password_key
from sopuli.config.secret_refs import parse_secret_ref
from sopuli.generate import password_key as generate_key


def bound(ref: str | None, *, vault: str | None = "vault-dev") -> Binding:
    secret = None if ref is None else parse_secret_ref(ref)
    return Binding(account="acme_web_user", target="appdb-alpha", secret=secret, vault=vault)


def key(ref: str, *, vault: str | None = "vault-dev") -> PasswordKey:
    found = password_key(bound(ref, vault=vault))
    assert found is not None
    return found


def test_two_spellings_of_one_path_are_one_key() -> None:
    assert key("apps//acme/db/#DB") == key("/apps/acme/db#DB")


def test_the_pointer_is_decoded() -> None:
    """``a~1b`` is the key ``a/b``, one level, not ``a`` then ``b``."""
    assert key("apps/acme#DB/a~1b").place == ("DB", "a/b")
    assert key("apps/acme#DB/a/b").place == ("DB", "a", "b")
    assert key("apps/acme#DB/a~1b") != key("apps/acme#DB/a/b")


def test_a_ref_with_no_field_is_the_whole_document() -> None:
    assert key("apps/acme").place == ()


def test_the_store_is_part_of_the_key() -> None:
    assert key("apps/acme#DB", vault="vault-dev") != key("apps/acme#DB", vault="vault-prod")


def test_a_binding_with_no_ref_has_no_key() -> None:
    assert password_key(bound(None)) is None


def test_a_binding_with_no_store_yet_has_a_key_for_the_loader_and_none_for_generate() -> None:
    """C15: the loader compares bindings as the file states their stores, and
    ``creds generate`` refuses a binding whose store never arrived."""
    binding = bound("apps/acme#DB", vault=None)

    loader = password_key(binding)
    assert loader is not None
    assert loader.store is None
    assert generate_key(binding) is None


def test_generate_uses_the_same_key() -> None:
    binding = bound("apps//acme#DB/acme_web_user")
    assert generate_key(binding) == password_key(binding)


@pytest.mark.parametrize(
    ("one", "other", "overlap"),
    [
        ("apps/acme#DB", "apps/acme#DB", True),
        ("apps/acme#DB", "apps/acme#DB/acme_api_user", True),
        ("apps/acme", "apps/acme#DB/acme_api_user", True),
        ("apps/acme#DB/acme_web_user", "apps/acme#DB/acme_api_user", False),
        ("apps/acme#DB", "apps/acme#DBX", False),
        ("apps/acme#DB", "apps/beta#DB", False),
        ("apps/acme#DB/a~1b", "apps/acme#DB/a", False),
    ],
    ids=[
        "same-place",
        "field-contains-pointer",
        "document-contains-everything",
        "sibling-pointers",
        "field-prefix-is-not-nesting",
        "another-document",
        "an-escaped-slash-is-not-a-level",
    ],
)
def test_nesting(one: str, other: str, overlap: bool) -> None:
    assert key(one).overlaps(key(other)) is overlap
    assert key(other).overlaps(key(one)) is overlap


def test_one_place_in_two_stores_does_not_overlap() -> None:
    assert not key("apps/acme#DB", vault="vault-dev").overlaps(
        key("apps/acme#DB", vault="vault-prod")
    )
