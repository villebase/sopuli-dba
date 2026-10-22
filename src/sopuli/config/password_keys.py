"""What "the same password" means, for every check that asks.

A password is a place in one document of one store: the field, then the
pointer's segments. Two bindings with one key hold one password, whatever else
differs. Four places ask the question. The loader refuses two accounts on one
password and one password under two policies. ``creds generate`` draws each
password once and refuses a write that carries two values for one. The
promotion gate in ``creds apply`` asks whether a credential confirmed on another
target. All four must agree, and a key each would agree only while each
normalised the same way. This module is the one definition, and it is in
the config layer so that the loader, :mod:`sopuli.generate` and the CLI can all
import it.

Pure: no I/O, as the rest of config parsing (CLAUDE.md, *Keep pure layers pure*).
"""

from __future__ import annotations

from dataclasses import dataclass

from sopuli.config.model import Binding
from sopuli.config.secret_refs import SecretRef, normalise_path

__all__ = ["PasswordKey", "declared_password_key", "place_of"]


@dataclass(frozen=True)
class PasswordKey:
    """One password: a place in one document of one store.

    ``store`` and ``path`` are what :func:`sopuli.lock.keys.lock_key` builds the
    document's lock from, so "shares a password" cannot disagree with "shares a
    write". ``store`` is ``None`` for a binding whose store comes later, from a
    profile or ``SOPULI_VAULT`` (C15). The loader compares such bindings as the
    file states them, and ``creds generate`` never sees one.

    ``place`` is the field, then the pointer's segments, decoded (RFC 6901), so
    ``#DB/a~1b`` is the key ``a/b`` and not two levels. A ref with no field is the
    whole document, the empty place.
    """

    store: str | None
    path: str
    place: tuple[str, ...]

    def overlaps(self, other: PasswordKey) -> bool:
        """Whether one key's place contains the other's, or they are one place.

        Writing a place replaces everything inside it, so ``#DB`` and
        ``#DB/acme_api_user`` in one document are two passwords that cannot both
        be kept.
        """
        if (self.store, self.path) != (other.store, other.path):
            return False
        shorter = min(len(self.place), len(other.place))
        return self.place[:shorter] == other.place[:shorter]


def place_of(ref: SecretRef) -> tuple[str, ...]:
    """Where in its document a ref's value lives: the field, then the decoded pointer."""
    return () if ref.field is None else (ref.field, *ref.pointer_segments)


def declared_password_key(binding: Binding) -> PasswordKey | None:
    """Where ``binding``'s password is stored, with the store as the file declares it.

    ``None`` if it names no ref. ``store`` is ``None`` where the store comes
    later. :func:`sopuli.generate.password_key` is the one to use once a run has
    its stores: it gives no key for a binding that has none.
    """
    ref = binding.secret
    if ref is None:
        return None
    return PasswordKey(store=binding.vault, path=normalise_path(ref.path), place=place_of(ref))
