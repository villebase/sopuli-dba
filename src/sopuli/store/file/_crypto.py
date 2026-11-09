"""age encryption for the ``file`` store, through ``pyrage`` (#1415).

ADR-006 rule 1: the vendor client is imported inside the backend, never at
package import. ``pyrage`` is imported in each function that uses it, so this
module imports cleanly in a base install, where the install-shape test imports
it with the clients blocked.

**What leaves the process is ciphertext.** :func:`seal` hands the store's
document, passwords included, to ``pyrage`` in this process, and only the
encrypted bytes it returns are written to disk. That call is the store's
write, as the vault write is invariant 2's first exception.

**The identity is revealed here and nowhere else.** It is the store's own
secret key, read from a MaterialRef (`01-configuration.md` §3a). It is handed
to ``pyrage`` to decrypt in this process and is never written or sent, as the
HashiCorp token is presented in ``_transport.py``.

**This build encrypts to X25519 recipients only.** The config accepts any
``age1…`` recipient's shape. A plugin recipient (``age1yubikey1…``) needs the
plugin's own program and may prompt, and a post-quantum one is not read by
``pyrage``'s X25519 type. Both are refused when the store opens, with the
recipient's position, rather than failing in the middle of a write.

Every message here names a position or a kind, never a key's text. A recipient
is public, but a value in that list may be a secret key pasted by mistake.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from sopuli.exit_codes import ExitCode
from sopuli.secrets import Secret
from sopuli.store.protocol import StoreError

if TYPE_CHECKING:
    from pyrage import x25519

#: How an age-encrypted file starts, binary and armoured. An identity file that
#: starts this way is passphrase-protected: opening it needs a prompt, which a
#: scheduled run cannot answer (#1415).
ENCRYPTED_PREFIXES = (b"age-encryption.org/v1", b"-----BEGIN AGE ENCRYPTED FILE-----")

#: How an X25519 secret key line starts. A plugin identity starts
#: ``AGE-PLUGIN-``.
SECRET_KEY_PREFIX = "AGE-SECRET-KEY-1"

#: What to write instead, for every refusal of the identity's text.
ONE_SECRET_KEY = "write one `AGE-SECRET-KEY-1…` line, as `age-keygen` prints it"


class IdentityError(StoreError):
    """The age identity cannot open the store. Fixed in the identity or the config."""

    # A config problem on the boundary's terms: exit 9, as a MaterialRef that
    # names nothing is.
    category = "config"
    exit_code = ExitCode.CONFIG_INVALID


@dataclass(frozen=True)
class Keys:
    """What the store encrypts to, and the identity that decrypts it.

    ``repr`` of a ``pyrage`` identity names no key, and this class adds none.
    """

    identity: x25519.Identity
    recipients: tuple[x25519.Recipient, ...]


def keys(identity: Secret, recipients: tuple[str, ...] | None) -> Keys:
    """The store's keys: its identity, and every recipient it encrypts to.

    The identity's own public key is always the first recipient, so the next
    run can read what this one wrote. ``recipients`` adds to it (#1415).
    """
    own = load_identity(identity)
    return Keys(identity=own, recipients=(own.to_public(), *_recipients(recipients or ())))


def load_identity(text: Secret) -> x25519.Identity:
    """The one X25519 identity in an age identity file's text.

    Comment lines (``#``) and blank lines are skipped, as ``age`` does. One key
    and only one: a store has one identity, and the first of several would be
    a guess about which one the others were for.
    """
    import pyrage
    from pyrage import x25519

    raw = text.reveal()
    if raw.encode("utf-8").lstrip().startswith(ENCRYPTED_PREFIXES):
        raise IdentityError(
            "the file store's identity is passphrase-protected",
            hint=(
                "opening it would need a prompt, which a scheduled run cannot answer; "
                "keep an unprotected identity readable only by the tool's own user"
            ),
        )
    lines = [line.strip() for line in raw.splitlines()]
    found = [line for line in lines if line and not line.startswith("#")]
    if any(line.startswith("AGE-PLUGIN-") for line in found):
        raise IdentityError(
            "the file store's identity is an age plugin identity",
            hint="this build opens a file store with an X25519 identity, from `age-keygen`",
        )
    if len(found) != 1 or not found[0].startswith(SECRET_KEY_PREFIX):
        raise IdentityError(
            "the file store's identity is not one age secret key", hint=ONE_SECRET_KEY
        )
    try:
        return x25519.Identity.from_str(found[0])
    except pyrage.IdentityError:
        # pyrage's message names no key, but it is not repeated either: the
        # line is a secret.
        raise IdentityError(
            "the file store's identity is not a valid age secret key", hint=ONE_SECRET_KEY
        ) from None


def _recipients(values: tuple[str, ...]) -> tuple[x25519.Recipient, ...]:
    import pyrage
    from pyrage import x25519

    parsed = []
    for index, value in enumerate(values):
        try:
            parsed.append(x25519.Recipient.from_str(value))
        except pyrage.RecipientError:
            raise IdentityError(
                f"recipients[{index}] is not an X25519 age recipient",
                hint=(
                    "this build encrypts a file store to X25519 keys only, as "
                    "`age-keygen -y` prints them; plugin and post-quantum recipients "
                    "are not supported"
                ),
            ) from None
    return tuple(parsed)


def seal(plaintext: bytes, keys: Keys) -> bytes:
    """``plaintext`` encrypted to every recipient in ``keys``."""
    import pyrage

    try:
        return bytes(pyrage.encrypt(plaintext, list(keys.recipients)))
    except pyrage.EncryptError:
        raise StoreError("the file store could not encrypt its document") from None


def unseal(ciphertext: bytes, keys: Keys) -> bytes:
    """What ``ciphertext`` holds, decrypted with the store's identity.

    A file this identity cannot open, and a file that is not age at all, are
    told apart where ``pyrage`` tells them apart: "no matching keys" is the
    identity's fault, and anything else is the file's.
    """
    import pyrage

    try:
        return bytes(pyrage.decrypt(ciphertext, [keys.identity]))
    except pyrage.DecryptError as error:
        if "no matching keys" in str(error).lower():
            raise IdentityError(
                "the file store's identity cannot decrypt its file",
                hint=(
                    "the file was encrypted to other keys; name the identity it was "
                    "written for in `identity:`"
                ),
            ) from None
        raise StoreError(
            "the file store's file is not an age-encrypted file it can read",
            hint="the file is damaged or was replaced; restore it from a backup",
        ) from None
