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
ENCRYPTED_PREFIXES = ("age-encryption.org/v1", "-----BEGIN AGE ENCRYPTED FILE-----")

#: The store's own file is always written binary by :func:`seal`.
BINARY_HEADER = b"age-encryption.org/v1\n"

#: The stanza a passphrase (``age -p``) writes in a binary header.
SCRYPT_STANZA = b"\n-> scrypt "

#: A UTF-8 byte-order mark, which Windows editors write before text. Built
#: with `chr` so the character is visible in the source.
BYTE_ORDER_MARK = chr(0xFEFF)

#: How an X25519 secret key line starts. A plugin identity starts
#: ``AGE-PLUGIN-``.
SECRET_KEY_PREFIX = "AGE-SECRET-KEY-1"

#: What to write instead, for every refusal of the identity's text.
ONE_SECRET_KEY = "write one `AGE-SECRET-KEY-1…` line, as `age-keygen` prints it"


class KeysError(StoreError):
    """The store's keys cannot open or encrypt it: its identity or its recipients.

    Fixed in the identity file or the config. Not named ``IdentityError``,
    which is ``pyrage``'s own class for a key it cannot parse.
    """

    # A config problem on the boundary's terms: exit 9, as a MaterialRef that
    # names nothing is.
    category = "config"
    exit_code = ExitCode.CONFIG_INVALID


class Identity:
    """The store's age identity, which renders as ``***`` (invariant 2).

    ``str`` of a ``pyrage`` identity is the ``AGE-SECRET-KEY-1…`` text itself,
    so the object is kept only inside this wrapper, as a password is kept
    inside :class:`~sopuli.secrets.Secret`. :meth:`decrypt` is the one place
    it leaves the wrapper, to go to ``pyrage``.
    """

    __slots__ = ("_key",)

    def __init__(self, key: x25519.Identity) -> None:
        self._key = key

    def __str__(self) -> str:
        return "***"

    def __repr__(self) -> str:
        return "***"

    def public(self) -> x25519.Recipient:
        """The identity's own public key, which is not a secret."""
        return self._key.to_public()

    def decrypt(self, ciphertext: bytes) -> bytes:
        """``ciphertext`` decrypted with this identity, by ``pyrage``.

        Raises ``pyrage.DecryptError``; :func:`unseal` says what it means.
        """
        import pyrage

        return bytes(pyrage.decrypt(ciphertext, [self._key]))


@dataclass(frozen=True)
class Keys:
    """What the store encrypts to, and the identity that decrypts it."""

    identity: Identity
    recipients: tuple[x25519.Recipient, ...]


def keys(identity: Secret, recipients: tuple[str, ...] | None) -> Keys:
    """The store's keys: its identity, and every recipient it encrypts to.

    The identity's own public key is always the first recipient, so the next
    run can read what this one wrote. ``recipients`` adds to it (#1415). A
    recipient listed twice, or the identity's own key listed again, is kept
    once.
    """
    own = load_identity(identity)
    found: dict[str, x25519.Recipient] = {}
    for one in (own.public(), *_recipients(recipients or ())):
        found.setdefault(str(one), one)
    return Keys(identity=own, recipients=tuple(found.values()))


def load_identity(text: Secret) -> Identity:
    """The one X25519 identity in an age identity file's text.

    Comment lines (``#``) and blank lines are skipped, as ``age`` does, and so
    is a UTF-8 byte-order mark, which Windows editors write. One key and only
    one: a store has one identity, and the first of several would be a guess
    about which one the others were for.

    A passphrase-protected identity is refused here when its text reaches
    this function, as the armoured form does. The binary form is not UTF-8
    text, so the store must look at the file's first bytes before decoding
    it, and refuse it there with the same words (#1372).
    """
    import pyrage
    from pyrage import x25519

    raw = text.reveal().removeprefix(BYTE_ORDER_MARK)
    if raw.lstrip().startswith(ENCRYPTED_PREFIXES):
        raise KeysError(
            "the file store's identity is passphrase-protected",
            hint=(
                "opening it would need a prompt, which a scheduled run cannot answer; "
                "keep an unprotected identity readable only by the tool's own user"
            ),
        )
    lines = [line.strip() for line in raw.splitlines()]
    found = [line for line in lines if line and not line.startswith("#")]
    if any(line.startswith("AGE-PLUGIN-") for line in found):
        raise KeysError(
            "the file store's identity is an age plugin identity",
            hint="this build opens a file store with an X25519 identity, from `age-keygen`",
        )
    if len(found) != 1 or not found[0].startswith(SECRET_KEY_PREFIX):
        raise KeysError("the file store's identity is not one age secret key", hint=ONE_SECRET_KEY)
    try:
        return Identity(x25519.Identity.from_str(found[0]))
    except pyrage.IdentityError:
        # pyrage's message names no key, but it is not repeated either: the
        # line is a secret.
        raise KeysError(
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
            raise KeysError(
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


#: What to check before anything else when the store's file cannot be read. A
#: wrong ``addr`` gives the same errors as a wrong identity or a damaged file,
#: and restoring a store that was fine loses the passwords written since.
CHECK_FIRST = (
    "first check that the store's `addr` names this store's file, and that "
    "`identity` names the key it was written for"
)


def unseal(ciphertext: bytes, keys: Keys) -> bytes:
    """What ``ciphertext`` holds, decrypted with the store's identity.

    Whether the file is age at all is read from its first bytes, not from
    ``pyrage``'s wording. An age file that does not decrypt is the identity's
    fault when ``pyrage`` says no key matched; any other failure is damage.
    If a later ``pyrage`` words that message differently, a wrong identity is
    reported as damage, and the hint still says to check ``addr`` and
    ``identity`` before restoring anything.
    """
    import pyrage

    # The bytes as they are, not stripped: pyrage is given these same bytes,
    # and would refuse what a stripped check had let through.
    if not ciphertext.startswith(tuple(prefix.encode() for prefix in ENCRYPTED_PREFIXES)):
        raise StoreError(
            "the file store's file is not an age-encrypted file",
            hint=f"{CHECK_FIRST}; if both are right, restore the file from a backup",
        )
    # The store always writes a binary header, which is text up to `---`. A
    # passphrase stanza there means `age -p` made the file, not this store.
    if ciphertext.startswith(BINARY_HEADER) and (SCRYPT_STANZA in ciphertext.split(b"\n---", 1)[0]):
        raise StoreError(
            "the file store's file is encrypted with a passphrase, not to the store's keys",
            hint=(
                "this store did not write it: check that the store's `addr` names this "
                "store's file. A file store is opened with its identity, never a passphrase"
            ),
        )
    try:
        return keys.identity.decrypt(ciphertext)
    except pyrage.DecryptError as error:
        if "no matching keys" in str(error).lower():
            raise KeysError(
                "the file store's identity cannot decrypt its file",
                hint=f"{CHECK_FIRST}; the file was encrypted to other keys",
            ) from None
        raise StoreError(
            "the file store's file is an age file that cannot be decrypted",
            hint=(
                f"{CHECK_FIRST}; if both are right, the file is damaged: restore it "
                "from a backup, and check that what it holds still matches the databases"
            ),
        ) from None
