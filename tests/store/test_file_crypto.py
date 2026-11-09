"""The file store's age encryption, through pyrage (#1415).

Tier 0: pyrage is installed by the `file` extra and runs in the process. Keys
are generated per test, so no key is written into the repository.
"""

from __future__ import annotations

import pytest

pyrage = pytest.importorskip("pyrage", reason="the file extra is not installed")

from pyrage import x25519  # noqa: E402

from sopuli.exit_codes import ExitCode  # noqa: E402
from sopuli.secrets import Secret  # noqa: E402
from sopuli.store.file._crypto import (  # noqa: E402
    KeysError,
    keys,
    load_identity,
    seal,
    unseal,
)
from sopuli.store.protocol import StoreError  # noqa: E402

PLAINTEXT = b'{"current":"Pw-acme-not-a-real-1"}'


def new_identity() -> tuple[str, str]:
    """A fresh X25519 key pair, as `age-keygen` would print it: secret, public."""
    identity = x25519.Identity.generate()
    return str(identity), str(identity.to_public())


def test_what_is_sealed_unseals_with_the_identity() -> None:
    secret, _ = new_identity()
    store = keys(Secret(secret), None)

    sealed = seal(PLAINTEXT, store)

    assert sealed.startswith(b"age-encryption.org/v1")
    assert PLAINTEXT not in sealed
    assert unseal(sealed, store) == PLAINTEXT


def test_the_identity_s_own_key_is_always_a_recipient() -> None:
    """A recipients list that leaves out the identity's key would make a store
    the next run cannot read (#1418's review)."""
    secret, public = new_identity()
    _, colleague = new_identity()

    store = keys(Secret(secret), (colleague,))

    assert [str(one) for one in store.recipients] == [public, colleague]
    assert unseal(seal(PLAINTEXT, store), store) == PLAINTEXT


def test_every_recipient_can_read_what_is_sealed() -> None:
    secret, _ = new_identity()
    colleague_secret, colleague = new_identity()

    sealed = seal(PLAINTEXT, keys(Secret(secret), (colleague,)))

    assert unseal(sealed, keys(Secret(colleague_secret), None)) == PLAINTEXT


def test_an_identity_file_with_comments_is_read() -> None:
    secret, public = new_identity()
    text = f"# created: 2026-11-09T10:00:00Z\n# public key: {public}\n\n{secret}\n"

    assert str(load_identity(Secret(text)).public()) == public


def test_a_byte_order_mark_before_the_identity_is_skipped() -> None:
    """Windows editors and PowerShell 5 write one."""
    secret, public = new_identity()

    assert str(load_identity(Secret(chr(0xFEFF) + secret + "\n")).public()) == public


def test_the_identity_never_renders_its_key() -> None:
    """str of a pyrage identity is the secret key; the wrapper shows ***."""
    secret, _ = new_identity()
    store = keys(Secret(secret), None)

    assert secret not in str(store.identity)
    assert secret not in repr(store.identity)
    assert secret not in repr(store)
    assert secret not in f"{store}"


def test_the_identity_s_own_key_listed_again_is_kept_once() -> None:
    secret, public = new_identity()
    _, colleague = new_identity()

    store = keys(Secret(secret), (public, colleague, colleague))

    assert [str(one) for one in store.recipients] == [public, colleague]


@pytest.mark.parametrize(
    "text",
    [
        "age-encryption.org/v1\n-> scrypt abc 18\n",
        "-----BEGIN AGE ENCRYPTED FILE-----\nYWdl\n-----END AGE ENCRYPTED FILE-----\n",
    ],
    ids=["binary-header-only", "armoured"],
)
def test_a_passphrase_protected_identity_is_refused(text: str) -> None:
    """The armoured form is text and reaches this check as it is. A real
    binary file is not UTF-8, so only its text header can be shown here: the
    store must refuse the binary file before decoding it (#1372)."""
    with pytest.raises(KeysError) as caught:
        load_identity(Secret(text))

    assert "passphrase-protected" in str(caught.value)
    assert "prompt" in str(caught.value)


def test_a_plugin_identity_is_refused() -> None:
    with pytest.raises(KeysError) as caught:
        load_identity(Secret("AGE-PLUGIN-YUBIKEY-1QQQQQQQQQQQQQQQQQQQQQQQ\n"))

    assert "plugin identity" in str(caught.value)


def test_two_keys_are_refused() -> None:
    first, _ = new_identity()
    second, _ = new_identity()

    with pytest.raises(KeysError) as caught:
        load_identity(Secret(f"{first}\n{second}\n"))

    assert "not one age secret key" in str(caught.value)
    assert first not in str(caught.value)


@pytest.mark.parametrize("text", ["", "# only a comment\n", "hunter2"])
def test_text_that_is_not_a_secret_key_is_refused_without_repeating_it(text: str) -> None:
    with pytest.raises(KeysError) as caught:
        load_identity(Secret(text))

    assert "not one age secret key" in str(caught.value)
    if text.strip():
        assert text.strip() not in str(caught.value)


def test_a_damaged_secret_key_is_refused_without_repeating_it() -> None:
    secret, _ = new_identity()
    broken = secret[:-4] + "QQQQ"

    with pytest.raises(KeysError) as caught:
        load_identity(Secret(broken))

    assert "not a valid age secret key" in str(caught.value)
    assert broken not in str(caught.value)


def test_an_identity_problem_is_a_config_error() -> None:
    with pytest.raises(KeysError) as caught:
        load_identity(Secret(""))

    assert caught.value.category == "config"
    assert caught.value.exit_code == ExitCode.CONFIG_INVALID


@pytest.mark.parametrize(
    "recipient",
    ["age1yubikey1" + "q" * 50, "age1pq1" + "q" * 60],
    ids=["plugin", "post-quantum"],
)
def test_a_recipient_that_is_not_x25519_is_refused_by_position(recipient: str) -> None:
    """The config accepts the shape; this build encrypts to X25519 only."""
    secret, _ = new_identity()
    _, colleague = new_identity()

    with pytest.raises(KeysError) as caught:
        keys(Secret(secret), (colleague, recipient))

    assert "recipients[1] is not an X25519 age recipient" in str(caught.value)


def test_another_identity_cannot_open_the_store() -> None:
    secret, _ = new_identity()
    other, _ = new_identity()
    sealed = seal(PLAINTEXT, keys(Secret(secret), None))

    with pytest.raises(KeysError) as caught:
        unseal(sealed, keys(Secret(other), None))

    assert "cannot decrypt its file" in str(caught.value)
    # A wrong `addr` gives the same error, so the hint names both.
    assert "`addr` names this store's file" in (caught.value.hint or "")
    assert "`identity` names the key" in (caught.value.hint or "")


def test_pyrage_still_words_a_wrong_identity_as_this_module_expects() -> None:
    """The tripwire for the one place this module reads pyrage's wording: if
    it changes, a wrong identity is reported as damage, and this fails."""
    secret, _ = new_identity()
    other, _ = new_identity()
    sealed = pyrage.encrypt(PLAINTEXT, [x25519.Identity.from_str(secret).to_public()])

    with pytest.raises(pyrage.DecryptError, match="(?i)no matching keys"):
        pyrage.decrypt(sealed, [x25519.Identity.from_str(other)])


def test_a_file_that_is_not_age_is_a_store_error_not_an_identity_error() -> None:
    secret, _ = new_identity()

    with pytest.raises(StoreError) as caught:
        unseal(b"plain text, not age", keys(Secret(secret), None))

    assert not isinstance(caught.value, KeysError)
    assert "not an age-encrypted file" in str(caught.value)
    hint = caught.value.hint or ""
    assert hint.index("`addr` names this store's file") < hint.index("restore")


def test_an_armoured_file_with_leading_space_is_not_age_rather_than_damaged() -> None:
    """The check reads the same bytes pyrage would, so a file pyrage refuses
    is never let through and then called damaged."""
    secret, _ = new_identity()

    with pytest.raises(StoreError) as caught:
        unseal(b"\n  -----BEGIN AGE ENCRYPTED FILE-----\n", keys(Secret(secret), None))

    assert "not an age-encrypted file" in str(caught.value)


def test_a_file_encrypted_with_a_passphrase_is_named_as_such() -> None:
    """Not reported as a wrong identity: `age -p` made it, not this store."""
    secret, _ = new_identity()
    sealed = pyrage.passphrase.encrypt(PLAINTEXT, "a passphrase")

    with pytest.raises(StoreError) as caught:
        unseal(sealed, keys(Secret(secret), None))

    assert not isinstance(caught.value, KeysError)
    assert "encrypted with a passphrase" in str(caught.value)
    assert "`addr`" in (caught.value.hint or "")


def test_a_damaged_age_file_says_to_check_before_restoring() -> None:
    secret, _ = new_identity()
    sealed = seal(PLAINTEXT, keys(Secret(secret), None))

    with pytest.raises(StoreError) as caught:
        unseal(sealed[:-20], keys(Secret(secret), None))

    assert "cannot be decrypted" in str(caught.value)
    hint = caught.value.hint or ""
    assert hint.index("`addr` names this store's file") < hint.index("restore")
