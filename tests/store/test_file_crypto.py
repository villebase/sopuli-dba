"""The file store's age encryption, through pyrage (#1415).

Tier 0: pyrage is installed by the `file` extra and runs in the process. Keys
are generated per test, so no key is written into the repository.
"""

from __future__ import annotations

import pytest
from pyrage import x25519

from sopuli.exit_codes import ExitCode
from sopuli.secrets import Secret
from sopuli.store.file._crypto import IdentityError, keys, load_identity, seal, unseal
from sopuli.store.protocol import StoreError

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

    assert str(load_identity(Secret(text)).to_public()) == public


@pytest.mark.parametrize(
    "text",
    [
        "age-encryption.org/v1\n-> scrypt abc 18\n",
        "-----BEGIN AGE ENCRYPTED FILE-----\nYWdl\n-----END AGE ENCRYPTED FILE-----\n",
    ],
    ids=["binary", "armoured"],
)
def test_a_passphrase_protected_identity_is_refused(text: str) -> None:
    with pytest.raises(IdentityError) as caught:
        load_identity(Secret(text))

    assert "passphrase-protected" in str(caught.value)
    assert "prompt" in str(caught.value)


def test_a_plugin_identity_is_refused() -> None:
    with pytest.raises(IdentityError) as caught:
        load_identity(Secret("AGE-PLUGIN-YUBIKEY-1QQQQQQQQQQQQQQQQQQQQQQQ\n"))

    assert "plugin identity" in str(caught.value)


def test_two_keys_are_refused() -> None:
    first, _ = new_identity()
    second, _ = new_identity()

    with pytest.raises(IdentityError) as caught:
        load_identity(Secret(f"{first}\n{second}\n"))

    assert "not one age secret key" in str(caught.value)
    assert first not in str(caught.value)


@pytest.mark.parametrize("text", ["", "# only a comment\n", "hunter2"])
def test_text_that_is_not_a_secret_key_is_refused_without_repeating_it(text: str) -> None:
    with pytest.raises(IdentityError) as caught:
        load_identity(Secret(text))

    assert "not one age secret key" in str(caught.value)
    if text.strip():
        assert text.strip() not in str(caught.value)


def test_a_damaged_secret_key_is_refused_without_repeating_it() -> None:
    secret, _ = new_identity()
    broken = secret[:-4] + "QQQQ"

    with pytest.raises(IdentityError) as caught:
        load_identity(Secret(broken))

    assert "not a valid age secret key" in str(caught.value)
    assert broken not in str(caught.value)


def test_an_identity_problem_is_a_config_error() -> None:
    with pytest.raises(IdentityError) as caught:
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

    with pytest.raises(IdentityError) as caught:
        keys(Secret(secret), (colleague, recipient))

    assert "recipients[1] is not an X25519 age recipient" in str(caught.value)


def test_another_identity_cannot_open_the_store() -> None:
    secret, _ = new_identity()
    other, _ = new_identity()
    sealed = seal(PLAINTEXT, keys(Secret(secret), None))

    with pytest.raises(IdentityError) as caught:
        unseal(sealed, keys(Secret(other), None))

    assert "cannot decrypt its file" in str(caught.value)


def test_a_file_that_is_not_age_is_a_store_error_not_an_identity_error() -> None:
    secret, _ = new_identity()

    with pytest.raises(StoreError) as caught:
        unseal(b"plain text, not age", keys(Secret(secret), None))

    assert not isinstance(caught.value, IdentityError)
    assert "not an age-encrypted file" in str(caught.value)
