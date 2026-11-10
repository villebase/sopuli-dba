"""The ``file`` store: one age-encrypted file, read and written whole (#1415).

Tier 0, with real files and real age encryption: pyrage runs in the process.
Keys are generated per test. The store is not reachable from a config yet
(``store.py`` adds ``connect``, #1372 split 4), so these build it with
``open_store`` or directly.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

pyrage = pytest.importorskip("pyrage", reason="the file extra is not installed")

from pyrage import x25519  # noqa: E402

from sopuli.config.model import MaterialRef, Vault  # noqa: E402
from sopuli.secrets import Secret  # noqa: E402
from sopuli.store.file import _crypto, _disk  # noqa: E402
from sopuli.store.file._crypto import KeysError  # noqa: E402
from sopuli.store.file._disk import FileChangedError  # noqa: E402
from sopuli.store.file._store import FileStore, open_store  # noqa: E402
from sopuli.store.protocol import (  # noqa: E402
    CAS,
    DEGRADED,
    LIST,
    MERGE_PATCH,
    OK,
    UNREACHABLE,
    VERSIONING,
    CasConflictError,
    PathMetadata,
    SecretStore,
    StoreError,
)

NAME = "acme-dev"
START = datetime(2026, 11, 10, 9, 0, tzinfo=UTC)


class Clock:
    """A clock that moves a minute per reading."""

    def __init__(self) -> None:
        self.now = START

    def __call__(self) -> datetime:
        self.now += timedelta(minutes=1)
        return self.now


def new_secret() -> str:
    return str(x25519.Identity.generate())


def make_store(
    path: Path, *, secret: str | None = None, max_versions: int | None = None
) -> FileStore:
    return FileStore(
        name=NAME,
        path=path,
        keys=_crypto.keys(Secret(secret or new_secret()), None, store=NAME),
        max_versions=max_versions,
        clock=Clock(),
    )


@pytest.fixture
def store(tmp_path: Path) -> FileStore:
    return make_store(tmp_path / "store.age")


def data_of(store: FileStore, path: str, version: int | None = None) -> Any:
    found = store.read(path, version=version)
    return None if found is None else found.data


# ------------------------------------------------------------ the protocol ---


def test_it_is_a_secret_store(store: FileStore) -> None:
    assert isinstance(store, SecretStore)


def test_it_supports_versioning_and_list_and_no_cas(store: FileStore) -> None:
    """P2's table: no `cas`, so a changing command needs `advisory-only`."""
    assert store.supports() == frozenset({VERSIONING, LIST})
    assert CAS not in store.supports()
    assert MERGE_PATCH not in store.supports()


def test_an_empty_store_reads_nothing_and_has_no_file(store: FileStore) -> None:
    assert store.read("acme/app") is None
    assert store.list("") == ()
    assert store.versions("acme/app") is None
    assert store.metadata("acme/app") is None
    assert not store.path.exists()


def test_a_write_is_read_back_with_its_version(store: FileStore) -> None:
    assert store.write("acme/app", {"current": "Pw-acme-1"}, cas=0) == 1
    assert store.write("acme/app", {"current": "Pw-acme-2"}, cas=1) == 2

    found = store.read("acme/app")
    assert found is not None
    assert found.data == {"current": "Pw-acme-2"}
    assert found.version == 2


def test_the_file_is_encrypted(store: FileStore) -> None:
    store.write("acme/app", {"current": "Pw-acme-1"}, cas=None)

    raw = store.path.read_bytes()
    assert raw.startswith(b"age-encryption.org/v1")
    assert b"Pw-acme-1" not in raw
    assert b"acme/app" not in raw


def test_a_pinned_version_is_read_until_it_is_pruned(tmp_path: Path) -> None:
    store = make_store(tmp_path / "store.age", max_versions=2)
    for n in range(1, 4):
        store.write("acme/app", {"current": f"Pw-acme-{n}"}, cas=None)

    assert data_of(store, "acme/app", 2) == {"current": "Pw-acme-2"}
    assert data_of(store, "acme/app", 1) is None
    assert data_of(store, "acme/app", 4) is None


def test_a_write_keeps_another_path_written_meanwhile(tmp_path: Path) -> None:
    """Every call reads the file afresh: a write by another run to another
    path, between this run's read and its write, is kept."""
    path = tmp_path / "store.age"
    secret = new_secret()
    this_run = make_store(path, secret=secret)
    other_run = make_store(path, secret=secret)
    this_run.write("acme/app", {"current": "a"}, cas=0)
    seen = this_run.read("acme/app")
    assert seen is not None

    other_run.write("acme/other", {"current": "b"}, cas=0)
    this_run.write("acme/app", {"current": "a2"}, cas=seen.version)

    assert data_of(other_run, "acme/other") == {"current": "b"}
    assert data_of(other_run, "acme/app") == {"current": "a2"}


def test_a_cas_that_moved_is_refused_and_nothing_is_written(store: FileStore) -> None:
    store.write("acme/app", {"current": "a"}, cas=0)
    store.write("acme/app", {"current": "b"}, cas=1)

    with pytest.raises(CasConflictError, match="is at version 2, and the write expected 1"):
        store.write("acme/app", {"current": "c"}, cas=1)
    with pytest.raises(CasConflictError):
        store.write("acme/app", {"current": "c"}, cas=0)

    assert data_of(store, "acme/app") == {"current": "b"}


def test_a_file_changed_inside_a_write_is_refused(
    store: FileStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Another run's replace between this write's own read and its replace."""
    store.write("acme/app", {"current": "a"}, cas=0)
    other = make_store(store.path, secret=None)
    other.keys = store.keys
    seal = _crypto.seal

    def another_run_writes(plaintext: bytes, keys: _crypto.Keys) -> bytes:
        monkeypatch.setattr(_crypto, "seal", seal)
        other.write("acme/other", {"current": "b"}, cas=0)
        return seal(plaintext, keys)

    monkeypatch.setattr(_crypto, "seal", another_run_writes)

    with pytest.raises(FileChangedError):
        store.write("acme/app", {"current": "a2"}, cas=1)

    assert data_of(store, "acme/app") == {"current": "a"}
    assert data_of(store, "acme/other") == {"current": "b"}


def test_versions_list_numbers_and_times_oldest_first(tmp_path: Path) -> None:
    store = make_store(tmp_path / "store.age", max_versions=2)
    for n in range(1, 4):
        store.write("acme/app", {"current": str(n)}, cas=None)

    history = store.versions("acme/app")

    assert history is not None
    assert history.current == 3
    assert history.oldest_kept == 2
    assert [one.version for one in history.versions] == [2, 3]
    assert [one.created_at for one in history.versions] == [
        START + timedelta(minutes=2),
        START + timedelta(minutes=3),
    ]
    assert not any(one.deleted or one.destroyed for one in history.versions)


def test_metadata_says_no_cas_required_and_the_kept_count(tmp_path: Path) -> None:
    store = make_store(tmp_path / "store.age", max_versions=3)
    store.write("acme/app", {"current": "a"}, cas=None)

    assert store.metadata("acme/app") == PathMetadata(cas_required=False, max_versions=3)


def test_list_is_bounded_and_sorted(store: FileStore) -> None:
    for path in ("locks/b", "locks/a", "locksmiths/x", "locks"):
        store.write(path, {"v": 1}, cas=None)

    assert store.list("locks") == ("locks/a", "locks/b")
    assert store.list("/locks/") == ("locks/a", "locks/b")
    assert store.list("") == ("locks", "locks/a", "locks/b", "locksmiths/x")


def test_patch_and_require_cas_are_refused_with_the_store_named(store: FileStore) -> None:
    with pytest.raises(StoreError, match=f'file store "{NAME}" cannot apply a merge patch'):
        store.patch("acme/app", {"current": "a"}, cas=None)
    with pytest.raises(StoreError, match="advisory-only"):
        store.require_cas("acme/app")


def test_the_store_never_renders_its_identity(store: FileStore) -> None:
    secret = new_secret()
    named = make_store(store.path, secret=secret)

    assert secret not in repr(named)


# ------------------------------------------------------------------ health ---


def test_health_is_ok_for_a_store_with_no_file_yet(store: FileStore) -> None:
    health = store.health()

    assert health.status == OK
    assert health.server_time is None
    assert not store.path.exists()


def test_health_is_degraded_for_another_identity(store: FileStore) -> None:
    store.write("acme/app", {"current": "a"}, cas=None)
    stranger = make_store(store.path)

    health = stranger.health()

    assert health.status == DEGRADED
    assert health.authenticated is False
    assert "cannot decrypt" in (health.detail or "")


def test_health_is_degraded_for_a_damaged_file(store: FileStore) -> None:
    _disk.replace(store.path, b"not age", expected=_disk.ABSENT)

    health = store.health()

    assert health.status == DEGRADED
    assert "not an age-encrypted file" in (health.detail or "")


def test_health_is_unreachable_without_the_directory(tmp_path: Path) -> None:
    store = make_store(tmp_path / "missing" / "store.age")

    assert store.health().status == UNREACHABLE


def test_a_damaged_document_names_the_store(store: FileStore) -> None:
    _disk.replace(store.path, _crypto.seal(b"{}", store.keys), expected=_disk.ABSENT)

    with pytest.raises(StoreError) as caught:
        store.read("acme/app")

    assert str(caught.value).startswith(f'file store "{NAME}": ')


# -------------------------------------------------------------- open_store ---


def vault(tmp_path: Path, identity: MaterialRef, **fields: Any) -> Vault:
    return Vault(
        name=NAME, type="file", addr=str(tmp_path / "store.age"), identity=identity, **fields
    )


def test_open_store_reads_the_identity_from_a_file(tmp_path: Path) -> None:
    secret = new_secret()
    identity = tmp_path / "identity.txt"
    identity.write_text(f"# a comment\n{secret}\n", encoding="utf-8")

    store = open_store(
        vault(tmp_path, MaterialRef(kind="file", location=str(identity)), max_versions=3), env={}
    )

    assert store.path == tmp_path / "store.age"
    assert store.max_versions == 3
    store.write("acme/app", {"current": "a"}, cas=0)
    assert data_of(make_store(store.path, secret=secret), "acme/app") == {"current": "a"}


def test_open_store_reads_the_identity_from_a_variable(tmp_path: Path) -> None:
    secret = new_secret()

    store = open_store(
        vault(tmp_path, MaterialRef(kind="env", location="SOPULI_FILE_IDENTITY")),
        env={"SOPULI_FILE_IDENTITY": secret},
    )

    assert str(store.keys.identity.public()) == str(x25519.Identity.from_str(secret).to_public())


def test_open_store_refuses_a_binary_age_p_identity_before_decoding_it(tmp_path: Path) -> None:
    """What `age -p` writes is binary, not UTF-8: refused as
    passphrase-protected, not as text that is not UTF-8 (#1372)."""
    identity = tmp_path / "identity.age"
    identity.write_bytes(
        bytes(pyrage.passphrase.encrypt(f"{new_secret()}\n".encode(), "a passphrase"))
    )

    with pytest.raises(
        KeysError, match=f'file store "{NAME}": the identity is passphrase-protected'
    ):
        open_store(vault(tmp_path, MaterialRef(kind="file", location=str(identity))), env={})


def test_open_store_encrypts_to_the_listed_recipients_too(tmp_path: Path) -> None:
    colleague = x25519.Identity.generate()
    store = open_store(
        vault(
            tmp_path,
            MaterialRef(kind="env", location="SOPULI_FILE_IDENTITY"),
            recipients=(str(colleague.to_public()),),
        ),
        env={"SOPULI_FILE_IDENTITY": new_secret()},
    )
    store.write("acme/app", {"current": "a"}, cas=0)

    assert data_of(make_store(store.path, secret=str(colleague)), "acme/app") == {"current": "a"}
