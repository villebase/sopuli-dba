"""The OS keyring as a source of the tool's own credentials (#1417).

Tier 0, against a fake ``keyring`` library: CI has no unlocked OS keyring to
reach. The real runs are recorded on the PR, with the platform each was made on.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli import os_keyring
from sopuli.admin import AdminCredentialError, resolve
from sopuli.config.auth import read_material
from sopuli.config.errors import ConfigError, KeyPath
from sopuli.config.model import AdminAuth, AdminCredential, ExpandedTarget, MaterialRef, Target
from sopuli.config.targets import read_admin_auth
from sopuli.exit_codes import ExitCode
from sopuli.material import MaterialError
from sopuli.material import resolve as resolve_material
from sopuli.secrets import Secret

WHERE = 'vault "vault-dev" auth method "token" key "token"'


def backend_class(module: str, *, priority: float = 5) -> type:
    """A backend whose module is ``module``: the allow-list is keyed on it."""

    class Backend:
        def __init__(self) -> None:
            self.priority = priority
            self.entries: dict[tuple[str, str], str] = {}
            self.error: BaseException | None = None

        def get_password(self, service: str, user: str) -> str | None:
            if self.error is not None:
                raise self.error
            return self.entries.get((service, user))

    Backend.__module__ = module
    return Backend


WINDOWS = "keyring.backends.Windows"
PLAINTEXT = "keyrings.alt.file"
FAIL = "keyring.backends.fail"


class Library:
    """The fake `keyring` module: `get_keyring()` and nothing else."""

    def __init__(self, found: Any) -> None:
        self.found = found

    def get_keyring(self) -> Any:
        return self.found


@pytest.fixture
def windows(monkeypatch: pytest.MonkeyPatch) -> Any:
    found = backend_class(WINDOWS)()
    monkeypatch.setattr(os_keyring, "loader", lambda: Library(found))
    return found


def test_an_entry_is_read_under_the_fixed_service(windows: Any) -> None:
    windows.entries[("sopuli", "vault-dev")] = "hvs.example"
    ref = MaterialRef(kind="keyring", location="vault-dev")

    assert resolve_material(ref, env={}, where=WHERE) == Secret("hvs.example")


def test_a_missing_entry_names_it_the_backend_and_the_verb(windows: Any) -> None:
    with pytest.raises(MaterialError) as refused:
        os_keyring.read("vault-dev", where=WHERE)

    message = str(refused.value)
    assert "sopuli/vault-dev" in message
    assert WINDOWS in message
    assert "the user name `vault-dev`" in (refused.value.hint or "")
    assert refused.value.exit_code == ExitCode.CONFIG_INVALID


def test_an_empty_entry_counts_as_missing(windows: Any) -> None:
    windows.entries[("sopuli", "vault-dev")] = ""

    with pytest.raises(MaterialError, match="is not in"):
        os_keyring.read("vault-dev", where=WHERE)


def test_a_locked_keyring_is_an_error_that_names_the_entry(windows: Any) -> None:
    windows.error = OSError("the collection is locked")

    with pytest.raises(MaterialError) as refused:
        os_keyring.read("vault-dev", where=WHERE)

    assert "sopuli/vault-dev" in str(refused.value)
    assert "locked" in str(refused.value)


def test_a_plaintext_backend_is_refused_rather_than_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """`keyrings.alt` writes a file: that is the `file:` source under another name."""
    plaintext = backend_class(PLAINTEXT, priority=10)()
    plaintext.entries[("sopuli", "vault-dev")] = "hvs.example"
    monkeypatch.setattr(os_keyring, "loader", lambda: Library(plaintext))

    with pytest.raises(MaterialError) as refused:
        os_keyring.read("vault-dev", where=WHERE)

    assert "no OS keyring" in str(refused.value)
    assert PLAINTEXT in str(refused.value)


def test_the_os_backend_is_chosen_from_a_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    """The library wraps several viable backends in a chainer. The OS one is
    used even where a plaintext one ranks higher."""
    plaintext = backend_class(PLAINTEXT, priority=10)()
    windows = backend_class(WINDOWS, priority=5)()
    windows.entries[("sopuli", "vault-dev")] = "from-windows"
    chainer = backend_class("keyring.backends.chainer", priority=-1)()
    chainer.backends = [plaintext, windows]
    monkeypatch.setattr(os_keyring, "loader", lambda: Library(chainer))

    assert os_keyring.read("vault-dev", where=WHERE) == Secret("from-windows")


def test_a_server_with_no_keyring_says_what_to_use_instead(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Measured shape: on Linux with no session bus the library returns `fail`."""
    monkeypatch.setattr(os_keyring, "loader", lambda: Library(backend_class(FAIL, priority=0)()))

    with pytest.raises(MaterialError) as refused:
        os_keyring.read("vault-dev", where=WHERE)

    assert "`env:` or `file:`" in (refused.value.hint or "")


def test_without_the_extra_the_message_names_it(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing() -> Any:
        raise ModuleNotFoundError("No module named 'keyring'", name="keyring")

    monkeypatch.setattr(os_keyring, "loader", missing)

    with pytest.raises(MaterialError) as refused:
        os_keyring.read("vault-dev", where=WHERE)

    assert 'pip install "sopuli-dba[keyring]"' in (refused.value.hint or "")


@pytest.mark.parametrize(
    "module",
    [
        "keyring.backends.Windows",
        "keyring.backends.macOS",
        "keyring.backends.SecretService",
        "keyring.backends.libsecret",
        "keyring.backends.kwallet",
    ],
)
def test_each_os_backend_counts(module: str) -> None:
    chosen = backend_class(module)()

    assert os_keyring.choose([chosen]) is chosen


@pytest.mark.parametrize("module", [FAIL, "keyring.backends.null", PLAINTEXT])
def test_no_other_backend_counts(module: str) -> None:
    assert os_keyring.choose([backend_class(module)()]) is None


# ------------------------------------------------------------------- config ---


def test_a_material_ref_may_name_a_keyring_entry() -> None:
    ref = read_material({"keyring": "vault-dev"}, at=KeyPath(("vaults", "vault-dev", "auth")))

    assert ref == MaterialRef(kind="keyring", location="vault-dev")


def test_admin_keyring_needs_its_entry() -> None:
    with pytest.raises(ConfigError, match="needs `entry`"):
        read_admin_auth({"method": "keyring"}, at=KeyPath(("targets", 0, "admin", "auth")))


def test_admin_keyring_cannot_be_written_as_a_bare_value() -> None:
    with pytest.raises(ConfigError, match="cannot be written as a bare value"):
        read_admin_auth("keyring", at=KeyPath(("targets", 0, "admin", "auth")))


def test_admin_keyring_reads_its_entry() -> None:
    auth = read_admin_auth(
        {"method": "keyring", "entry": "cdb-root-dev"},
        at=KeyPath(("targets", 0, "admin", "auth")),
    )

    assert auth == AdminAuth(method="keyring", entry="cdb-root-dev")


# -------------------------------------------------------------------- admin ---


def keyring_target(entry: str = "cdb-root-dev") -> ExpandedTarget:
    auth = AdminAuth(method="keyring", entry=entry)
    admin = AdminCredential(username="C##SOPULI_SVC", auth=auth)
    return ExpandedTarget(
        target=Target(
            name="cdb-root-dev",
            type="oracle",
            dsn="db-dev.example.com:1521/CDBDEV.pdb.example.com",
            admin=admin,
        ),
        index=0,
    )


def test_the_admin_credential_is_read_and_not_flagged(windows: Any) -> None:
    """Decision 4: a keyring entry is the exposure of a `0600` file, not of a
    variable, so it is not low-assurance."""
    windows.entries[("sopuli", "cdb-root-dev")] = "admin-password"

    resolved = resolve(keyring_target(), env={})

    assert resolved.credential.secret == Secret("admin-password")
    assert resolved.credential.username == "C##SOPULI_SVC"
    assert resolved.source == "the OS keyring entry sopuli/cdb-root-dev"
    assert not resolved.low_assurance


def test_a_missing_admin_entry_points_at_the_entry_key(windows: Any) -> None:
    with pytest.raises(AdminCredentialError) as refused:
        resolve(keyring_target(), env={})

    assert "cdb-root-dev" in str(refused.value)
    assert refused.value.at.parts[-1] == "entry"
    assert refused.value.exit_code == ExitCode.CONFIG_INVALID
