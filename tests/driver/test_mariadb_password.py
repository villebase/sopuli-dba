"""The values MariaDB stores for a password, computed on the client
(invariant 15). Tier 0.

The vectors are the values the server itself stored for each password with
``IDENTIFIED VIA <plugin> USING PASSWORD(…)`` over a ``utf8mb4`` connection,
read back from ``mysql.user`` as root: the same on 10.11.19, 11.4.13, 11.8.9 and
12.3.3 (``sql/mariadb/09_password_length_probe.py``, PW3).
"""

from __future__ import annotations

import pytest

from sopuli.config.model import ExpandedTarget, Target
from sopuli.driver.protocol import Timeouts
from sopuli.secrets import Secret

# Before the module, which imports PyNaCl: it comes with the `mariadb` extra.
pytest.importorskip("nacl", reason="PyNaCl comes with the `mariadb` extra")

from sopuli.driver.mariadb.password import (  # noqa: E402
    ED25519,
    NATIVE,
    VALUES,
    PasswordNotAdmissibleError,
    admit,
    alter_user,
    alter_user_rollover,
    ed25519_value,
    native_value,
    scrub,
)

LONG = "Acme-Long-" * 30

SERVER_VALUES = [
    (NATIVE, "Acme-Vector-1", "*BCF4821599FD729D65B1D7FD05E7F500E4353A95"),
    (NATIVE, "pässwörd-é", "*90CD6D75F1B3F438B7F982777542A9E4479A252D"),
    (NATIVE, LONG, "*028C62DD118198F89D80E6C42D1FEA2869F94C81"),
    (ED25519, "Acme-Vector-1", "dqRDrLM3a3AWJrFD6+djW8n30QHqxVemmN5u/6RydE8"),
    (ED25519, "pässwörd-é", "S7h7+pLYaV0vchpKE7ou3ooRNfyTTGxVuXj3CPd5rhM"),
    (ED25519, LONG, "TOe22qLnfsCgQIX4C0MkoHz7M5yy9/FVv40uu6jgQvU"),
]


@pytest.mark.parametrize(("plugin", "password", "stored"), SERVER_VALUES)
def test_the_value_agrees_with_the_servers_own(plugin: str, password: str, stored: str) -> None:
    assert VALUES[plugin](Secret(password)).reveal() == stored


def test_the_long_password_is_longer_than_an_ed25519_seed() -> None:
    """The vector covers what a seed-only library gets wrong."""
    assert len(LONG.encode("utf-8")) == 300


@pytest.mark.parametrize("plugin", [NATIVE, ED25519])
def test_the_value_is_a_secret(plugin: str) -> None:
    """A native value and one captured handshake log in (#1267, decision 4)."""
    value = VALUES[plugin](Secret("Acme-App-pw1"))

    assert isinstance(value, Secret)
    assert str(value) == repr(value) == "***"


def test_the_values_have_the_servers_shape() -> None:
    native = native_value(Secret("Acme-App-pw1")).reveal()
    ed = ed25519_value(Secret("Acme-App-pw1")).reveal()

    assert native.startswith("*")
    assert len(native) == 41
    assert native[1:] == native[1:].upper()
    assert len(ed) == 43, "32 bytes in base 64, without the trailing `=`"
    assert not ed.endswith("=")


def test_the_value_does_not_carry_the_password() -> None:
    password = "Acme-App-pw1"

    for compute in VALUES.values():
        assert password not in compute(Secret(password)).reveal()


@pytest.mark.parametrize(
    ("password", "words"),
    [
        ("", "is empty"),
        ("Acme\x00pw", "control characters"),
        ("Acme\npw", "control characters"),
        ("Acme\ud800pw", "cannot be encoded"),
    ],
)
def test_a_password_the_target_cannot_take_is_refused(password: str, words: str) -> None:
    with pytest.raises(PasswordNotAdmissibleError, match=words) as caught:
        admit(Secret(password))

    assert caught.value.category == "policy"
    if password:
        assert password not in str(caught.value)


@pytest.mark.parametrize(
    "password",
    ["A" * 1024, "é" * 512, "é€😀-Acme", "x"],
    ids=["1024 bytes", "1024 bytes not ASCII", "not ASCII", "1 byte"],
)
def test_up_to_the_limit_any_character_is_admitted(password: str) -> None:
    """ASCII or not, a password was set and logged in on every release (PW1,
    PW2). The limit is decided on #1270."""
    admit(Secret(password))


@pytest.mark.parametrize("password", ["A" * 1025, "é" * 512 + "A"], ids=["ASCII", "not ASCII"])
def test_a_password_over_1024_bytes_is_refused(password: str) -> None:
    """Counted in UTF-8 bytes, not characters: 513 characters of `é` is 1025
    bytes."""
    with pytest.raises(PasswordNotAdmissibleError, match="1025 bytes") as caught:
        admit(Secret(password))

    assert "at most 1024" in str(caught.value)
    assert caught.value.category == "policy"


def test_the_session_says_the_limit_and_no_other_constraint() -> None:
    """Neither reads the server, so a session with no connection answers."""
    session_module = pytest.importorskip("sopuli.driver.mariadb.session")
    session = session_module.MariadbSession(
        connection=None,
        target=ExpandedTarget(
            target=Target(name="mariadb-dev", type="mariadb", dsn="mariadb-dev.example.com:3306")
        ),
        correlation_id="tier0",
        timeouts=Timeouts(),
    )

    limit = session.byte_limit()

    assert (limit.max_bytes, limit.encoding) == (1024, "utf-8")
    assert session.password_constraints("acme_app_user@%") is None


def test_the_reset_refuses_to_keep_a_rollover_before_anything_is_read() -> None:
    """The driver's own line for `--keep-rollover` (#1272): a session with no
    connection refuses it, so nothing was read or sent."""
    from sopuli.driver.protocol import KEEP_ROLLOVER, UnsupportedCapabilityError

    session_module = pytest.importorskip("sopuli.driver.mariadb.session")
    session = session_module.MariadbSession(
        connection=None,
        target=ExpandedTarget(
            target=Target(name="mariadb-dev", type="mariadb", dsn="mariadb-dev.example.com:3306")
        ),
        correlation_id="tier0",
        timeouts=Timeouts(),
    )

    with pytest.raises(UnsupportedCapabilityError) as caught:
        session.reset_password(
            "acme_app@%", Secret("Acme-Vector-1"), expire=True, keep_rollover=True
        )

    assert caught.value.capability == KEEP_ROLLOVER
    assert "joined by OR" in str(caught.value.hint)


@pytest.mark.parametrize("old_password", ["retain", "keep"])
def test_keeping_the_old_password_without_it_is_refused_before_anything_is_read(
    old_password: str,
) -> None:
    """#1271: the rollover sends the old value again, so the command must pass
    it. A session with no connection refuses, so nothing was read or sent."""
    from sopuli.driver.protocol import DriverError

    session_module = pytest.importorskip("sopuli.driver.mariadb.session")
    session = session_module.MariadbSession(
        connection=None,
        target=ExpandedTarget(
            target=Target(name="mariadb-dev", type="mariadb", dsn="mariadb-dev.example.com:3306")
        ),
        correlation_id="tier0",
        timeouts=Timeouts(),
    )

    with pytest.raises(DriverError) as caught:
        session.set_password("acme_app@%", Secret("Acme-Vector-1"), old_password=old_password)

    assert "fault in sopuli" in str(caught.value.hint)
    assert caught.value.password_sent is False


def test_finishing_a_rollover_without_the_current_password_is_refused_first() -> None:
    from sopuli.driver.protocol import DriverError

    session_module = pytest.importorskip("sopuli.driver.mariadb.session")
    session = session_module.MariadbSession(
        connection=None,
        target=ExpandedTarget(
            target=Target(name="mariadb-dev", type="mariadb", dsn="mariadb-dev.example.com:3306")
        ),
        correlation_id="tier0",
        timeouts=Timeouts(),
    )

    with pytest.raises(DriverError) as caught:
        session.finish_rollover("acme_app@%")

    assert "fault in sopuli" in str(caught.value.hint)
    assert caught.value.password_sent is False


def test_apply_finds_the_hook_it_looks_up_by_name() -> None:
    """`creds apply` reads it with getattr, outside the protocol, and a missing
    `verifies_before_change` means a login before the change, which #1270
    decision 4 refuses. A rename must fail here. There is no `confirm_change`:
    MariaDB keeps no change time the tool can read."""
    session_module = pytest.importorskip("sopuli.driver.mariadb.session")

    assert getattr(session_module.MariadbSession, "verifies_before_change", True) is False
    assert not hasattr(session_module.MariadbSession, "confirm_change")


@pytest.mark.parametrize(
    ("plugin", "password", "stored"),
    [vector for vector in SERVER_VALUES if vector[1] == "Acme-Vector-1"],
)
def test_the_statement_carries_the_value_for_the_account_s_plugin(
    plugin: str, password: str, stored: str
) -> None:
    statement = alter_user("acme_app", "10.%", plugin, Secret(password))

    assert statement == f"ALTER USER `acme_app`@`10.%` IDENTIFIED VIA {plugin} USING '{stored}'"
    assert password not in statement


def test_a_reset_sets_and_expires_by_one_statement() -> None:
    """`account reset-password` (#1272): a failure leaves neither done."""
    statement = alter_user("acme_app", "%", NATIVE, Secret("Acme-Vector-1"), expire=True)

    assert statement.startswith(f"ALTER USER `acme_app`@`%` IDENTIFIED VIA {NATIVE} USING '*")
    assert statement.endswith("' PASSWORD EXPIRE")
    assert "PASSWORD EXPIRE" in scrub(statement)
    assert "USING '***'" in scrub(statement)


def test_the_account_is_backquoted_whatever_its_name() -> None:
    statement = alter_user("acme`x", "%", NATIVE, Secret("Acme-Vector-1"))

    assert statement.startswith("ALTER USER `acme``x`@`%` ")


def test_a_value_of_the_wrong_shape_is_never_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(VALUES, NATIVE, lambda secret: Secret("*AB' OR 1=1"))

    with pytest.raises(ValueError, match="wrong shape"):
        alter_user("acme_app", "%", NATIVE, Secret("Acme-Vector-1"))


#: Each plugin's two vectors for a rollover: the new password and the old one.
ROLLOVERS = [
    (NATIVE, SERVER_VALUES[0][2], SERVER_VALUES[1][2]),
    (ED25519, SERVER_VALUES[3][2], SERVER_VALUES[4][2]),
]


@pytest.mark.parametrize(("plugin", "new", "old"), ROLLOVERS)
def test_a_rollover_sends_the_new_value_first_or_the_old(plugin: str, new: str, old: str) -> None:
    """#1271: PyMySQL logs in only by the first method of an ed25519 `OR`, so
    the new password comes first (`11_rollover_expiry_probe.py`, RE5)."""
    statement = alter_user_rollover(
        "acme_app", "10.%", plugin, Secret("Acme-Vector-1"), Secret("pässwörd-é")
    )

    assert statement == (
        f"ALTER USER `acme_app`@`10.%` IDENTIFIED VIA {plugin} USING '{new}' "
        f"OR {plugin} USING '{old}'"
    )
    assert "Acme-Vector-1" not in statement
    assert "pässwörd-é" not in statement


@pytest.mark.parametrize("which", ["new", "old"])
def test_a_rollover_value_of_the_wrong_shape_is_never_sent(
    monkeypatch: pytest.MonkeyPatch, which: str
) -> None:
    real = native_value
    bad = Secret("Acme-Bad-1")
    monkeypatch.setitem(
        VALUES,
        NATIVE,
        lambda secret: Secret("*AB' OR 1=1") if secret is bad else real(secret),
    )
    good = Secret("Acme-Vector-1")

    with pytest.raises(ValueError, match="wrong shape"):
        alter_user_rollover(
            "acme_app", "%", NATIVE, *((bad, good) if which == "new" else (good, bad))
        )


@pytest.mark.parametrize(("plugin", "new", "old"), ROLLOVERS)
def test_the_scrub_hides_both_values_of_a_rollover(plugin: str, new: str, old: str) -> None:
    statement = alter_user_rollover(
        "acme_app", "%", plugin, Secret("Acme-Vector-1"), Secret("pässwörd-é")
    )
    quoted = f"Operation ALTER USER failed for {statement}"
    bare = f"values {new} and {old} are malformed"

    for message in (quoted, bare):
        assert new not in scrub(message)
        assert old not in scrub(message)
    assert scrub(quoted).count("USING '***'") == 2


@pytest.mark.parametrize(("plugin", "password", "stored"), SERVER_VALUES)
def test_the_scrub_hides_each_value(plugin: str, password: str, stored: str) -> None:
    quoted = f"Operation ALTER USER failed near 'USING '{stored}''"
    bare = f"hash {stored} is malformed"

    assert stored not in scrub(quoted)
    assert stored not in scrub(bare)
    assert "***" in scrub(bare)
