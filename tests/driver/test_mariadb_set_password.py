"""`set_password` and `verify_password` on the tier-1 `mariadb` service, as
the tool account (#1270).

Tier 1. The driver sends ``IDENTIFIED VIA <plugin> USING '<value>'`` with the
value for the account's own plugin, and the account then logs in with the
password. With every log the server keeps turned on, the password is in none of
them (invariant 15, ``02-mariadb-privileges.md`` §6). The session's
`verify_password` checks it by a login that confirms the account (§7).
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import suppress
from typing import Any, NoReturn

import pytest

from sopuli.config.model import ExpandedTarget, Target, TargetMysql
from sopuli.driver.protocol import (
    FAIL,
    OLD_KEEP,
    OLD_RETAIN,
    PASS,
    PASSWORD_VALUE,
    UNAVAILABLE,
    VERIFY_BOTH,
    VERIFY_HASH,
    Credential,
    DriverError,
    Timeouts,
    UnsupportedCapabilityError,
)
from sopuli.secrets import Secret

pymysql = pytest.importorskip("pymysql")
session_module = pytest.importorskip("sopuli.driver.mariadb.session")
accounts_module = pytest.importorskip("sopuli.driver.mariadb.accounts")
password_module = pytest.importorskip("sopuli.driver.mariadb.password")
ED25519_ROLLOVER = session_module.ED25519_ROLLOVER


@pytest.fixture
def session(live_mariadb: Any) -> Iterator[Any]:
    target = ExpandedTarget(
        target=Target(
            name="tier1-mariadb",
            type="mariadb",
            dsn=live_mariadb.dsn,
            mariadb=TargetMysql(ssl_mode="REQUIRED"),
        )
    )
    driver = session_module.MariadbDriver(correlation_id="tier1-set", timeouts=Timeouts())
    opened = driver.connect(
        target,
        Credential(username=live_mariadb.tool_user, secret=Secret(live_mariadb.tool_password)),
    )
    try:
        yield opened
    finally:
        opened.close()


@pytest.fixture
def user(live_mariadb: Any) -> Iterator[str]:
    name = f"acme_{uuid.uuid4().hex[:8]}"
    try:
        yield name
    finally:
        with live_mariadb.connect() as admin, admin.cursor() as cursor, suppress(pymysql.Error):
            cursor.execute("drop user if exists %s@'%%'", (name,))


def test_a_password_validation_plugin_takes_away_password_value(
    live_mariadb: Any, session: Any, user: str
) -> None:
    """#1310: with `simple_password_check` active and
    `strict_password_validation` ON, the default, the server refuses every
    value the driver sends (`12_password_check_probe.py`, PC1). The scope
    says so, `doctor`'s audit says why, and `set_password` refuses before it
    sends, naming the plugin. The fixture's session reads its scope on first
    use, which is after the install."""
    _root(live_mariadb, "create user %s@'%%' identified by 'Acme-Check-Old-pw1'", (user,))
    try:
        # IF NOT EXISTS, and IF EXISTS below: a run interrupted between the two
        # leaves the plugin loaded, and the next run must still start clean.
        _root(
            live_mariadb,
            "install plugin if not exists simple_password_check soname 'simple_password_check'",
        )
        assert not session.scope().supports(PASSWORD_VALUE)
        lines = session.privileges().remedies
        with pytest.raises(UnsupportedCapabilityError) as caught:
            session.set_password(f"{user}@%", Secret("Acme-Check-New-pw2#"))
    finally:
        _root(live_mariadb, "uninstall plugin if exists simple_password_check")

    assert "simple_password_check" in str(caught.value.hint)
    assert any("simple_password_check refuses every password value" in one for one in lines)
    assert _login(live_mariadb, user, "Acme-Check-Old-pw1"), "nothing was sent"


#: The statement consumers the invariant-15 test turns on.
CONSUMERS = "where name in ('events_statements_current', 'events_statements_history_long')"


def _root(live_mariadb: Any, statement: str, arguments: tuple[Any, ...] = ()) -> None:
    with live_mariadb.connect() as admin, admin.cursor() as cursor:
        cursor.execute(statement, arguments)


def _create(live_mariadb: Any, user: str, plugin: str) -> None:
    _root(
        live_mariadb,
        f"create user %s@'%%' identified via {plugin} using password(%s)",
        (user, uuid.uuid4().hex),
    )


@pytest.mark.parametrize("plugin", ["mysql_native_password", "ed25519"])
def test_a_password_is_set_by_its_value_and_logs_in(
    live_mariadb: Any, session: Any, user: str, plugin: str
) -> None:
    _create(live_mariadb, user, plugin)
    password = f"Acme-{uuid.uuid4().hex[:12]}-ä"

    result = session.set_password(f"{user}@%", Secret(password))

    assert (result.changed, result.discarded) == (True, True)
    with live_mariadb.connect() as admin, admin.cursor() as cursor:
        cursor.execute("select plugin from mysql.user where User = %s", (user,))
        assert cursor.fetchone()[0] == plugin, "the plugin is the account's own"
    live_mariadb.connect_as(user, password).close()


@pytest.mark.parametrize("rollover", [False, True], ids=["set", "rollover"])
def test_a_password_set_by_the_driver_reaches_no_log(
    live_mariadb: Any, session: Any, user: str, rollover: bool
) -> None:
    """Invariant 15 on MariaDB. With the general log on, written to a table,
    and performance_schema's long statement history on, the driver sets a
    password. The statement is in both and in the binary log, and the password
    is in none of them. A rollover sends the old password's value too, and
    the old password is in none of them either (#1271)."""
    old = f"Acme-Old-{uuid.uuid4().hex[:12]}"
    # By its value, so the old password is in no log even where one is on.
    _root(
        live_mariadb,
        "create user %s@'%%' identified via mysql_native_password using %s",
        (user, password_module.native_value(Secret(old)).reveal()),
    )
    password = f"Acme-Leak-{uuid.uuid4().hex[:12]}"
    mode: dict[str, Any] = {"old_password": OLD_RETAIN, "previous": Secret(old)} if rollover else {}
    # The long history keeps a statement only while `current` is on as well;
    # a new server has both off (`01_password_text_probe.py`).
    with live_mariadb.connect() as admin, admin.cursor() as cursor:
        cursor.execute("select @@global.log_output, @@global.general_log")
        log_output, general_log = cursor.fetchone()
        cursor.execute(f"select name, enabled from performance_schema.setup_consumers {CONSUMERS}")
        consumers = cursor.fetchall()
        cursor.execute("show binlog status")
        status = cursor.fetchone()
    if status is None:
        pytest.skip("the server runs without a binary log; the tier-1 service has one")
    binlog = status[0]
    # A general log already written to a table keeps its rows: the CSV table
    # can only be emptied whole, and those rows are not this test's.
    ours = not (general_log and "TABLE" in str(log_output).upper())
    _root(live_mariadb, "set global log_output = 'TABLE'")
    _root(live_mariadb, "set global general_log = 'ON'")
    _root(
        live_mariadb,
        f"update performance_schema.setup_consumers set enabled = 'YES' {CONSUMERS}",
    )
    try:
        session.set_password(f"{user}@%", Secret(password), **mode)
        with live_mariadb.connect() as admin, admin.cursor() as cursor:
            cursor.execute(
                "select convert(argument using utf8mb4) from mysql.general_log "
                "where convert(argument using utf8mb4) like %s",
                (f"%{user}%",),
            )
            logged = [row[0] for row in cursor.fetchall()]
            cursor.execute(
                "select sql_text from performance_schema.events_statements_history_long "
                "where sql_text like %s",
                (f"%{user}%",),
            )
            history = [row[0] for row in cursor.fetchall()]
            cursor.execute(f"show binlog events in '{binlog}'")
            binary = [str(row[-1]) for row in cursor.fetchall() if user in str(row[-1])]
    finally:
        # The server as it was, and none of the rows this test made it log
        # where the log was this test's alone.
        _root(live_mariadb, "set global general_log = 'OFF'")
        if ours:
            _root(live_mariadb, "truncate table mysql.general_log")
        _root(live_mariadb, "set global log_output = %s", (log_output,))
        _root(live_mariadb, "set global general_log = %s", (general_log,))
        for name, enabled in consumers:
            _root(
                live_mariadb,
                "update performance_schema.setup_consumers set enabled = %s where name = %s",
                (enabled, name),
            )

    seen = {"general log": logged, "history": history, "binary log": binary}
    for where, lines in seen.items():
        assert any("IDENTIFIED VIA" in line.upper() for line in lines), f"the {where} saw it"
    for secret in (password, old):
        assert not any(secret in line for lines in seen.values() for line in lines)
    if rollover:
        assert any(" OR " in line.upper() for line in logged), "the rollover was logged"
    live_mariadb.connect_as(user, password).close()


def test_an_account_on_another_plugin_is_refused_before_anything_is_sent(
    live_mariadb: Any, session: Any, user: str
) -> None:
    _root(live_mariadb, "create user %s@'%%' identified via unix_socket", (user,))

    with pytest.raises(accounts_module.OtherPluginError) as caught:
        session.set_password(f"{user}@%", Secret("Acme-not-sent-1"))

    assert caught.value.password_sent is False


def test_a_missing_account_is_refused_before_anything_is_sent(session: Any) -> None:
    with pytest.raises(DriverError) as caught:
        session.set_password("acme_nobody@%", Secret("Acme-not-sent-1"))

    assert "does not exist" in str(caught.value)
    assert caught.value.password_sent is False


def _login(live_mariadb: Any, user: str, password: str) -> bool:
    """Whether ``password`` logs in over PyMySQL and a statement runs."""
    try:
        live_mariadb.connect_as(user, password).close()
    except pymysql.err.MySQLError:
        return False
    return True


def test_a_rollover_keeps_the_old_password_until_it_is_finished(
    live_mariadb: Any, session: Any, user: str
) -> None:
    """#1271: `retain` sends the new value `OR` the old one, and both log in.
    `finish_rollover` sends the current value alone, and the old one stops;
    a second run sends it again and reports a change, because the tool cannot
    read whether a rollover is open (#1267, decision 3)."""
    old, new = f"Acme-Old-{uuid.uuid4().hex[:8]}", f"Acme-New-{uuid.uuid4().hex[:8]}"
    _root(live_mariadb, "create user %s@'%%' identified by %s", (user, old))

    opened = session.set_password(
        f"{user}@%", Secret(new), old_password=OLD_RETAIN, previous=Secret(old)
    )

    assert (opened.changed, opened.retained, opened.discarded) == (True, True, False)
    assert opened.caveat is None, "mysql_native_password: PyMySQL uses both methods"
    assert session.require_rollover(f"{user}@%") is None
    assert _login(live_mariadb, user, new)
    assert _login(live_mariadb, user, old)
    assert session.verify_password(f"{user}@%", Secret(new)).result == PASS

    first = session.finish_rollover(f"{user}@%", current=Secret(new))
    second = session.finish_rollover(f"{user}@%", current=Secret(new))

    assert (first.changed, second.changed) == (True, True)
    assert first.detail == "any second password ended; the current password was sent alone"
    assert _login(live_mariadb, user, new)
    assert not _login(live_mariadb, user, old)


def test_an_ed25519_rollover_s_new_password_logs_in_over_pymysql(
    live_mariadb: Any, session: Any, user: str
) -> None:
    """PyMySQL takes only the first method of an ed25519 `OR`, so the new
    value comes first (`11_rollover_expiry_probe.py`, RE5), and the login
    after the change confirms it. The pre-flight and the change both carry
    the caveat (`SOPULI-W064`, #1271), and a PyMySQL login with the old
    password fails as it says."""
    pytest.importorskip("nacl", reason="PyNaCl comes with the `mariadb` extra")
    old, new = f"Acme-Old-{uuid.uuid4().hex[:8]}", f"Acme-New-{uuid.uuid4().hex[:8]}"
    _root(
        live_mariadb, "create user %s@'%%' identified via ed25519 using password(%s)", (user, old)
    )

    assert session.require_rollover(f"{user}@%") == ED25519_ROLLOVER
    opened = session.set_password(
        f"{user}@%", Secret(new), old_password=OLD_RETAIN, previous=Secret(old)
    )
    again = session.set_password(
        f"{user}@%", Secret(new), old_password=OLD_KEEP, previous=Secret(old)
    )

    assert opened.caveat == again.caveat == ED25519_ROLLOVER
    assert _login(live_mariadb, user, new)
    assert not _login(live_mariadb, user, old), "PyMySQL cannot use the second method"
    assert session.verify_password(f"{user}@%", Secret(new)).result == PASS
    with live_mariadb.connect() as admin, admin.cursor() as cursor:
        cursor.execute("select plugin from mysql.user where User = %s", (user,))
        assert cursor.fetchone()[0] == "ed25519", "the plugin is the account's own"


def test_a_held_rollover_set_again_keeps_its_window(
    live_mariadb: Any, session: Any, user: str
) -> None:
    """`keep`: `creds apply` sets a rollover's `pending` again while its
    promotion is held. The statement names its methods, so it sends the old
    value again, and the old password keeps logging in."""
    old, new = f"Acme-Old-{uuid.uuid4().hex[:8]}", f"Acme-New-{uuid.uuid4().hex[:8]}"
    _root(live_mariadb, "create user %s@'%%' identified by %s", (user, old))
    session.set_password(f"{user}@%", Secret(new), old_password=OLD_RETAIN, previous=Secret(old))

    again = session.set_password(
        f"{user}@%", Secret(new), old_password=OLD_KEEP, previous=Secret(old)
    )

    assert (again.changed, again.retained, again.discarded) == (True, False, False)
    assert _login(live_mariadb, user, new)
    assert _login(live_mariadb, user, old)


def test_a_discard_ends_a_rollover(live_mariadb: Any, session: Any, user: str) -> None:
    old, new = f"Acme-Old-{uuid.uuid4().hex[:8]}", f"Acme-New-{uuid.uuid4().hex[:8]}"
    _root(live_mariadb, "create user %s@'%%' identified by %s", (user, old))
    session.set_password(f"{user}@%", Secret(new), old_password=OLD_RETAIN, previous=Secret(old))

    session.set_password(f"{user}@%", Secret(new))

    assert _login(live_mariadb, user, new)
    assert not _login(live_mariadb, user, old)


@pytest.mark.parametrize("plugin", ["mysql_native_password", "ed25519"])
def test_a_set_password_verifies_and_a_wrong_one_fails(
    live_mariadb: Any, session: Any, user: str, plugin: str
) -> None:
    """The account is `user@%` and the user's only one, and the target
    requires TLS, so a refusal is the password's (§7)."""
    _create(live_mariadb, user, plugin)
    password = f"Acme-{uuid.uuid4().hex[:12]}"
    session.set_password(f"{user}@%", Secret(password))

    right = session.verify_password(f"{user}@%", Secret(password))
    wrong = session.verify_password(f"{user}@%", Secret("Acme-wrong-password-1"))

    assert right.result == PASS
    assert wrong.result == FAIL


def test_a_missing_account_is_unavailable_without_a_login(session: Any) -> None:
    result = session.verify_password("acme_nobody@%", Secret("Acme-not-sent-1"))

    assert result.result == UNAVAILABLE
    assert "no account" in (result.detail or "")


#: A host the tool does not connect from, for the user's second account.
OTHER_HOST = "192.0.2.%"


@pytest.fixture
def two_accounts(live_mariadb: Any, user: str) -> Iterator[tuple[str, str]]:
    """The user at `%` and at :data:`OTHER_HOST`, with their passwords."""
    password, theirs = f"Acme-{uuid.uuid4().hex[:12]}", f"Acme-{uuid.uuid4().hex[:12]}"
    _root(live_mariadb, "create user %s@'%%' identified by %s", (user, password))
    _root(live_mariadb, "create user %s@%s identified by %s", (user, OTHER_HOST, theirs))
    try:
        yield password, theirs
    finally:
        _root(live_mariadb, "drop user if exists %s@%s", (user, OTHER_HOST))


def test_a_check_where_another_account_could_answer_logs_in_nowhere(
    session: Any, user: str, two_accounts: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The user also exists at a host the tool does not connect from, so a
    login could reach an account the config does not declare, and a wrong
    password would count toward its `max_password_errors`. Without a change
    in this session, nothing is tried (#1270, decision 3). MariaDB keeps that
    count in memory only, so the test watches the login itself."""
    password, theirs = two_accounts
    _refuse_any_login(monkeypatch)

    right = session.verify_password(f"{user}@%", Secret(password))
    wrong = session.verify_password(f"{user}@%", Secret("Acme-wrong-password-1"))
    elsewhere = session.verify_password(f"{user}@{OTHER_HOST}", Secret(theirs))

    assert [right.result, wrong.result, elsewhere.result] == [UNAVAILABLE] * 3
    assert not any(one.attempted for one in (right, wrong, elsewhere))
    assert "no login was attempted" in (wrong.detail or "")
    assert f"{user}@{OTHER_HOST}" in (wrong.detail or "")


def test_the_reaching_login_logs_in_where_the_check_would_not(
    session: Any, user: str, two_accounts: tuple[str, str]
) -> None:
    """#1270 decision 5: it reaches `user@%` and passes where `CURRENT_USER()`
    names it (#1267, decision 8). `creds apply` asks it once per staged
    `pending` and target, after writing the vault mark (#1316)."""
    password = f"Acme-{uuid.uuid4().hex[:12]}"
    session.set_password(f"{user}@%", Secret(password))

    after = session.verify_reaching(f"{user}@%", Secret(password))

    assert after.result == PASS
    assert after.attempted


def test_a_reaching_login_s_refusal_says_nothing_where_another_account_could_answer(
    session: Any, user: str, two_accounts: tuple[str, str]
) -> None:
    """Another account could have sent the refusal, so it is no fail."""
    session.set_password(f"{user}@%", Secret(f"Acme-{uuid.uuid4().hex[:12]}"))

    wrong = session.verify_reaching(f"{user}@%", Secret("Acme-wrong-password-1"))

    assert wrong.result == UNAVAILABLE
    assert f"{user}@{OTHER_HOST}" in (wrong.detail or "")


def _refuse_any_login(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail the test, by name, if the session logs in as the account."""

    def login(*args: Any, **kwargs: Any) -> NoReturn:
        raise AssertionError("the session logged in where it must not")

    monkeypatch.setattr(session_module.verification, "login", login)


@pytest.mark.parametrize("method", [VERIFY_HASH, VERIFY_BOTH])
def test_a_check_by_the_stored_value_is_refused_by_capability(
    live_mariadb: Any, session: Any, user: str, method: str
) -> None:
    # The account exists, so the refusal cannot be for a missing one.
    _create(live_mariadb, user, "mysql_native_password")

    with pytest.raises(UnsupportedCapabilityError):
        session.verify_password(f"{user}@%", Secret("Acme-not-sent-1"), method=method)


def test_a_check_of_another_plugin_is_refused(live_mariadb: Any, session: Any, user: str) -> None:
    _root(live_mariadb, "create user %s@'%%' identified via unix_socket", (user,))

    with pytest.raises(accounts_module.OtherPluginError):
        session.verify_password(f"{user}@%", Secret("Acme-not-sent-1"))
