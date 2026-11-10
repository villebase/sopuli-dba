"""The Oracle account survey for UC-5's reports, against a fake cursor (tier 0).

What a PDB cannot read truthfully is ``None`` with a reason
(``02-oracle-privileges.md`` §2). These tests pin each such case, because a
report that read the wrong value would call a locked account open.
"""

from __future__ import annotations

from typing import Any

import pytest

from sopuli.config.model import ExpandedTarget, Target
from sopuli.driver.oracle.accounts import (
    SURVEY_LCOUNT_QUERY,
    SURVEY_LIMITS_QUERY,
    SURVEY_LIMITS_QUERY_LEGACY,
    SURVEY_USERS_QUERY,
    SURVEY_USERS_QUERY_LEGACY,
    DictionaryUnreadableError,
    survey,
    survey_with_profiles,
)
from sopuli.driver.protocol import OFFLINE_VERIFY, Scope
from sopuli.driver.survey import SurveyedAccount


class _Cursor:
    """A cursor answering per statement. An exception is raised on fetch."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.asked: list[str] = []
        self.binds: list[Any] = []
        self.sql = ""

    def execute(self, sql: str, parameters: Any = None, /) -> _Cursor:
        self.asked.append(sql)
        self.binds.append(parameters)
        self.sql = sql
        return self

    def fetchone(self) -> Any:
        raise AssertionError("the survey reads every row")

    def __enter__(self) -> _Cursor:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def fetchall(self) -> Any:
        answer = self.answers.get(self.sql)
        if isinstance(answer, Exception):
            raise answer
        return answer if isinstance(answer, list) else []


def _ora(code: str, message: str = "") -> RuntimeError:
    return RuntimeError(f"{code}: {message or 'something the server said'}")


def _limits(
    profile: str,
    *,
    lifetime: str = "DEFAULT",
    lifetime_resolved: str = "UNLIMITED",
    attempts: str = "5",
    attempts_resolved: str | None = None,
    common: str | None = "NO",
) -> list[tuple[Any, ...]]:
    """``SURVEY_LIMITS_QUERY``'s rows for one profile."""
    return [
        (profile, "PASSWORD_LIFE_TIME", lifetime, lifetime_resolved, common),
        (profile, "FAILED_LOGIN_ATTEMPTS", attempts, attempts_resolved or attempts, common),
    ]


def _run(
    users: list[tuple[Any, ...]],
    limits: list[tuple[Any, ...]],
    *,
    own_container: bool = False,
    user_dollar: bool = True,
    application: bool = False,
    lcount: list[tuple[Any, ...]] | Exception | None = None,
    extra: dict[str, Any] | None = None,
) -> tuple[tuple[SurveyedAccount, ...], _Cursor]:
    answers: dict[str, Any] = {
        SURVEY_USERS_QUERY: users,
        SURVEY_LIMITS_QUERY: limits,
        SURVEY_LCOUNT_QUERY: lcount if lcount is not None else [],
    }
    answers.update(extra or {})
    cursor = _Cursor(answers)
    surveyed = survey(
        cursor, own_container=own_container, user_dollar=user_dollar, application=application
    )
    return surveyed, cursor


def test_local_account_in_a_pdb_reads_everything() -> None:
    accounts, _ = _run(
        [("ACME_APP_USER", "OPEN", "ACME_PROF", "NO", "N")],
        _limits("ACME_PROF"),
        lcount=[("ACME_APP_USER", 2)],
    )
    assert accounts == (
        SurveyedAccount(
            name="ACME_APP_USER",
            status="OPEN",
            locked=False,
            profile="ACME_PROF",
            common=False,
            vendor_maintained=False,
            password_lifetime="unlimited",
            failed_login_limit=5,
            failed_logins=2,
            unreadable=(),
        ),
    )


def test_common_account_in_a_pdb_has_no_lock_limits_or_count() -> None:
    accounts, _ = _run(
        [("C##ACME_ADM", "OPEN", "ACME_PROF", "YES", "N")],
        _limits("ACME_PROF"),
        lcount=[("C##ACME_ADM", 0)],
    )
    (account,) = accounts
    assert account.common is True
    assert account.held_elsewhere is True
    assert account.locked is None
    assert account.password_lifetime is None
    assert account.failed_login_limit is None
    assert account.failed_logins is None
    assert account.status == "OPEN"
    assert len(account.unreadable) == 4
    assert all("CDB$ROOT" in reason for reason in account.unreadable)


def test_common_account_in_the_root_reads_everything() -> None:
    accounts, _ = _run(
        [("C##ACME_ADM", "LOCKED", "C##ACME_PROF", "YES", "N")],
        _limits("C##ACME_PROF", attempts="DEFAULT", attempts_resolved="10", common="YES"),
        own_container=True,
        lcount=[("C##ACME_ADM", 3)],
    )
    (account,) = accounts
    assert account.held_elsewhere is False
    assert account.locked is True
    assert account.password_lifetime == "unlimited"
    assert account.failed_login_limit == 10
    assert account.failed_logins == 3
    assert account.unreadable == ()


def test_default_limit_on_a_common_profile_in_a_pdb_is_unreadable() -> None:
    accounts, _ = _run(
        [("ACME_APP_USER", "OPEN", "C##ACME_PROF", "NO", "N")],
        _limits(
            "C##ACME_PROF",
            lifetime="180",
            lifetime_resolved="180",
            attempts="DEFAULT",
            attempts_resolved="2",
            common="YES",
        ),
        lcount=[("ACME_APP_USER", 0)],
    )
    (account,) = accounts
    assert account.password_lifetime == 180
    assert account.failed_login_limit is None
    (reason,) = account.unreadable
    assert "FAILED_LOGIN_ATTEMPTS" in reason
    assert "C##ACME_PROF" in reason


def test_a_set_limit_on_a_common_profile_is_read() -> None:
    accounts, _ = _run(
        [("ACME_APP_USER", "OPEN", "C##ACME_PROF", "NO", "N")],
        _limits(
            "C##ACME_PROF", lifetime="180", lifetime_resolved="180", attempts="7", common="YES"
        ),
        lcount=[("ACME_APP_USER", 0)],
    )
    (account,) = accounts
    assert account.failed_login_limit == 7
    assert account.unreadable == ()


def test_no_offline_verify_means_no_count() -> None:
    accounts, cursor = _run(
        [("ACME_APP_USER", "OPEN", "ACME_PROF", "NO", "N")],
        _limits("ACME_PROF"),
        user_dollar=False,
    )
    (account,) = accounts
    assert account.failed_logins is None
    (reason,) = account.unreadable
    assert "GRANT SELECT ON SYS.USER$" in reason
    assert SURVEY_LCOUNT_QUERY not in cursor.asked


def test_a_refused_user_dollar_read_is_a_reason_not_a_failure() -> None:
    accounts, _ = _run(
        [("ACME_APP_USER", "OPEN", "ACME_PROF", "NO", "N")],
        _limits("ACME_PROF"),
        lcount=_ora("ORA-00942", "table or view does not exist"),
    )
    (account,) = accounts
    assert account.failed_logins is None
    (reason,) = account.unreadable
    assert "ORA-00942" in reason


def test_an_account_with_no_user_dollar_row_has_no_count() -> None:
    accounts, _ = _run(
        [("ACME_APP_USER", "OPEN", "ACME_PROF", "NO", "N")],
        _limits("ACME_PROF"),
        lcount=[("acme_app_user", 4)],
    )
    (account,) = accounts
    assert account.failed_logins is None
    assert len(account.unreadable) == 1


def test_release_without_common_or_oracle_maintained() -> None:
    no_column = _ora("ORA-00904", '"COMMON": invalid identifier')
    accounts, cursor = _run(
        [],
        [],
        own_container=True,
        lcount=[("SYSTEM", 0), ("ACME_APP_USER", 1)],
        extra={
            SURVEY_USERS_QUERY: no_column,
            SURVEY_USERS_QUERY_LEGACY: [
                ("ACME_APP_USER", "OPEN", "DEFAULT", None, None),
                ("SYSTEM", "OPEN", "DEFAULT", None, None),
            ],
            SURVEY_LIMITS_QUERY: no_column,
            SURVEY_LIMITS_QUERY_LEGACY: _limits(
                "DEFAULT", lifetime="180", lifetime_resolved="180", attempts="10", common=None
            ),
        },
    )
    by_name = {account.name: account for account in accounts}
    assert by_name["SYSTEM"].vendor_maintained is True
    assert by_name["ACME_APP_USER"].vendor_maintained is False
    assert not any(account.common for account in accounts)
    assert by_name["ACME_APP_USER"].password_lifetime == 180
    assert by_name["ACME_APP_USER"].failed_logins == 1
    assert SURVEY_USERS_QUERY_LEGACY in cursor.asked
    assert SURVEY_LIMITS_QUERY_LEGACY in cursor.asked


def test_without_common_a_prefixed_account_in_a_pdb_is_taken_as_common() -> None:
    """If the narrowed shape answers in a PDB, the C## prefix decides, as the
    lockout guard's does, so a locked common account is never read as open."""
    no_column = _ora("ORA-00904", '"COMMON": invalid identifier')
    accounts, _ = _run(
        [],
        [],
        lcount=[("C##ACME_ADM", 0), ("ACME_APP_USER", 0)],
        extra={
            SURVEY_USERS_QUERY: no_column,
            SURVEY_USERS_QUERY_LEGACY: [
                ("ACME_APP_USER", "OPEN", "ACME_PROF", None, None),
                ("C##ACME_ADM", "OPEN", "ACME_PROF", None, None),
            ],
            SURVEY_LIMITS_QUERY: no_column,
            SURVEY_LIMITS_QUERY_LEGACY: _limits("ACME_PROF", common=None),
        },
    )
    by_name = {account.name: account for account in accounts}
    admin = by_name["C##ACME_ADM"]
    assert admin.common is True
    assert admin.locked is None
    assert admin.failed_logins is None
    local = by_name["ACME_APP_USER"]
    assert local.common is False
    assert local.locked is False
    # The lifetime is DEFAULT on a profile whose COMMON was not read.
    assert local.password_lifetime is None
    assert local.failed_login_limit == 5
    (reason,) = local.unreadable
    assert "whether the profile is common" in reason


def test_in_an_application_container_the_reasons_say_unmeasured() -> None:
    accounts, _ = _run(
        [("ACME_APP_ADM", "OPEN", "ACME_PROF", "YES", "N")],
        _limits("ACME_PROF"),
        lcount=[("ACME_APP_ADM", 0)],
        application=True,
    )
    (account,) = accounts
    assert account.locked is None
    assert len(account.unreadable) == 4
    assert all("not been measured" in reason for reason in account.unreadable)
    assert not any("CDB$ROOT" in reason for reason in account.unreadable)


def test_an_empty_lcount_is_told_from_a_missing_row() -> None:
    accounts, _ = _run(
        [
            ("ACME_APP_USER", "OPEN", "ACME_PROF", "NO", "N"),
            ("ACME_WEB_USER", "OPEN", "ACME_PROF", "NO", "N"),
        ],
        _limits("ACME_PROF"),
        lcount=[("ACME_APP_USER", None)],
    )
    by_name = {account.name: account for account in accounts}
    assert by_name["ACME_APP_USER"].unreadable == ("SYS.USER$.LCOUNT is empty for ACME_APP_USER",)
    assert by_name["ACME_WEB_USER"].unreadable == ("SYS.USER$ has no row for ACME_WEB_USER",)


def test_oracle_maintained_is_read_where_the_column_exists() -> None:
    accounts, _ = _run(
        [("DBSNMP", "OPEN", "DEFAULT", "NO", "Y"), ("SCOTT", "OPEN", "DEFAULT", "NO", "N")],
        _limits("DEFAULT", lifetime="180", lifetime_resolved="180", attempts="10"),
        own_container=True,
    )
    by_name = {account.name: account for account in accounts}
    assert by_name["DBSNMP"].vendor_maintained is True
    # On the supplied list, but the column says no, and the column decides.
    assert by_name["SCOTT"].vendor_maintained is False


@pytest.mark.parametrize(
    ("status", "locked"),
    [
        ("LOCKED", True),
        ("LOCKED(TIMED)", True),
        ("EXPIRED & LOCKED", True),
        ("OPEN", False),
        ("EXPIRED(GRACE)", False),
        ("OPEN & IN ROLLOVER", False),
    ],
)
def test_locked_statuses(status: str, locked: bool) -> None:
    accounts, _ = _run(
        [("ACME_APP_USER", status, "ACME_PROF", "NO", "N")],
        _limits("ACME_PROF"),
        own_container=True,
    )
    assert accounts[0].locked is locked


def test_a_limit_that_is_not_a_whole_number_is_unreadable() -> None:
    accounts, _ = _run(
        [("ACME_APP_USER", "OPEN", "ACME_PROF", "NO", "N")],
        _limits("ACME_PROF", lifetime=".0416", lifetime_resolved=".0416"),
        own_container=True,
        lcount=[("ACME_APP_USER", 0)],
    )
    (account,) = accounts
    assert account.password_lifetime is None
    (reason,) = account.unreadable
    assert ".0416" in reason


def test_accounts_come_back_ordered_by_name() -> None:
    accounts, _ = _run(
        [
            ("SYSTEM", "OPEN", "DEFAULT", "NO", "Y"),
            ("ACME_APP_USER", "OPEN", "DEFAULT", "NO", "N"),
        ],
        _limits("DEFAULT", lifetime="180", lifetime_resolved="180", attempts="10"),
        own_container=True,
    )
    assert [account.name for account in accounts] == ["ACME_APP_USER", "SYSTEM"]


def test_no_statement_reads_a_verifier_and_none_binds_anything() -> None:
    _, cursor = _run(
        [("ACME_APP_USER", "OPEN", "ACME_PROF", "NO", "N")],
        _limits("ACME_PROF"),
    )
    for statement in cursor.asked:
        lowered = statement.lower()
        assert "password" not in lowered.replace("password_life_time", "")
        assert "spare4" not in lowered
    assert all(parameters in (None, {}) for parameters in cursor.binds)
    user_dollar = [statement for statement in cursor.asked if "user$" in statement.lower()]
    assert user_dollar == [SURVEY_LCOUNT_QUERY]


class _Connection:
    def cursor(self) -> Any:
        return _Cursor({})


@pytest.mark.parametrize(
    ("scope_type", "capabilities", "own_container", "user_dollar", "application"),
    [
        ("pdb", frozenset({OFFLINE_VERIFY}), False, True, False),
        ("cdb_root", frozenset(), True, False, False),
        ("non_cdb", frozenset({OFFLINE_VERIFY}), True, True, False),
        ("app_pdb", frozenset(), False, False, True),
        ("app_root", frozenset(), False, False, True),
        ("unknown", frozenset(), False, False, False),
    ],
)
def test_the_session_passes_its_scope_to_the_survey(
    session_module: Any,
    monkeypatch: pytest.MonkeyPatch,
    scope_type: str,
    capabilities: frozenset[str],
    own_container: bool,
    user_dollar: bool,
    application: bool,
) -> None:
    seen: dict[str, bool] = {}

    def fake_survey(
        cursor: Any, *, own_container: bool, user_dollar: bool, application: bool
    ) -> tuple[SurveyedAccount, ...]:
        seen.update(own_container=own_container, user_dollar=user_dollar, application=application)
        return ()

    monkeypatch.setattr(session_module, "survey", fake_survey)
    session = session_module.OracleSession(
        connection=_Connection(),
        target=ExpandedTarget(
            target=Target(name="orders", type="oracle", dsn="db.example.com:1521/orders"),
            index=0,
        ),
        correlation_id="00000000-0000-0000-0000-000000000000",
    )
    session._scope = Scope(type=scope_type, capabilities=capabilities)
    assert session.survey_accounts() == ()
    assert seen == {
        "own_container": own_container,
        "user_dollar": user_dollar,
        "application": application,
    }


def test_a_refused_dba_users_read_names_the_grant() -> None:
    with pytest.raises(DictionaryUnreadableError) as raised:
        _run(
            [],
            [],
            extra={SURVEY_USERS_QUERY: _ora("ORA-00942", "table or view does not exist")},
        )
    assert raised.value.code == "ORA-00942"
    assert "DBA_USERS" in str(raised.value)


# --------------------------------------------- the target's profiles (#1390) ---


def test_the_profile_names_come_from_the_limits_rows_with_no_statement_added() -> None:
    """Every profile has a row per resource, so the limits statement already
    names every profile, including one no account is on (#1390)."""
    cursor = _Cursor(
        {
            SURVEY_USERS_QUERY: [("ACME_APP_USER", "OPEN", "APP_USERS", "NO", "N")],
            SURVEY_LIMITS_QUERY: _limits("DEFAULT") + _limits("APP_USERS") + _limits("UNUSED"),
            SURVEY_LCOUNT_QUERY: [],
        }
    )
    accounts, profiles = survey_with_profiles(
        cursor, own_container=True, user_dollar=False, application=False
    )
    assert [account.name for account in accounts] == ["ACME_APP_USER"]
    assert profiles == frozenset({"DEFAULT", "APP_USERS", "UNUSED"})
    assert cursor.asked == [SURVEY_USERS_QUERY, SURVEY_LIMITS_QUERY]


def test_the_session_surveys_accounts_and_profiles_on_one_scope(
    session_module: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, bool] = {}

    def fake(
        cursor: Any, *, own_container: bool, user_dollar: bool, application: bool
    ) -> tuple[tuple[SurveyedAccount, ...], frozenset[str]]:
        seen.update(own_container=own_container, user_dollar=user_dollar, application=application)
        return (), frozenset({"DEFAULT"})

    monkeypatch.setattr(session_module, "survey_with_profiles", fake)
    session = session_module.OracleSession(
        connection=_Connection(),
        target=ExpandedTarget(
            target=Target(name="orders", type="oracle", dsn="db.example.com:1521/orders"),
            index=0,
        ),
        correlation_id="00000000-0000-0000-0000-000000000000",
    )
    session._scope = Scope(type="pdb", capabilities=frozenset({OFFLINE_VERIFY}))
    assert session.survey_with_profiles() == ((), frozenset({"DEFAULT"}))
    assert seen == {"own_container": False, "user_dollar": True, "application": False}
