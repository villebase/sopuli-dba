"""How `creds apply` keeps a SQL Server login's policy flags around a change
(#1551, ``02-mssql-privileges.md`` §6.2). Tier 0: the session and the vault
are fakes, and the helpers are the command's own."""

from __future__ import annotations

from typing import Any

import pytest

from sopuli import cli
from sopuli.driver.protocol import DriverError, UnsupportedCapabilityError
from sopuli.policy_flags import PolicyFlags

#: The command's helpers, typed loosely: the fakes below stand in for its types.
keep: Any = cli._keep_flags
restore: Any = cli._restore_flags
refuse: Any = cli._refuse_flags_in_metadata

ON = PolicyFlags(check_policy=True, check_expiration=True)
OFF = PolicyFlags(check_policy=False, check_expiration=False)


class Binding:
    target = "mssql-dev"
    secret = object()


class Marks:
    """The vault's record, in memory. ``fail`` makes every write fail."""

    def __init__(self, recorded: PolicyFlags | None = None, *, fail: str | None = None) -> None:
        self.recorded = recorded
        self.fail = fail
        self.writes: list[str] = []

    def flags_recorded(self, binding: Any) -> PolicyFlags | None:
        return self.recorded

    def record_flags(self, binding: Any, flags: PolicyFlags) -> str | None:
        if self.fail:
            return self.fail
        self.writes.append("record")
        self.recorded = flags
        return None

    def remove_flags(self, binding: Any) -> str | None:
        if self.fail:
            return self.fail
        self.writes.append("remove")
        self.recorded = None
        return None


class Session:
    def __init__(self, flags: PolicyFlags) -> None:
        self.flags = flags
        self.restored: list[PolicyFlags] = []

    def policy_flags(self, account: str) -> PolicyFlags:
        return self.flags

    def restore_policy(self, account: str, flags: PolicyFlags) -> bool:
        self.restored.append(flags)
        return True


def test_step_1_records_the_flags_before_the_change() -> None:
    marks = Marks()
    keep(Binding(), Session(ON), "acme_app", marks)
    assert (marks.writes, marks.recorded) == (["record"], ON)


def test_a_record_already_there_is_kept_and_not_read_again() -> None:
    """A run that stopped after step 2 left the policy off: reading now would
    record it off."""
    marks = Marks(recorded=ON)
    keep(Binding(), Session(OFF), "acme_app", marks)
    assert (marks.writes, marks.recorded) == ([], ON)


def test_flags_both_off_need_no_record() -> None:
    marks = Marks()
    keep(Binding(), Session(OFF), "acme_app", marks)
    assert marks.writes == []


def test_a_record_that_cannot_be_written_stops_the_change() -> None:
    with pytest.raises(DriverError, match="no change was sent: the vault refused"):
        keep(Binding(), Session(ON), "acme_app", Marks(fail="the vault refused"))


def test_no_vault_to_write_to_stops_the_change() -> None:
    with pytest.raises(DriverError, match="cannot write them"):
        keep(Binding(), Session(ON), "acme_app", None)


def test_step_4_sets_the_recorded_flags_back_and_removes_the_record() -> None:
    marks, session = Marks(recorded=ON), Session(OFF)
    assert restore(Binding(), session, "acme_app", marks)
    assert (session.restored, marks.writes, marks.recorded) == ([ON], ["remove"], None)


def test_step_4_without_a_record_does_nothing() -> None:
    marks, session = Marks(), Session(OFF)
    assert not restore(Binding(), session, "acme_app", marks)
    assert (session.restored, marks.writes) == ([], [])


def test_a_record_left_after_the_flags_were_set_back_is_reported() -> None:
    marks, session = Marks(recorded=ON, fail="the vault refused"), Session(OFF)
    with pytest.raises(DriverError, match="did not remove its record"):
        restore(Binding(), session, "acme_app", marks)
    assert session.restored == [ON]


class Expanded:
    def __init__(self, kind: str) -> None:
        self.target = type("T", (), {"type": kind})()


class Bound:
    def __init__(self, target: str) -> None:
        self.target = target
        self.secret = object()
        self.vault = "oci-vault"
        self.account = "acme_app"


@pytest.mark.parametrize(("kind", "refused"), [("mssql", True), ("postgresql", False)])
def test_a_sql_server_credential_staged_natively_is_refused_at_plan_time(
    monkeypatch: pytest.MonkeyPatch, kind: str, refused: bool
) -> None:
    monkeypatch.setattr(cli, "_expanded", lambda config, name: Expanded(kind))
    monkeypatch.setattr(cli, "_lock_key", lambda binding: binding)
    monkeypatch.setattr(cli, "_is_native", lambda stores, key: True)
    bindings = [Bound("db-dev")]
    if not refused:
        refuse(bindings, {}, None)
        return
    with pytest.raises(UnsupportedCapabilityError) as caught:
        refuse(bindings, {}, None)
    assert caught.value.capability == cli.POLICY_FLAGS_IN_METADATA
    assert "#1584" in (caught.value.hint or "")
