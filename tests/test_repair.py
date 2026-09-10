"""Reading a previous run's document back in (`creds apply --repair`, #391).

Tier 0: a document is a JSON file and this module is pure logic over one, so
none of this needs a container. The one thing it does touch is the filesystem,
which is what `tmp_path` is for -- a run document arrives as a *path* from an
operator, and the failures worth covering are the ones a path has.

The refusals carry more weight here than the happy path. `--repair` narrows,
and invariant 5 plus `apply`'s idempotency make a stale or partly-wrong document
wasteful rather than dangerous -- so the only thing that must not get through is
a document describing a *different estate*, and the tests below spend most of
their length on that and on the shapes that are not run documents at all.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from sopuli.clock import to_rfc3339, utc_now
from sopuli.config.errors import ArgumentError
from sopuli.diagnostics import REPAIR_DOCUMENT_STALE
from sopuli.exit_codes import ExitCode
from sopuli.repair import STALE_AFTER, read, staleness

ESTATE = "/etc/sopuli/estate.yaml"


def document(
    *,
    command: str = "creds.apply",
    results: list[dict[str, Any]] | None = None,
    config_files: list[str] | None = None,
    estate: bool = True,
    finished: str | None = None,
) -> dict[str, Any]:
    """A run document with only what this flag reads.

    Deliberately not a full one: everything below has to keep working against a
    document from an older minor version, so a fixture carrying every property
    the current schema allows would hide a dependency on a new one.
    """
    invocation: dict[str, Any] = {"correlation_id": "x", "dry_run": False}
    if config_files is not None:
        invocation["config_files"] = config_files
    elif estate:
        invocation["config_files"] = [ESTATE]
    if finished is not None:
        invocation["finished_at"] = finished
    return {
        "schema_version": "1.20",
        "command": command,
        "invocation": invocation,
        "results": results if results is not None else [],
        "exit_code": 4,
    }


def written(tmp_path: Path, body: Any, name: str = "run.json") -> Path:
    path = tmp_path / name
    path.write_text(body if isinstance(body, str) else json.dumps(body), encoding="utf-8")
    return path


def row(account: str, target: str, state: str) -> dict[str, Any]:
    return {"account": account, "target": target, "state": state, "changed": False}


# ------------------------------------------------------- the repair set ---


def test_the_set_is_what_did_not_confirm(tmp_path: Path) -> None:
    path = written(
        tmp_path,
        document(
            results=[
                row("acme_web_user", "appdb-dev-alpha", "IN_SYNC"),
                row("acme_batch_user", "appdb-dev-alpha", "DRIFT"),
                row("acme_web_user", "appdb-dev-beta", "LOCKED"),
            ]
        ),
    )

    found = read(path, sources=[Path(ESTATE)])

    assert found.pairs == (
        ("acme_batch_user", "appdb-dev-alpha"),
        ("acme_web_user", "appdb-dev-beta"),
    )


def test_a_rollover_window_counts_as_confirmed(tmp_path: Path) -> None:
    """The target took the new password and both authenticate, so what remains
    is `creds finish-rollover` rather than an apply. Repairing it would spend a
    login to discover nothing was wrong."""
    path = written(tmp_path, document(results=[row("a", "t", "ROLLOVER_ACTIVE")]))

    assert read(path, sources=[Path(ESTATE)]).pairs == ()


def test_a_document_with_nothing_unconfirmed_yields_an_empty_set(tmp_path: Path) -> None:
    """Valid to hand over, and the run it produces does nothing and says so.
    Refusing would make "did my repair already happen" un-askable."""
    path = written(tmp_path, document(results=[row("a", "t", "IN_SYNC")]))

    assert read(path, sources=[Path(ESTATE)]).pairs == ()


def test_a_row_missing_a_name_is_skipped_not_refused(tmp_path: Path) -> None:
    """Both are schema-required, so a document without them is malformed in a
    way this flag has no better answer to than acting on the whole rows."""
    path = written(
        tmp_path,
        document(results=[{"state": "DRIFT"}, row("a", "t", "DRIFT")]),
    )

    assert read(path, sources=[Path(ESTATE)]).pairs == (("a", "t"),)


def test_a_document_from_an_older_minor_version_is_still_readable(tmp_path: Path) -> None:
    """`03-json-output.md` §8's compatibility rule, now cutting both ways (#391).

    Nothing here may require a property the schema marks optional, so a document
    carrying only the minimum still resolves to a repair set.
    """
    path = written(
        tmp_path,
        {
            "schema_version": "1.10",
            "command": "creds.check",
            "invocation": {"config_files": [ESTATE]},
            "results": [row("a", "t", "DRIFT")],
        },
    )

    found = read(path, sources=[Path(ESTATE)])

    assert found.pairs == (("a", "t"),)
    assert found.age is None


# ----------------------------------------------------------- refusals ---


class TestRefusals:
    """All of them exit 2, because `--repair` feeds a filter and a filter that
    does not resolve is an invocation that did not resolve (J7)."""

    def test_a_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(ArgumentError) as caught:
            read(tmp_path / "nosuch.json", sources=[Path(ESTATE)])

        assert caught.value.exit_code == ExitCode.USAGE
        assert "cannot be read" in str(caught.value)

    def test_a_file_that_is_not_json(self, tmp_path: Path) -> None:
        with pytest.raises(ArgumentError) as caught:
            read(written(tmp_path, "not json at all"), sources=[Path(ESTATE)])

        assert "is not JSON" in str(caught.value)

    def test_json_that_is_not_a_run_document(self, tmp_path: Path) -> None:
        with pytest.raises(ArgumentError) as caught:
            read(written(tmp_path, {"hello": "world"}), sources=[Path(ESTATE)])

        assert "not a run document" in str(caught.value)

    def test_a_json_array(self, tmp_path: Path) -> None:
        """A list parses and has no `command`, so the type check has to come
        before the lookup rather than after it."""
        with pytest.raises(ArgumentError):
            read(written(tmp_path, [1, 2, 3]), sources=[Path(ESTATE)])

    def test_a_command_that_reports_no_repair_set(self, tmp_path: Path) -> None:
        """`creds generate` names accounts and asked no database anything, so
        every row would be unconfirmed -- which is not the same claim."""
        path = written(tmp_path, document(command="creds.generate"))

        with pytest.raises(ArgumentError) as caught:
            read(path, sources=[Path(ESTATE)])

        assert "reports no repair set" in str(caught.value)

    def test_a_document_from_a_different_estate(self, tmp_path: Path) -> None:
        """The one failure narrowing does not make harmless: the pairs may well
        exist in this estate too, and would then be acted on."""
        path = written(tmp_path, document(config_files=["/etc/sopuli/other.yaml"]))

        with pytest.raises(ArgumentError) as caught:
            read(path, sources=[Path(ESTATE)])

        assert "different configuration" in str(caught.value)
        assert "other.yaml" in str(caught.value)

    def test_a_document_naming_no_config_files(self, tmp_path: Path) -> None:
        """Every document written before #402 is in this position. Refused
        rather than trusted: the estate check cannot be performed, and the
        check is on whether the field is there rather than on a version."""
        path = written(tmp_path, document(estate=False))

        with pytest.raises(ArgumentError) as caught:
            read(path, sources=[Path(ESTATE)])

        assert "names no config files" in str(caught.value)

    def test_the_same_files_in_a_different_order_are_a_different_estate(
        self, tmp_path: Path
    ) -> None:
        """Order is the layering order (`01-configuration.md` §5), so two runs
        over the same files in the opposite order resolved different settings."""
        path = written(tmp_path, document(config_files=["/a.yaml", "/b.yaml"]))

        with pytest.raises(ArgumentError):
            read(path, sources=[Path("/b.yaml"), Path("/a.yaml")])

    def test_the_same_file_spelled_differently_is_the_same_estate(self, tmp_path: Path) -> None:
        """A scheduled run and a hand-typed repair may disagree about the
        working directory without disagreeing about the file."""
        real = tmp_path / "estate.yaml"
        real.write_text("version: 1\n", encoding="utf-8")
        path = written(tmp_path, document(config_files=[str(real)]))

        found = read(path, sources=[Path(str(real).replace("\\", "/"))])

        assert found.command == "creds.apply"


# ---------------------------------------------------------- staleness ---


class TestStaleness:
    """A warning and never a gate: a threshold that refused would have to be
    wrong for somebody, and the run it stopped would have been safe."""

    def _read(self, tmp_path: Path, ago: timedelta) -> Any:
        stamp = to_rfc3339(utc_now() - ago)
        return read(
            written(tmp_path, document(finished=stamp)),
            sources=[Path(ESTATE)],
        )

    def test_a_recent_document_warns_about_nothing(self, tmp_path: Path) -> None:
        assert staleness(self._read(tmp_path, timedelta(minutes=5))) is None

    def test_an_old_one_warns_and_names_its_age(self, tmp_path: Path) -> None:
        found = staleness(self._read(tmp_path, timedelta(days=11)))

        assert found is not None
        assert found.code == REPAIR_DOCUMENT_STALE
        assert found.level == "warning"
        assert "11 days" in found.message

    def test_the_boundary_does_not_warn(self, tmp_path: Path) -> None:
        assert staleness(self._read(tmp_path, STALE_AFTER - timedelta(minutes=1))) is None

    def test_hours_are_used_below_a_day(self, tmp_path: Path) -> None:
        found = staleness(self._read(tmp_path, timedelta(hours=20)))

        assert found is not None
        assert "20 hours" in found.message

    def test_a_document_with_no_timestamp_reports_no_age(self, tmp_path: Path) -> None:
        """`None` rather than zero, so "nothing to report" cannot be read as
        "fresh" by whatever asks next."""
        found = read(written(tmp_path, document()), sources=[Path(ESTATE)])

        assert found.age is None
        assert staleness(found) is None

    def test_an_unparseable_timestamp_reports_no_age(self, tmp_path: Path) -> None:
        path = written(tmp_path, document(finished="the day before yesterday"))

        assert read(path, sources=[Path(ESTATE)]).age is None
