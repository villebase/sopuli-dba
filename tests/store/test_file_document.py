"""The file store's document: versions, pruning, and the strict reader (#1415).

Tier 0, pure: bytes in and out, no file and no encryption.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from sopuli.store.file._document import (
    DEFAULT_MAX_VERSIONS,
    EMPTY,
    FORMAT,
    FORMAT_VERSION,
    Document,
    DocumentError,
    dumps,
    loads,
)
from sopuli.store.protocol import StoreError

NOW = datetime(2026, 11, 9, 10, 0, tzinfo=UTC)
PATH = "acme/app"
PASSWORD = "Pw-acme-not-a-real-1"


def written(document: Document, *values: Any, max_versions: int | None = None) -> Document:
    for index, value in enumerate(values):
        document, _ = document.written(
            PATH, value, now=NOW + timedelta(minutes=index), max_versions=max_versions
        )
    return document


def body(document: Document) -> dict[str, Any]:
    parsed: dict[str, Any] = json.loads(dumps(document))
    return parsed


def damaged_with(change: Any) -> bytes:
    """A one-version document's JSON after ``change`` edits its parsed body."""
    parsed = body(written(EMPTY, {"current": PASSWORD}))
    change(parsed)
    return json.dumps(parsed).encode("utf-8")


# ----------------------------------------------------------------- versions ---


def test_the_first_write_is_version_one() -> None:
    document, number = EMPTY.written(PATH, {"current": "a"}, now=NOW, max_versions=None)

    assert number == 1
    latest = document.latest(PATH)
    assert latest is not None
    assert (latest.number, latest.created_at, latest.data) == (1, NOW, {"current": "a"})


def test_each_write_is_the_next_version_and_older_ones_stay_readable() -> None:
    document = written(EMPTY, {"v": 1}, {"v": 2}, {"v": 3})

    latest = document.latest(PATH)
    first = document.version(PATH, 1)
    assert latest is not None
    assert first is not None
    assert latest.number == 3
    assert first.data == {"v": 1}


def test_the_oldest_versions_beyond_max_versions_are_dropped() -> None:
    document = written(EMPTY, *({"v": n} for n in range(1, 6)), max_versions=2)

    assert [one.number for one in document.paths[PATH].versions] == [4, 5]
    assert document.version(PATH, 3) is None


def test_pruning_never_reuses_a_number() -> None:
    """`current` stands after pruning, so a compare-and-set token that named a
    pruned version still fails, as on KV v2."""
    document = written(EMPTY, {"v": 1}, {"v": 2}, max_versions=1)

    assert document.paths[PATH].current == 2
    _, number = document.written(PATH, {"v": 3}, now=NOW, max_versions=1)
    assert number == 3


def test_absent_max_versions_keeps_ten() -> None:
    document = written(EMPTY, *({"v": n} for n in range(1, 13)))

    assert len(document.paths[PATH].versions) == DEFAULT_MAX_VERSIONS == 10


def test_a_write_does_not_change_the_document_it_came_from() -> None:
    before = written(EMPTY, {"v": 1})
    after = written(before, {"v": 2})

    assert before.paths[PATH].current == 1
    assert after.paths[PATH].current == 2


def test_the_data_is_copied_so_a_later_change_by_the_caller_does_not_reach_it() -> None:
    data = {"current": "a"}
    document, _ = EMPTY.written(PATH, data, now=NOW, max_versions=None)
    data["current"] = "b"

    latest = document.latest(PATH)
    assert latest is not None
    assert latest.data == {"current": "a"}


def test_data_that_is_not_json_is_refused_without_repeating_it() -> None:
    with pytest.raises(StoreError) as caught:
        EMPTY.written(PATH, {"current": {PASSWORD}}, now=NOW, max_versions=None)

    assert "not plain JSON" in str(caught.value)
    assert PASSWORD not in str(caught.value)


@pytest.mark.parametrize(
    "value", [float("nan"), float("inf"), "\ud800"], ids=["nan", "infinity", "lone-surrogate"]
)
def test_a_value_the_file_cannot_hold_is_refused_at_the_write(value: Any) -> None:
    """Not later, when the whole store is written out."""
    with pytest.raises(StoreError) as caught:
        EMPTY.written(PATH, {"current": value}, now=NOW, max_versions=None)

    assert "not plain JSON" in str(caught.value)


@pytest.mark.parametrize("value", ["x", ["x"], None])
def test_data_that_is_not_an_object_is_refused(value: Any) -> None:
    with pytest.raises(StoreError) as caught:
        EMPTY.written(PATH, value, now=NOW, max_versions=None)

    assert "not a JSON object" in str(caught.value)


def test_a_time_with_no_zone_is_refused() -> None:
    """A naive time would be written converted from local time, so the time in
    memory and the time on disk would differ."""
    with pytest.raises(ValueError, match="zone"):
        EMPTY.written(PATH, {"v": 1}, now=datetime(2026, 11, 9, 10, 0), max_versions=None)


def test_changing_what_was_read_changes_no_document() -> None:
    first = written(EMPTY, {"list": [1]})
    second = written(first, {"list": [2]})

    read = second.version(PATH, 1)
    assert read is not None
    read.data["list"].append(99)

    for document in (first, second):
        again = document.version(PATH, 1)
        assert again is not None
        assert again.data == {"list": [1]}


def test_a_newest_version_missing_from_the_file_reads_as_gone() -> None:
    """Answering with the version before it would read a superseded password
    as current."""
    raw = damaged_with(lambda b: b["paths"][PATH].update(current=2))

    document = loads(raw)

    assert document.latest(PATH) is None
    assert document.version(PATH, 1) is not None


def test_an_unknown_path_reads_as_nothing() -> None:
    assert EMPTY.latest(PATH) is None
    assert EMPTY.version(PATH, 1) is None


# -------------------------------------------------------------- round trip ---


def test_a_document_reads_back_as_it_was_written() -> None:
    document = written(EMPTY, {"current": PASSWORD}, {"current": "x", "pending": "y"})

    assert loads(dumps(document)) == document


def test_equal_documents_are_equal_bytes() -> None:
    first = written(EMPTY, {"b": 1, "a": 2})
    second = written(EMPTY, {"a": 2, "b": 1})

    assert dumps(first) == dumps(second)


def test_the_written_document_says_what_it_is() -> None:
    written_body = body(written(EMPTY, {"v": 1}))

    assert written_body["format"] == FORMAT
    assert written_body["format_version"] == FORMAT_VERSION
    assert written_body["paths"][PATH]["versions"][0]["created_at"] == "2026-11-09T10:00:00Z"


def test_an_empty_store_round_trips() -> None:
    assert loads(dumps(EMPTY)) == EMPTY


# ----------------------------------------------------------- strict reader ---


@pytest.mark.parametrize(
    ("raw", "problem"),
    [
        (b"\xff\xfe", "not UTF-8 JSON"),
        (b"{not json", "not UTF-8 JSON"),
        (b"[]", f"not a {FORMAT} document"),
        (json.dumps({"format": "other"}).encode(), f"not a {FORMAT} document"),
    ],
)
def test_bytes_that_are_not_a_store_document_are_refused(raw: bytes, problem: str) -> None:
    with pytest.raises(DocumentError) as caught:
        loads(raw)

    assert problem in str(caught.value)


@pytest.mark.parametrize(
    ("change", "problem"),
    [
        (lambda b: b.update(format_version=2), "format_version is not 1"),
        (lambda b: b.update(format_version=True), "format_version is not 1"),
        (lambda b: b.update(format_version=1.0), "format_version is not 1"),
        (
            lambda b: b["paths"][PATH]["versions"][0].update(created_at="2026-11-09"),
            "created_at",
        ),
        (
            lambda b: b["paths"][PATH]["versions"][0].update(created_at="2026-11-09T10:00:00"),
            "created_at",
        ),
        (lambda b: b["paths"][PATH]["versions"][0].update(data="x"), "not an object"),
        (lambda b: b.update(extra=True), "unknown extra"),
        (lambda b: b["paths"][PATH].pop("current"), "missing current"),
        (lambda b: b["paths"][PATH].update(current=-1), "not a whole number"),
        (lambda b: b["paths"][PATH].update(current=True), "not a whole number"),
        (lambda b: b["paths"][PATH].update(current=0), "past `current`"),
        (lambda b: b["paths"][PATH]["versions"][0].update(version=0), "above 0"),
        (lambda b: b["paths"][PATH]["versions"][0].update(created_at="soon"), "created_at"),
        (lambda b: b["paths"][PATH]["versions"][0].pop("data"), "missing data"),
        (
            lambda b: b["paths"][PATH]["versions"].append(b["paths"][PATH]["versions"][0]),
            "out of order",
        ),
    ],
)
def test_a_damaged_document_is_refused_without_quoting_its_data(change: Any, problem: str) -> None:
    with pytest.raises(DocumentError) as caught:
        loads(damaged_with(change))

    assert problem in str(caught.value)
    assert PASSWORD not in str(caught.value)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"format":"sopuli-file-store","format":"sopuli-file-store"}',
        b'{"format":"sopuli-file-store","format_version":1,"paths":'
        b'{"a":{"current":0,"versions":[]},"a":{"current":0,"versions":[]}}}',
    ],
    ids=["top-level", "path"],
)
def test_a_key_named_twice_is_refused(raw: bytes) -> None:
    """The parser would keep the last and drop the rest without a word."""
    with pytest.raises(DocumentError) as caught:
        loads(raw)

    assert "names one key twice" in str(caught.value)


def test_nan_in_the_file_is_refused() -> None:
    raw = damaged_with(lambda b: None).replace(PASSWORD.encode(), b"x").replace(b'"x"', b"NaN")

    with pytest.raises(DocumentError) as caught:
        loads(raw)

    assert "not UTF-8 JSON" in str(caught.value)
