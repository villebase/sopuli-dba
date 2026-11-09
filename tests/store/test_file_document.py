"""The file store's document: versions, pruning, and the strict reader (#1415).

Tier 0, pure: bytes in and out, no file and no encryption.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from types import MappingProxyType
from typing import Any

import pytest

from sopuli.store.file._document import (
    DEFAULT_MAX_VERSIONS,
    EMPTY,
    FORMAT,
    FORMAT_VERSION,
    MAX_DEPTH,
    Document,
    DocumentError,
    Version,
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


class WideInt(int):
    """An int whose `str` would pass a check that `json` does not use."""

    def __str__(self) -> str:
        return "0"


class QuietStr(str):
    """A str whose `encode` hides that it is not valid UTF-8."""

    def encode(self, encoding: str = "utf-8", errors: str = "strict") -> bytes:
        return b""


def numbers(document: Document) -> list[int]:
    return [one.number for one in document.paths[PATH]]


def body(document: Document) -> dict[str, Any]:
    parsed: dict[str, Any] = json.loads(dumps(document))
    return parsed


def damaged_with(change: Any) -> bytes:
    """A two-version document's JSON after ``change`` edits its parsed body."""
    parsed = body(written(EMPTY, {"current": PASSWORD}, {"current": PASSWORD}))
    change(parsed)
    return json.dumps(parsed).encode("utf-8")


def first_version(parsed: dict[str, Any]) -> dict[str, Any]:
    found: dict[str, Any] = parsed["paths"][PATH][0]
    return found


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
    assert latest.number == document.current(PATH) == 3
    assert first.data == {"v": 1}


def test_the_oldest_versions_beyond_max_versions_are_dropped() -> None:
    document = written(EMPTY, *({"v": n} for n in range(1, 6)), max_versions=2)

    assert numbers(document) == [4, 5]
    assert document.version(PATH, 3) is None


def test_pruning_never_reuses_a_number() -> None:
    """The newest is always kept, so the next number follows it, and a version
    number names one write for good."""
    document = written(EMPTY, {"v": 1}, {"v": 2}, max_versions=1)

    assert numbers(document) == [2]
    _, number = document.written(PATH, {"v": 3}, now=NOW, max_versions=1)
    assert number == 3


def test_a_lower_max_versions_prunes_every_path_at_the_next_write() -> None:
    """Old passwords leave the file at the next write, not when each path is
    next rotated."""
    document = written(EMPTY, *({"v": n} for n in range(1, 5)))
    document, _ = document.written("acme/other", {"v": 1}, now=NOW, max_versions=1)

    assert numbers(document) == [4]


def test_absent_max_versions_keeps_ten() -> None:
    document = written(EMPTY, *({"v": n} for n in range(1, 13)))

    assert len(document.paths[PATH]) == DEFAULT_MAX_VERSIONS == 10


def test_a_write_does_not_change_the_document_it_came_from() -> None:
    before = written(EMPTY, {"v": 1})
    after = written(before, {"v": 2})

    assert before.current(PATH) == 1
    assert after.current(PATH) == 2


def test_the_data_is_copied_so_a_later_change_by_the_caller_does_not_reach_it() -> None:
    data = {"current": "a"}
    document, _ = EMPTY.written(PATH, data, now=NOW, max_versions=None)
    data["current"] = "b"

    latest = document.latest(PATH)
    assert latest is not None
    assert latest.data == {"current": "a"}


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


def test_changing_a_version_reached_through_paths_changes_nothing() -> None:
    """Data is kept as JSON text, and each read of `data` is a new copy."""
    document = written(EMPTY, {"current": "a"})

    document.paths[PATH][0].data["current"] = "changed"

    latest = document.latest(PATH)
    assert latest is not None
    assert latest.data == {"current": "a"}
    assert json.loads(dumps(document))["paths"][PATH][0]["data"] == {"current": "a"}


@pytest.mark.parametrize(
    ("path", "problem"),
    [("", "empty"), ("acme/\ud800", "not valid UTF-8"), (3, "not text")],
    ids=["empty", "lone-surrogate", "not-text"],
)
def test_a_path_the_file_cannot_hold_is_refused_at_the_write(path: Any, problem: str) -> None:
    with pytest.raises(StoreError) as caught:
        EMPTY.written(path, {"v": 1}, now=NOW, max_versions=None)

    assert problem in str(caught.value)
    assert caught.value.hint is not None


def test_a_tuple_is_stored_as_a_list() -> None:
    document, _ = EMPTY.written(PATH, {"targets": ("a", "b")}, now=NOW, max_versions=None)

    latest = document.latest(PATH)
    assert latest is not None
    assert latest.data == {"targets": ["a", "b"]}


@pytest.mark.parametrize(
    ("value", "problem"),
    [
        ({"current": {PASSWORD}}, "a value of type set"),
        ({"current": float("nan")}, "not finite"),
        ({"current": float("inf")}, "not finite"),
        ({"current": "\ud800"}, "not valid UTF-8"),
        ({1: "a"}, "a key that is not text"),
        ({"k": {2: PASSWORD}}, "a key that is not text"),
        ({"current": 10**5000}, "wider than 14000 bits"),
        ({"current": WideInt(10**5000)}, "wider than 14000 bits"),
        ({"current": QuietStr("\ud800")}, "not valid UTF-8"),
    ],
    ids=[
        "set",
        "nan",
        "infinity",
        "lone-surrogate",
        "int-key",
        "nested-int-key",
        "huge-int",
        "huge-int-subclass",
        "str-subclass",
    ],
)
def test_data_the_file_cannot_hold_as_it_is_is_refused_without_repeating_it(
    value: Any, problem: str
) -> None:
    """Refused at the write, not changed, and not failed on later when the
    whole store is written out."""
    with pytest.raises(StoreError) as caught:
        EMPTY.written(PATH, value, now=NOW, max_versions=None)

    assert problem in str(caught.value)
    assert PASSWORD not in str(caught.value)
    assert caught.value.hint is not None


def test_data_nested_too_deep_is_refused() -> None:
    value: Any = "x"
    for _ in range(MAX_DEPTH + 2):
        value = {"k": value}

    with pytest.raises(StoreError) as caught:
        EMPTY.written(PATH, value, now=NOW, max_versions=None)

    assert "nested more than" in str(caught.value)


@pytest.mark.parametrize("value", ["x", ["x"], None])
def test_data_that_is_not_an_object_is_refused(value: Any) -> None:
    with pytest.raises(StoreError) as caught:
        EMPTY.written(PATH, value, now=NOW, max_versions=None)

    assert "not a JSON object" in str(caught.value)
    assert caught.value.hint is not None


def test_a_time_with_no_zone_is_refused() -> None:
    """A naive time would be written converted from local time, so the time in
    memory and the time on disk would differ."""
    with pytest.raises(ValueError, match="zone"):
        EMPTY.written(PATH, {"v": 1}, now=datetime(2026, 11, 9, 10, 0), max_versions=None)


def test_a_time_outside_the_utc_range_is_refused_at_the_write() -> None:
    edge = datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=2)))

    with pytest.raises(ValueError, match="outside the range"):
        EMPTY.written(PATH, {"v": 1}, now=edge, max_versions=None)


@pytest.mark.parametrize(
    "paths",
    [
        {PATH: ()},
        {"": (Version(1, NOW, "{}"),)},
        {PATH: (Version(1, NOW, "{}"), Version(3, NOW, "{}"))},
    ],
    ids=["no-versions", "empty-name", "gap"],
)
def test_a_document_the_reader_would_refuse_cannot_be_built(paths: Any) -> None:
    """So `dumps` cannot write a file this module would call damaged."""
    with pytest.raises(ValueError, match="a document path"):
        Document(MappingProxyType(paths))


@pytest.mark.parametrize(
    ("number", "created_at", "text", "problem"),
    [
        (0, NOW, "{}", "above 0"),
        (1, datetime(2026, 11, 9, 10, 0), "{}", "carry its zone"),
        (1, datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=2))), "{}", "UTC range"),
        (1, NOW, "[]", "JSON object"),
        (1, NOW, '{"a":NaN}', "no NaN"),
        (1, NOW, '{"a":' + "[" * 40 + "]" * 40 + "}", "plain values"),
    ],
    ids=["number-zero", "naive-time", "time-out-of-range", "not-an-object", "nan", "too-deep"],
)
def test_a_version_the_reader_would_refuse_cannot_be_built(
    number: int, created_at: datetime, text: str, problem: str
) -> None:
    with pytest.raises(ValueError, match=problem):
        Version(number, created_at, text)


def test_a_document_keeps_no_container_its_caller_can_change() -> None:
    versions = [Version(1, NOW, "{}")]
    given = {PATH: versions}
    document = Document(given)  # type: ignore[arg-type]

    versions.append(Version(3, NOW, "{}"))
    given["acme/other"] = []

    assert document.paths[PATH] == (Version(1, NOW, "{}"),)
    assert "acme/other" not in document.paths
    assert loads(dumps(document)) == document


def test_a_document_holds_only_versions() -> None:
    with pytest.raises(ValueError, match="Version objects"):
        Document(MappingProxyType({PATH: ("not a version",)}))  # type: ignore[dict-item]


@pytest.mark.parametrize("number", [True, 1.0])
def test_a_pin_that_is_not_an_int_is_refused(number: Any) -> None:
    """Both equal 1 in Python; neither is a version number."""
    with pytest.raises(TypeError):
        written(EMPTY, {"v": 1}).version(PATH, number)


def test_a_pin_outside_the_kept_versions_reads_as_nothing() -> None:
    document = written(EMPTY, *({"v": n} for n in range(1, 5)), max_versions=2)

    assert [document.version(PATH, n) is not None for n in range(0, 6)] == [
        False,
        False,
        False,
        True,
        True,
        False,
    ]


def test_dumps_writes_exactly_what_json_would_write_for_the_whole_body() -> None:
    """dumps places each version's stored text as it is; this holds it to the
    form a full serialisation gives, across several paths and odd text."""
    document = written(EMPTY, {"b": [1, 2.5, None, True], "a": "ä "})
    for path in ("z/last", "a/first", "m/ä"):
        document, _ = document.written(path, {"k": {"n": 1}}, now=NOW, max_versions=None)
    full = {
        "format": FORMAT,
        "format_version": FORMAT_VERSION,
        "paths": {
            path: [
                {"version": one.number, "created_at": "2026-11-09T10:00:00Z", "data": one.data}
                for one in versions
            ]
            for path, versions in document.paths.items()
        },
    }

    expected = json.dumps(
        full, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    assert dumps(document) == expected.encode("utf-8")


def test_the_damage_hint_says_what_to_check_before_restoring() -> None:
    """A store that is fine, at another path or read under a lower limit,
    would lose the passwords written since a backup if it were restored."""
    with pytest.raises(DocumentError) as caught:
        loads(b"{not json")

    hint = caught.value.hint or ""
    assert hint.startswith("first check that the store's `addr` names this store's file")
    assert "PYTHONINTMAXSTRDIGITS" in hint
    assert hint.index("first check") < hint.index("restore it from a backup")


def test_an_unknown_path_reads_as_nothing() -> None:
    assert EMPTY.latest(PATH) is None
    assert EMPTY.version(PATH, 1) is None
    assert EMPTY.current(PATH) == 0


# -------------------------------------------------------------- round trip ---


def test_a_document_reads_back_as_it_was_written() -> None:
    document = written(EMPTY, {"current": PASSWORD}, {"current": "x", "pending": "y"})

    assert loads(dumps(document)) == document


def test_the_same_document_is_the_same_bytes_whatever_the_key_order() -> None:
    first = written(EMPTY, {"b": 1, "a": 2})
    second = written(EMPTY, {"a": 2, "b": 1})

    assert dumps(first) == dumps(second)


def test_the_written_document_says_what_it_is() -> None:
    written_body = body(written(EMPTY, {"v": 1}))

    assert written_body["format"] == FORMAT
    assert written_body["format_version"] == FORMAT_VERSION
    assert first_version(written_body)["created_at"] == "2026-11-09T10:00:00Z"


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
        (b"[" * 100_000 + b"]" * 100_000, "nests too deeply to read"),
    ],
    ids=["not-utf8", "not-json", "a-list", "other-format", "deep"],
)
def test_bytes_that_are_not_a_store_document_are_refused(raw: bytes, problem: str) -> None:
    with pytest.raises(DocumentError) as caught:
        loads(raw)

    assert problem in str(caught.value)


def test_a_newer_format_says_to_upgrade_not_to_restore() -> None:
    """Restoring an older file would drop every password written since, while
    the databases hold them."""
    with pytest.raises(DocumentError) as caught:
        loads(damaged_with(lambda b: b.update(format_version=2)))

    assert "a newer build wrote it" in str(caught.value)
    assert caught.value.hint is not None
    assert "upgrade" in caught.value.hint
    assert "do not restore" in caught.value.hint


@pytest.mark.parametrize(
    ("change", "problem"),
    [
        (lambda b: b.update(format_version=0), "format_version is not 1"),
        (lambda b: b.update(format_version=True), "format_version is not 1"),
        (lambda b: b.update(format_version=1.0), "format_version is not 1"),
        (lambda b: b.update(extra=True), "1 unknown"),
        (lambda b: b["paths"].update({PATH: []}), "non-empty list of versions"),
        (lambda b: b["paths"].update({PATH: {"versions": []}}), "non-empty list of versions"),
        (lambda b: first_version(b).update(version=0), "above 0"),
        (lambda b: first_version(b).update(version=True), "above 0"),
        (lambda b: first_version(b).update(created_at="soon"), "created_at"),
        (lambda b: first_version(b).update(created_at="2026-11-09"), "created_at"),
        (lambda b: first_version(b).update(created_at="2026-11-09T10:00:00"), "created_at"),
        (lambda b: first_version(b).update(data="x"), "not a plain object"),
        (lambda b: first_version(b).pop("data"), "missing data"),
        # A gap means a version was lost, and the newest kept might not be the
        # newest written. The second of two is renumbered, so the list is 1, 3.
        (lambda b: b["paths"][PATH][1].update(version=3), "not consecutive"),
        (lambda b: b["paths"][PATH].reverse(), "not consecutive"),
    ],
)
def test_a_damaged_document_is_refused_without_quoting_its_data(change: Any, problem: str) -> None:
    with pytest.raises(DocumentError) as caught:
        loads(damaged_with(change))

    assert problem in str(caught.value)
    assert PASSWORD not in str(caught.value)
    assert caught.value.hint is not None
    assert "restore it from a backup" in caught.value.hint


def test_an_unknown_field_is_counted_not_named() -> None:
    """In a damaged file a name may be anything, a password among them."""
    with pytest.raises(DocumentError) as caught:
        loads(damaged_with(lambda b: first_version(b).update({PASSWORD: 1})))

    assert "1 unknown" in str(caught.value)
    assert PASSWORD not in str(caught.value)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"format":"sopuli-file-store","format":"sopuli-file-store"}',
        b'{"format":"sopuli-file-store","format_version":1,"paths":{"a":[],"a":[]}}',
    ],
    ids=["top-level", "path"],
)
def test_a_key_named_twice_is_refused(raw: bytes) -> None:
    """The parser would keep the last and drop the rest without a word."""
    with pytest.raises(DocumentError) as caught:
        loads(raw)

    assert "names one key twice" in str(caught.value)


def test_a_path_name_in_the_file_that_is_not_valid_is_refused_by_position() -> None:
    """It would otherwise load, and the next save would fail outside the
    store's own errors, carrying the whole document."""
    raw = (
        b'{"format":"sopuli-file-store","format_version":1,"paths":{"\\ud800":'
        + json.dumps(body(written(EMPTY, {"v": 1}))["paths"][PATH]).encode()
        + b"}}"
    )

    with pytest.raises(DocumentError) as caught:
        loads(raw)

    assert "the name of path 1 is not valid UTF-8" in str(caught.value)


def test_a_damaged_path_is_named_by_position_not_by_name() -> None:
    """In a damaged file a path name may be anything, a password among them."""
    raw = damaged_with(lambda b: b["paths"].update({PASSWORD: []}))

    with pytest.raises(DocumentError) as caught:
        loads(raw)

    assert "path 2 is not a non-empty list of versions" in str(caught.value)
    assert PASSWORD not in str(caught.value)


@pytest.mark.parametrize("created_at", ["0001-01-01T00:00:00+05:00", "9999-12-31T23:59:59-05:00"])
def test_a_timestamp_at_the_edge_of_the_range_is_damage_not_a_crash(created_at: str) -> None:
    with pytest.raises(DocumentError) as caught:
        loads(damaged_with(lambda b: first_version(b).update(created_at=created_at)))

    assert "no readable `created_at`" in str(caught.value)


def test_data_nested_too_deep_in_the_file_is_refused() -> None:
    nested: Any = "x"
    for _ in range(MAX_DEPTH + 8):
        nested = {"k": nested}

    with pytest.raises(DocumentError) as caught:
        loads(damaged_with(lambda b: first_version(b).update(data=nested)))

    assert "not a plain object" in str(caught.value)


def test_nan_in_the_file_is_refused() -> None:
    raw = damaged_with(lambda b: None).replace(f'"{PASSWORD}"'.encode(), b"NaN")

    with pytest.raises(DocumentError) as caught:
        loads(raw)

    assert "not UTF-8 JSON" in str(caught.value)
