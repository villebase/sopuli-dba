"""What a ``file`` store holds, as the bytes that get encrypted (#1415).

Pure: no I/O and no encryption. The store encrypts what :func:`dumps` returns
with age, and decrypts what :func:`loads` reads.

One document per store, holding every path and up to ``max_versions`` versions
of each. A version's number is never reused: pruning drops the oldest versions
and leaves ``current`` where it was, so a compare-and-set token that named a
pruned version still fails, as on KV v2.

The document is JSON::

    {
      "format": "sopuli-file-store",
      "format_version": 1,
      "paths": {
        "acme/app": {
          "current": 3,
          "versions": [
            {"version": 2, "created_at": "2026-11-09T10:00:00Z", "data": {...}},
            {"version": 3, "created_at": "2026-11-09T11:00:00Z", "data": {...}}
          ]
        }
      }
    }

**Every error here names no data.** The data holds passwords in clear, so a
message that quoted a malformed value could print one. The errors say what
was wrong and where, never what was there.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Any

from sopuli.clock import from_rfc3339, to_rfc3339
from sopuli.store.protocol import StoreError

FORMAT = "sopuli-file-store"

#: The version of the document's shape. A reader refuses a version it does not
#: know rather than guessing, because a guess that drops a field it did not
#: understand would write the store back without it.
FORMAT_VERSION = 1

#: How many versions of a path are kept when the store's ``max_versions`` is not
#: set (#1415).
DEFAULT_MAX_VERSIONS = 10


class DocumentError(StoreError):
    """The store's file decrypted, and what it holds is not a store document."""

    def __init__(self, problem: str) -> None:
        super().__init__(
            f"the file store's document is not readable: {problem}",
            hint=(
                "the file was written by another program or another format version, "
                "or was edited by hand; restore it from a backup"
            ),
        )


@dataclass(frozen=True)
class Version:
    """One kept version of a path."""

    number: int
    created_at: datetime
    data: Any


@dataclass(frozen=True)
class Entry:
    """A path: the newest version number it has had, and the versions kept.

    ``current`` may be higher than the last kept version's number only if the
    store ever drops a newest version, which it does not today. It is kept
    apart from the list because the list is pruned and the counter is not.
    """

    current: int
    versions: tuple[Version, ...]


@dataclass(frozen=True)
class Document:
    """Every path in the store."""

    paths: Mapping[str, Entry]

    def latest(self, path: str) -> Version | None:
        entry = self.paths.get(path)
        if entry is None or not entry.versions:
            return None
        return entry.versions[-1]

    def version(self, path: str, number: int) -> Version | None:
        entry = self.paths.get(path)
        if entry is None:
            return None
        return next((one for one in entry.versions if one.number == number), None)

    def written(
        self, path: str, data: Any, *, now: datetime, max_versions: int | None
    ) -> tuple[Document, int]:
        """This document with ``data`` as the next version of ``path``, and its number.

        The oldest versions beyond ``max_versions`` are dropped. The data is
        copied through JSON, so a caller that changes its own object later
        does not change the document, and a value JSON cannot hold fails here
        rather than when the file is written.
        """
        keep = DEFAULT_MAX_VERSIONS if max_versions is None else max_versions
        if keep < 1:
            raise ValueError("max_versions must be at least 1")
        try:
            copied = json.loads(json.dumps(data))
        except (TypeError, ValueError):
            # The value is not repeated: it may be a password.
            raise StoreError(
                f"the data for {path!r} cannot be stored: it is not plain JSON"
            ) from None
        entry = self.paths.get(path, Entry(current=0, versions=()))
        number = entry.current + 1
        versions = (*entry.versions, Version(number=number, created_at=now, data=copied))
        paths = dict(self.paths)
        paths[path] = Entry(current=number, versions=versions[-keep:])
        return Document(MappingProxyType(paths)), number


EMPTY = Document(MappingProxyType({}))


def dumps(document: Document) -> bytes:
    """The document as UTF-8 JSON, keys sorted, so equal documents are equal bytes."""
    body = {
        "format": FORMAT,
        "format_version": FORMAT_VERSION,
        "paths": {
            path: {
                "current": entry.current,
                "versions": [
                    {
                        "version": one.number,
                        "created_at": to_rfc3339(one.created_at),
                        "data": one.data,
                    }
                    for one in entry.versions
                ],
            }
            for path, entry in document.paths.items()
        },
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def loads(raw: bytes) -> Document:
    """The document in ``raw``, or :class:`DocumentError` saying what is wrong.

    Strict: an unknown format, an unknown version, a missing or extra field, or
    a version list out of order is refused. A store document is written only by
    this module, so anything else in it is damage, and reading past damage is
    how a rotation writes a password where nothing reads it.
    """
    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise DocumentError("it is not UTF-8 JSON") from None
    if not isinstance(body, dict) or body.get("format") != FORMAT:
        raise DocumentError(f"it is not a {FORMAT} document")
    if body.get("format_version") != FORMAT_VERSION:
        raise DocumentError(
            f"its format_version is not {FORMAT_VERSION}, the only one this build reads"
        )
    _exact_keys(body, {"format", "format_version", "paths"}, where="the document")
    paths = body["paths"]
    if not isinstance(paths, dict):
        raise DocumentError("`paths` is not a mapping")
    return Document(MappingProxyType({path: _entry(path, raw) for path, raw in paths.items()}))


def _entry(path: str, raw: Any) -> Entry:
    where = f"path {path!r}"
    if not isinstance(raw, dict):
        raise DocumentError(f"{where} is not a mapping")
    _exact_keys(raw, {"current", "versions"}, where=where)
    current = raw["current"]
    if not _count(current):
        raise DocumentError(f"{where} has a `current` that is not a whole number")
    if not isinstance(raw["versions"], list):
        raise DocumentError(f"{where} has `versions` that is not a list")
    versions = tuple(_version(where, one) for one in raw["versions"])
    numbers = [one.number for one in versions]
    if numbers != sorted(set(numbers)) or (numbers and numbers[-1] > current):
        raise DocumentError(f"{where} has versions out of order, or past `current`")
    return Entry(current=current, versions=versions)


def _version(where: str, raw: Any) -> Version:
    if not isinstance(raw, dict):
        raise DocumentError(f"{where} has a version that is not a mapping")
    _exact_keys(raw, {"version", "created_at", "data"}, where=f"a version of {where}")
    number = raw["version"]
    if not _count(number) or number < 1:
        raise DocumentError(f"{where} has a version number that is not a whole number above 0")
    created_at = raw["created_at"]
    try:
        moment = from_rfc3339(created_at) if isinstance(created_at, str) else None
    except ValueError:
        moment = None
    if moment is None:
        raise DocumentError(f"version {number} of {where} has no readable `created_at`")
    return Version(number=number, created_at=moment, data=raw["data"])


def _exact_keys(raw: dict[str, Any], expected: set[str], *, where: str) -> None:
    if set(raw) != expected:
        missing = sorted(expected - set(raw))
        extra = sorted(set(raw) - expected)
        detail = ", ".join(
            part
            for part in (
                f"missing {', '.join(missing)}" if missing else "",
                f"unknown {', '.join(extra)}" if extra else "",
            )
            if part
        )
        raise DocumentError(f"{where} has the wrong fields ({detail})")


def _count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0
