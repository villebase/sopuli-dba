"""What a ``file`` store holds, as the bytes that get encrypted (#1415).

Pure: no I/O and no encryption. The store encrypts what :func:`dumps` returns
with age, and decrypts what :func:`loads` reads. `00-principles.md` P2, *The
file store's file*, specifies the format; this module is its one reader and
writer.

One document per store, holding every path and up to ``max_versions`` versions
of each, oldest first. Pruning drops only the oldest, so the kept numbers are
consecutive and the newest kept is the path's current version. A number is
never reused: the next write is the newest plus one, so a compare-and-set token
that named a pruned version still fails, as on KV v2.

**Every error here names no data.** The data holds passwords in clear, so a
message that quoted a malformed value could print one. The errors say what
was wrong and where, never what was there.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from dataclasses import dataclass, replace
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

#: How deep a version's data may nest. A credential payload is two or three
#: levels deep; the limit keeps a damaged or hostile value from exhausting the
#: interpreter's stack in the copy or the parser.
MAX_DEPTH = 32

#: What every refusal of a damaged file says to do.
RESTORE = (
    "the file was damaged, or edited by hand; restore it from a backup, and check "
    "that what it holds still matches the databases"
)


class DocumentError(StoreError):
    """The store's file decrypted, and what it holds is not a store document."""

    def __init__(self, problem: str, *, hint: str = RESTORE) -> None:
        super().__init__(f"the file store's document is not readable: {problem}", hint=hint)


@dataclass(frozen=True)
class Version:
    """One kept version of a path. ``data`` is always a JSON object."""

    number: int
    created_at: datetime
    data: dict[str, Any]


@dataclass(frozen=True)
class Document:
    """Every path in the store, each with its kept versions, oldest first.

    A read returns a copy of the version's data, so a caller that changes what
    it read changes neither this document nor any document it was made from.
    """

    paths: Mapping[str, tuple[Version, ...]]

    def current(self, path: str) -> int:
        """The newest version number ``path`` has, or 0 where it has none."""
        versions = self.paths.get(path, ())
        return versions[-1].number if versions else 0

    def latest(self, path: str) -> Version | None:
        versions = self.paths.get(path, ())
        return _copied(versions[-1]) if versions else None

    def version(self, path: str, number: int) -> Version | None:
        found = next((one for one in self.paths.get(path, ()) if one.number == number), None)
        return None if found is None else _copied(found)

    def written(
        self, path: str, data: Any, *, now: datetime, max_versions: int | None
    ) -> tuple[Document, int]:
        """This document with ``data`` as the next version of ``path``, and its number.

        The oldest versions beyond ``max_versions`` are dropped. ``data`` must
        be a JSON object of plain values: string keys, strings that are valid
        UTF-8, finite numbers, booleans, ``None``, lists and objects. A tuple is
        stored as a list, as JSON has no other sequence. Anything else is
        refused here rather than changed or failed on when the file is written.
        ``now`` must carry its zone, so the time in memory is the time on disk.
        """
        keep = DEFAULT_MAX_VERSIONS if max_versions is None else max_versions
        if keep < 1:
            raise ValueError("max_versions must be at least 1")
        if now.tzinfo is None:
            raise ValueError("now must carry its zone")
        if not isinstance(data, dict):
            raise StoreError(
                f"the data for {path!r} cannot be stored: it is not a JSON object",
                hint="this is a fault in the tool; report it with the command that ran",
            )
        problem = _not_plain(data, depth=0)
        if problem is not None:
            # The value is not repeated: it may be a password.
            raise StoreError(
                f"the data for {path!r} cannot be stored: it holds {problem}",
                hint="this is a fault in the tool; report it with the command that ran",
            )
        number = self.current(path) + 1
        created = Version(number=number, created_at=now, data=_copy(data))
        paths = dict(self.paths)
        paths[path] = (*self.paths.get(path, ()), created)[-keep:]
        return Document(MappingProxyType(paths)), number


EMPTY = Document(MappingProxyType({}))


def _not_plain(value: Any, *, depth: int) -> str | None:
    """What in ``value`` JSON would not hold as it is, or ``None``. Names no value."""
    if depth > MAX_DEPTH:
        return f"values nested more than {MAX_DEPTH} levels deep"
    if value is None or isinstance(value, bool | int):
        return None
    if isinstance(value, float):
        return None if math.isfinite(value) else "a number that is not finite"
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            return "text that is not valid UTF-8"
        return None
    if isinstance(value, list | tuple):
        for item in value:
            found = _not_plain(item, depth=depth + 1)
            if found is not None:
                return found
        return None
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                return "a key that is not text"
            found = _not_plain(key, depth=depth + 1) or _not_plain(item, depth=depth + 1)
            if found is not None:
                return found
        return None
    return f"a value of type {type(value).__name__}"


def _json(value: Any) -> str:
    """The one JSON form the store writes: sorted, compact, UTF-8, no ``NaN``."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def _copy(data: dict[str, Any]) -> dict[str, Any]:
    """``data`` through the file's own JSON, the one copy for reads and writes."""
    copied: dict[str, Any] = json.loads(_json(data))
    return copied


def _copied(version: Version) -> Version:
    return replace(version, data=_copy(version.data))


def dumps(document: Document) -> bytes:
    """The document as UTF-8 JSON, keys sorted.

    The same document is always the same bytes. Two documents that compare
    equal need not be: ``1`` and ``1.0`` are equal in Python and written apart.
    """
    body = {
        "format": FORMAT,
        "format_version": FORMAT_VERSION,
        "paths": {
            path: [
                {"version": one.number, "created_at": to_rfc3339(one.created_at), "data": one.data}
                for one in versions
            ]
            for path, versions in document.paths.items()
        },
    }
    return _json(body).encode("utf-8")


class _DuplicateKeyError(ValueError):
    """A JSON object names one key twice. Raised inside the parser."""


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """``json``'s ``object_pairs_hook``: refuse a key named twice.

    The parser would keep the last and drop the rest silently, and a path
    named twice in a damaged file would lose its other entry on the next write.
    """
    found: dict[str, Any] = {}
    for key, value in pairs:
        if key in found:
            raise _DuplicateKeyError
        found[key] = value
    return found


def _reject_constant(name: str) -> Any:
    """``json``'s ``parse_constant``: ``NaN`` and ``Infinity`` are not JSON."""
    raise ValueError(name)


def loads(raw: bytes) -> Document:
    """The document in ``raw``, or :class:`DocumentError` saying what is wrong.

    Strict: an unknown format, a missing or extra field, a key named twice,
    data that is not an object or nests too deep, a timestamp in another form
    than :func:`dumps` writes, or version numbers that are not consecutive is
    refused. A store document is written only by this module, so anything else
    in it is damage, and reading past damage is how a rotation writes a
    password where nothing reads it.

    A newer ``format_version`` is not damage: a newer build wrote it. Its hint
    says to upgrade, because restoring an older file would drop every password
    written since, while the databases hold them.
    """
    try:
        body = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_reject_constant
        )
    except _DuplicateKeyError:
        raise DocumentError("an object in it names one key twice") from None
    except RecursionError:
        raise DocumentError(f"it nests more than {MAX_DEPTH} levels deep") from None
    except (UnicodeDecodeError, ValueError):
        raise DocumentError("it is not UTF-8 JSON") from None
    if not isinstance(body, dict) or body.get("format") != FORMAT:
        raise DocumentError(f"it is not a {FORMAT} document")
    format_version = body.get("format_version")
    # `type() is int`, so `true` and `1.0`, which equal 1 in Python, are refused.
    if type(format_version) is int and format_version > FORMAT_VERSION:
        raise DocumentError(
            f"a newer build wrote it, in format_version {format_version}",
            hint=(
                "upgrade sopuli-dba on this machine to the release that wrote it; do not "
                "restore an older file, which would lose the passwords written since"
            ),
        )
    if type(format_version) is not int or format_version != FORMAT_VERSION:
        raise DocumentError(f"its format_version is not {FORMAT_VERSION}")
    _exact_keys(body, {"format", "format_version", "paths"}, where="the document")
    paths = body["paths"]
    if not isinstance(paths, dict):
        raise DocumentError("`paths` is not a mapping")
    return Document(
        MappingProxyType({path: _versions(path, versions) for path, versions in paths.items()})
    )


def _versions(path: str, raw: Any) -> tuple[Version, ...]:
    where = f"path {path!r}"
    if not isinstance(raw, list) or not raw:
        raise DocumentError(f"{where} is not a non-empty list of versions")
    versions = tuple(_version(where, one) for one in raw)
    first = versions[0].number
    if [one.number for one in versions] != list(range(first, first + len(versions))):
        # Pruning drops only the oldest, so a gap means a version was lost,
        # and the newest kept might not be the newest written.
        raise DocumentError(f"{where} has version numbers that are not consecutive")
    return versions


def _version(where: str, raw: Any) -> Version:
    if not isinstance(raw, dict):
        raise DocumentError(f"{where} has a version that is not a mapping")
    _exact_keys(raw, {"version", "created_at", "data"}, where=f"a version of {where}")
    number = raw["version"]
    if type(number) is not int or number < 1:
        raise DocumentError(f"{where} has a version number that is not a whole number above 0")
    created_at = raw["created_at"]
    try:
        moment = from_rfc3339(created_at) if isinstance(created_at, str) else None
    except ValueError:
        moment = None
    # Only the form `dumps` writes: from_rfc3339 also reads a bare date or a
    # time with no offset, and neither came from this module.
    if moment is None or to_rfc3339(moment) != created_at:
        raise DocumentError(f"version {number} of {where} has no readable `created_at`")
    data = raw["data"]
    if not isinstance(data, dict) or _not_plain(data, depth=0) is not None:
        raise DocumentError(f"version {number} of {where} has `data` that is not a plain object")
    return Version(number=number, created_at=moment, data=data)


def _exact_keys(raw: dict[str, Any], expected: set[str], *, where: str) -> None:
    missing = sorted(expected - set(raw))
    unknown = sorted(set(raw) - expected)
    if not missing and not unknown:
        return
    parts = []
    if missing:
        parts.append(f"missing {', '.join(missing)}")
    if unknown:
        # Counted, not named: in a damaged file a name may be anything.
        parts.append(f"{len(unknown)} unknown")
    raise DocumentError(f"{where} has the wrong fields ({'; '.join(parts)})")
