"""What a ``file`` store holds, as the bytes that get encrypted (#1415).

Pure: no I/O and no encryption. The store encrypts what :func:`dumps` returns
with age, and decrypts what :func:`loads` reads. `00-principles.md` P2, *The
file store's file*, specifies the format; this module is its one reader and
writer.

One document per store, holding every path and up to ``max_versions`` versions
of each, oldest first. Pruning drops only the oldest, so the kept numbers are
consecutive and the newest kept is the path's current version. A number is
never reused: the next write is the newest plus one, so a version number names
one write for good. The store has no compare-and-set (#1415).

**Every error here names no data.** The data holds passwords in clear, so a
message that quoted a malformed value could print one. The errors say what
was wrong and where, never what was there. A path the tool asked to write is
named, as every store names the paths it writes; a name read from a damaged
file is not, because it may be anything.
"""

from __future__ import annotations

import json
import math
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

#: How deep a version's data may nest. A credential payload is two or three
#: levels deep. Checked on the write and on each version the reader parses;
#: the parser itself stops at the interpreter's recursion limit, which
#: :func:`loads` reports as damage too.
MAX_DEPTH = 32

#: The widest integer the store writes, in bits: about 4,200 decimal digits,
#: under Python's default limit of 4,300 on converting between an integer and
#: text (``sys.get_int_max_str_digits``). Measured in bits so the check is the
#: same in every process, whatever limit that process runs with, and a file
#: one process writes is never too wide for another to read.
MAX_INT_BITS = 14_000

#: What a write refusal says: the store writes what the tool built, so a value
#: it cannot hold is the tool's fault.
TOOL_FAULT = "this is a fault in the tool; report it with the command that ran"

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
    """One kept version of a path.

    The data is held as its canonical JSON text, and :attr:`data` parses a new
    copy on every read. So no caller, through :meth:`Document.latest` or
    through :attr:`Document.paths`, can change a kept version in place.
    """

    number: int
    created_at: datetime
    text: str

    @property
    def data(self) -> dict[str, Any]:
        """A fresh copy of the version's data, always a JSON object."""
        parsed: dict[str, Any] = json.loads(self.text)
        return parsed


@dataclass(frozen=True)
class Document:
    """Every path in the store, each with its kept versions, oldest first.

    Built only in the shape :func:`loads` accepts, so :func:`dumps` can never
    write a file this module would then call damaged: each path is valid text
    and has at least one version, numbered consecutively.
    """

    paths: Mapping[str, tuple[Version, ...]]

    def __post_init__(self) -> None:
        for path, versions in self.paths.items():
            if _path_problem(path) is not None or not versions:
                raise ValueError("a document path must be valid text with versions")
            if not _consecutive(versions):
                raise ValueError("a document path's version numbers must be consecutive")

    def current(self, path: str) -> int:
        """The newest version number ``path`` has, or 0 where it has none."""
        versions = self.paths.get(path, ())
        return versions[-1].number if versions else 0

    def latest(self, path: str) -> Version | None:
        versions = self.paths.get(path, ())
        return versions[-1] if versions else None

    def version(self, path: str, number: int) -> Version | None:
        return next((one for one in self.paths.get(path, ()) if one.number == number), None)

    def written(
        self, path: str, data: Any, *, now: datetime, max_versions: int | None
    ) -> tuple[Document, int]:
        """This document with ``data`` as the next version of ``path``, and its number.

        The oldest versions beyond ``max_versions`` are dropped. ``path`` must
        be non-empty text, valid as UTF-8. ``data`` must be a JSON object of
        plain values: text keys, text that is valid UTF-8, finite numbers,
        integers JSON can write, booleans, ``None``, lists and objects. Two
        conversions JSON forces are made: a tuple is stored as a list, and a
        subclass of ``str``, ``int`` or ``float`` as the plain type. Anything
        else is refused here rather than failed on when the file is written.
        ``now`` must carry its zone, so the time in memory is the time on disk.
        """
        keep = DEFAULT_MAX_VERSIONS if max_versions is None else max_versions
        if keep < 1:
            raise ValueError("max_versions must be at least 1")
        if now.tzinfo is None:
            raise ValueError("now must carry its zone")
        try:
            to_rfc3339(now)
        except OverflowError:
            raise ValueError("now is outside the range of a UTC timestamp") from None
        problem = _path_problem(path)
        if problem is not None:
            raise StoreError(f"a path cannot be stored: it is {problem}", hint=TOOL_FAULT)
        if not isinstance(data, dict):
            raise StoreError(
                f"the data for {path!r} cannot be stored: it is not a JSON object",
                hint=TOOL_FAULT,
            )
        problem = _not_plain(data, depth=0)
        if problem is not None:
            # The value is not repeated: it may be a password.
            raise StoreError(
                f"the data for {path!r} cannot be stored: it holds {problem}", hint=TOOL_FAULT
            )
        number = self.current(path) + 1
        created = Version(number=number, created_at=now, text=_json(data))
        paths = dict(self.paths)
        paths[path] = (*self.paths.get(path, ()), created)[-keep:]
        return Document(MappingProxyType(paths)), number


EMPTY = Document(MappingProxyType({}))


def _not_plain(value: Any, *, depth: int) -> str | None:
    """What in ``value`` JSON would not hold as it is, or ``None``. Names no value."""
    if depth > MAX_DEPTH:
        return f"values nested more than {MAX_DEPTH} levels deep"
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        # `bit_length` is int's own, so a subclass cannot change the answer.
        if int.bit_length(value) > MAX_INT_BITS:
            return f"a whole number wider than {MAX_INT_BITS} bits"
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


def _path_problem(path: Any) -> str | None:
    """What makes ``path`` unusable as a path in the file, or ``None``. Names no path."""
    if not isinstance(path, str):
        return "not text"
    if not path:
        return "empty"
    try:
        path.encode("utf-8")
    except UnicodeEncodeError:
        return "not valid UTF-8"
    return None


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
                {
                    "version": one.number,
                    "created_at": to_rfc3339(one.created_at),
                    "data": one.data,
                }
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
        raise DocumentError("it nests too deeply to read") from None
    except (UnicodeDecodeError, ValueError):
        # ValueError also covers an integer longer than Python will read.
        raise DocumentError("it is not UTF-8 JSON this build can read") from None
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
        MappingProxyType(
            {
                path: _versions(position, path, versions)
                for position, (path, versions) in enumerate(paths.items(), start=1)
            }
        )
    )


def _versions(position: int, path: str, raw: Any) -> tuple[Version, ...]:
    # Named by position, not by name: in a damaged file a name may be
    # anything, a password among them.
    where = f"path {position}"
    problem = _path_problem(path)
    if problem is not None:
        raise DocumentError(f"the name of {where} is {problem}")
    if not isinstance(raw, list) or not raw:
        raise DocumentError(f"{where} is not a non-empty list of versions")
    versions = tuple(_version(where, one) for one in raw)
    if not _consecutive(versions):
        # Pruning drops only the oldest, so a gap means a version was lost,
        # and the newest kept might not be the newest written.
        raise DocumentError(f"{where} has version numbers that are not consecutive")
    return versions


def _consecutive(versions: tuple[Version, ...]) -> bool:
    first = versions[0].number
    return [one.number for one in versions] == list(range(first, first + len(versions)))


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
        # Only the form `dumps` writes: from_rfc3339 also reads a bare date or
        # a time with no offset, and neither came from this module. Inside the
        # try, because converting a time at the edge of the range to UTC
        # overflows.
        same = moment is not None and to_rfc3339(moment) == created_at
    except (ValueError, OverflowError):
        same = False
    if not same or moment is None:
        raise DocumentError(f"version {number} of {where} has no readable `created_at`")
    data = raw["data"]
    if not isinstance(data, dict) or _not_plain(data, depth=0) is not None:
        raise DocumentError(f"version {number} of {where} has `data` that is not a plain object")
    return Version(number=number, created_at=moment, text=_json(data))


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
