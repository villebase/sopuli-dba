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
from dataclasses import dataclass, field
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

#: The highest ``format_version`` the reader takes to be a newer build's. Any
#: higher is damage, not a release that could exist.
NEWEST_PLAUSIBLE = 99

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
#: same in every process, whatever limit that process runs with. A process
#: running Python's default limit can read any file the store writes; one run
#: with a lower limit may not.
MAX_INT_BITS = 14_000

#: What a write refusal says: the store writes what the tool built, so a value
#: it cannot hold is the tool's fault.
TOOL_FAULT = "this is a fault in the tool; report it with the command that ran"

#: What every refusal of a file this build cannot read says to do. Restoring
#: is the last step, not the first: a store that is fine but was not the file
#: meant, or a process that reads it under other limits, would lose every
#: password written since the backup.
RESTORE = (
    "first check that the store's `addr` names this store's file, and that this "
    "process runs with Python's default limits (no lower PYTHONINTMAXSTRDIGITS). "
    "If both hold, the file was damaged or edited by hand: restore it from a "
    "backup, check that what it holds still matches the databases, and check any "
    "`@version=N` pin, because version numbers written since the backup will be "
    "used again"
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

    **The text holds passwords in clear**, so it is left out of ``repr``: a
    failed assertion, a traceback that shows locals, or a log line that
    formats a document prints numbers and times, never data (invariant 2).

    **This class is the one check of a version.** :meth:`Document.written`
    and :func:`loads` both build versions through it, so the writer and the
    reader cannot drift apart. Each refusal is a ``ValueError`` whose message
    names the problem and no data; the two callers turn it into their own
    error.
    """

    number: int
    created_at: datetime
    text: str = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.number) is not int or self.number < 1:
            raise ValueError("a version number that is not a whole number above 0")
        if self.created_at.tzinfo is None:
            raise ValueError("a time with no zone")
        try:
            to_rfc3339(self.created_at)
        except OverflowError:
            raise ValueError("a time outside the UTC range") from None
        problem = _text_problem(self.text)
        if problem is not None:
            raise ValueError(problem)

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
    and has at least one version, numbered consecutively, and each
    :class:`Version` checks its own fields.
    """

    paths: Mapping[str, tuple[Version, ...]]

    def __post_init__(self) -> None:
        # Copied into an immutable mapping of tuples first, so a caller that
        # keeps the dict or lists it passed cannot change them after the check.
        frozen = MappingProxyType({path: tuple(versions) for path, versions in self.paths.items()})
        for path, versions in frozen.items():
            if _path_problem(path) is not None or not versions:
                raise ValueError("a document path must be valid text with versions")
            if not all(isinstance(one, Version) for one in versions):
                raise ValueError("a document path's versions must be Version objects")
            if not _consecutive(versions):
                raise ValueError("a document path's version numbers must be consecutive")
        object.__setattr__(self, "paths", frozen)

    def current(self, path: str) -> int:
        """The newest version number ``path`` has, or 0 where it has none."""
        newest = self.latest(path)
        return 0 if newest is None else newest.number

    def latest(self, path: str) -> Version | None:
        versions = self.paths.get(path, ())
        return versions[-1] if versions else None

    def version(self, path: str, number: int) -> Version | None:
        """Version ``number`` of ``path``, or ``None`` where it is not kept.

        ``number`` must be an ``int``: ``True`` and ``1.0`` equal 1 in Python
        and are refused rather than read as a pin.
        """
        if type(number) is not int:
            raise TypeError("a version number must be an int")
        versions = self.paths.get(path, ())
        # The numbers are consecutive, so the position is the difference.
        index = number - versions[0].number if versions else -1
        return versions[index] if 0 <= index < len(versions) else None

    def written(
        self, path: str, data: Any, *, now: datetime, max_versions: int | None
    ) -> tuple[Document, int]:
        """This document with ``data`` as the next version of ``path``, and its number.

        The oldest versions beyond ``max_versions`` are dropped from **every**
        path, not only this one, so lowering the setting takes the old
        passwords out of the file at the next write. ``path`` must
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
        problem = _path_problem(path)
        if problem is not None:
            raise StoreError(f"a path cannot be stored: it is {problem}", hint=TOOL_FAULT)
        if not isinstance(data, dict):
            raise StoreError(
                f"the data for {path!r} cannot be stored: it is not a JSON object",
                hint=TOOL_FAULT,
            )
        # Walked here as well as in Version, because this walk sees the
        # caller's own objects: a key that is not text, a set or a subclass is
        # visible only before JSON has converted it.
        problem = _not_plain(data, depth=0)
        if problem is not None:
            # The value is not repeated: it may be a password.
            raise StoreError(
                f"the data for {path!r} cannot be stored: it holds {problem}", hint=TOOL_FAULT
            )
        try:
            text = _json(data)
        except ValueError:
            # The one way past the walk: a process run with a lower limit on
            # turning integers into text than Python's default.
            raise StoreError(
                f"the data for {path!r} cannot be stored: this process cannot write one of "
                "its numbers as text",
                hint="run with Python's default limits (unset PYTHONINTMAXSTRDIGITS)",
            ) from None
        number = self.current(path) + 1
        # A time with no zone or outside the UTC range is the caller's error,
        # and Version's ValueError says which.
        created = Version(number=number, created_at=now, text=text)
        paths = {name: versions[-keep:] for name, versions in self.paths.items()}
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
        # str's own encode, as int's own bit_length above: a subclass cannot
        # change the answer.
        try:
            str.encode(value, "utf-8")
        except UnicodeEncodeError:
            return "text that is not valid UTF-8"
        return None
    # Exact types for containers: the JSON encoder reads a list's or a dict's
    # storage directly, so a subclass that iterates differently could hide a
    # value from this walk, and a namedtuple would lose its field names.
    if type(value) is list or type(value) is tuple:
        for item in value:
            found = _not_plain(item, depth=depth + 1)
            if found is not None:
                return found
        return None
    if type(value) is dict:
        for key, item in value.items():
            if not isinstance(key, str):
                return "a key that is not text"
            found = _not_plain(key, depth=depth + 1) or _not_plain(item, depth=depth + 1)
            if found is not None:
                return found
        return None
    return f"a value of type {type(value).__name__}"


def _text_problem(text: Any) -> str | None:
    """What makes ``text`` unusable as a version's data, or ``None``. Names no data.

    It must be the canonical JSON of a plain object, exactly as :func:`_json`
    writes it: so no key named twice, no ``NaN``, nothing nested too deep, and
    no other spacing or key order, any of which :func:`dumps` would copy into
    the file as it is.
    """
    if type(text) is not str:
        return "data that is not text"
    try:
        parsed = json.loads(text, object_pairs_hook=_unique, parse_constant=_reject_constant)
    except _DuplicateKeyError:
        return "an object that names one key twice"
    except RecursionError:
        return "data nested too deeply to read"
    except ValueError:
        return "data that is not JSON this build can read"
    if type(parsed) is not dict:
        return "data that is not an object"
    problem = _not_plain(parsed, depth=0)
    if problem is not None:
        return problem
    try:
        canonical = _json(parsed)
    except ValueError:
        return "data that is not JSON this build can write"
    if canonical != text:
        return "data that is not in the store's canonical form"
    return None


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
        str.encode(path, "utf-8")
    except UnicodeEncodeError:
        return "not valid UTF-8"
    return None


def dumps(document: Document) -> bytes:
    """The document as UTF-8 JSON, keys sorted.

    The same document is always the same bytes. Two documents that compare
    equal need not be: ``1`` and ``1.0`` are equal in Python and written apart.

    Each version's data is already held as :func:`_json`'s text, so it is
    placed in the output as it is rather than parsed and written again. The
    rest is written in :func:`_json`'s form by hand: keys in sorted order
    (``created_at``, ``data``, ``version``; paths sorted), no spaces. A test
    holds this equal to :func:`_json` of the whole body.
    """
    paths = ",".join(
        _json(path) + ":[" + ",".join(_version_json(one) for one in document.paths[path]) + "]"
        for path in sorted(document.paths)
    )
    head = _json(FORMAT)
    text = f'{{"format":{head},"format_version":{FORMAT_VERSION},"paths":{{{paths}}}}}'
    return text.encode("utf-8")


def _version_json(version: Version) -> str:
    created_at = _json(to_rfc3339(version.created_at))
    return f'{{"created_at":{created_at},"data":{version.text},"version":{version.number}}}'


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
    except ValueError:  # UnicodeDecodeError is one too
        # ValueError also covers an integer longer than Python will read.
        raise DocumentError("it is not UTF-8 JSON this build can read") from None
    if not isinstance(body, dict) or body.get("format") != FORMAT:
        raise DocumentError(f"it is not a {FORMAT} document")
    format_version = body.get("format_version")
    # `type() is int`, so `true` and `1.0`, which equal 1 in Python, are refused.
    # Only a plausible next version reads as a newer build's: a huge number in
    # a damaged header is damage, and quoting it would print the whole thing.
    if type(format_version) is int and FORMAT_VERSION < format_version <= NEWEST_PLAUSIBLE:
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
    if type(data) is not dict:
        raise DocumentError(f"version {number} of {where} has `data` that is not a plain object")
    try:
        # Version is the one check of a version, so the reader accepts exactly
        # what the writer can build.
        return Version(number=number, created_at=moment, text=_json(data))
    except ValueError as problem:
        # Version's messages name the problem and no data. _json's own
        # ValueError, from a lower integer limit, says nothing either.
        raise DocumentError(
            f"version {number} of {where} has `data` that is not a plain object ({problem})"
        ) from None


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
