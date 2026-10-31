"""Probe: could 1Password be a sopuli secret store?

Written for #1193. A store is the master record that UC-1 writes to, and
``src/sopuli/store/protocol.py`` says what one must do: a versioned read, a
write with compare-and-set, and the ``pending`` and ``current`` stages with a
promotion between them. 1Password's documentation does not say how its SDK
behaves on the points that decide this, so each check below measures one.

Not a pytest test. A spike, run by hand against a real 1Password account, as
``test/oci_vault_probe.py`` is run against OCI. It needs the ``[onepassword]``
extra and a service account with read and write items on one vault. Set:

    SOPULI_TEST_ONEPASSWORD_TOKEN_FILE   a file holding the service account token
    OP_PROBE_VAULT                       the vault's name (default: sopuli-test)

    python test/onepassword_store_probe.py          # every check
    python test/onepassword_store_probe.py s1 s4    # only the checks named

Every item it creates is titled ``acme-probe-<UTC timestamp>-<n>`` and is
deleted at the end. Field values are placeholders such as ``probe-1``, never a
real credential. The token is never printed.

Results, 2026-10-31, ``onepassword-sdk`` 0.4.2, ``op`` 2.41.1, an account
whose service account limits are those 1Password publishes for the 1Password
and Families plans. S1 to S4 and S7 ran twice with the same results, apart
from the timings. S1's concurrent puts and S6 were added after the first run;
S6's costs ran once.

- **S1** ``Items.put`` is a compare-and-set on the item's ``version``. A put
  whose version is not the item's current one is refused, whether it is
  behind, ahead by 5, or 0. The refusal is a plain ``Exception``: ``invalid
  user input: encountered the following errors: The submitted item is not up
  to date. Refetch the item and retry the request.`` A stale put is refused
  even when it changes only a field the winning put did not touch. Two puts of
  one version sent at once: in each of five attempts one was accepted and the
  other refused with another message, ``data conflict occurred on the server:
  performing a vault operation``. A put that changes nothing is accepted and
  makes a new version (2 to 3).
- **S2** No call reads an older version. ``Items.get`` takes a vault and an
  item id only. A secret reference with ``?version=1`` or ``?revision=1`` is
  refused before any request: ``secret reference has invalid query parameter
  key``.
- **S3** One put changes two fields together under one version: ``current``
  and ``pending`` became ``current`` alone, version 1 to 2. The notes field
  holds JSON and reads back as written. A field id may hold letters, digits,
  ``-``, ``_``, ``.`` and a space; ``acme/alpha`` is refused by the SDK
  before any request.
- **S4** A title is not a key. A second item with an existing title is
  created without complaint, and a reference to that title then fails with
  ``more than one item matched the secret reference query``. A title may hold
  ``/``, but a reference to it cannot be parsed. A title holding ``@`` and
  ``=`` is created, and a reference to it is refused: ``secret references must
  only contain alphanumeric, _, . or - characters``. A title with a space
  resolves. A reference matches a title without regard to case:
  ``acme-probe-upper-…`` resolved the item titled ``ACME-PROBE-UPPER-…``.
- **S6** ``op service-account ratelimit`` shows ``token write`` 100 and
  ``token read`` 1000 an hour, and ``account read_write`` 1000 a day. Five
  of each call cost: ``get`` 5 reads; ``put`` 5 writes and 10 reads (15
  against the daily limit); ``secrets.resolve`` 5 reads; ``items.list``
  nothing.
- **S7** An item id that never existed: ``item couldn't be found``. A deleted
  item, read or put: ``item is not in an active state``. A get in a vault id
  that does not exist: ``vault couldn't be found``; a list of the same vault
  id: ``item couldn't be found``. Every one is a plain ``Exception``. The
  service account sees only the vault it was granted, so a vault it may not
  read looks like one that does not exist.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from onepassword import Client
from onepassword import types as t

STAMP = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
CREATED: list[str] = []
CALLS = 0


def say(text: str) -> None:
    print(text, flush=True)


async def call(what: str, fn: Callable[[], Awaitable[Any]]) -> Any:
    """Run one SDK call, count it, and print how long it took."""
    global CALLS
    CALLS += 1
    started = time.monotonic()
    try:
        result = await fn()
    except Exception as error:  # noqa: BLE001 -- the SDK raises plain Exception
        say(f"    {what}: {type(error).__name__} after {time.monotonic() - started:.2f}s: {error}")
        raise
    say(f"    {what}: ok in {time.monotonic() - started:.2f}s")
    return result


def field(name: str, value: str, *, concealed: bool = True) -> t.ItemField:
    return t.ItemField(
        id=name,
        title=name,
        field_type=t.ItemFieldType.CONCEALED if concealed else t.ItemFieldType.TEXT,
        value=value,
    )


def value_of(item: t.Item, name: str) -> str | None:
    for each in item.fields:
        if each.id == name:
            return each.value
    return None


def set_value(item: t.Item, name: str, value: str) -> None:
    for each in item.fields:
        if each.id == name:
            each.value = value
            return
    item.fields.append(field(name, value))


async def create(
    client: Client, vault_id: str, n: int, fields: list[t.ItemField], title: str | None = None
) -> t.Item:
    item = await call(
        f"create item {n}",
        lambda: client.items.create(
            t.ItemCreateParams(
                category=t.ItemCategory.PASSWORD,
                vault_id=vault_id,
                title=title or f"acme-probe-{STAMP}-{n}",
                fields=fields,
            )
        ),
    )
    CREATED.append(item.id)
    return item


async def outcome(what: str, fn: Callable[[], Awaitable[Any]]) -> Any:
    """Like :func:`call`, but a refusal is a result, not a failure."""
    try:
        return await call(what, fn)
    except Exception as error:  # noqa: BLE001
        return error


def verdict(result: Any) -> str:
    if isinstance(result, Exception):
        return f"REFUSED: {result}"
    version = getattr(result, "version", None)
    return "ACCEPTED" if version is None else f"ACCEPTED, version {version}"


def stages(item: t.Item) -> str:
    current, pending = value_of(item, "current"), value_of(item, "pending")
    return f"version {item.version}: current={current} pending={pending}"


async def s1(client: Client, vault_id: str) -> None:
    """Check-and-set: is a put of a stale item refused?"""
    say("S1 check-and-set")
    item = await create(client, vault_id, 1, [field("current", "probe-1")])
    say(f"    created at version {item.version}")
    first = await call("get (reader A)", lambda: client.items.get(vault_id, item.id))
    second = await call("get (reader B)", lambda: client.items.get(vault_id, item.id))
    say(f"    A and B read version {first.version} and {second.version}")
    set_value(first, "current", "probe-2")
    written = await call("put from A", lambda: client.items.put(first))
    say(f"    A's put returned version {written.version}")
    set_value(second, "current", "probe-3")
    result = await outcome("put from B (stale)", lambda: client.items.put(second))
    if isinstance(result, Exception):
        say(f"    B's stale put REFUSED: {type(result).__name__}: {result}")
    else:
        say(f"    B's stale put ACCEPTED, returned version {result.version}")
    now = await call("get", lambda: client.items.get(vault_id, item.id))
    say(f"    item now version {now.version}, current = {value_of(now, 'current')}")

    say("    a put whose version is ahead of the item's")
    ahead = await call("get", lambda: client.items.get(vault_id, item.id))
    ahead.version = ahead.version + 5
    set_value(ahead, "current", "probe-4")
    result = await outcome("put with version + 5", lambda: client.items.put(ahead))
    say(f"    {verdict(result)}")

    say("    a put with version 0")
    zero = await call("get", lambda: client.items.get(vault_id, item.id))
    zero.version = 0
    set_value(zero, "current", "probe-5")
    result = await outcome("put with version 0", lambda: client.items.put(zero))
    say(f"    {verdict(result)}")

    say("    a put that changes nothing")
    same = await call("get", lambda: client.items.get(vault_id, item.id))
    before = same.version
    result = await outcome("put unchanged", lambda: client.items.put(same))
    if not isinstance(result, Exception):
        say(f"    version {before} -> {result.version}")

    say("    a stale put that changes only a field the winner did not touch")
    base = await call("get (C)", lambda: client.items.get(vault_id, item.id))
    other = await call("get (D)", lambda: client.items.get(vault_id, item.id))
    set_value(base, "current", "probe-6")
    await call("put from C (current)", lambda: client.items.put(base))
    set_value(other, "pending", "probe-7")
    result = await outcome("put from D (pending only, stale)", lambda: client.items.put(other))
    say(f"    {verdict(result)}")

    say("    two puts of one version sent at once, five times")
    for attempt in range(1, 6):
        left = await call("get (E)", lambda: client.items.get(vault_id, item.id))
        right = await call("get (F)", lambda: client.items.get(vault_id, item.id))
        set_value(left, "current", f"probe-e{attempt}")
        set_value(right, "current", f"probe-f{attempt}")
        results = await asyncio.gather(
            outcome("put E", lambda left=left: client.items.put(left)),
            outcome("put F", lambda right=right: client.items.put(right)),
        )
        won = [isinstance(r, Exception) for r in results].count(False)
        say(f"    attempt {attempt}: {won} of 2 accepted")


async def s2(client: Client, vault_id: str) -> None:
    """Older versions: can anything read an earlier version of an item?"""
    say("S2 older versions")
    item = await create(client, vault_id, 2, [field("current", "probe-1")])
    item = await call("get", lambda: client.items.get(vault_id, item.id))
    set_value(item, "current", "probe-2")
    item = await call("put", lambda: client.items.put(item))
    say(f"    item at version {item.version}")
    import inspect

    for name in ("get", "get_all", "list"):
        say(f"    Items.{name}{inspect.signature(getattr(client.items, name))}")
    say(f"    Secrets.resolve{inspect.signature(client.secrets.resolve)}")
    vault = (await call("get vault overview", lambda: client.vaults.get_overview(vault_id))).title
    for query in ("", "?version=1", "?revision=1"):
        ref = f"op://{vault}/{item.id}/current{query}"
        result = await outcome(f"resolve {ref}", lambda ref=ref: client.secrets.resolve(ref))
        say(f"    {ref} -> {'error: ' + str(result) if isinstance(result, Exception) else result}")


async def s3(client: Client, vault_id: str) -> None:
    """Stages: does one put change two fields together, under one version?"""
    say("S3 stages in one item")
    item = await create(
        client, vault_id, 3, [field("current", "probe-1"), field("pending", "probe-2")]
    )
    item = await call("get", lambda: client.items.get(vault_id, item.id))
    say(f"    {stages(item)}")
    set_value(item, "current", "probe-2")
    item.fields = [each for each in item.fields if each.id != "pending"]
    item = await call(
        "put (promote: current := pending, drop pending)", lambda: client.items.put(item)
    )
    item = await call("get", lambda: client.items.get(vault_id, item.id))
    say(f"    {stages(item)}")
    say("    a field id holding /")
    set_value(item, "acme/alpha", "probe-3")
    result = await outcome("put", lambda: client.items.put(item))
    say(f"    {verdict(result)}")
    item = await call("get", lambda: client.items.get(vault_id, item.id))
    say("    a field id holding . and the notes holding JSON")
    set_value(item, "acme.alpha", "probe-3")
    item.notes = '{"targets": ["db1.example.com"], "generation": 2}'
    item = await call("put", lambda: client.items.put(item))
    item = await call("get", lambda: client.items.get(vault_id, item.id))
    dotted = value_of(item, "acme.alpha")
    say(f"    version {item.version}: acme.alpha={dotted} notes={item.notes!r}")
    vault = (await call("get vault overview", lambda: client.vaults.get_overview(vault_id))).title
    ref = f"op://{vault}/{item.title}/current"
    result = await outcome(f"resolve {ref}", lambda: client.secrets.resolve(ref))
    say(f"    -> {'error: ' + str(result) if isinstance(result, Exception) else result}")


async def s4(client: Client, vault_id: str) -> None:
    """Paths: are titles unique keys, and what may a title hold?"""
    say("S4 paths")
    title = f"acme-probe-{STAMP}-dup"
    await create(client, vault_id, 41, [field("current", "probe-a")], title=title)
    result = await outcome(
        "create a second item with the same title",
        lambda: create(client, vault_id, 42, [field("current", "probe-b")], title=title),
    )
    say(f"    second title: {verdict(result)}")
    vault = (await call("get vault overview", lambda: client.vaults.get_overview(vault_id))).title
    ref = f"op://{vault}/{title}/current"
    result = await outcome(f"resolve {ref}", lambda: client.secrets.resolve(ref))
    say(f"    -> {'error: ' + str(result) if isinstance(result, Exception) else result}")
    for n, odd in enumerate(
        ("apps/acme/db", "ACME-PROBE-UPPER", "acme probe space", "acme@probe=1"), start=43
    ):
        odd_title = f"{odd}-{STAMP}"
        result = await outcome(
            f"create title {odd_title!r}",
            lambda odd_title=odd_title, n=n: create(
                client, vault_id, n, [field("current", f"probe-{n}")], title=odd_title
            ),
        )
        if isinstance(result, Exception):
            continue
        ref = f"op://{vault}/{odd_title}/current"
        got = await outcome(f"resolve {ref}", lambda ref=ref: client.secrets.resolve(ref))
        say(f"    -> {'error: ' + str(got) if isinstance(got, Exception) else got}")
    say("    is a title match case-sensitive?")
    lower = f"acme-probe-upper-{STAMP}"
    ref = f"op://{vault}/{lower}/current"
    got = await outcome(f"resolve {ref}", lambda: client.secrets.resolve(ref))
    say(f"    -> {'error: ' + str(got) if isinstance(got, Exception) else got}")
    overviews = await call("list items", lambda: client.items.list(vault_id))
    say(f"    the vault lists {len(overviews)} items; a lookup by title is a list then a get")


async def s7(client: Client, vault_id: str) -> None:
    """Errors: not found, a deleted item, a vault the account cannot see."""
    say("S7 errors")
    await outcome("get an item id that never existed", lambda: client.items.get(vault_id, "a" * 26))
    item = await create(client, vault_id, 7, [field("current", "probe-1")])
    stale = await call("get", lambda: client.items.get(vault_id, item.id))
    await call("delete", lambda: client.items.delete(vault_id, item.id))
    CREATED.remove(item.id)
    await outcome("get the deleted item", lambda: client.items.get(vault_id, item.id))
    set_value(stale, "current", "probe-2")
    await outcome("put the deleted item", lambda: client.items.put(stale))
    await outcome(
        "get in a vault id that does not exist", lambda: client.items.get("b" * 26, item.id)
    )
    await outcome("list a vault id that does not exist", lambda: client.items.list("b" * 26))
    vaults = await call("list vaults", lambda: client.vaults.list())
    say(f"    the service account sees {len(vaults)} vault(s): {[v.title for v in vaults]}")


async def s6(client: Client, vault_id: str) -> None:
    """Rate limits: what does the account allow, and what did this run use?

    The SDK has no call for it, so this asks the ``op`` CLI, with the token in
    its environment and not in its arguments.
    """
    say("S6 rate limits")
    say(limits())
    item = await create(client, vault_id, 6, [field("current", "probe-0")])
    before = used()
    for _ in range(5):
        item = await call("get", lambda item=item: client.items.get(vault_id, item.id))
    after_gets = used()
    for n in range(1, 6):
        set_value(item, "current", f"probe-{n}")
        item = await call("put", lambda item=item: client.items.put(item))
    after_puts = used()
    for _ in range(5):
        await call("resolve", lambda: client.secrets.resolve(f"op://{vault_id}/{item.id}/current"))
    after_resolves = used()
    for _ in range(5):
        await call("list", lambda: client.items.list(vault_id))
    after_lists = used()
    for label, start, end in (
        ("5 gets", before, after_gets),
        ("5 puts", after_gets, after_puts),
        ("5 resolves", after_puts, after_resolves),
        ("5 lists", after_resolves, after_lists),
    ):
        spent = {key: end[key] - start[key] for key in start}
        say(f"    {label} used {spent}")


def limits() -> str:
    """``op service-account ratelimit``, with the token in the environment only."""
    token_file = os.environ["SOPULI_TEST_ONEPASSWORD_TOKEN_FILE"]
    env = dict(os.environ, OP_SERVICE_ACCOUNT_TOKEN=Path(token_file).read_text("utf-8").strip())
    done = subprocess.run(
        ["op", "service-account", "ratelimit"], env=env, capture_output=True, text=True
    )
    return done.stdout.rstrip() or done.stderr.rstrip()


def used() -> dict[str, int]:
    """The USED column of :func:`limits`, keyed by type and action."""
    counts = {}
    for line in limits().splitlines()[1:]:
        kind, action, _limit, spent = line.split()[:4]
        counts[f"{kind} {action}"] = int(spent)
    return counts


CHECKS = {"s1": s1, "s2": s2, "s3": s3, "s4": s4, "s7": s7, "s6": s6}


async def main(names: list[str]) -> int:
    token_file = os.environ.get("SOPULI_TEST_ONEPASSWORD_TOKEN_FILE")
    if not token_file:
        say("set SOPULI_TEST_ONEPASSWORD_TOKEN_FILE")
        return 2
    token = Path(token_file).read_text(encoding="utf-8").strip()
    client = await Client.authenticate(
        auth=token, integration_name="sopuli-dba store probe", integration_version="v1"
    )
    del token
    vault_name = os.environ.get("OP_PROBE_VAULT", "sopuli-test")
    vaults = await client.vaults.list()
    vault_id = next(v.id for v in vaults if v.title == vault_name)
    failed = 0
    try:
        for name in names or list(CHECKS):
            try:
                await CHECKS[name](client, vault_id)
            except Exception as error:  # noqa: BLE001
                failed += 1
                say(f"  {name} stopped: {type(error).__name__}: {error}")
    finally:
        for item_id in CREATED:
            await outcome(
                f"delete {item_id}", lambda item_id=item_id: client.items.delete(vault_id, item_id)
            )
        say(f"SDK calls made: {CALLS}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main([a.lower() for a in sys.argv[1:]])))
