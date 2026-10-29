"""How a store says it is waiting, without writing to a stream.

An OCI secret is busy for about 20 seconds after every write, and the store
waits it out (decision 8, #1133). A wait that long with nothing on the screen
looks like a hang, so it runs under the spinner, naming the secret. The store
layer writes to no stream, though, and must not import the output layer: it is
the CLI that knows whether a spinner may be drawn at all.

So the CLI hands a factory in for the length of a verb, with :func:`showing`,
and a store wraps each wait in :func:`waiting`. Outside a verb, in a test or a
library caller, :func:`waiting` does nothing. A ``ContextVar`` rather than a
module global, so :func:`showing` puts back what was there before, and one
verb's spinner never outlives it.

A store calls :func:`waiting` only around a wait inside one of its own calls.
Nothing prompts or prints there, which is what keeps the spinner clear of
:mod:`sopuli.output.spinner`'s rule about never being live across a prompt.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager, nullcontext
from contextvars import ContextVar

Notice = Callable[[str], AbstractContextManager[object]]

_NOTICE: ContextVar[Notice | None] = ContextVar("sopuli_store_notice", default=None)


def waiting(message: str) -> AbstractContextManager[object]:
    """The context a store holds while it waits; ``message`` says for what."""
    notice = _NOTICE.get()
    return nullcontext() if notice is None else notice(message)


@contextmanager
def showing(notice: Notice) -> Iterator[None]:
    """Show every store wait inside the block with ``notice``."""
    token = _NOTICE.set(notice)
    try:
        yield
    finally:
        _NOTICE.reset(token)
