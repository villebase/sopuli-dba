"""The part of a driver's error map that every driver shares.

Each driver classifies its vendor's failures into a ``Diagnosis`` of its own:
``sopuli.driver.oracle.errors``, ``sopuli.driver.postgres.errors`` and
``sopuli.driver.mysql.errors``. They differ in the fields they read off the
exception and in how the vendor code is written in front of the message. What a
diagnosis becomes when a caller raises it is the same for all of them, and is
here: :meth:`Diagnosis.as_error` and :class:`MappedError`.
"""

from __future__ import annotations

from sopuli.driver.protocol import AuthenticationError, DriverError
from sopuli.exit_codes import ExitCode


class Diagnosis:
    """The base of each driver's ``Diagnosis``: one failure, classified.

    A driver's subclass is a frozen dataclass that supplies the fields below.
    ``code`` is the vendor code as the vendor writes it. ``retryable`` is
    ``None`` unless the driver's map says whether the failure clears by itself.
    """

    code: str
    category: str
    exit_code: ExitCode
    message: str
    hint: str | None
    retryable: bool | None = None

    @property
    def prefix(self) -> str:
        """What is written in front of the message: the code, by default. A
        driver whose client prints more there, such as MySQL's SQLSTATE,
        overrides it."""
        return self.code

    @property
    def coded_message(self) -> str:
        """The message with :attr:`prefix` in front, so that every view that
        prints the message prints the code. A driver whose server writes the
        code into the message itself, as Oracle's does, overrides it."""
        message = self.message.strip()
        return f"{self.prefix}: {message}" if message else self.prefix

    @property
    def regenerate(self) -> bool:
        """Whether the password itself was refused and another should be
        drawn. ``False`` unless the driver's map says so."""
        return False

    def as_error(self) -> DriverError:
        """This diagnosis as something to raise, with :attr:`coded_message` as
        its message. An authentication failure is an
        :class:`~sopuli.driver.protocol.AuthenticationError`, exit 6, so that a
        caller which wants ``except AuthenticationError`` has one. Anything
        else is a :class:`MappedError` with this diagnosis's own category and
        exit code."""
        if self.category == AuthenticationError.category:
            return AuthenticationError(
                self.coded_message, hint=self.hint, code=self.code, retryable=self.retryable
            )
        return MappedError(self)


class MappedError(DriverError):
    """A :class:`Diagnosis` that a caller decided to raise.

    ``category`` and ``exit_code`` are set on the *instance*, shadowing the class
    attributes :class:`~sopuli.driver.protocol.DriverError` declares. The class
    ones are the default for a driver failure nobody classified; these are what
    the code actually means, and the boundary reads the same attribute either
    way.
    """

    def __init__(self, diagnosis: Diagnosis) -> None:
        super().__init__(
            diagnosis.coded_message,
            hint=diagnosis.hint,
            code=diagnosis.code,
            retryable=diagnosis.retryable,
        )
        self.category = diagnosis.category
        self.exit_code = diagnosis.exit_code
        # The one thing above the driver that needs this answer cannot ask a
        # `Diagnosis` for it: `sopuli.apply` is vendor-neutral and does not
        # import a driver's error map. Carried onto the instance, where
        # `DriverError` declares it, so the boundary reads one attribute
        # whoever raised it.
        self.regenerate = diagnosis.regenerate
        self.diagnosis = diagnosis
