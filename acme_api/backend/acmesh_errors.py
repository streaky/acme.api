"""Exception hierarchy for acme.sh backend failures.

Kept in its own module so both the subprocess wrapper and the output-parsing
helpers can raise these without importing each other.
"""

from __future__ import annotations


class AcmeShError(Exception):
    """Base exception for acme.sh errors.

    Subclasses distinguish transient failures (DNS propagation, rate limits) from terminal
    ones (account invalid, misconfiguration). The API layer maps these to HTTP statuses.
    """


class TerminalAcmeShError(AcmeShError):
    """An error that will not resolve by retrying the same operation."""

    def __init__(self, message: str, *, stderr: str = "") -> None:
        super().__init__(message)
        self.stderr = stderr


class TransientAcmeShError(AcmeShError):
    """An error that may resolve on retry (DNS propagation, transient CA outage)."""

    def __init__(self, message: str, *, stderr: str = "") -> None:
        super().__init__(message)
        self.stderr = stderr
