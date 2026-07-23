"""Shared public contracts for certificate lifecycle services."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from acme_api.models.certificate import Certificate
from acme_api.webhooks import WebhookDispatcher


class CertificateLifecycleError(Exception):
    """Base exception for lifecycle service errors."""


class CertificateConflictError(CertificateLifecycleError):
    """Raised when a request identity conflicts with an existing certificate."""


class CertificateBackendUnavailableError(CertificateLifecycleError):
    """Raised when a transient backend failure prevents request creation."""


class CertificateNotFoundError(CertificateLifecycleError):
    """Raised when a requested certificate does not exist."""


class CertificateNotRenewableError(CertificateLifecycleError):
    """Raised when a certificate is not eligible for renewal."""


class RenewalSchedulerProtocol(Protocol):
    """Scheduler operations used by certificate lifecycle services."""

    def schedule_certificate(self, certificate: Certificate) -> object | None:
        """Schedule future renewal for a certificate."""

    def remove_certificate(self, certificate_id: uuid.UUID) -> None:
        """Remove queued renewal jobs for a certificate."""


WebhookDispatcherFactory = Callable[[AsyncSession], WebhookDispatcher]
