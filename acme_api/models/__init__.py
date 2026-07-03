"""SQLAlchemy model registry for the ACME API data layer.

Public API — import everything you need from this single entry point::

    from acme_api.models import (
        Base,
        TimestampMixin,
        Certificate,
        CertificateStatus,
        Event,
        RenewalAttempt,
        WebhookConfig,
    )
"""

from __future__ import annotations

from acme_api.models.api_key import APIKey, APIKeyRole
from acme_api.models.base import Base, TimestampMixin
from acme_api.models.certificate import Certificate, CertificateStatus
from acme_api.models.event import Event
from acme_api.models.renewal_attempt import RenewalAttempt
from acme_api.models.webhook import WebhookConfig

__all__ = [
    "APIKey",
    "APIKeyRole",
    "Base",
    "Certificate",
    "CertificateStatus",
    "Event",
    "RenewalAttempt",
    "TimestampMixin",
    "WebhookConfig",
]
