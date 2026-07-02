"""Webhook payload signing and delivery."""

from __future__ import annotations

import asyncio
import dataclasses as dc
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx2
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from acme_api.models.certificate import Certificate
from acme_api.models.event import Event
from acme_api.models.webhook import WebhookConfig

SIGNATURE_HEADER = "X-Webhook-Signature"
EVENT_HEADER = "X-Webhook-Event"


@dc.dataclass(frozen=True)
class WebhookDeliverySettings:
    """Runtime settings for outbound webhook delivery."""

    timeout_seconds: float = 5.0
    max_retries: int = 3
    backoff_seconds: float = 1.0


@dc.dataclass(frozen=True)
class WebhookPayload:
    """Canonical webhook payload."""

    event: str
    certificate_name: str
    domains: list[str]
    expiry: datetime | None
    certificate_id: uuid.UUID | None = None
    details: dict[str, Any] = dc.field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable payload."""
        expiry = self.expiry
        if expiry and expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return {
            "event": self.event,
            "certificate_id": str(self.certificate_id) if self.certificate_id else None,
            "certificate_name": self.certificate_name,
            "expiry": expiry.astimezone(timezone.utc).isoformat() if expiry else None,
            "domains": self.domains,
            "details": self.details,
        }


class WebhookDeliveryError(Exception):
    """Raised when a webhook delivery exhausts all retry attempts."""


def encode_payload(payload: WebhookPayload) -> bytes:
    """Serialize a webhook payload using stable JSON formatting."""
    return json.dumps(
        payload.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sign_payload(secret: str, payload_body: bytes) -> str:
    """Return the HMAC-SHA256 signature header value for a payload."""
    digest = hmac.new(secret.encode("utf-8"), payload_body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def payload_for_certificate(
    event_type: str,
    certificate: Certificate,
    details: dict[str, Any] | None = None,
) -> WebhookPayload:
    """Build a webhook payload from a certificate row."""
    return WebhookPayload(
        event=event_type,
        certificate_id=certificate.id,
        certificate_name=certificate.name,
        domains=list(certificate.domains),
        expiry=certificate.expiry_date,
        details=details or {},
    )


class WebhookDispatcher:
    """Delivers lifecycle events to configured webhook subscriptions."""

    def __init__(
        self,
        session: AsyncSession,
        settings: WebhookDeliverySettings | None = None,
        client: httpx2.AsyncClient | None = None,
    ) -> None:
        self._session = session
        self._settings = settings or WebhookDeliverySettings()
        self._client = client
        self._owns_client = client is None

    async def __aenter__(self) -> "WebhookDispatcher":
        if self._client is None:
            self._client = httpx2.AsyncClient(timeout=self._settings.timeout_seconds)
        return self

    async def __aexit__(self, *_exc_info: object) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()

    async def dispatch_certificate_event(
        self,
        event_type: str,
        certificate: Certificate,
        details: dict[str, Any] | None = None,
    ) -> int:
        """Deliver a certificate lifecycle event to subscribed webhooks."""
        payload = payload_for_certificate(event_type, certificate, details)
        return await self.dispatch(payload)

    async def dispatch(self, payload: WebhookPayload) -> int:
        """Deliver a payload to all enabled subscribers and return delivery count."""
        configs = await self._matching_configs(payload.event)
        delivered = 0
        for config in configs:
            try:
                await self._deliver_to_config(config, payload)
                delivered += 1
            except WebhookDeliveryError as exc:
                self._session.add(
                    Event(
                        event_type="webhook.delivery_failed",
                        certificate_id=payload.certificate_id,
                        details={
                            "webhook_id": str(config.id),
                            "url": config.url,
                            "event": payload.event,
                            "error": str(exc),
                        },
                    )
                )
        await self._session.commit()
        return delivered

    async def _matching_configs(self, event_type: str) -> list[WebhookConfig]:
        """Return enabled webhook configs subscribed to an event."""
        result = await self._session.execute(
            select(WebhookConfig).where(WebhookConfig.enabled.is_(True))
        )
        return [
            config
            for config in result.scalars().all()
            if "*" in config.events or event_type in config.events
        ]

    async def _deliver_to_config(
        self,
        config: WebhookConfig,
        payload: WebhookPayload,
    ) -> None:
        """Deliver a single webhook subscription with retry."""
        if self._client is None:
            raise RuntimeError("WebhookDispatcher must be used as an async context manager")

        body = encode_payload(payload)
        headers = {
            "Content-Type": "application/json",
            EVENT_HEADER: payload.event,
            SIGNATURE_HEADER: sign_payload(config.secret, body),
        }
        attempts = self._settings.max_retries + 1
        last_error = ""

        for attempt_number in range(1, attempts + 1):
            try:
                response = await self._client.post(config.url, content=body, headers=headers)
                if 200 <= response.status_code < 300:
                    return
                last_error = f"HTTP {response.status_code}"
            except httpx2.HTTPError as exc:
                last_error = str(exc)

            if attempt_number < attempts and self._settings.backoff_seconds > 0:
                await asyncio.sleep(self._settings.backoff_seconds * attempt_number)

        raise WebhookDeliveryError(last_error or "delivery failed")
