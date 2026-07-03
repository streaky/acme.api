"""Tests for event schemas."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from acme_api.schemas.event import EventRead


def test_event_read_details_default_is_per_instance() -> None:
    """EventRead instances do not share the default details mapping."""
    first = EventRead(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        event_type="certificate.created",
    )
    second = EventRead(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        event_type="certificate.renewed",
    )

    first.details["changed"] = True

    assert second.details == {}
