"""Schemas for authenticated API-client management."""

from __future__ import annotations

import datetime as dt
import uuid

from pydantic import BaseModel, Field

from acme_api.models.api_key import APIKeyRole


class APIClientCreate(BaseModel):
    """Request to create a persisted API client."""

    name: str = Field(min_length=1, max_length=255)
    role: APIKeyRole


class APIClientRead(BaseModel):
    """Safe persisted API-client metadata."""

    id: uuid.UUID
    name: str
    role: APIKeyRole
    is_active: bool
    expires_at: dt.datetime | None
    created_at: dt.datetime
    updated_at: dt.datetime

    model_config = {"from_attributes": True}


class APIClientCredential(APIClientRead):
    """Creation or rotation response containing a one-time raw credential."""

    credential: str
