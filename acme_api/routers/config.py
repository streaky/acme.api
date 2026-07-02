"""Read-only routes for config-owned integrations."""

from __future__ import annotations

from typing import cast

from fastapi import APIRouter, Depends, Request

from acme_api.auth.rbac import require_readonly
from acme_api.config import AppSettings
from acme_api.schemas.config_readonly import AcmeAccountRead, DnsProviderRead

router = APIRouter(prefix="/v1", tags=["Configuration"])


def get_settings(request: Request) -> AppSettings:
    """Return application settings from FastAPI state."""
    return cast(AppSettings, request.app.state.settings)


@router.get(
    "/accounts",
    response_model=list[AcmeAccountRead],
    summary="List ACME accounts",
    responses={200: {"description": "Configured ACME account aliases returned."}},
)
async def list_acme_accounts(
    _: object = Depends(require_readonly),
    settings: AppSettings = Depends(get_settings),
) -> list[AcmeAccountRead]:
    """Return configured ACME account aliases."""
    return [
        AcmeAccountRead(name=account.name, server_url=account.server_url)
        for account in settings.acme_accounts
    ]


@router.get(
    "/providers",
    response_model=list[DnsProviderRead],
    summary="List DNS providers",
    responses={200: {"description": "Configured DNS provider aliases returned."}},
)
async def list_dns_providers(
    _: object = Depends(require_readonly),
    settings: AppSettings = Depends(get_settings),
) -> list[DnsProviderRead]:
    """Return configured DNS provider aliases."""
    return [
        DnsProviderRead(name=provider.name, provider_name=provider.provider_name)
        for provider in settings.dns_providers
    ]
