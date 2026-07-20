"""Tests for Phase 4 Authentication & Authorization."""

from __future__ import annotations

import datetime as _dt
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from acme_api.auth.bootstrap import seed_initial_keys
from acme_api.auth.hash import (
    AuthenticatedUser,
    AuthenticationError,
    api_key_lookup_hash,
    hash_api_key,
    verify_api_key,
)
from acme_api.config import AcmeConfig, AppSettings, DatabaseConfig, DeploymentConfig
from acme_api.db import get_session_factory, init_db, init_engine
from acme_api.main import create_app
from acme_api.models.api_key import APIKey, APIKeyRole


@pytest.fixture
def sample_keys() -> dict[str, str]:
    """Sample raw API keys for testing."""
    return {
        "admin": "admin-key-12345",
        "operator": "operator-key-12345",
        "readonly": "readonly-key-12345",
    }


class TestHashUtility:
    def test_hash_api_key_creates_hash(self, sample_keys: dict[str, str]) -> None:
        """hash_api_key returns a valid PBKDF2 hash."""
        raw = sample_keys["admin"]
        hashed = hash_api_key(raw)

        assert hashed != raw
        assert len(hashed) > 50  # PBKDF2 hashes are long

    def test_verify_correct_password(self, sample_keys: dict[str, str]) -> None:
        """verify_api_key returns True for matching credentials."""
        raw = sample_keys["operator"]
        hashed = hash_api_key(raw)

        assert verify_api_key(raw, hashed) is True

    def test_verify_incorrect_password(self, sample_keys: dict[str, str]) -> None:
        """verify_api_key returns False for wrong password."""
        raw = sample_keys["admin"]
        hashed = hash_api_key(raw)

        assert verify_api_key("wrong-password", hashed) is False

    def test_hash_empty_input_raises(self) -> None:
        """hash_api_key raises ValueError for empty input."""
        with pytest.raises(ValueError, match="must be at least 8 characters"):
            hash_api_key("")

    def test_api_key_lookup_hash_is_deterministic(self) -> None:
        """api_key_lookup_hash returns a stable SHA-256 hex digest."""
        digest = api_key_lookup_hash("admin-key-12345")

        assert digest == api_key_lookup_hash("admin-key-12345")
        assert len(digest) == 64


class TestAuthenticatedUser:
    def test_authenticated_user_creation(self, sample_keys: dict[str, str]) -> None:
        """Can create AuthenticatedUser from APIKey model."""
        raw = sample_keys["admin"]
        hashed = hash_api_key(raw)

        key_obj = APIKey(
            name="test-admin",
            hashed_key=hashed,
            role=APIKeyRole.ADMIN,
            is_active=True,
            expires_at=_dt.datetime.now(_dt.UTC) + _dt.timedelta(days=365),
        )

        user = AuthenticatedUser(
            key_id=key_obj.id,
            role=key_obj.role,
            name=key_obj.name,
            expires_at=key_obj.expires_at,
        )

        assert user.role == APIKeyRole.ADMIN
        assert user.name == "test-admin"


class TestRBACDependencies:
    def test_admin_role_valid(self, sample_keys: dict[str, str]) -> None:
        """Admin role can be validated."""
        raw = sample_keys["admin"]
        hashed = hash_api_key(raw)

        assert verify_api_key(raw, hashed) is True

    def test_operator_role_valid(self, sample_keys: dict[str, str]) -> None:
        """Operator role can be validated."""
        raw = sample_keys["operator"]
        hashed = hash_api_key(raw)

        assert verify_api_key(raw, hashed) is True

    def test_readonly_role_valid(self, sample_keys: dict[str, str]) -> None:
        """Read-only role can be validated."""
        raw = sample_keys["readonly"]
        hashed = hash_api_key(raw)

        assert verify_api_key(raw, hashed) is True


class TestBootstrapKeys:
    @pytest.mark.anyio
    async def test_seed_initial_keys_rejects_unknown_role(self, tmp_path: Path) -> None:
        """Bootstrap config only accepts known API key roles."""
        settings = AppSettings(
            database=DatabaseConfig(url=f"sqlite+aiosqlite:///{tmp_path}/test.db"),
            deployment=DeploymentConfig(directory=tmp_path / "certs"),
            acme=AcmeConfig(home_dir=tmp_path / "acmesh"),
            api_keys={"owner": "owner-key-12345"},
        )
        engine = init_engine(settings)
        try:
            await init_db(engine)
            async with get_session_factory()() as session:
                with pytest.raises(ValueError, match="Invalid bootstrap key role"):
                    await seed_initial_keys(session, settings)
        finally:
            await engine.dispose()

    @pytest.mark.anyio
    async def test_seed_initial_keys_backfills_lookup_hash(self, tmp_path: Path) -> None:
        """Existing bootstrap keys get a lookup hash when raw config is present."""
        settings = AppSettings(
            database=DatabaseConfig(url=f"sqlite+aiosqlite:///{tmp_path}/test.db"),
            deployment=DeploymentConfig(directory=tmp_path / "certs"),
            acme=AcmeConfig(home_dir=tmp_path / "acmesh"),
            api_keys={"readonly": "readonly-key-12345"},
        )
        engine = init_engine(settings)
        try:
            await init_db(engine)
            async with get_session_factory()() as session:
                session.add(
                    APIKey(
                        name="bootstrap-readonly",
                        hashed_key=hash_api_key("readonly-key-12345"),
                        role=APIKeyRole.READONLY,
                        is_active=True,
                    )
                )
                await session.commit()

                created = await seed_initial_keys(session, settings)
                row = await session.scalar(select(APIKey).where(APIKey.name == "bootstrap-readonly"))

            assert created == []
            assert row is not None
            assert row.key_lookup_hash == api_key_lookup_hash("readonly-key-12345")
        finally:
            await engine.dispose()


class TestAuthenticationErrors:
    def test_authentication_error_has_status_code(self) -> None:
        """AuthenticationError includes HTTP status code."""
        err = AuthenticationError("Not authorized")

        assert err.status_code == 401


class TestRBACRoutes:
    def test_route_auth_matrix(self, tmp_path: Path) -> None:
        """Routes return 401/403/2xx according to API key role."""
        settings = AppSettings(
            database=DatabaseConfig(url=f"sqlite+aiosqlite:///{tmp_path}/test.db"),
            deployment=DeploymentConfig(directory=tmp_path / "certs"),
            acme=AcmeConfig(home_dir=tmp_path / "acmesh"),
            api_keys={
                "admin": "admin-key-12345",
                "operator": "operator-key-12345",
                "readonly": "readonly-key-12345",
            },
        )
        app = create_app(settings=settings)

        with TestClient(app) as client:
            assert client.get("/v1/certificates").status_code == 401
            readonly_headers = {"Authorization": "Bearer readonly-key-12345"}
            operator_headers = {"Authorization": "Bearer operator-key-12345"}

            assert client.get("/v1/certificates", headers=readonly_headers).status_code == 200
            assert (
                client.post(
                    "/v1/certificates",
                    headers=readonly_headers,
                    json={
                        "name": "example",
                        "domains": ["example.com"],
                        "acme_account_ref": "le",
                        "dns_provider_ref": "cf",
                    },
                ).status_code
                == 403
            )
            assert (
                client.post(
                    "/v1/certificates",
                    headers=operator_headers,
                    json={
                        "name": "example",
                        "domains": ["example.com"],
                        "acme_account_ref": "le",
                        "dns_provider_ref": "cf",
                    },
                ).status_code
                == 202
            )

    def test_auth_verifies_only_lookup_candidate(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Auth filters by lookup digest before running PBKDF2 verification."""
        settings = AppSettings(
            database=DatabaseConfig(url=f"sqlite+aiosqlite:///{tmp_path}/test.db"),
            deployment=DeploymentConfig(directory=tmp_path / "certs"),
            acme=AcmeConfig(home_dir=tmp_path / "acmesh"),
            api_keys={
                "admin": "admin-key-12345",
                "operator": "operator-key-12345",
                "readonly": "readonly-key-12345",
            },
        )
        app = create_app(settings=settings)
        calls = 0

        def _counting_verify(candidate: str, stored_hash: str) -> bool:
            nonlocal calls
            calls += 1
            return verify_api_key(candidate, stored_hash)

        monkeypatch.setattr("acme_api.auth.rbac.verify_api_key", _counting_verify)

        with TestClient(app) as client:
            resp = client.get(
                "/v1/certificates",
                headers={"Authorization": "Bearer readonly-key-12345"},
            )

        assert resp.status_code == 200
        assert calls == 1
