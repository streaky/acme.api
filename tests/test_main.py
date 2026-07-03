"""Tests for application factory and CLI entry point."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from acme_api.config import (
    AcmeConfig,
    AppSettings,
    DatabaseConfig,
    DeploymentConfig,
)
from acme_api.main import create_app


@pytest.fixture()
def settings(tmp_path: Path) -> AppSettings:
    return AppSettings(
        database=DatabaseConfig(url=f"sqlite+aiosqlite:///{tmp_path}/test.db"),
        deployment=DeploymentConfig(directory=tmp_path / "certs"),
        acme=AcmeConfig(home_dir=tmp_path / "acmesh"),
    )


class TestCreateApp:
    def test_returns_fastapi_instance(self, settings: AppSettings) -> None:
        app = create_app(settings=settings)
        assert app.title == "acme.api"

    def test_health_endpoint_ok(self, settings: AppSettings) -> None:
        app = create_app(settings=settings)
        with TestClient(app) as client:
            resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
        assert isinstance(resp.json()["uptime_seconds"], float)

    def test_ready_endpoint_ok(self, settings: AppSettings, tmp_path: Path) -> None:
        acme_binary = tmp_path / "acme.sh"
        acme_binary.write_text("#!/bin/sh\n", encoding="utf-8")
        acme_binary.chmod(0o755)
        settings.acme.binary_path = str(acme_binary)
        app = create_app(settings=settings)

        with TestClient(app) as client:
            resp = client.get("/ready")

        assert resp.status_code == 200
        assert resp.json()["status"] == "ready"
        assert resp.json()["checks"]["database"]["ok"] is True
        assert resp.json()["checks"]["acme_binary"]["ok"] is True

    def test_ready_endpoint_reports_missing_acme_binary(
        self, settings: AppSettings, tmp_path: Path
    ) -> None:
        settings.acme.binary_path = str(tmp_path / "missing-acme.sh")
        app = create_app(settings=settings)

        with TestClient(app) as client:
            resp = client.get("/ready")

        assert resp.status_code == 503
        assert resp.json()["status"] == "not_ready"
        assert resp.json()["checks"]["database"]["ok"] is True
        assert resp.json()["checks"]["acme_binary"]["ok"] is False

    def test_openapi_documents_health_and_certificate_errors(
        self, settings: AppSettings
    ) -> None:
        app = create_app(settings=settings)

        with TestClient(app) as client:
            spec = client.get("/openapi.json").json()

        assert "/ready" in spec["paths"]
        assert "503" in spec["paths"]["/ready"]["get"]["responses"]
        certificate_post = spec["paths"]["/v1/certificates"]["post"]
        assert "409" in certificate_post["responses"]

    def test_settings_stored_on_state(self, settings: AppSettings) -> None:
        app = create_app(settings=settings)
        stored = getattr(app.state, "settings", None)
        assert isinstance(stored, AppSettings)

    def test_unhandled_exception_returns_500(self, settings: AppSettings) -> None:
        """Uncaught exceptions in a route return 500 with generic detail."""
        app = create_app(settings=settings)

        @app.get("/boom")
        async def boom_route() -> str:
            raise RuntimeError("kaboom")

        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.get("/boom")
        assert resp.status_code == 500
        assert "detail" in resp.json()


class TestLifespan:
    @pytest.mark.anyio
    async def test_lifespan_yields(self, settings: AppSettings) -> None:
        """Verify the lifespan context manager yields once."""
        app = create_app(settings=settings)
        steps = []

        from acme_api.main import lifespan

        async with lifespan(app):
            steps.append("inside")
        steps.append("after")

        assert steps == ["inside", "after"]


class TestMain:
    def test_main_runs_uvicorn(self, tmp_path: Path) -> None:
        """Smoke-test that main() loads config and calls uvicorn.run."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("renewal:\n  window_days: 15\n")

        with (
            patch("acme_api.main.load_config", return_value=AppSettings()),
            patch("uvicorn.run") as mock_run,
            patch.dict("os.environ", {}, clear=True),
        ):
            from acme_api.main import main

            main()

        mock_run.assert_called_once()
        call_kwargs = mock_run.call_args.kwargs
        assert call_kwargs["factory"] is True
        assert call_kwargs["port"] == 8000

    def test_main_honors_host_and_port_env(self) -> None:
        with (
            patch("acme_api.main.load_config", return_value=AppSettings()),
            patch("uvicorn.run") as mock_run,
            patch.dict(
                "os.environ",
                {"ACME_API_HOST": "127.0.0.1", "ACME_API_PORT": "8080"},
                clear=True,
            ),
        ):
            from acme_api.main import main

            main()

        call_kwargs = mock_run.call_args.kwargs
        assert call_kwargs["host"] == "127.0.0.1"
        assert call_kwargs["port"] == 8080
