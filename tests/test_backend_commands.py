"""Tests for ACME backend command construction, parsing, and errors."""

from __future__ import annotations

import os
import pathlib
from unittest.mock import AsyncMock, patch

import pytest

from acme_api.backend.acmesh_backend import (
    AcmeShBackend,
    TerminalAcmeShError,
    TransientAcmeShError,
    _AcmeShBackendConfig,
    _load_env_vars,
    parse_cert_expiry,
)
from acme_api.backend.mock_backend import MockAcmeBackend

SUCCESS_OUTPUT = (
    "Issue for domain: example.com\n"
    "Your cert is in /acmesh/cert.pem, your cert key is in /acmesh/privkey.pem, "
    "the CA certificates are in /acmesh/chain.pem, and the total chain length is 2.\n"
    "*** Expired at: 2026-12-31 23:59:59+0000"
)


@pytest.fixture()
def tmp_config(tmp_path: pathlib.Path) -> _AcmeShBackendConfig:
    """Return an isolated acme.sh backend config."""
    return _AcmeShBackendConfig(
        binary_path=tmp_path / "acme.sh",
        home_dir=tmp_path / "acmesh",
        log_file=None,
        force_renewal=False,
        dnssleep_seconds=30,
    )


@pytest.fixture()
def backend(tmp_config: _AcmeShBackendConfig) -> AcmeShBackend:
    """Return an acme.sh backend using the temporary config."""
    return AcmeShBackend(tmp_config)


def successful_process(output: str = SUCCESS_OUTPUT) -> AsyncMock:
    """Return a mocked successful subprocess."""
    mock_proc = AsyncMock()
    mock_proc.communicate.return_value = (output.encode(), b"")
    mock_proc.returncode = 0
    return mock_proc


def failed_process(stderr: str, returncode: int = 1) -> AsyncMock:
    """Return a mocked failed subprocess."""
    mock_proc = AsyncMock()
    mock_proc.communicate.return_value = (b"", stderr.encode())
    mock_proc.returncode = returncode
    return mock_proc


class TestRegisterAccountCommand:
    """Verify the register command is constructed correctly."""

    @pytest.mark.anyio
    async def test_register_account_basic(
        self, backend: AcmeShBackend, tmp_path: pathlib.Path
    ) -> None:
        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = successful_process()
            acct_key = tmp_path / "acmesh" / "acct.key"
            acct_key.parent.mkdir(parents=True, exist_ok=True)
            acct_key.write_bytes(b"fake-key")

            result = await backend.register_account(
                email="admin@example.com",
                server_url="https://acme-staging-v02.api.letsencrypt.org/directory",
            )

        call_args = mock_run.call_args.args
        assert "--home" in call_args
        assert str(tmp_path / "acmesh") in call_args
        assert "--register" in call_args
        assert "--email=admin@example.com" in call_args
        assert "--server=https://acme-staging-v02.api.letsencrypt.org/directory" in call_args
        assert "--nocaptcha" in call_args
        assert "--accountkey-file" in call_args
        assert str(acct_key) in call_args
        assert result.email == "admin@example.com"
        assert result.key_path == str(acct_key)


class TestIssueCertificateDns01:
    """Verify DNS-01 challenge command construction."""

    @pytest.mark.anyio
    async def test_issue_certificate_dns_01(self, backend: AcmeShBackend) -> None:
        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = successful_process()

            result = await backend.issue_certificate(
                domains=["example.com", "www.example.com"],
                method="dns-01",
                challenge_params={
                    "dns_provider": "cloudflare",
                    "env_vars_file": None,
                },
            )

        call_args = mock_run.call_args.args
        assert "--issue" in call_args
        assert "--domain=example.com" in call_args
        assert "--domain=www.example.com" in call_args
        assert "--dns=cloudflare" in call_args
        assert "--dnssleep" in call_args
        assert "30" in call_args
        assert result.domains == ["example.com", "www.example.com"]

    @pytest.mark.anyio
    async def test_dns_credentials_are_passed_per_subprocess(
        self, backend: AcmeShBackend, tmp_path: pathlib.Path
    ) -> None:
        env_file = tmp_path / "cloudflare.env"
        env_file.write_text("export CF_Token='secret token'\n", encoding="utf-8")

        with patch.dict(os.environ, {}, clear=False), patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock
        ) as mock_run:
            mock_run.return_value = successful_process()

            await backend.issue_certificate(
                domains=["example.com"],
                method="dns-01",
                challenge_params={
                    "dns_provider": "cloudflare",
                    "env_vars_file": env_file,
                },
            )

        env = mock_run.call_args.kwargs["env"]
        assert env["CF_Token"] == "secret token"
        assert os.environ.get("CF_Token") is None


class TestIssueCertificateWebroot:
    """Verify webroot command construction remains isolated from DNS flags."""

    @pytest.mark.anyio
    async def test_issue_certificate_webroot(self, backend: AcmeShBackend) -> None:
        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = successful_process()

            await backend.issue_certificate(
                domains=["example.com"],
                method="webroot",
                challenge_params={"webroot_dir": "/var/www/certbot"},
            )

        call_args = mock_run.call_args.args
        assert "--issue" in call_args
        assert "--domain=example.com" in call_args
        assert "--webroot=/var/www/certbot" in call_args
        assert "--dns=" not in " ".join(call_args)


class TestRenewCertificate:
    """Verify renewal command construction."""

    @pytest.mark.anyio
    async def test_renew_certificate_force(self, backend: AcmeShBackend) -> None:
        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = successful_process()

            result = await backend.renew_certificate(
                domains=["example.com", "www.example.com"],
                force_renewal=True,
            )

        call_args = mock_run.call_args.args
        assert "--renew" in call_args
        assert "--domain=example.com" in call_args
        assert "--domain=www.example.com" in call_args
        assert "--force" in call_args
        assert result.domains == ["example.com", "www.example.com"]


class TestParsing:
    """Verify supported acme.sh output parsing variants."""

    def test_parse_synthetic_issue_output(self) -> None:
        result = parse_cert_expiry(SUCCESS_OUTPUT)
        assert result.cert_path == "/acmesh/cert.pem"
        assert result.privkey_path == "/acmesh/privkey.pem"
        assert result.chain_path == "/acmesh/chain.pem"
        assert result.fullchain_path == "/acmesh/fullchain.pem"
        assert result.expires_at.year == 2026

    def test_parse_common_multiline_acmesh_output(self) -> None:
        output = (
            "Your cert is in /root/.acme.sh/example.com_ecc/example.com.cer\n"
            "Your cert key is in /root/.acme.sh/example.com_ecc/example.com.key\n"
            "The intermediate CA cert is in /root/.acme.sh/example.com_ecc/ca.cer\n"
            "And the full chain certs is there: /root/.acme.sh/example.com_ecc/fullchain.cer\n"
            "Le_NextRenewTimeStr='2026-12-31 23:59:59 UTC'\n"
        )

        result = parse_cert_expiry(output)

        assert result.cert_path.endswith("example.com.cer")
        assert result.privkey_path.endswith("example.com.key")
        assert result.chain_path.endswith("ca.cer")
        assert result.fullchain_path.endswith("fullchain.cer")
        assert result.expires_at.year == 2026

    def test_parse_failure_is_terminal(self) -> None:
        with pytest.raises(TerminalAcmeShError):
            parse_cert_expiry("unexpected output")

    def test_load_env_vars_handles_exports_and_quotes(self, tmp_path: pathlib.Path) -> None:
        env_file = tmp_path / "dns.env"
        env_file.write_text(
            "# comment\nexport CF_Token='secret token'\nCF_Account_ID=abc123\n",
            encoding="utf-8",
        )

        assert _load_env_vars(env_file) == {
            "CF_Token": "secret token",
            "CF_Account_ID": "abc123",
        }


class TestErrorClassification:
    """Verify subprocess failures map to retryable or terminal errors."""

    @pytest.mark.anyio
    async def test_transient_dns_error(self, backend: AcmeShBackend) -> None:
        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = failed_process("TXT record not found")

            with pytest.raises(TransientAcmeShError):
                await backend.issue_certificate(
                    domains=["example.com"],
                    method="dns-01",
                    challenge_params={"dns_provider": "cloudflare"},
                )

    @pytest.mark.anyio
    async def test_terminal_account_error(self, backend: AcmeShBackend) -> None:
        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = failed_process("account key invalid")

            with pytest.raises(TerminalAcmeShError):
                await backend.issue_certificate(
                    domains=["example.com"],
                    method="dns-01",
                    challenge_params={"dns_provider": "cloudflare"},
                )


class TestMockBackend:
    """Verify the mock backend can satisfy future API tests without acme.sh."""

    @pytest.mark.anyio
    async def test_mock_backend_registers_account(self, tmp_path: pathlib.Path) -> None:
        backend = MockAcmeBackend(tmp_path)

        result = await backend.register_account(
            email="admin@example.com",
            server_url="https://example.test/acme",
        )

        assert result.email == "admin@example.com"
        assert result.server_url == "https://example.test/acme"
        assert result.key_path == str(tmp_path / "acct.key")

    @pytest.mark.anyio
    async def test_mock_backend_issues_certificate(self, tmp_path: pathlib.Path) -> None:
        backend = MockAcmeBackend(tmp_path)

        result = await backend.issue_certificate(
            domains=["example.com"],
            method="dns-01",
            challenge_params={"dns_provider": "mock"},
        )

        assert result.domains == ["example.com"]
        assert result.cert.cert_path.endswith("example.com/cert.pem")

    @pytest.mark.anyio
    async def test_mock_backend_renews_and_reads_expiry(self, tmp_path: pathlib.Path) -> None:
        backend = MockAcmeBackend(tmp_path)

        renewed = await backend.renew_certificate(
            domains=["*.example.com", "example.com"],
            force_renewal=True,
        )
        expiry = await backend.get_certificate_expiry("/custom/cert.pem")

        assert renewed.domains == ["*.example.com", "example.com"]
        assert "wildcard.example.com" in renewed.cert.cert_path
        assert expiry.cert_path == "/custom/cert.pem"
