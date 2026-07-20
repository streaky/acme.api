# Agent Notes

## Project Overview

**acme.api** is a lightweight, self-hosted REST service for managing ACME certificates via DNS-01 validation. It delegates the ACME protocol to `acme.sh` and exposes a modern HTTP API for certificate lifecycle management, automatic renewals, and webhook notifications. See `docs/outline.md` for full design.

## Architecture (v1)

- **Backend**: `acme.sh` (only supported ACME implementation at this time).
- **Validation**: DNS-01 only; DNS providers are admin-defined aliases referenced by name in the API.
- **Deployment**: Single Docker container; certificates written atomically to a shared filesystem (`/certificates/<domain>/`).
- **Config**: `config.yaml` (YAML-based, parsed via PyYAML).

## Directory Layout

```
acme_api/          # main package: API, auth, DB, backend wrapper, scheduler, webhooks
tests/             # pytest test suite; integration tests and fixtures live here
dev/               # helper scripts (e.g. per-file coverage checker)
docs/              # project outline and design docs
Makefile           # all build/lint/test commands
```

## Development Standards

- Follow PEP 8 and modern Python practices.
- Use type hints for all functions and methods.
- Write maintainable, modular, testable, and well-documented code.
- Add docstrings for all public functions and classes.
- Configuration is stored in `config.yaml`.
- Do not use noqa or disable linter warnings any other way without a strong justification. Opt towards refactoring instead of silencing warnings, and if you must silence a warning, add a brief comment explaining why.

## Project Commands

| Command | Description |
|---|---|
| `make dev` | Create the locked uv development environment. |
| `make deps-update` | Upgrade the uv lock and regenerate hashed requirement exports. |
| `make deps-check` | Verify `uv.lock` and requirement exports agree. |
| `make test` | Run split unit, integration, and ordinary end-to-end suites plus coverage gates. |
| `make test-unit` | Run deterministic unit tests. |
| `make test-integration` | Run mock-backed integration tests. |
| `make test-e2e` | Run the ordinary end-to-end boundary. |
| `make test-harness` | Run the optional Docker-backed Pebble DNS-01 test. |
| `make type-check` | Run strict mypy. |
| `make format-check` | Check Ruff formatting. |
| `make lint` | Run Ruff and Pylint. |
| `make max-lines` | Enforce the 500-line Python source limit. |
| `make verify` | Run dependency, format, lint, type, and test gates in one shot. |
| `make simulate-ci` | Execute the GitHub Actions workflow locally with `act`. |
| `make build` | Build Docker image via docker compose. |
| `make start` | Start the service (depends on build). |
| `make stop` | Stop the service. |
| `make logs` | Follow container logs. |

## Fixtures And Documentation

- Tests are split into `tests/unit/`, `tests/integration/`, and `tests/e2e/`; fixtures live in `tests/fixtures/`.
- Use `make verify` before declaring substantial work complete; it enforces the canonical quality and coverage gates.
- Update `README.md` with project description, installation instructions, usage, and other relevant information.
- Update this file (`AGENTS.md`) with useful information that may help future agents.
