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

## Project Commands

| Command | Description |
|---|---|
| `make dev` | Set up venv + install all dependencies (required before other targets). |
| `make deps-update` | Regenerate pinned `requirements.txt` / `requirements-dev.txt` from pyproject.toml via pip-tools. |
| `make test [TEST=...]` | Run pytest with coverage. Scope to a file/path with `TEST=path/to/test.py`. Runs per-file coverage gate (default 80%). |
| `make typecheck` | Run mypy (strict mode, Python 3.14). |
| `make lint` | Run flake8 + pylint (fail-under 10.0). |
| `make isort` | Check import ordering (--check-only --diff). |
| `make format` | Apply isort formatting in-place. |
| `make combined-check` | Run typecheck, lint, flake8, isort, check-max-lines, and test in one shot. |
| `make simulate-ci` | Run the GitHub Actions workflow locally with `act` (requires ACT_* env settings). |
| `make build` | Build Docker image via docker compose. |
| `make start` | Start the service (depends on build). |
| `make stop` | Stop the service. |
| `make logs` | Follow container logs. |

## Fixtures And Documentation

- Tests live in `tests/`; end-to-end mock-backed integration tests live in `tests/integration/`; fixtures live in `tests/fixtures/`.
- Use `make test` (not raw pytest) to ensure coverage gates are enforced.
- Update `README.md` with project description, installation instructions, usage, and other relevant information.
- Update this file (`AGENTS.md`) with useful information that may help future agents.
