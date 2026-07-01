# Implementation Plan — acme.api v1

> Derived from `docs/outline.md`. Targets Python 3.14, strict mypy, 80% per-file coverage gate.
> Greenfield codebase: `acme_api/` and `tests/` are currently empty. Infrastructure (Makefile, pyproject.toml) exists.

---

## Phase 0 — Dependencies & Project Wiring

**Goal:** Resolve the runtime dependency list and wire a working entry point so `make dev` + `make test` passes on an empty package.

- Update `pyproject.toml` `[project.dependencies]`:
  - FastAPI, Uvicorn (ASGI server)
  - SQLAlchemy 2.x (async SQLite)
  - APScheduler (renewal jobs)
  - Pydantic Settings (`pydantic-settings`) — config loading beyond flat YAML
  - HTTPX (webhook delivery; acme.sh subprocess parsing is local but webhooks are HTTP)
  - Prometheus Client (`prometheus-client`)
  - Passlib + bcrypt (API key hashing)
  - `aiofiles` (async filesystem writes for atomic deployment)
- Update `[project.scripts]` entry point pointing to the main CLI.
- Regenerate `requirements.txt` / `requirements-dev.txt` via `make deps-update`.
- Bootstrap package skeleton:
  - `acme_api/__init__.py`, `main.py` (app factory + uvicorn entry), `config.py` (YAML → Pydantic config model)
  - `tests/conftest.py` (shared pytest fixtures, async support via anyio)
- Create placeholder `GET /health` returning `{"status": "ok"}` to verify the pipeline.

**Acceptance:** `make combined-check` passes; Docker build succeeds with a health endpoint responding 200 OK.

---

## Phase 1 — Configuration & Logging

**Goal:** Runtime configuration from `config.yaml`, structured JSON logging, and app startup wiring.

- `acme_api/config.py`:
  - Pydantic model representing the full config schema (ACME paths, SQLite DSN, cert deployment dir, DNS providers, ACME accounts, log level).
  - Config loader reads `config.yaml` from a configurable path (`ACME_API_CONFIG` env var).
  - Validation on startup: reject missing required fields with clear errors.
- Structured JSON logging setup (`acme_api/logging.py`):
  - JSON-formatted records to stdout and optionally to file.
  - Configurable log level via config.
  - Request ID context propagation (middleware injects per-request correlation ID).
- Example `config.yaml` shipped in the repo root as a reference (`config.example.yaml`).

**Acceptance:** App starts with valid/invalid configs; structured logs emitted for lifecycle events; config validation errors surfaced at startup.

---

## Phase 2 — Database Layer & Data Models

**Goal:** SQLite-backed ORM models with migrations for all persistent entities defined in the outline (certificates, accounts, providers, renewal schedule, webhook configuration, audit log).

- `acme_api/db.py`: async SQLAlchemy engine setup, session factory, connection pooling.
- `acme_api/models/` package:
  - **Certificate**: id (UUID), name, domains (JSON array), acme_account_ref, dns_provider_ref, key_algorithm, expiry_date, status (Pending | Issuing | Valid | Renewing | Failed | Revoked), created_at, updated_at.
  - **ACMEAccount**: name, server_url (LE prod/staging, ZeroSSL, Buypass), account_key_path (filesystem path managed by acme.sh).
  - **DNSProvider**: name, provider_name (acme.sh provider alias e.g. `cloudflare`), env_vars_file_path (path to file with DNS credentials — avoids passing secrets in memory from the API layer).
  - **WebhookConfig**: id, url, events (JSON array of event types it subscribes to), secret (for HMAC signing).
  - **Event** (audit log): id, timestamp, event_type, certificate_ref (nullable), details (JSON), status.
- Alembic integration for migrations: initial migration covering all tables.
- Pydantic schemas (`acme_api/schemas/`) mirroring each model for API serialization with validators (domain format, RFC-compliant expiry parsing).

**Acceptance:** All models create/migrate cleanly; CRUD operations on every entity work via async session; schemas serialize/deserialize round-trip.

---

## Phase 3 — ACME Backend Abstraction & acme.sh Integration

**Goal:** Clean backend interface (`AcmeBackend` protocol) with a concrete `acmesh_backend.py` implementation wrapping the `acme.sh` CLI. The public API remains independent of the backend (per outline architecture).

- `acme_api/backend/protocol.py`:
  - `AcmeBackend` Protocol: `register_account()`, `issue_certificate()`, `renew_certificate()`, `get_certificate_expiry()`.
  - Return types are domain-model agnostic (dict or dataclass) — the API layer maps to models.
- `acme_api/backend/acmesh_backend.py`:
  - Subprocess wrapper around `acme.sh` with configurable binary path.
  - DNS-01 via `--dns` flag; DNS persist mode (`--dnssleep`, `--force`).
  - Account management: `--register --nocaptcha`.
  - Certificate issuance/renewal: maps to acme.sh issue / renew subcommands.
  - Parses output (log or stdout) for expiry dates, cert paths.
  - Error handling: distinguishes transient failures (DNS propagation) from terminal errors (account invalid).
- Configuration-driven ACME home directory (`/acmesh` in container) mounted persistently.

**Acceptance:** Backend can register an account against LE staging; issue and renew a certificate with DNS-01; parse expiry dates correctly. Mock backend available for tests without acme.sh installed.

---

## Phase 4 — Core API Endpoints (Certificates, Accounts, Providers, Events)

**Goal:** Full CRUD REST API backed by the database layer and ACME backend abstraction. OpenAPI metadata on all endpoints per outline spec.

### Certificates (`/v1/certificates`)
- `POST /v1/certificates` — create certificate request (name, domains, acme_account, dns_provider, key_algorithm). Transitions: Pending → Issuing → Valid or Failed. Triggers immediate issuance via backend.
- `GET /v1/certificates` — list with pagination (`?offset=&limit=`), filter by status, domain search.
- `GET /v1/certificates/{id}` — single certificate detail including expiry and status.
- `DELETE /v1/certificates/{id}` — soft delete (mark as Revoked; remove from renewal schedule).
- `POST /v1/certificates/{id}/renew` — manual renewal trigger.

### Accounts (`/v1/accounts`)
- `GET /v1/accounts` — list configured ACME accounts.

### Providers (`/v1/providers`)
- `GET /v1/providers` — list configured DNS providers.

### Events (`/v1/events`)
- `GET /v1/events` — query audit/event log with filtering by type, certificate, time range.

### Implementation Details
- FastAPI router structure: `acme_api/routes/certificates.py`, `accounts.py`, `providers.py`, `events.py`.
- Dependency injection for DB sessions and backend instances.
- OpenAPI metadata on all endpoints (tags, summary, responses).

**Acceptance:** All endpoints respond with correct status codes; input validation via Pydantic schemas; database CRUD wired end-to-end; OpenAPI docs at `/docs` reflect the API.

---

## Phase 5 — Certificate Filesystem Deployment

**Goal:** Atomic deployment of certificate artifacts to the shared filesystem (`/certificates/<domain>/`).

- `acme_api/deployer.py`:
  - On successful issuance/renewal, writes cert files atomically:
    1. Write `.pem.tmp` files to a temp directory in the same filesystem.
    2. `os.fsync()` each file handle.
    3. `os.rename()` (atomic on POSIX) to final paths.
    4. Emit webhook event (Phase 7 hook).
  - File layout per domain:
    ```
    /certificates/<primary_domain>/
        cert.pem          # server certificate
        chain.pem         # CA chain
        fullchain.pem     # cert + chain concatenated
        privkey.pem       # private key
        metadata.json     # API-generated metadata (issuer, expiry, domains)
    ```
  - SAN certificates: deploy under the first domain listed; symlink or additional entries for other domains if needed.

**Acceptance:** Deployment produces correct file layout; atomic rename guarantees consumers never see partial writes; filesystem permissions are set correctly (`0644` for certs, `0600` for keys).

---

## Phase 6 — Renewal Scheduler

**Goal:** Automatic renewal of certificates before expiry using APScheduler. State tracked internally per outline (Pending → Issuing → Valid → Renewing → Valid/Failed).

- `acme_api/scheduler.py`:
  - On certificate creation/update: schedule next run based on `expiry_date` minus configured window (default 30 days, configurable via config.yaml).
  - Job stores the certificate ID; looks up latest state at execution time.
  - State transitions during renewal: Valid → Renewing → Valid or Failed.
  - Retry policy: configurable retries with exponential backoff for transient failures.
  - Graceful shutdown: scheduler pauses jobs on SIGTERM, waits for in-flight renewals to complete (configurable timeout).
- Scheduler initialized at app startup; persisted job state not required (jobs reconstructed from DB on restart — any cert expiring within the window is rescheduled immediately).

**Acceptance:** Certificates within renewal window are picked up on startup; scheduled jobs execute and trigger backend renewal; failures logged and reflected in certificate status.

---

## Phase 7 — Webhook Notifications

**Goal:** HTTP webhook delivery for all lifecycle events with HMAC signing and retries. Events per outline: `certificate.created`, `.issued`, `.renewed`, `.failed`, `.expiring`, `.revoked`.

- `acme_api/webhooks.py`:
  - Payload structure per outline spec (event, certificate name, expiry, domains).
  - Per-webhook HMAC-SHA256 signature in `X-Webhook-Signature` header.
  - Async HTTP delivery via HTTPX with timeout and retry logic (configurable: max retries, backoff).
  - Failed deliveries logged to the Event table for auditability.

**Acceptance:** Webhooks fire on all lifecycle events; payload matches spec; HMAC signature verifiable by consumer; failed deliveries retried and logged.

---

## Phase 8 — Authentication & Authorization (API Keys)

**Goal:** API key-based auth with role-based access control (Admin, Operator, Read Only). Per outline: v1 supports API Keys only.

- `acme_api/auth/`:
  - **APIKey model**: id, name, hashed_key, role (`admin`, `operator`, `readonly`), created_at, expires_at (nullable).
  - For v1, keys defined in `config.yaml` are sufficient; the DB model is prepared for future API-managed key lifecycle.
  - **Middleware**: validates `Authorization: Bearer <key>` header; extracts role from config or DB lookup.
  - **RBAC enforcement** via FastAPI dependencies:
    - Admin: all endpoints (CRUD on certificates, accounts, providers, webhooks).
    - Operator: create/renew certificates, view status, view events.
    - Read Only: GET endpoints only.
  - API key hashing via Passlib + bcrypt for storage.

**Acceptance:** Unauthenticated requests return 401; insufficient role returns 403; all roles can access their permitted endpoints.

---

## Phase 9 — Metrics & Health/Readiness Checks

**Goal:** Prometheus metrics endpoint and Kubernetes-ready health probes per outline spec.

- `acme_api/metrics.py`:
  - Prometheus Client SDK integration.
  - Counters: `certificates_total`, `renewals_total`, `renewals_failed_total`, `webhook_deliveries_total`, `webhook_failures_total`.
  - Gauge: `certificates_expiring` (count of certs expiring within N days).
  - Metrics endpoint at `/metrics`.
- Health/Readiness endpoints per outline:
  - `GET /health` — always returns 200 with uptime.
  - `GET /ready` — checks DB connectivity and acme.sh binary availability; returns 503 if any dependency is down.

**Acceptance:** `/metrics` exposes all defined metrics in Prometheus format; `/health` responds 200 on startup; `/ready` reflects actual dependency state.

---

## Phase 10 — Docker Container & Deployment

**Goal:** Production-ready container image with multi-stage build and persistent volumes (`/data`, `/certificates`, `/acmesh`) per outline spec.

- `Dockerfile`:
  - Multi-stage: builder (install deps) → runner (copy artifacts).
  - Based on Python 3.14 slim image.
  - Installs acme.sh into the container (script runs on first start if not present).
  - Non-root user (`acmeapi`).
- `docker-compose.yml`:
  - Service definition with volumes:
    - `/data` — SQLite database.
    - `/certificates` — deployed certificate artifacts.
    - `/acmesh` — acme.sh state directory (accounts, DNS records).
  - Health check configured against `/health`.
  - Environment variable support for config path override.

**Acceptance:** `make build start` produces a running container; health endpoint accessible; volumes persist data across restarts; certificates are deployed to the mounted filesystem.

---

## Phase 11 — OpenAPI Documentation & Final Polish

**Goal:** Complete API documentation and project polish. Outline: "The REST API should be fully described using OpenAPI."

- FastAPI auto-generates OpenAPI spec at `/openapi.json`; Swagger UI at `/docs`.
- Ensure all endpoints have proper tags, descriptions, response models, and error schemas (400, 401, 403, 404, 422, 500).
- `README.md` updated with installation, configuration, API overview, and deployment instructions.
- Final pass on linting, type-checking, formatting (`make combined-check`).

**Acceptance:** OpenAPI docs are comprehensive; Swagger UI interactive; all quality gates pass at 80%+ coverage per file; mypy strict mode clean.

---

## Phase 12 — Integration Tests & End-to-End Verification

**Goal:** Validate the full system with integration tests covering real-world flows.

- `tests/integration/`:
  - **Full certificate lifecycle**: create → issue → deploy → renew → revoke, using acme.sh against LE staging (or a mock ACME server like Pebble).
  - **Renewal scheduling**: cert expiring soon is picked up by scheduler and renewed.
  - **Webhook delivery**: events fire and are delivered to a test HTTP endpoint.
  - **Auth flows**: all roles tested against all endpoints for correct RBAC.
  - **Docker smoke test**: container starts, health checks pass, API responds.
- Fixtures in `tests/fixtures/`: sample config.yaml, mock DNS provider env files, test certificate data.

**Acceptance:** Integration tests run via `make test`; coverage gate met; E2E flow produces a real (staging) certificate deployed to the filesystem.

---

## Dependency Graph & Parallelism

Phases with no hard dependencies can be worked in parallel:

```
Phase 0 ──┐
          ├──> Phase 1 ──> Phase 2 ──┐
          │                          ├──> Phase 3 ──> Phase 4
          │                          │
          └──────────────────────────┘
                                        │
                              Phase 5   │   (parallel with Phase 6)
Phase 5 ──────────────────────/         │   Phase 6 ────────────────\
                                       ├──> Phase 7 ──────────────\
                                                                  │
                                    Phase 8 ──────────────────────┤
                                                                  ├──> Phase 9
                                   Phase 10 (can start after 4)   │
                                                                  │
Phase 11 ←────────────────────────────────────────────────────────/
                                                                    \
Phase 12 ←──────────────────────────────────────────────────────────-/
```

**Strict ordering:**
- Phase 0 → Phase 1 → Phase 2 (config and DB must exist before anything else).
- Phase 2 + Phase 3 → Phase 4 (API needs both DB models and backend abstraction).
- Phase 4 → Phase 5, 6, 7 (deployment, scheduling, webhooks all act on certificates created by the API).
- Phase 5–9 can proceed in parallel once Phase 4 is complete.
- Phase 10 depends on a working application (Phase 4+).
- Phase 11 and 12 are final polish — depend on everything else.

---

## Testing Strategy Per Phase

| Phase | Test Type | Coverage Target |
|-------|-----------|-----------------|
| 0     | Unit: entry point, config parse | 80% |
| 1     | Unit: config validation, log formatting | 80% |
| 2     | Unit + Integration: ORM CRUD, migrations, schema validation | 90% |
| 3     | Unit (mock subprocess) + Integration (staging acme.sh) | 80% / 70% |
| 4     | Integration: API endpoints via TestClient | 85% |
| 5     | Unit: atomic write, permissions, metadata JSON | 90% |
| 6     | Unit (mock backend): scheduling logic, state transitions | 90% |
| 7     | Unit (mock HTTPX): payload construction, HMAC, retry | 85% |
| 8     | Integration: auth middleware, RBAC matrix | 90% |
| 9     | Unit: metric counters, health checks | 85% |
| 10    | Smoke test: container build + startup | — |
| 11    | Regression: full `make combined-check` | 80% |
| 12    | E2E: full lifecycle against staging ACME | 70% |

---

## Risk & Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| acme.sh subprocess flakiness (DNS propagation) | False test failures | Mock backend for unit tests; Pebble/staging for integration with generous timeouts |
| Atomic deploy on non-POSIX FS | Partial cert visible to consumers | Test with `os.rename` semantics; fallback to copy+rename if needed |
| SQLite concurrency under load | Write conflicts | WAL mode enabled; connection pooling configured conservatively |
| API key rotation without downtime | Auth outage during transition | Support multiple active keys; soft-delete old keys |
