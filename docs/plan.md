# Implementation Plan — acme.api v1

> Derived from `docs/outline.md`. Targets Python 3.14, strict mypy, 80% per-file coverage gate.
> Phase 0/1 foundation exists: package skeleton, config loading, structured logging, request IDs, health endpoint, and tests are wired.
> Phases 2-9 now provide the core DB models, backend abstraction, auth, API routes, atomic deployer, renewal scheduler, webhook dispatcher, lifecycle orchestration, and health/readiness probes.
> Implementation lesson: lifecycle behavior belongs behind an application service boundary so FastAPI routes and APScheduler callbacks stay thin while backend calls, artifact deployment, state changes, scheduling, audit events, and webhooks remain testable together.

---

## Phase 0 — Dependencies & Project Wiring

**Goal:** Resolve the runtime dependency list and wire a working entry point so `make dev` + `make test` passes on the package foundation.

- Update `pyproject.toml` `[project.dependencies]`:
  - FastAPI, Uvicorn (ASGI server)
  - SQLAlchemy 2.x (async SQLite)
  - APScheduler (renewal jobs)
  - Pydantic Settings (`pydantic-settings`) — config loading beyond flat YAML
  - HTTPX2 (webhook delivery; acme.sh subprocess parsing is local but webhooks are HTTP)
  - Passlib (PBKDF2-SHA512 API key hashing)
  - `aiofiles` (async filesystem writes for atomic deployment)
- Update `[project.scripts]` entry point pointing to the main CLI.
- Regenerate `requirements.txt` / `requirements-dev.txt` via `make deps-update`.
- Bootstrap package skeleton:
  - `acme_api/__init__.py`, `main.py` (app factory + uvicorn entry), `config.py` (YAML → Pydantic config model)
  - `tests/conftest.py` (shared pytest fixtures, async support via anyio)
- Create placeholder `GET /health` returning `{"status": "ok"}` to verify the pipeline.

**Acceptance:** `make combined-check` passes; health endpoint responds 200 OK in tests.

---

## Phase 1 — Configuration & Logging

**Goal:** Runtime configuration from `config.yaml`, structured JSON logging, and app startup wiring.

- `acme_api/config.py`:
  - Pydantic model representing the full config schema (ACME paths, SQLite DSN, cert deployment dir, DNS providers, ACME accounts, log level).
  - Config loader reads `config.yaml` from a configurable path (`ACME_API_CONFIG` env var).
  - Validation on startup: reject missing required fields with clear errors.
  - Unknown config keys are rejected so stale examples or typos fail fast.
  - Missing config files fail fast instead of silently falling back to defaults.
  - Runtime directory creation is separate from config validation.
- Structured JSON logging setup (`acme_api/logging.py`):
  - JSON-formatted records to stdout and optionally to file.
  - Configurable log level via config.
  - Request ID context propagation (middleware preserves inbound `X-Request-ID` or injects a new per-request correlation ID).
- Example `config.yaml` shipped in the repo root as a reference (`config.example.yaml`).

**Acceptance:** App starts with valid/invalid configs; structured logs emitted for lifecycle events; config validation errors surfaced at startup.

---

## v1 Persistence Boundary

Mutable runtime state lives in SQLite. Administrator-managed external integrations live in `config.yaml`.

- **Config-owned in v1:**
  - ACME accounts.
  - DNS provider aliases and credential file paths.
  - Initial/bootstrap API keys, if needed.
- **DB-owned in v1:**
  - Certificates and their lifecycle state.
  - Renewal attempts / scheduling metadata.
  - Webhook configurations.
  - Event/audit log.
  - API keys, if API-managed key lifecycle is implemented in v1.

Accounts and providers are exposed through read-only API endpoints, but are not API-mutated in v1.

---

## Phase 2 — Database Layer & Data Models

**Goal:** SQLite-backed async database foundation and migrations for mutable runtime state.

- `acme_api/db.py`: async SQLAlchemy engine setup, session factory, connection pooling.
- SQLite pragmas for service usage:
  - WAL mode.
  - Foreign keys enabled.
  - Conservative pool configuration.
- Alembic integration for migrations: initial migration covering foundation tables.
- `acme_api/models/` package:
  - **Certificate**: id (UUID), name, domains (JSON array), acme_account_ref, dns_provider_ref, key_algorithm, expiry_date, status (Pending | Issuing | Valid | Renewing | Failed | Revoked), created_at, updated_at.
  - **Event** (audit log): id, timestamp, event_type, certificate_ref (nullable), details (JSON), status.
  - **RenewalAttempt** or renewal metadata table: certificate_ref, attempted_at, status, error category/details, next_retry_at.
- Pydantic schemas (`acme_api/schemas/`) for certificate/event serialization with validators (domain format, RFC-compliant expiry parsing).
- Config-backed read schemas for ACME accounts and DNS providers.

**Acceptance:** DB engine/session wiring works; migrations create all Phase 2 tables cleanly; certificate/event CRUD works via async session; schemas serialize/deserialize round-trip; config-owned accounts/providers are available through typed read models.

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

**Acceptance:** Mock subprocess tests cover command construction, success parsing, expiry parsing, and transient/terminal error mapping. Mock backend available for API tests without acme.sh installed. Optional integration test can register/issue/renew against Pebble or LE staging when DNS credentials are available.

---

## Phase 4 — Authentication & Authorization (API Keys)

**Goal:** API key-based auth with role-based access control (Admin, Operator, Read Only). Auth is introduced before the user-facing API endpoints so routes, tests, and OpenAPI metadata are built around the final access model.

- `acme_api/auth/`:
  - **APIKey model** if API-managed key lifecycle is in v1: id, name, hashed_key, role (`admin`, `operator`, `readonly`), created_at, expires_at (nullable).
  - Bootstrap/config keys may be defined in `config.yaml`; DB-backed keys can be added for API-managed lifecycle.
  - **Middleware/dependency** validates `Authorization: Bearer <key>` header and extracts role.
  - **RBAC enforcement** via FastAPI dependencies:
    - Admin: all endpoints.
    - Operator: create/renew certificates, view status, view events.
    - Read Only: GET endpoints only.
  - API key hashing via Passlib PBKDF2-SHA512 for storage.

**Acceptance:** Unauthenticated requests return 401; insufficient role returns 403; role dependencies are reusable by later route modules; auth behavior is covered by an RBAC test matrix.

**Implementation note:** API keys are hashed with Passlib PBKDF2-SHA512. This avoids bcrypt's 72-byte input truncation behavior for high-entropy API keys while still using Passlib.

---

## Phase 5 — Core API Endpoints (Certificates, Accounts, Providers, Events)

**Goal:** Full CRUD REST API backed by the database layer and ACME backend abstraction. OpenAPI metadata on all endpoints per outline spec.

### Certificates (`/v1/certificates`)
- `POST /v1/certificates` — create certificate request (name, domains, acme_account, dns_provider, key_algorithm). Creates a DB record and starts issuance work. Returns `202 Accepted` with certificate id/status instead of blocking on DNS propagation.
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
- FastAPI router structure: `acme_api/routers/certificates.py`, `config.py`, `events.py`.
- Dependency injection for DB sessions and backend instances.
- Auth/RBAC dependencies applied at route level.
- Initial implementation may create DB records and expose routes before full asynchronous issuance orchestration is wired.
- Issuance state transitions: Pending → Issuing → Valid or Failed.
- OpenAPI metadata on all endpoints (tags, summary, responses).

**Acceptance:** All endpoints respond with correct status codes; input validation via Pydantic schemas; database CRUD wired end-to-end; OpenAPI docs at `/docs` reflect the API.

**Implementation note:** The current Phase 5 route layer is DB-backed and RBAC-protected, but certificate creation and manual renewal do not yet run the ACME backend/deployer. That is now tracked explicitly in Phase 8.5.

---

## Phase 6 — Certificate Filesystem Deployment

**Goal:** Atomic deployment of certificate artifacts to the shared filesystem (`/certificates/<domain>/`).

- `acme_api/deployer.py`:
  - On successful issuance/renewal, writes cert files atomically:
    1. Write `.pem.tmp` files to a temp directory in the same filesystem.
    2. `os.fsync()` each file handle.
    3. `os.rename()` (atomic on POSIX) to final paths.
    4. Emit webhook event (Phase 8 hook).
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

**Implementation note:** The deployer is implemented as a reusable boundary. It is not yet called from certificate issuance/renewal flows; that wiring belongs in Phase 8.5.

---

## Phase 7 — Renewal Scheduler

**Goal:** Automatic renewal of certificates before expiry using APScheduler. State tracked internally per outline (Pending → Issuing → Valid → Renewing → Valid/Failed).

- `acme_api/scheduler.py`:
  - On certificate creation/update: schedule next run based on `expiry_date` minus configured window (default 30 days, configurable via config.yaml).
  - Job stores the certificate ID; looks up latest state at execution time.
  - State transitions during renewal: Valid → Renewing → Valid or Failed.
  - Retry policy: configurable retries with exponential backoff for transient failures.
  - Graceful shutdown: scheduler pauses jobs on SIGTERM, waits for in-flight renewals to complete (configurable timeout).
- Scheduler initialized at app startup; persisted job state not required (jobs reconstructed from DB on restart — any cert expiring within the window is rescheduled immediately).

**Acceptance:** Certificates within renewal window are picked up on startup; scheduled jobs execute and trigger backend renewal; failures logged and reflected in certificate status.

**Implementation note:** The scheduler can renew valid certificates through an injected backend and emit renewed/failed webhooks. Deployment after renewal and full lifecycle integration are tracked in Phase 8.5.

---

## Phase 8 — Webhook Notifications

**Goal:** HTTP webhook delivery for all lifecycle events with HMAC signing and retries. Events per outline: `certificate.created`, `.issued`, `.renewed`, `.failed`, `.expiring`, `.revoked`.

- `WebhookConfig` DB model: id, url, events (JSON array of event types it subscribes to), secret (for HMAC signing), created_at, updated_at, enabled.
- `acme_api/webhooks.py`:
  - Payload structure per outline spec (event, certificate name, expiry, domains).
  - Per-webhook HMAC-SHA256 signature in `X-Webhook-Signature` header.
  - Async HTTP delivery via HTTPX2 with timeout and retry logic (configurable: max retries, backoff).
  - Failed deliveries logged to the Event table for auditability.

**Acceptance:** Webhooks fire on all lifecycle events; payload matches spec; HMAC signature verifiable by consumer; failed deliveries retried and logged.

**Implementation note:** The webhook dispatcher, HMAC signing, retry handling, DB-backed subscriptions, and failed-delivery audit events are implemented. Not every lifecycle event is emitted by route/service flows yet; that wiring belongs in Phase 8.5.

---

## Phase 8.5 — Lifecycle Orchestration Gap Closure

**Goal:** Stitch the implemented pieces from Phases 3, 5, 6, 7, and 8 into complete certificate workflows before adding readiness checks and production packaging.

### Certificate Creation
- `POST /v1/certificates` should:
  - Create the DB record as `Pending`.
  - Start issuance work without blocking on DNS propagation.
  - Transition `Pending -> Issuing -> Valid` or `Failed`.
  - Call the configured ACME backend with DNS-01 provider/account settings.
  - Deploy successful issuance artifacts through `acme_api/deployer.py`.
  - Set `expiry_date` from backend results.
  - Emit audit events and webhooks for `certificate.created`, `certificate.issued`, and `certificate.failed`.

### Manual Renewal
- `POST /v1/certificates/{id}/renew` should:
  - Trigger the same renewal path used by the scheduler.
  - Deploy renewed artifacts on success.
  - Emit `certificate.renewed` or `certificate.failed`.
  - Return `202 Accepted` after queuing/starting work, not after DNS propagation.

### Revocation / Soft Delete
- `DELETE /v1/certificates/{id}` should:
  - Mark the row `Revoked`.
  - Remove pending renewal jobs for the certificate.
  - Emit `certificate.revoked`.
  - Defer actual ACME CA revocation unless explicitly added as a separate backend capability.

### Expiry Notifications
- Scheduler should emit `certificate.expiring` for certificates inside the configured notification window without duplicating events every startup.

### Service Boundary
- Add an application service layer instead of putting workflow logic inside FastAPI route functions or APScheduler callbacks.
- Keep backend, deployer, webhook dispatcher, and scheduler injectable for tests.

**Acceptance:** Create, scheduled renew, manual renew, revoke, deploy, audit events, and webhooks work end-to-end with the mock backend; real acme.sh integration remains covered by subprocess-level tests and optional staging/Pebble tests.

**Implementation note:** Creation now creates a pending row, queues issuance, calls the configured ACME backend with DNS-01 account/provider settings, deploys successful artifacts, transitions to `Valid` or `Failed`, schedules renewal, and emits lifecycle audit/webhook events. Manual renewals queue the same scheduler renewal path, which deploys renewed artifacts on success. Soft delete marks rows `Revoked`, removes scheduler jobs, and emits `certificate.revoked`. Startup renewal reconstruction emits one non-duplicated `certificate.expiring` event for certificates already inside the renewal window.

---

## Phase 9 — Readiness Checks

**Goal:** Kubernetes-ready health probes that reflect actual runtime dependencies.

- Health/Readiness endpoints per outline:
  - `GET /health` — always returns 200 with uptime.
  - `GET /ready` — checks DB connectivity and acme.sh binary availability; returns 503 if any dependency is down.

**Acceptance:** `/health` responds 200 on startup; `/ready` reflects actual dependency state.

**Deferred:** Prometheus-compatible metrics are useful but not part of the immediate v1 path. See `docs/future.md`.

**Implementation note:** `/health` is a liveness probe that returns status and process uptime. `/ready` checks SQLite connectivity and the configured `acme.sh` binary path, returning HTTP 503 with per-check details when either dependency is unavailable.

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

**Acceptance:** Integration tests run via `make test`; coverage gate met; default E2E flow works with mock/Pebble-compatible backends; real staging ACME tests are optional and gated on DNS credentials.

---

## Phase 12.5 — Continuous Integration

**Goal:** Add GitHub Actions CI that matches local quality gates and can be exercised locally before pushing.

- Add `.github/workflows/ci.yml`.
- CI should run on pull requests and pushes to the default branch.
- CI should install Python 3.14 and project dependencies from pinned requirements.
- CI should run the same gates developers run locally:
  - `make typecheck`
  - `make lint`
  - `make isort`
  - `make check-max-lines`
  - `make test`
- Prefer calling `make combined-check` from CI unless splitting jobs provides clearer failure reporting.
- Keep optional staging/Pebble ACME tests gated behind secrets or explicit workflow inputs.
- Keep Docker build smoke tests separate from the fast unit/integration gate if runtime becomes too slow.
- Use the existing local CI simulator before considering the workflow done:
  - `make simulate-ci`

**Local prerequisites:** `simulate-ci` uses `act`; configure `ACT_VERSION`, `ACT_PLATFORM`, and `ACT_IMAGE` in `.env` or the shell environment.

**Acceptance:** GitHub Actions workflow is committed, `make simulate-ci` passes locally, and the remote workflow passes on the branch/PR.

---

## Dependency Graph & Parallelism

Phases with no hard dependencies can be worked in parallel:

```
Phase 0 -> Phase 1 -> Phase 2
                     ├──> Phase 3
                     └──> Phase 4

Phase 2 + Phase 3 + Phase 4 -> Phase 5

Phase 5 -> Phase 6
        -> Phase 7
        -> Phase 8
        -> Phase 10

Phase 6 + Phase 7 + Phase 8 -> Phase 8.5
Phase 8.5 -> Phase 9
Phase 8.5 + Phase 9 + Phase 10 -> Phase 11 -> Phase 12 -> Phase 12.5
```

**Strict ordering:**
- Phase 0 → Phase 1 → Phase 2 (config and DB must exist before anything else).
- Phase 2 → Phase 4 (auth needs config and, if DB-backed keys are enabled, DB foundation).
- Phase 2 + Phase 3 + Phase 4 → Phase 5 (API needs DB models, backend abstraction, and final auth dependencies).
- Phase 5 → Phase 6, 7, 8 (deployment, scheduling, webhooks all act on certificates created by the API).
- Phase 6–8 can proceed in parallel once Phase 5 is complete.
- Phase 8.5 depends on Phases 3, 5, 6, 7, and 8 because it wires backend, API routes, deployer, scheduler, and webhooks into full lifecycle workflows.
- Phase 9 should follow Phase 8.5 so readiness checks validate the final lifecycle dependencies.
- Phase 10 depends on a working application (Phase 5+).
- Phase 11 and 12 are final polish — depend on everything else.
- Phase 12.5 depends on the final local gates and integration suite so CI reflects the project’s real release criteria.

---

## Testing Strategy Per Phase

| Phase | Test Type | Coverage Target |
|-------|-----------|-----------------|
| 0     | Unit: entry point, config parse | 80% |
| 1     | Unit: config validation, log formatting | 80% |
| 2     | Unit + Integration: ORM CRUD, migrations, schema validation | 90% |
| 3     | Unit: mock subprocess command construction, parsing, error mapping | 85% |
| 4     | Integration: auth middleware/dependencies, RBAC matrix | 90% |
| 5     | Integration: API endpoints via TestClient | 85% |
| 6     | Unit: atomic write, permissions, metadata JSON | 90% |
| 7     | Unit (mock backend): scheduling logic, state transitions | 90% |
| 8     | Unit (mock HTTPX2): payload construction, HMAC, retry | 85% |
| 8.5   | Integration: mock backend full lifecycle through API/service | 90% |
| 9     | Unit/integration: health and readiness checks | 85% |
| 10    | Smoke test: container build + startup | — |
| 11    | Regression: full `make combined-check` | 80% |
| 12    | E2E: full lifecycle against mock/Pebble; optional staging ACME | 70% |
| 12.5  | CI workflow: GitHub Actions plus local `make simulate-ci` | — |

---

## Risk & Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| acme.sh subprocess flakiness (DNS propagation) | False test failures | Mock backend for unit tests; Pebble/staging for integration with generous timeouts |
| Atomic deploy on non-POSIX FS | Partial cert visible to consumers | Test with `os.rename` semantics; fallback to copy+rename if needed |
| SQLite concurrency under load | Write conflicts | WAL mode enabled; connection pooling configured conservatively |
| API key rotation without downtime | Auth outage during transition | Support multiple active keys; soft-delete old keys |
| Phase helpers remain disconnected | API appears complete but does not issue/deploy/notify end-to-end | Phase 8.5 service-layer integration before readiness/final polish |
