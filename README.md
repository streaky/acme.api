# acme.api

A lightweight, self-hosted REST service for managing ACME certificates — backed by `acme.sh`.

## Philosophy

**acme.api is not another ACME client.** It's a certificate management service with a clean REST interface that delegates all protocol work to mature tooling. By separating the infrastructure API from the ACME implementation, applications integrate once and remain independent of the underlying ACME client.

## Quick Start

```sh
docker run -d \
  --name acme-api \
  -v /path/to/certs:/certificates \
  -v /path/acme.sh-data:/acmesh \
  -p 8080:8080 \
  ghcr.io/acme.api/acme.api:latest
```

Three persistent volumes — `/data`, `/certificates`, `/acmesh` — each with a distinct purpose. See the [deployment section](#deployment) for details.

Then interact via the REST API:

```sh
# Check readiness
curl http://localhost:8080/ready

# List certificates
curl http://localhost:8080/v1/certificates
```

## Features

| Area | What's included (v1) |
|---|---|
| **Certificate lifecycle** | Issue, renew, revoke via REST API |
| **Validation** | DNS-01 with persistent provider mode — credentials configured once by admin |
| **ACME backend** | `acme.sh` — extensible to lego or native later without API changes |
| **Accounts** | Manage multiple CA accounts (Let's Encrypt prod/staging, ZeroSSL) |
| **Renewals** | Automatic before expiry with tracked state machine |
| **Webhooks** | Events on issue/renew/fail/expiry/revocation |
| **Metrics** | Prometheus-compatible counters for certs, renewals, webhooks |
| **Logging** | Structured JSON to stdout and file |
| **Auth (v1)** | API key authentication with RBAC roles: Admin, Operator, Read Only |

### Out of scope (v1)

HTTP-01, TLS-ALPN-01, per-request DNS credentials, web UI, HA/clustering.

## REST API

Full OpenAPI spec is generated from the codebase. Key endpoints:

| Method | Path | Description |
|---|---|---|
| `POST`   | `/v1/certificates` | Register and issue a certificate |
| `GET`    | `/v1/certificates` | List all certificates |
| `GET`    | `/v1/certificates/{id}` | Get certificate details |
| `DELETE` | `/v1/certificates/{id}` | Revoke and remove |
| `POST`   | `/v1/certificates/{id}/renew` | Force renewal |
| `GET`    | `/v1/accounts` | List ACME accounts |
| `GET`    | `/v1/providers` | List DNS providers |
| `GET`    | `/v1/events` | Event history |
| `GET`    | `/health` | Liveness probe |
| `GET`    | `/ready` | Readiness probe |

### Example: issue a certificate

```json
POST /v1/certificates

{
  "name": "mail.example.com",
  "domains": ["*.example.com", "example.com"],
  "dns_provider": "production",
  "account": "letsencrypt-production"
}
```

### Certificate key algorithms

- RSA (default)
- ECDSA P-256
- ECDSA P-384

## Architecture

```
                    REST API
                        │
        ┌───────────────┴───────────────┐
        │                               │
 Certificate Manager           Renewal Scheduler
        │                               │
        └───────────────┬───────────────┘
                        │
                  ACME Backend
                        │
                    acme.sh
                        │
      Let's Encrypt / ZeroSSL / Buypass
```

The public API is backend-independent. The ACME implementation (currently `acme.sh`) is an internal detail.

## Deployment

### Docker volumes

| Mount | Purpose | Survives upgrades? |
|---|---|---|
| `/data` | SQLite database — certs, accounts, providers, webhooks, audit log | Yes |
| `/certificates` | Issued certificate files — atomic deployment via rename | Yes |
| `/acmesh` | `acme.sh` home directory and account state | Yes |

### Shared filesystem model

Certificates are written atomically: temporary files → flush → rename. Consumers never see partially-written certificates. Layout per domain:

```
/certificates/mail.example.com/
    cert.pem
    chain.pem
    fullchain.pem
    privkey.pem
    metadata.json
```

## Design Principles

- **API-first** — everything through REST, no CLI dependency
- **Backend-independent** — swap ACME client without breaking integrations
- **Simple deployment** — one container, three volumes, YAML config
- **Opinionated defaults** — works out of the box with sensible settings
- **Minimal configuration** — DNS providers configured once by admin
- **No Kubernetes requirement** — runs anywhere Docker does
- **No external database** — SQLite is sufficient for v1

## Project status

Prototype. API surface and architecture are defined; implementation underway. See `docs/outline.md` for the full specification.

## License

See [LICENSE](LICENSE).
