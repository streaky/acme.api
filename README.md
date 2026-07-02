# acme.api

Lightweight, self-hosted REST service for managing ACME certificates through a modern API while delegating ACME protocol work to `acme.sh`.

## Status

Prototype v1 implementation. The core API, SQLite state, API key auth, `acme.sh` backend wrapper, atomic certificate deployment, renewal scheduler, lifecycle webhooks, health/readiness probes, and Docker packaging are implemented. End-to-end staging/Pebble integration tests are still planned.

## Quick Start

Build and start the local container:

```sh
make build
make start
curl http://localhost:8080/health
curl http://localhost:8080/ready
```

The compose file uses named volumes for persistent runtime state:

| Volume | Container path | Purpose |
|---|---|---|
| `acme-api-data` | `/data` | SQLite database |
| `acme-api-certificates` | `/certificates` | Atomically deployed certificate files |
| `acme-api-acmesh` | `/acmesh` | `acme.sh` account and certificate state |

The bundled compose config at `docker/config.yaml` is intentionally minimal so the service can boot for health checks. For real issuance, copy `config.example.yaml`, configure ACME accounts, DNS provider aliases, API keys, and credential file mounts, then set `ACME_API_CONFIG` to that file inside the container.

## Local Development

```sh
make dev
make combined-check
```

Useful targets:

| Command | Description |
|---|---|
| `make test` | Run pytest with coverage and the per-file coverage gate |
| `make typecheck` | Run strict mypy |
| `make lint` | Run flake8 and pylint |
| `make isort` | Check import ordering |
| `make build` | Build the Docker image |
| `make start` | Start the Docker compose service |
| `make stop` | Stop the Docker compose service |
| `make logs` | Follow container logs |

## Configuration

Configuration is YAML. By default the app loads `./config.yaml`; set `ACME_API_CONFIG=/path/to/config.yaml` to override it. See `config.example.yaml` for a complete reference.

Certificate issuance requires:

- one or more `acme_accounts`
- one or more `dns_providers`
- a DNS provider env file readable by the container
- at least one bootstrap API key in `api_keys`

Example certificate request:

```json
{
  "name": "wildcard-example",
  "domains": ["*.example.com", "example.com"],
  "acme_account_ref": "letsencrypt-production",
  "dns_provider_ref": "production",
  "key_algorithm": "ecdsa"
}
```

## REST API

OpenAPI is generated at `/openapi.json`; Swagger UI is available at `/docs`.

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/health` | none | Liveness probe with uptime |
| `GET` | `/ready` | none | DB and `acme.sh` readiness |
| `POST` | `/v1/certificates` | operator | Create and queue issuance |
| `GET` | `/v1/certificates` | readonly | List certificates |
| `GET` | `/v1/certificates/{id}` | readonly | Read certificate details |
| `POST` | `/v1/certificates/{id}/renew` | operator | Queue manual renewal |
| `DELETE` | `/v1/certificates/{id}` | operator | Soft-delete as revoked |
| `GET` | `/v1/accounts` | readonly | List configured ACME accounts |
| `GET` | `/v1/providers` | readonly | List configured DNS providers |
| `GET` | `/v1/events` | readonly | Query audit events |

Authenticated requests use bearer API keys:

```sh
curl \
  -H "Authorization: Bearer $ACME_API_KEY" \
  http://localhost:8080/v1/certificates
```

## Certificate Deployment

Successful issuance and renewal deploy artifacts under the first requested domain:

```text
/certificates/example.com/
    cert.pem
    chain.pem
    fullchain.pem
    privkey.pem
    metadata.json
```

Files are copied to temporary names, flushed, permissioned, and atomically renamed into place. Default permissions are `0644` for certificate files and `0600` for private keys.

## Architecture

```text
                    REST API
                        |
        +---------------+---------------+
        |                               |
 Certificate Lifecycle          Renewal Scheduler
        |                               |
        +---------------+---------------+
                        |
                  ACME Backend
                        |
                    acme.sh
```

The public API is independent of the ACME backend. v1 supports DNS-01 through `acme.sh`; future backends can be added behind the same internal protocol.

## Non-Goals For v1

- HTTP-01 validation
- TLS-ALPN-01 validation
- per-request DNS credentials
- web UI
- high availability or clustering
- implementing the ACME protocol directly

