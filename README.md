# acme.api

Lightweight, self-hosted REST service for managing ACME certificates through a modern API while delegating ACME protocol work to `acme.sh`.

## Warning

This project is entirely experimental currently. Do not use it for production, important certificates, or anything you are not prepared to delete and rebuild.

`acme.api` is meant to be consumed only by applications that enforce strict access controls as part of the application stack — it is never intended for direct exposure on the internet or general internal systems. A system like this has severe security implications if misconfigured or misused, and the author is not responsible for any damage caused by its use. I considered a tool like this to be necessary for some specific systems I was working on, and I'd have had to essentially build it regardless as part of that other system, so I thought why not genericize it and share it.

## Status

Prototype v1 implementation. The core API, SQLite state, API key auth, `acme.sh` backend wrapper, atomic certificate deployment, renewal scheduler, lifecycle webhooks, health/readiness probes, Docker packaging, mock-backed end-to-end integration tests, and GitHub Actions CI are implemented. Real staging/Pebble ACME tests remain optional and credential-gated.

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

The bundled compose config at `docker/config.yaml` is intentionally minimal so the service can boot for health checks. For real issuance, copy `config.example.yaml`, configure ACME accounts, DNS provider aliases, and credential file mounts, then set `ACME_API_CONFIG` to that file inside the container.

## Local Development

```sh
make dev
make verify
```

Useful targets:

| Command | Description |
|---|---|
| `make test` | Run the unit, integration, and ordinary end-to-end suites plus coverage gates |
| `make test-unit` | Run deterministic unit tests |
| `make test-integration` | Run mock-backed integration tests |
| `make test-e2e` | Run the Pebble-backed Docker Compose end-to-end test stack |
| `make deps-check` | Verify `uv.lock` and both hashed requirements exports |
| `make deps-update` | Upgrade dependencies and regenerate `uv.lock` and exports |
| `make format-check` | Check Ruff formatting |
| `make lint` | Run Ruff and Pylint |
| `make type-check` | Run strict type checking |
| `make verify` | Run the full local quality and test gate |
| `make simulate-ci` | Execute the GitHub Actions workflow locally with `act` |
| `make build` | Build the Docker image |
| `make start` | Start the Docker compose service |
| `make stop` | Stop the Docker compose service |
| `make logs` | Follow container logs |

Development uses `uv` for locking and export verification. `make dev` follows Vulpine's hashed-install workflow: it bootstraps `.venv` and installs `requirements-dev.txt` with `--require-hashes --no-deps`.


## Configuration

Configuration is YAML. By default the app loads `./config.yaml`; set `ACME_API_CONFIG=/path/to/config.yaml` to override it. See `config.example.yaml` for a complete reference.

Certificate issuance requires an `acme_accounts` entry and an authenticated API
client. Fresh acme.api installations intentionally create no API clients:

```sh
printf '%s' "$ADMIN_KEY" | acme-api admin initialize --key-stdin
```

This stdin-only command is the one-time local administrative trust boundary and
can run only while the persisted API-client table is empty. It creates the
initial `admin` client; afterward, authenticated admins create, rotate, revoke,
and list `admin`, `operator`, and `readonly` clients at `/v1/admin/clients`.
Configuration has no `api_keys` setting. If every admin credential is lost,
stop the service, back up the database, and remove only the API-client records;
preserve certificate, account, renewal, deployment, and audit rows. Standard
DNS-01 issuance additionally requires a configured `dns_providers` alias and a
provider credential file readable by the container. DNS Persist issuance does
not require either: its one-time TXT record is generated from the selected account.

### Deployment configuration

`deployment.directory` is the artifact root. Mount it read/write only in the
acme.api container and read-only in certificate consumers. `permissions_cert`
and `permissions_key` are decimal file modes; their defaults are `420` (`0644`)
and `384` (`0600`) respectively.

Set `deployment.artifact_group_id` only when a separate unprivileged consumer
must read private keys. It is a numeric GID, not a group name, and acme.api must
run with that GID as a supplementary group. If it cannot assign the group to a
deployment directory or artifact, issuance or renewal records a deployment
failure rather than publishing an unexpected access policy. A typical
shared-volume configuration uses `permissions_key: 416` (`0640`) and grants

read-only consumers membership in the same GID. When configured, acme.api sets
directories it owns—or whose group it changes—to that group with `0750` mode,
ensuring consumers can traverse them even with a restrictive umask.
Pre-provisioned directories owned by another user retain their ownership and
mode only when they already belong to the configured GID, so a non-root service
can use an administrator-managed volume without `CAP_CHOWN`.

Enable `deployment.generation_aware` to preserve every successful issuance or
renewal as an immutable artifact set. acme.api publishes a complete generation
directory, then atomically switches the `current` symlink. The established
`cert.pem`, `chain.pem`, `fullchain.pem`, `privkey.pem`, and `metadata.json`
paths become symlinks through that pointer, so existing consumers keep their
predictable paths. `generation_retention_count` and
`generation_retention_days` may be set independently; a generation is removed
only when it exceeds every configured limit. The selected generation and any
explicitly pinned generation are never removed.

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

### DNS Persist certificates

For a zone managed manually, create a request with `"challenge_method": "dns-persist"` and
omit `dns_provider_ref`. The response remains `pending_dns` and contains an account-bound
TXT instruction at `_validation-persist.<primary-domain>`. Publish that exact value and
retain it for the certificate's lifetime, then call `POST /v1/certificates/{id}/authorize`.
The service issues with the selected account only after that explicit authorization. DNS Persist
SANs must be the primary domain or its subdomains. Multi-SAN and wildcard requests receive a
`policy=wildcard` instruction, which deliberately authorizes that primary domain's subdomains;
use separate requests for unrelated domains.

Creation with the same name, domains, and account resumes the stored request and instruction;
it does not create another ACME order. A different account creates a distinct instruction and
cannot replace an existing request's account. Once valid, DNS Persist certificates renew
unattended through the normal scheduler without DNS provider credentials or another TXT update.
The instruction is returned only from authenticated certificate endpoints.

#### Held DNS Persist workflow

Set `"held": true` when creating a DNS Persist request to persist its stable TXT
instruction without allowing issuance. After publishing the record, call
`POST /v1/certificates/{id}/authorize`; this advances the request to
`authorization_ready` but still does not issue. To release the current prepared
revision, call `POST /v1/certificates/{id}/release` with an `Idempotency-Key`
header and a JSON body containing the response's current `revision`, for example:

```json
{"revision": 1}
```

Release is accepted only once for that revision and queues asynchronous issuance.
Retry the same request with the same idempotency key if the client does not receive
the response; a retry also re-queues issuance if the stored request is still
`released`. Delete a held, authorization-ready, released, or release-derived
issuing request to cancel it.

## REST API

OpenAPI is generated at `/openapi.json`; Swagger UI is available at `/docs`.

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/health` | none | Liveness probe with uptime |
| `GET` | `/ready` | none | DB and `acme.sh` readiness |
| `POST` | `/v1/certificates` | operator | Create a certificate request; DNS Persist returns its stored TXT instruction |
| `GET` | `/v1/certificates` | readonly | List certificates |
| `GET` | `/v1/certificates/{id}` | readonly | Read certificate detail and DNS Persist instruction |
| `POST` | `/v1/certificates/{id}/authorize` | operator | Authorize or retry DNS Persist issuance after publishing TXT |
| `POST` | `/v1/certificates/{id}/release` | operator | Release a held DNS Persist revision; requires `Idempotency-Key` and `{ "revision": n }` |
| `POST` | `/v1/certificates/{id}/renew` | operator | Queue manual renewal |
| `POST` | `/v1/certificates/{id}/revoke` | operator | Revoke the issued primary domain through acme.sh; requires `Idempotency-Key` |
| `DELETE` | `/v1/certificates/{id}` | operator | Soft-delete as revoked |
| `GET` | `/v1/accounts` | readonly | List configured ACME accounts |
| `GET` | `/v1/providers` | readonly | List configured DNS providers |
| `GET` | `/v1/events` | readonly | Query audit events |
| `GET` | `/v1/admin/clients` | admin | List safe API-client metadata |
| `POST` | `/v1/admin/clients` | admin | Create an API client and return its credential once |
| `POST` | `/v1/admin/clients/{id}/rotate` | admin | Rotate a client credential and return its replacement once |
| `POST` | `/v1/admin/clients/{id}/revoke` | admin | Revoke an API client |

Authenticated requests use bearer API keys:

```sh
curl \
  -H "Authorization: Bearer $ACME_API_KEY" \
  http://localhost:8080/v1/certificates
```

### Certificate revocation

`DELETE /v1/certificates/{id}` only changes the local request record; it does
not contact a certificate authority. To revoke an issued certificate at its
configured CA, call `POST /v1/certificates/{id}/revoke` with an
`Idempotency-Key` header and, optionally, an RFC 5280 reason:

```sh
curl -X POST \
  -H "Authorization: Bearer $ACME_API_KEY" \
  -H "Idempotency-Key: revoke-example-20260724" \
  -H "Content-Type: application/json" \
  --data '{"reason": 1}' \
  http://localhost:8080/v1/certificates/$CERTIFICATE_ID/revoke
```

The operation invokes acme.sh as `--revoke --domain <primary-domain>` and adds
`--revoke-reason` when requested. It does not delete deployed artifacts,
disable renewal, or otherwise modify the local certificate record. Reusing the
same key returns the durable original result without another acme.sh command.
Reasons `0` through `10` are accepted except `7`, which RFC 5280 leaves unused.

## Certificate Deployment

Successful issuance and renewal deploy artifacts under the `deployment_directory`
reported by every authenticated certificate API response, relative to the configured
deployment root. For ordinary certificates it is the first requested domain:

```text
/certificates/example.com/
    cert.pem
    chain.pem
    fullchain.pem
    privkey.pem
    metadata.json
```


With generation-aware deployment enabled, each immutable publication is stored
below a dedicated namespace:

```text
/certificates/example.com/
    current -> generations/<generation_id>
    fullchain.pem -> current/fullchain.pem
    privkey.pem -> current/privkey.pem
    generations/<generation_id>/
        cert.pem
        chain.pem
        fullchain.pem
        privkey.pem
        metadata.json
```

The `generations/` component is intentional rather than redundant: it
unambiguously separates immutable historical artifacts from the stable
compatibility projection and future deployment control files.
Wildcard domains use a portable collision-free name: a request for
`*.example.com` reports `deployment_directory: "@wildcard@.example.com"` and
deploys under `/certificates/@wildcard@.example.com/`. This cannot collide with a
separate request for the valid literal name `wildcard.example.com`. Clients
consuming the shared certificate volume must always resolve artifact paths from
the API's `deployment_directory` field, never derive them from the requested identifier.

Files are copied to temporary names. acme.api assigns configured group and mode
through each open file descriptor, then fsyncs the content and access-control
metadata before atomically renaming artifacts into place. It also sets the
deployment root and target directory to the configured group with `0750`
traversal mode. The same process runs for initial issuance and renewal, so
consumers never need to repair ownership or permissions themselves.

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
