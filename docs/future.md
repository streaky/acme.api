# Future Work

This document captures useful ideas that are intentionally outside the immediate v1 implementation path.

## Observability

### Prometheus Metrics

Prometheus-compatible metrics are useful, but should wait until the certificate lifecycle service boundary is stable. Metrics added too early risk counting helper-level activity instead of real user-visible lifecycle outcomes.

Potential metrics:

* `certificates_total`
* `certificates_expiring`
* `renewals_total`
* `renewals_failed_total`
* `webhook_deliveries_total`
* `webhook_failures_total`

Potential endpoint:

* `GET /metrics`

Before implementing metrics, decide:

* Whether Prometheus should be a hard runtime dependency or optional extra.
* Whether `/metrics` requires auth or is intended for a trusted network only.
* Which events are counted: requested, started, completed, failed, retried, or deployed.
* How to handle process restarts with SQLite-backed state and in-memory counters.

## ACME and Validation

* Additional ACME backends.
* HTTP-01 support.
* TLS-ALPN-01 support.
* ACME External Account Binding (EAB).

### Pebble / Staging E2E Tests

The default test suite should stay deterministic and mock-backed, but a separate
real-ACME compatibility suite would be useful for hardening releases.

Potential shape:

* Add `tests/e2e/` with `@pytest.mark.e2e` tests excluded from the default gate.
* Add a `make e2e` target that only runs when explicit prerequisites are present.
* Exercise `acme.sh` against Pebble or Let's Encrypt staging with DNS-01 credentials
  supplied through secrets or local env files.
* Verify the minimal full path: app/container starts, certificate request is accepted,
  ACME issuance succeeds, artifacts deploy, and the certificate becomes `valid`.
* Run in CI only through `workflow_dispatch`, scheduled nightly jobs, or protected
  secret-backed environments to avoid flaky pull request gates.

## Deployment Targets

* Remote deployment targets such as SSH, Kubernetes Secrets, S3-compatible object storage, or Vault.
* Multi-node deployments.

## Product Surface

* Web administration interface.
* Fine-grained permissions.
* Event streaming.
* CLI generated from the OpenAPI specification.
* Certificate inventory search.
* CA-level certificate revocation.
