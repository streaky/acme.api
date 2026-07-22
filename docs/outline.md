# acme.api

## Overview

**acme.api** is a lightweight, self-hosted REST service for managing ACME certificates.

It provides a modern HTTP API, automatic renewals, webhook notifications and shared filesystem deployment, while delegating all ACME protocol implementation to a mature backend (initially `acme.sh`).

The project intentionally focuses on infrastructure integration rather than implementing the ACME protocol itself.

---

# Goals

* Provide a simple REST API for certificate lifecycle management.
* Support fully automated certificate issuance and renewal.
* Use proven ACME software rather than reimplementing the protocol.
* Be easy to deploy as a single Docker container.
* Be suitable for homelabs, hosting providers and internal infrastructure.
* Be completely open source.

---

# Non-Goals (v1)

The following are explicitly out of scope for the initial release:

* HTTP-01 validation
* TLS-ALPN-01 validation
* Per-request DNS credentials
* Web user interface
* High availability / clustering
* Certificate authority implementation
* Reimplementation of the ACME protocol

---

# Architecture

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

The ACME backend is considered an implementation detail.

The public API must remain independent from the backend implementation.

---

# Backend

Version 1 uses:

* acme.sh

Future versions may support:

* lego
* native implementation
* other ACME libraries

without changing the public API.

---

# Validation

## Supported

* DNS-01

## Required

* DNS Persist Mode

DNS providers are configured once by an administrator.

API clients reference configured providers by name.

Clients never transmit DNS credentials.

Example:

```json
{
  "name": "wildcard-example",
  "domains": [
    "*.example.com",
    "example.com"
  ],
  "dns_provider_ref": "production",
  "acme_account_ref": "letsencrypt-production",
  "key_algorithm": "ecdsa"
}
```

---

# ACME Accounts

The service manages one or more ACME accounts.

Example:

* letsencrypt-production
* letsencrypt-staging
* zerossl-production

Certificates reference an account by name.

---

# DNS Providers

DNS providers are administrator-defined aliases.

Example:

```
production
testing
internal
```

Each alias maps to the underlying acme.sh provider configuration.

Clients are unaware of the underlying provider implementation.

---

# REST API

## Certificates

```
POST   /v1/certificates

GET    /v1/certificates

GET    /v1/certificates/{id}

DELETE /v1/certificates/{id}

POST   /v1/certificates/{id}/renew
```

---

## Accounts

```
GET    /v1/accounts
```

---

## Providers

```
GET    /v1/providers
```

---

## Events

```
GET    /v1/events
```

---

## Health

```
GET    /health

GET    /ready
```

---

# Certificate Model

A certificate contains:

* unique identifier
* friendly name
* domains
* ACME account
* DNS provider
* key algorithm
* expiry date
* renewal policy
* current status
* metadata

Supported key algorithms:

* `ecdsa`
* `rsa-2048`
* `rsa-4096`

---

# Renewal

The service automatically renews certificates before expiry.

Renewal state is tracked internally.

Possible states include:

* Pending
* Issuing
* Valid
* Renewing
* Failed
* Revoked

---

# Shared Filesystem Deployment

Certificates are deployed into a shared filesystem.

Example layout:

```
/certificates/

    mail.example.com/

        cert.pem

        chain.pem

        fullchain.pem

        privkey.pem

        metadata.json
```

Deployment should be atomic.

Recommended process:

1. Write temporary files.
2. Flush to disk.
3. Atomic rename.
4. Emit webhook event.

Consumers never observe partially-written certificates.

Deployments can optionally assign artifacts to a configured consumer group. The
service must belong to that numeric group; private keys should use group-readable
`0640` mode while consumers mount the shared certificate storage read-only.

---

# Webhooks

Supported events include:

```
certificate.created

certificate.issued

certificate.renewed

certificate.failed

certificate.expiring

certificate.revoked
```

Webhook payload example:

```json
{
  "event": "certificate.renewed",
  "certificate_id": "0d15428a-9b52-4f1e-9965-31e57615c081",
  "certificate_name": "mail.example.com",
  "expiry": "2027-05-20T14:00:00+00:00",
  "domains": [
    "mail.example.com"
  ],
  "details": {}
}
```

Webhook requests are signed with `X-Webhook-Signature: sha256=<hmac>`.

---

# Security

Authentication should support:

* API Keys (v1)

Future versions may add:

* OAuth2
* OpenID Connect
* Mutual TLS

Authorization should be role-based.

Suggested roles:

* Administrator
* Operator
* Read Only

---

# Storage

Version 1 should use SQLite.

Persistent data includes:

* certificates
* bootstrap/API-managed API keys
* renewal schedule
* webhook configuration
* audit log

ACME accounts and DNS provider aliases are administrator-owned configuration
in v1 and are exposed through read-only API endpoints.

Certificate material remains on the filesystem.

---

# OpenAPI

The REST API should be fully described using OpenAPI.

Generated documentation should be published automatically.

---

# Container

Official Docker image.

Recommended persistent volumes:

```
/data

/certificates

/acmesh
```

The acme.sh home directory is mounted separately so its state survives upgrades.

---

# Logging

Structured JSON logging.

Support:

* stdout
* file output

Log levels:

* Error
* Warning
* Info
* Debug

---

# Design Principles

* API-first
* Backend-independent
* Simple deployment
* Opinionated defaults
* Minimal configuration
* No Kubernetes requirement
* No external database requirement
* No protocol reimplementation

---

# Future Roadmap

Potential future features include:

* Prometheus-compatible metrics
* Additional ACME backends
* HTTP-01 support
* TLS-ALPN-01 support
* ACME External Account Binding (EAB)
* Remote deployment targets (SSH, Kubernetes Secrets, S3, etc.)
* Certificate revocation
* Certificate inventory search
* Multi-node deployments
* Web administration interface
* Fine-grained permissions
* Event streaming
* CLI generated from the OpenAPI specification

---

# Philosophy

acme.api is not another ACME client.

It is a certificate management service with a clean REST interface that leverages mature, battle-tested ACME tooling underneath.

By separating the infrastructure API from the ACME implementation, applications integrate once with acme.api while remaining independent of the underlying ACME client.
