FROM python:3.14-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

COPY requirements.txt ./
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip setuptools wheel \
    && /opt/venv/bin/pip install -r requirements.txt

COPY pyproject.toml README.md ./
COPY acme_api ./acme_api
RUN /opt/venv/bin/pip install --no-deps .

FROM python:3.14-slim AS runner

ENV ACME_API_CONFIG=/config/config.yaml \
    ACME_API_HOST=0.0.0.0 \
    ACME_API_PORT=8080 \
    PATH="/opt/venv/bin:/home/acmeapi/.local/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl openssl socat \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --home-dir /home/acmeapi --shell /usr/sbin/nologin acmeapi \
    && mkdir -p /config /data /certificates /acmesh /home/acmeapi/.local/bin \
    && chown -R acmeapi:acmeapi /config /data /certificates /acmesh /home/acmeapi

COPY --from=builder /opt/venv /opt/venv
COPY docker/entrypoint.sh /usr/local/bin/acme-api-entrypoint

RUN chmod +x /usr/local/bin/acme-api-entrypoint

USER acmeapi
WORKDIR /app

EXPOSE 8080
VOLUME ["/config", "/data", "/certificates", "/acmesh"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${ACME_API_PORT}/health" >/dev/null || exit 1

ENTRYPOINT ["acme-api-entrypoint"]
CMD ["acme-api"]

