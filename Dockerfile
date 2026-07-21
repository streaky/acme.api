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

ARG ACME_SH_VERSION=3.1.4
ARG ACME_SH_SHA256=e5f8e187bbf5251e0cd8891f2622daab9850366bd17bea9f92c2fe2ee091fd32

ENV ACME_API_CONFIG=/config/config.yaml \
    ACME_API_HOST=0.0.0.0 \
    ACME_API_PORT=8080 \
    ACME_SH_HOME=/acmesh \
    ACME_SH_PATH=/usr/local/bin/acme.sh \
    PATH="/opt/venv/bin:/home/acmeapi/.local/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl openssl socat \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --home-dir /home/acmeapi --shell /usr/sbin/nologin acmeapi \
    && mkdir -p /config /data /certificates /acmesh /opt/acme.sh \
    && chown -R acmeapi:acmeapi /config /data /certificates /acmesh /home/acmeapi \
    && tmp_dir="$(mktemp -d)" \
    && archive="$tmp_dir/acme.sh.tar.gz" \
    && curl -fsSL "https://github.com/acmesh-official/acme.sh/archive/refs/tags/${ACME_SH_VERSION}.tar.gz" -o "$archive" \
    && echo "${ACME_SH_SHA256}  $archive" | sha256sum -c - \
    && tar -xzf "$archive" -C "$tmp_dir" --strip-components=1 \
    && cd "$tmp_dir" \
    && HOME=/home/acmeapi sh ./acme.sh --install --nocron --home /opt/acme.sh \
    && ln -sf /opt/acme.sh/acme.sh /usr/local/bin/acme.sh \
    && rm -rf "$tmp_dir" \
    && chown -R acmeapi:acmeapi /acmesh /home/acmeapi /opt/acme.sh

COPY --from=builder /opt/venv /opt/venv
COPY docker/entrypoint.sh /usr/local/bin/acme-api-entrypoint

RUN chmod +x /usr/local/bin/acme-api-entrypoint

USER acmeapi
WORKDIR /app

COPY --chown=acmeapi:acmeapi alembic.ini ./
COPY --chown=acmeapi:acmeapi alembic ./alembic

#EXPOSE 8080
VOLUME ["/config", "/data", "/certificates", "/acmesh"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${ACME_API_PORT}/health" >/dev/null || exit 1

ENTRYPOINT ["acme-api-entrypoint"]
CMD ["acme-api"]
