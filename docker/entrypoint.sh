#!/bin/sh
set -eu

ACME_SH_PATH="${ACME_SH_PATH:-/usr/local/bin/acme.sh}"

mkdir -p /config /data /certificates /acmesh "$(dirname "$ACME_SH_PATH")"

exec "$@"
