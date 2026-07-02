#!/bin/sh
set -eu

ACME_SH_PATH="${ACME_SH_PATH:-/home/acmeapi/.local/bin/acme.sh}"
ACME_SH_HOME="${ACME_SH_HOME:-/home/acmeapi/.acme.sh}"

mkdir -p /config /data /certificates /acmesh "$(dirname "$ACME_SH_PATH")"

if [ ! -x "$ACME_SH_PATH" ]; then
    tmp_dir="$(mktemp -d)"
    trap 'rm -rf "$tmp_dir"' EXIT
    curl -fsSL https://github.com/acmesh-official/acme.sh/archive/master.tar.gz \
        | tar -xz -C "$tmp_dir" --strip-components=1
    cd "$tmp_dir"
    HOME=/home/acmeapi sh ./acme.sh --install --nocron --home "$ACME_SH_HOME"
    ln -sf "$ACME_SH_HOME/acme.sh" "$ACME_SH_PATH"
fi

exec "$@"
