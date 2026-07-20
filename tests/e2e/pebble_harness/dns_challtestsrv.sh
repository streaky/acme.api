#!/usr/bin/env sh
# shellcheck shell=sh
# acme.sh dnsapi hook for Pebble's challtestsrv (test-only).
#
# Publishes DNS-01 TXT records via the challtestsrv management API instead of
# a real DNS provider. Mounted into acme.sh's dnsapi directory by
# docker-compose.harness.yaml and selected with `--dns dns_challtestsrv`.
#
# Configuration (from the provider's env_vars_file):
#   CHALLTESTSRV_URL - challtestsrv management endpoint
#                      (default: http://pebble-challtestsrv:8055)

# Usage: dns_challtestsrv_add _acme-challenge.example.test "txt-value"
dns_challtestsrv_add() {
  _ct_host="$1"
  _ct_value="$2"
  _ct_api="${CHALLTESTSRV_URL:-http://pebble-challtestsrv:8055}"
  curl -fsS -X POST "${_ct_api}/set-txt" \
    -d "{\"host\":\"${_ct_host}.\",\"value\":\"${_ct_value}\"}"
}

# Usage: dns_challtestsrv_rm _acme-challenge.example.test "txt-value"
dns_challtestsrv_rm() {
  _ct_host="$1"
  _ct_api="${CHALLTESTSRV_URL:-http://pebble-challtestsrv:8055}"
  curl -fsS -X POST "${_ct_api}/clear-txt" \
    -d "{\"host\":\"${_ct_host}.\"}"
}
