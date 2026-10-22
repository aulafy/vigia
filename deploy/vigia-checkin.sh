#!/bin/sh
# Report a backup run to Vigía. POSIX sh + openssl + curl, nothing else.
#
#   vigia-checkin.sh <asset-id> <job-id> <start|success|fail|restore> [json-body]
#
# Environment:
#   VIGIA_URL               e.g. https://vigia.example.com
#   VIGIA_CHECKIN_SECRET    this asset's key: run `node server.mjs key <asset-id>` on the Vigía host.
#                           Never the master CHECKIN_SECRET: a key only works for its own asset.
#
# Examples:
#   vigia-checkin.sh acme-shop db success '{"bytes":123456789}'
#   vigia-checkin.sh acme-shop db fail '{"message":"pg_dump exited with 1"}'
#   vigia-checkin.sh acme-shop db restore
set -eu

[ $# -ge 3 ] || { echo "usage: $0 <asset-id> <job-id> <start|success|fail|restore> [json-body]" >&2; exit 2; }
: "${VIGIA_URL:?set VIGIA_URL}"
: "${VIGIA_CHECKIN_SECRET:?set VIGIA_CHECKIN_SECRET}"

P="/api/backup/$1/$2?status=$3"
BODY=${4:-}
TS=$(date +%s)
SIG=$(printf '%s.%s.%s' "$TS" "$P" "$BODY" | openssl dgst -sha256 -hmac "$VIGIA_CHECKIN_SECRET" | sed 's/^.*= *//')

curl -fsS --max-time 20 -X POST "${VIGIA_URL%/}$P" \
  -H "content-type: application/json" \
  -H "x-vigia-timestamp: $TS" \
  -H "x-vigia-signature: $SIG" \
  --data "$BODY"
echo
