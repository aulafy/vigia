#!/bin/sh
# Collect what this server actually runs and push it to Vigía, signed. POSIX sh + openssl + curl.
#
#   vigia-collect.sh <asset-id> [sources…] [--dry-run]
#
# Sources (combine as many as apply):
#   --wp DIR            WordPress core, plugins and themes via WP-CLI (set WP_CLI="wp --allow-root" if run as root)
#   --npm FILE          package-lock.json (production dependencies only)
#   --composer FILE     composer.lock (production packages only)
#   --cyclonedx FILE    CycloneDX JSON SBOM (e.g. from `syft dir:/srv/app -o cyclonedx-json` or `trivy fs --format cyclonedx`)
#   --spdx FILE         SPDX JSON SBOM
#   --os                operating system from /etc/os-release
#   --runtimes          versions of php, node, nginx, apache, mysql/mariadb, postgresql, redis, openssl found on PATH
#   --dry-run           print the JSON instead of sending it
#
# Environment: VIGIA_URL, VIGIA_CHECKIN_SECRET (this asset's key: `node server.mjs key <asset-id>` on the Vigía host,
#              never the master CHECKIN_SECRET)
#
# Example (cron, daily):
#   15 3 * * * VIGIA_URL=https://vigia.example.com VIGIA_CHECKIN_SECRET=… /usr/local/bin/vigia-collect.sh acme-shop --wp /var/www/html --os --runtimes
set -eu

[ $# -ge 2 ] || { sed -n '3,20p' "$0" >&2; exit 2; }
ASSET=$1; shift
TMP=$(mktemp); PARTS=$(mktemp)
trap 'rm -f "$TMP" "$PARTS"' EXIT
WP=${WP_CLI:-wp}
DRY=0

jstr() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }   # escape a short string for JSON
add() { if [ -s "$PARTS" ]; then printf ',' >> "$PARTS"; fi; cat >> "$PARTS"; }
file_part() { [ -r "$2" ] || { echo "cannot read $2" >&2; exit 1; }; { printf '{"kind":"%s","%s":' "$1" "$3"; cat "$2"; printf '}'; } | add; }
runtime() { if [ -n "$2" ]; then printf '{"kind":"runtime","name":"%s","version":"%s"}' "$1" "$(jstr "$2")" | add; fi; }
has() { command -v "$1" >/dev/null 2>&1; }

while [ $# -gt 0 ]; do
  case $1 in
    --wp)
      D=$2; shift
      CORE=$($WP --path="$D" core version)
      { printf '{"kind":"wp","core":"%s","plugins":' "$(jstr "$CORE")"
        $WP --path="$D" plugin list --format=json --fields=name,status,version
        printf ',"themes":'
        $WP --path="$D" theme list --format=json --fields=name,status,version
        printf '}'; } | add ;;
    --npm) file_part npm-lock "$2" lock; shift ;;
    --composer) file_part composer-lock "$2" lock; shift ;;
    --cyclonedx) file_part cyclonedx "$2" bom; shift ;;
    --spdx) file_part spdx "$2" doc; shift ;;
    --os)
      if [ -r /etc/os-release ]; then
        ( . /etc/os-release; printf '{"kind":"os","id":"%s","version":"%s"}' "$(jstr "$ID")" "$(jstr "${VERSION_ID:-}")" ) | add
      else echo "no /etc/os-release, skipping --os" >&2; fi ;;
    --runtimes)
      if has php; then runtime php "$(php -r 'echo PHP_VERSION;' 2>/dev/null)"; fi
      if has node; then runtime nodejs "$(node -v 2>/dev/null)"; fi
      if has nginx; then runtime nginx "$(nginx -v 2>&1 | sed -n 's#.*nginx/\([0-9.]*\).*#\1#p')"; fi
      if has apache2 || has httpd; then runtime apache "$( (apache2 -v || httpd -v) 2>/dev/null | sed -n 's#.*Apache/\([0-9.]*\).*#\1#p')"; fi
      if has mysql; then
        V=$(mysql --version 2>/dev/null)
        case $V in
          *MariaDB*) runtime mariadb "$(printf '%s' "$V" | sed -n 's/.*[ -]\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)-MariaDB.*/\1/p')" ;;
          *) runtime mysql "$(printf '%s' "$V" | sed -n 's/.*Ver \([0-9][0-9.]*\).*/\1/p')" ;;
        esac
      fi
      if has psql; then runtime postgresql "$(psql --version | sed -n 's/.* \([0-9][0-9.]*\).*/\1/p')"; fi
      if has redis-server; then runtime redis "$(redis-server --version | sed -n 's/.*v=\([0-9.]*\).*/\1/p')"; fi
      if has openssl; then runtime openssl "$(openssl version | sed -n 's/^OpenSSL \([0-9][0-9.]*\).*/\1/p')"; fi ;;
    --dry-run) DRY=1 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

{ printf '{"host":"%s","collectedAt":"%s","parts":[' "$(jstr "$(hostname)")" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"; cat "$PARTS"; printf ']}'; } > "$TMP"
if [ "$DRY" = 1 ]; then cat "$TMP"; echo; exit 0; fi

: "${VIGIA_URL:?set VIGIA_URL}"
: "${VIGIA_CHECKIN_SECRET:?set VIGIA_CHECKIN_SECRET}"
P="/api/inventory/$ASSET"
TS=$(date +%s)
SIG=$({ printf '%s.%s.' "$TS" "$P"; cat "$TMP"; } | openssl dgst -sha256 -hmac "$VIGIA_CHECKIN_SECRET" | sed 's/^.*= *//')
curl -fsS --max-time 120 -X POST "${VIGIA_URL%/}$P" \
  -H "content-type: application/json" \
  -H "x-vigia-timestamp: $TS" \
  -H "x-vigia-signature: $SIG" \
  --data-binary @"$TMP"
echo
