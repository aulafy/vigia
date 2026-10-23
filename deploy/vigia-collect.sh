#!/bin/sh
# Collect what this server actually runs and push it to Vigía, signed. POSIX sh + openssl + curl.
#
#   vigia-collect.sh [asset-id] [sources…] [--dry-run]
#
# Installed by the one-line installer (install.sh), it runs daily as `vigia-collect --all` and reads its address, asset and key
# from /etc/vigia/agent.env (as root) or ~/.config/vigia/agent.env.
#
# Sources (combine as many as apply):
#   --wp DIR            WordPress core, plugins and themes via WP-CLI (set WP_CLI="wp --allow-root" if run as root)
#   --npm FILE          package-lock.json (production dependencies only)
#   --composer FILE     composer.lock (production packages only)
#   --cyclonedx FILE    CycloneDX JSON SBOM (e.g. from `syft dir:/srv/app -o cyclonedx-json` or `trivy fs --format cyclonedx`)
#   --spdx FILE         SPDX JSON SBOM
#   --os                operating system from /etc/os-release (Linux) or sw_vers (macOS)
#   --runtimes          versions of php, node, nginx, apache, mysql/mariadb, postgresql, redis, openssl found on PATH
#   --listening         TCP ports this machine listens on, from ss / netstat (Linux) or lsof (macOS). Nothing is scanned.
#   --av                antivirus: ClamAV, Microsoft Defender (mdatp), CrowdStrike, SentinelOne, Sophos, ESET; XProtect on macOS
#   --software          installed packages (dpkg / rpm / apk) or macOS applications, matched against exploited software
#   --all               --os --runtimes --listening --av --software
#   --dry-run           print the JSON instead of sending it
#
# Environment: VIGIA_URL, VIGIA_CHECKIN_SECRET (this asset's key: `node server.mjs key <asset-id>` on the Vigía host,
#              never the master CHECKIN_SECRET)
#
# Example (cron, daily):
#   15 3 * * * VIGIA_URL=https://vigia.example.com VIGIA_CHECKIN_SECRET=… /usr/local/bin/vigia-collect.sh acme-shop --wp /var/www/html --os --runtimes
set -eu
PATH=$PATH:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin

if [ -z "${VIGIA_URL:-}" ]; then
  for f in "${VIGIA_AGENT_ENV:-}" /etc/vigia/agent.env "${HOME:-/nonexistent}/.config/vigia/agent.env"; do
    if [ -n "$f" ] && [ -r "$f" ]; then . "$f"; break; fi
  done
fi
case ${1:-} in --*|'') ASSET=${VIGIA_ASSET:-} ;; *) ASSET=$1; shift ;; esac
[ -n "$ASSET" ] && [ $# -ge 1 ] || { sed -n '3,30p' "$0" >&2; exit 2; }
TMP=$(mktemp); PARTS=$(mktemp)
trap 'rm -f "$TMP" "$PARTS"' EXIT
WP=${WP_CLI:-wp}
DRY=0

jstr() { printf '%s' "$1" | tr -d '\000-\037' | sed 's/\\/\\\\/g; s/"/\\"/g'; }   # escape a short string for JSON (control characters dropped)
add() { if [ -s "$PARTS" ]; then printf ',' >> "$PARTS"; fi; cat >> "$PARTS"; }
file_part() { [ -r "$2" ] || { echo "cannot read $2" >&2; exit 1; }; { printf '{"kind":"%s","%s":' "$1" "$3"; cat "$2"; printf '}'; } | add; }
runtime() { if [ -n "$2" ]; then printf '{"kind":"runtime","name":"%s","version":"%s"}' "$1" "$(jstr "$2")" | add; fi; }
has() { command -v "$1" >/dev/null 2>&1; }
OSNAME=$(uname -s)
# one JSON object per line on stdin → "a,b,c"
joinl() { sed '/^$/d' | paste -sd, -; }

listening() {
  if [ "$OSNAME" = Darwin ]; then
    # lsof lists every process when run as root (the installed daemon is)
    lsof +c 0 -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1 { n=$9; p=n; sub(/.*:/, "", p); a=n; sub(/:[0-9]+$/, "", a); gsub(/[][]/, "", a); print "tcp\t" a "\t" p "\t" $1 }'
  elif has ss; then
    ss -Hltnp 2>/dev/null | awk '{ n=$4; p=n; sub(/.*:/, "", p); a=n; sub(/:[0-9]+$/, "", a); gsub(/[][]/, "", a); c=""; if (match($0, /users:\(\("[^"]+"/)) c=substr($0, RSTART+9, RLENGTH-10); print "tcp\t" a "\t" p "\t" c }'
  elif has netstat; then
    netstat -ltn 2>/dev/null | awk '$1 ~ /^tcp/ { n=$4; p=n; sub(/.*:/, "", p); a=n; sub(/:[0-9]+$/, "", a); print "tcp\t" a "\t" p "\t" }'
  fi | sort -u | while IFS="$(printf '\t')" read -r PROTO ADDR PORT CMD; do
    case $PORT in ''|*[!0-9]*) continue ;; esac
    printf '{"proto":"%s","addr":"%s","port":%s,"process":"%s"}\n' "$PROTO" "$(jstr "$ADDR")" "$PORT" "$(jstr "$CMD")"
  done | joinl
}

av_product() { printf '{"name":"%s","enabled":%s,"upToDate":%s,"signaturesAt":%s,"version":"%s"}\n' "$1" "$2" "$3" "$4" "$(jstr "$5")"; }
antivirus() {
  if has clamscan || has freshclam; then
    V=$( (clamscan --version || freshclam --version) 2>/dev/null | head -1)     # ClamAV 1.0.7/27440/Wed Oct 22 08:30:56 2025
    D=$(printf '%s' "$V" | cut -d/ -f3); AT=null
    if [ -n "$D" ] && T=$(date -u -d "$D" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null); then AT="\"$T\""; fi
    EN=null; if has systemctl; then if systemctl is-active -q clamav-daemon 2>/dev/null || systemctl is-active -q clamav-freshclam 2>/dev/null; then EN=true; fi; fi
    av_product ClamAV "$EN" null "$AT" "$(printf '%s' "$V" | sed -n 's#^ClamAV \([^/]*\).*#\1#p')"
  fi
  if has mdatp; then
    RT=$(mdatp health --field real_time_protection_enabled 2>/dev/null | tr -d '" ' || true)
    UP=$(mdatp health --field definitions_status 2>/dev/null | tr -d '" ' || true)
    av_product "Microsoft Defender" "$( [ "$RT" = true ] && echo true || echo false )" "$( [ -z "$UP" ] && echo null || { [ "$UP" = up_to_date ] && echo true || echo false; } )" null "$(mdatp version 2>/dev/null | sed -n 's/.*: *//p' | head -1)"
  fi
  for P in "CrowdStrike Falcon:/opt/CrowdStrike/falconctl" "SentinelOne:/opt/sentinelone" "Sophos:/opt/sophos-spl" "ESET:/opt/eset" "Bitdefender:/opt/bitdefender-security-tools" \
           "CrowdStrike Falcon:/Applications/Falcon.app" "SentinelOne:/Applications/SentinelOne" "Sophos:/Applications/Sophos" "ESET:/Applications/ESET Endpoint Security.app"; do
    if [ -e "${P#*:}" ]; then av_product "${P%%:*}" null null null ""; fi
  done
  # XProtect updates every few weeks on its own schedule: reported, but its age is not judged
  X=/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist
  if [ "$OSNAME" = Darwin ] && [ -r "$X" ]; then av_product XProtect true null null "$(defaults read "${X%.plist}" CFBundleShortVersionString 2>/dev/null || true)"; fi
}

software() {
  if [ "$OSNAME" = Darwin ]; then
    for APP in /Applications/*.app /Applications/*/*.app; do
      [ -d "$APP" ] || continue
      N=$(basename "$APP" .app); V=$(defaults read "$APP/Contents/Info" CFBundleShortVersionString 2>/dev/null || true)
      printf '{"name":"%s","version":"%s"}\n' "$(jstr "$N")" "$(jstr "$V")"
    done
  elif has dpkg-query; then dpkg-query -W -f='${Package}\t${Version}\n' 2>/dev/null
  elif has rpm; then rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' 2>/dev/null
  elif has apk; then apk info -v 2>/dev/null | sed 's/-\([0-9][^-]*-r[0-9]*\)$/\t\1/'
  fi | head -3000 | while IFS="$(printf '\t')" read -r N V; do
    case $N in '{'*) printf '%s\n' "$N" ;; *) printf '{"name":"%s","version":"%s"}\n' "$(jstr "$N")" "$(jstr "$V")" ;; esac
  done | joinl
}

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
    --all) shift; set -- --os --runtimes --listening --av --software "$@"; continue ;;
    --os)
      if [ "$OSNAME" = Darwin ]; then
        printf '{"kind":"os","id":"macos","version":"%s","name":"macOS %s"}' "$(sw_vers -productVersion)" "$(sw_vers -productVersion)" | add
      elif [ -r /etc/os-release ]; then
        ( . /etc/os-release; printf '{"kind":"os","id":"%s","version":"%s","name":"%s"}' "$(jstr "$ID")" "$(jstr "${VERSION_ID:-}")" "$(jstr "${PRETTY_NAME:-$ID}")" ) | add
      else echo "no /etc/os-release, skipping --os" >&2; fi ;;
    --listening) printf '{"kind":"listening","ports":[%s]}' "$(listening)" | add ;;
    --av) printf '{"kind":"av","products":[%s]}' "$(antivirus | joinl)" | add ;;
    --software) printf '{"kind":"software","items":[%s]}' "$(software)" | add ;;
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
