#!/usr/bin/env bash
# Vigía on a fresh Ubuntu 22.04+/Debian 12+ VPS, with HTTPS, in one command. Run as root:
#
#   curl -fsSL https://raw.githubusercontent.com/aulafy/vigia/main/deploy/vps/setup.sh | bash -s -- vigia.example.com
#
# Before running it, point the domain's DNS (an A record, and AAAA if the VPS has IPv6) to this server.
# What it does:
#   1. installs Docker if missing, and turns on the firewall (SSH, 80, 443 only)
#   2. writes /opt/vigia with docker-compose.yml, Caddyfile and an .env with fresh random secrets
#      (an existing .env is never overwritten: running it again only updates and restarts)
#   3. starts Vigía behind Caddy, which gets a Let's Encrypt certificate on its own
#   4. installs a daily backup of /opt/vigia/data (14 days kept in /opt/vigia/backups)
# Options (environment): VIGIA_LANG=es|en (default en) · VIGIA_DIR (default /opt/vigia) · VIGIA_NO_FIREWALL=1 · VIGIA_SETUP_DRY=1 (write files only)
set -euo pipefail

DOMAIN=${1:-}
DIR=${VIGIA_DIR:-/opt/vigia}
# where this script lives, when run from a checkout (worked out before any cd; empty when piped from curl)
here=$( [[ -f ${BASH_SOURCE[0]:-} ]] && cd "$(dirname "${BASH_SOURCE[0]}")" && pwd || true )
LANG_UI=${VIGIA_LANG:-en}
RAW=https://raw.githubusercontent.com/aulafy/vigia/main/deploy/vps
DRY=${VIGIA_SETUP_DRY:-0}
say() { printf '\033[1m%s\033[0m\n' "$*"; }
die() { printf 'vigia setup: %s\n' "$*" >&2; exit 1; }

[[ $DOMAIN =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$ ]] || die "usage: setup.sh <domain>   (for example vigia.example.com)"
[[ $LANG_UI =~ ^(en|es)$ ]] || die "VIGIA_LANG must be en or es"
if [[ $DRY != 1 ]]; then [[ $(id -u) == 0 ]] || die "run it as root (sudo -i)"; fi

# ---- 1. Docker and firewall ----
if [[ $DRY != 1 ]]; then
  if ! command -v docker >/dev/null || ! docker compose version >/dev/null 2>&1; then
    say "Installing Docker (official convenience script)…"
    curl -fsSL https://get.docker.com | sh
  fi
  if [[ ${VIGIA_NO_FIREWALL:-0} != 1 ]] && command -v ufw >/dev/null; then
    ufw allow OpenSSH >/dev/null; ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null
    ufw --force enable >/dev/null
    say "Firewall on: SSH, 80 and 443 only."
  fi
fi

# ---- 2. Files ----
mkdir -p "$DIR/data" "$DIR/backups"
cd "$DIR"
for f in docker-compose.yml Caddyfile; do
  if [[ -n $here && -f $here/setup.sh && -f $here/$f && $here != "$DIR" ]]; then cp "$here/$f" "$f"     # run from a checkout
  elif [[ ! -f $f || $DRY != 1 ]]; then curl -fsSL "$RAW/$f" -o "$f.tmp" && mv "$f.tmp" "$f"; fi
done

FIRST=0
if [[ ! -f .env ]]; then
  FIRST=1
  rand() { openssl rand -hex "$1"; }
  PASS=$(rand 12)
  umask 077
  cat > .env <<ENV
# Vigía on $DOMAIN, written by setup.sh on $(date -u +%F). Edit, then: cd $DIR && docker compose up -d
DOMAIN=$DOMAIN
PUBLIC_URL=https://$DOMAIN
VIGIA_LANG=$LANG_UI
DASH_PASS=$PASS
CHECKIN_SECRET=$(rand 32)
ACK_SECRET=$(rand 32)
NTFY_TOPIC=vigia-$(rand 8)
DIGEST_HOUR=9
DIGEST_TZ=Europe/Madrid

# Watch the watcher: create a free check at https://healthchecks.io (period 1 min, grace 5 min) and paste its ping URL
# HEARTBEAT_URL=

# Email (docs/alerts.md#email). Gmail/Workspace: smtp.gmail.com and an app password
# SMTP_HOST=smtp.gmail.com
# SMTP_PORT=587
# SMTP_USER=
# SMTP_PASS=
# MAIL_FROM=
# MAIL_TO=

# REPORT_BRAND=Your IT company
# WORDFENCE_API_KEY=        # free key; plan 1 GB of RAM with it
ENV
  chmod 600 .env
fi
# read back only what this script needs (never source .env: values like MAIL_FROM="Vigía <a@b>" are not shell)
envget() { sed -n "s/^$1=//p" .env | tail -n 1; }
DOMAIN=$(envget DOMAIN); DASH_PASS=$(envget DASH_PASS); NTFY_TOPIC=$(envget NTFY_TOPIC)
[[ -n $DOMAIN ]] || die ".env has no DOMAIN"

# ---- 3. Backups ----
if [[ $DRY != 1 ]]; then
  cat > /etc/cron.daily/vigia-backup <<CRON
#!/bin/sh
# Daily copy of Vigía's data (inventory, state, client settings) and .env; 14 days kept
tar -czf $DIR/backups/vigia-\$(date +%F).tar.gz -C $DIR data .env 2>/dev/null
find $DIR/backups -name 'vigia-*.tar.gz' -mtime +14 -delete
CRON
  chmod 755 /etc/cron.daily/vigia-backup
fi

if [[ $DRY == 1 ]]; then say "Dry run: files written to $DIR, nothing installed or started."; exit 0; fi

# ---- 4. Start ----
docker compose pull -q
docker compose up -d

# The DNS must point here before Let's Encrypt can issue the certificate
MYIP=$(curl -fsS --max-time 5 https://api.ipify.org || true)
DNSIP=$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk 'NR==1 { print $1 }' || true)
if [[ -n $MYIP && $DNSIP != "$MYIP" ]]; then
  say "Warning: $DOMAIN resolves to '${DNSIP:-nothing}', but this server is $MYIP. Fix the DNS A record; Caddy keeps retrying."
fi

say "Waiting for HTTPS…"
ok=0
for _ in $(seq 1 30); do
  if curl -fsS --max-time 5 "https://$DOMAIN/healthz" >/dev/null 2>&1; then ok=1; break; fi
  sleep 5
done

echo
if [[ $ok == 1 ]]; then say "Vigía is up: https://$DOMAIN"; else say "Vigía started, but https://$DOMAIN does not answer yet (DNS or certificate). Check: docker compose -f $DIR/docker-compose.yml logs caddy"; fi
if [[ $FIRST == 1 ]]; then
  echo
  say "Dashboard login (write it down now, it is only shown once):"
  echo "  user:     vigia"
  echo "  password: $DASH_PASS"
  echo
  say "Phone alerts: install the ntfy app and subscribe to this topic:"
  echo "  $NTFY_TOPIC"
fi
echo
echo "Configuration: $DIR/.env   ·   logs: cd $DIR && docker compose logs -f vigia   ·   update: cd $DIR && docker compose pull && docker compose up -d"
