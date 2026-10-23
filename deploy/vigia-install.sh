#!/bin/sh
# Add this Linux or macOS computer to a client in Vigía, and send its inventory every day. POSIX sh + curl + openssl.
#
#   curl -fsSL https://vigia.example.com/agent/install.sh | sudo sh -s -- https://vigia.example.com <token>
#   curl -fsSL https://vigia.example.com/agent/install.sh | sudo sh -s -- --uninstall
#
# The dashboard (Clients → a client → Add computer) shows the line with a fresh token. With sudo it installs for the whole
# machine (systemd timer, cron or launchd daemon); without, for the current user (crontab or LaunchAgent).
# What it sends: OS, runtimes, listening TCP ports, antivirus and installed software (see vigia-collect.sh). It scans nothing.
set -eu

OS=$(uname -s)
if [ "$(id -u)" = 0 ]; then BIN=/usr/local/bin; CONF=/etc/vigia; else BIN=$HOME/.local/bin; CONF=$HOME/.config/vigia; fi
UNIT=/etc/systemd/system/vigia-collect
CRON=/etc/cron.d/vigia-collect
if [ "$(id -u)" = 0 ]; then PLIST=/Library/LaunchDaemons/net.vigia.collect.plist; else PLIST=$HOME/Library/LaunchAgents/net.vigia.collect.plist; fi
say() { printf '%s\n' "$*"; }
die() { printf 'vigia: %s\n' "$*" >&2; exit 1; }

unschedule() {
  if [ "$OS" = Darwin ]; then
    if [ -f "$PLIST" ]; then launchctl unload "$PLIST" 2>/dev/null || true; rm -f "$PLIST"; fi
  elif [ "$(id -u)" = 0 ]; then
    if [ -f "$UNIT.timer" ]; then systemctl disable --now vigia-collect.timer 2>/dev/null || true; rm -f "$UNIT.timer" "$UNIT.service"; systemctl daemon-reload 2>/dev/null || true; fi
    rm -f "$CRON"
  else
    (crontab -l 2>/dev/null | grep -v vigia-collect || true) | crontab - 2>/dev/null || true
  fi
}

if [ "${1:-}" = --uninstall ]; then
  unschedule
  rm -f "$BIN/vigia-collect" "$CONF/agent.env"
  rmdir "$CONF" 2>/dev/null || true
  say "Vigía agent removed. Delete this computer from the dashboard too."
  exit 0
fi

[ $# -eq 2 ] || { sed -n '3,9p' "$0" >&2 2>/dev/null || true; die "usage: install.sh <vigia-url> <token>"; }
URL=${1%/}; TOKEN=$2
case $URL in
  https://*) ;;
  http://localhost*|http://127.*|http://10.*|http://192.168.*|http://172.1[6-9].*|http://172.2[0-9].*|http://172.3[01].*) say "warning: plain HTTP on the local network, the key travels unencrypted" ;;
  # over the Internet, plain HTTP would let anyone on the way swap the agent this computer runs as root
  http://*) [ "${VIGIA_INSECURE:-}" = 1 ] || die "plain HTTP outside your local network: use an https:// address (or VIGIA_INSECURE=1 at your own risk)" ;;
  *) die "the address must start with https:// or http://" ;;
esac
case $URL$TOKEN in *"'"*|*'"'*|*' '*) die "unexpected characters in the address or token" ;; esac
for c in curl openssl; do command -v $c >/dev/null 2>&1 || die "$c is required"; done

# A stable id for this machine, hashed: re-running the line updates the same computer instead of adding a new one
if [ "$OS" = Darwin ]; then RAW=$(ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/ { print $4 }')
else RAW=$(cat /etc/machine-id 2>/dev/null || cat /var/lib/dbus/machine-id 2>/dev/null || true); fi
[ -n "$RAW" ] || die "cannot read a machine id"
MID=$(printf '%s' "$RAW" | openssl dgst -sha256 | sed 's/^.*= *//')
HOST=$( (hostname -s 2>/dev/null || hostname) | tr -cd 'A-Za-z0-9._-' | cut -c1-63)
PLATFORM=linux; [ "$OS" = Darwin ] && PLATFORM=macos

mkdir -p "$BIN" "$CONF"
curl -fsSL "$URL/agent/vigia-collect.sh" -o "$BIN/vigia-collect.tmp" || die "cannot download the collector from $URL"
chmod 755 "$BIN/vigia-collect.tmp" && mv "$BIN/vigia-collect.tmp" "$BIN/vigia-collect"

OUT=$(curl -sS --max-time 60 -X POST "$URL/api/enroll" -H 'content-type: application/json' \
  --data "{\"token\":\"$TOKEN\",\"host\":\"$HOST\",\"machineId\":\"$MID\",\"platform\":\"$PLATFORM\"}" -w '\n%{http_code}') || die "cannot reach $URL"
CODE=$(printf '%s' "$OUT" | tail -n 1); BODY=$(printf '%s' "$OUT" | sed '$d')
field() { printf '%s' "$BODY" | sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p"; }
case $CODE in 200|201) ;; *) die "enrolment refused (HTTP $CODE): $(field error)" ;; esac
ASSET=$(field asset); KEY=$(field key)
[ -n "$ASSET" ] && [ -n "$KEY" ] || die "unexpected answer: $BODY"

umask 077
{ printf "VIGIA_URL='%s'\nVIGIA_ASSET='%s'\nVIGIA_CHECKIN_SECRET='%s'\n" "$URL" "$ASSET" "$KEY"; } > "$CONF/agent.env"
chmod 600 "$CONF/agent.env"

# Daily, at a random minute between 02:00 and 05:59, so a hundred computers do not push at once
M=$(awk 'BEGIN { srand(); print int(rand() * 60) }'); H=$(awk 'BEGIN { srand(); print 2 + int(rand() * 4) }')
unschedule
if [ "$OS" = Darwin ]; then
  mkdir -p "$(dirname "$PLIST")"
  cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>net.vigia.collect</string>
  <key>ProgramArguments</key><array><string>$BIN/vigia-collect</string><string>--all</string></array>
  <key>StartCalendarInterval</key><dict><key>Hour</key><integer>$H</integer><key>Minute</key><integer>$M</integer></dict>
  <key>StandardErrorPath</key><string>/tmp/vigia-collect.log</string>
</dict></plist>
EOF
  launchctl load -w "$PLIST" 2>/dev/null || say "warning: launchctl could not load $PLIST"
  WHEN="launchd ($PLIST)"
elif [ "$(id -u)" = 0 ] && [ -d /run/systemd/system ]; then
  printf '[Unit]\nDescription=Vigía inventory\nAfter=network-online.target\n\n[Service]\nType=oneshot\nExecStart=%s/vigia-collect --all\n' "$BIN" > "$UNIT.service"
  printf '[Unit]\nDescription=Vigía inventory, daily\n\n[Timer]\nOnCalendar=*-*-* %02d:%02d\nRandomizedDelaySec=15m\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n' "$H" "$M" > "$UNIT.timer"
  systemctl daemon-reload && systemctl enable --now vigia-collect.timer >/dev/null
  WHEN="systemd timer vigia-collect.timer"
elif [ "$(id -u)" = 0 ] && [ -d /etc/cron.d ]; then
  printf '%s %s * * * root %s/vigia-collect --all >/var/log/vigia-collect.log 2>&1\n' "$M" "$H" "$BIN" > "$CRON"
  WHEN="cron ($CRON)"
else
  (crontab -l 2>/dev/null | grep -v vigia-collect || true; printf '%s %s * * * %s/vigia-collect --all >/dev/null 2>&1\n' "$M" "$H" "$BIN") | crontab -
  WHEN="your crontab"
fi

say "Registered as $ASSET ($(field client)). Daily inventory: $WHEN."
"$BIN/vigia-collect" --all >/dev/null && say "First inventory sent. It shows up in the dashboard now." || say "warning: the first inventory failed; it will retry tomorrow ($BIN/vigia-collect --all to try again)"
