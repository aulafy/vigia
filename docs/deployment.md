# Deployment

Two rules:

1. **Run Vigía somewhere that is always on.** A laptop that sleeps is not monitoring.
2. **Run it outside the infrastructure it watches.** If it shares a server, provider or network with your clients' sites, the outage that takes them down takes it down too. A small VPS at a different provider is ideal.

Whatever you choose, configure `HEARTBEAT_URL` so that you hear about it when Vigía itself stops.

**Resources.** Node.js 20 or newer. About 150 MB of RAM for a few hundred assets. With `WORDFENCE_API_KEY`, plan for **1 GB**: the Wordfence feed is about 120 MB and is parsed in memory every 6 hours. A few hundred MB of disk for `data/`.

## Small VPS with HTTPS, one command (recommended for production)

What most people need: Vigía on a small cloud server (1 vCPU, 1–2 GB RAM, Ubuntu 22.04+ or Debian 12+), reachable over HTTPS so that agents, your phone and your clients' portal links work.

1. **Create the VPS** at any provider (Hetzner, OVH, Scaleway, DigitalOcean…), ideally not the one hosting your clients' sites. Note its IPv4 (and IPv6) address.
2. **Point a domain to it:** a DNS `A` record (and `AAAA` for IPv6), for example `vigia.example.com`. Let it propagate (`dig +short vigia.example.com`).
3. **Run the setup as root:**

   ```bash
   ssh root@vigia.example.com
   curl -fsSL https://raw.githubusercontent.com/aulafy/vigia/main/deploy/vps/setup.sh | VIGIA_LANG=en bash -s -- vigia.example.com
   ```

The script ([deploy/vps/setup.sh](../deploy/vps/setup.sh)):

| Step | Detail |
|---|---|
| Docker | Installed with the official script if missing |
| Firewall | `ufw`: SSH, 80 and 443 only (`VIGIA_NO_FIREWALL=1` to skip) |
| `/opt/vigia` | `docker-compose.yml` (Vigía + [Caddy](https://caddyserver.com)), `Caddyfile`, and an `.env` with fresh secrets: `DASH_PASS`, `CHECKIN_SECRET`, `ACK_SECRET`, a random `NTFY_TOPIC`, `PUBLIC_URL`. An existing `.env` is never overwritten, so running it again only updates and restarts |
| HTTPS | Caddy obtains and renews a Let's Encrypt certificate, adds HSTS and overwrites `X-Forwarded-For` (so `TRUST_PROXY=true` is safe). Only Caddy publishes ports; Vigía is not reachable around it |
| Backups | `/etc/cron.daily/vigia-backup`: `data/` and `.env` into `/opt/vigia/backups`, 14 days kept |
| Checks | Warns if the DNS does not point to the server yet, waits for `https://<domain>/healthz`, and prints the dashboard password and the ntfy topic **once** |

Then edit `/opt/vigia/.env` to add `HEARTBEAT_URL`, the SMTP settings and `REPORT_BRAND`, and apply it with `cd /opt/vigia && docker compose up -d`. Options: `VIGIA_LANG=es|en`, `VIGIA_DIR`, `VIGIA_SETUP_DRY=1` (write the files only).

Tested end to end with a local certificate (`vigia.localhost`): dashboard 401 without password and 200 with it, agent scripts public, HSTS present, and a forged `X-Forwarded-For` from a client ignored.

Running Vigía outside your clients' networks is also what makes the [Internet exposure check](computers.md#exposure-to-the-internet) meaningful.

## Docker Compose (recommended)

The image is published on GHCR for amd64 and arm64: `ghcr.io/aulafy/vigia` (tags `latest`, `0.10`, `0.10.0`…). You only need two files:

```bash
mkdir vigia && cd vigia
curl -fsSLO https://raw.githubusercontent.com/aulafy/vigia/main/docker-compose.yml
curl -fsSL https://raw.githubusercontent.com/aulafy/vigia/main/.env.example -o .env
nano .env                 # NTFY_TOPIC, DASH_PASS, HEARTBEAT_URL, CHECKIN_SECRET…
docker compose up -d
docker compose logs -f
```

To pin a version, use `image: ghcr.io/aulafy/vigia:0.10` in `docker-compose.yml`. To build from source instead, clone the repository and replace the `image:` line with `build: .`.

Set `DASH_PASS` in `.env` first: inside the container Vigía listens on all interfaces, and it refuses to start without a password there. State and inventory live in `./data` on the host. The dashboard is published on `127.0.0.1:4848` only. Reach it through an SSH tunnel:

```bash
ssh -L 4848:127.0.0.1:4848 user@your-vps
```

Then open http://localhost:4848.

## systemd (Linux without Docker)

```bash
sudo useradd --system --home /opt/vigia vigia
sudo git clone https://github.com/aulafy/vigia.git /opt/vigia
sudo cp /opt/vigia/.env.example /opt/vigia/.env && sudo nano /opt/vigia/.env
sudo mkdir -p /opt/vigia/data && sudo chown -R vigia: /opt/vigia/data
sudo cp /opt/vigia/deploy/vigia.service /etc/systemd/system/
sudo systemctl enable --now vigia
journalctl -u vigia -f
```

The unit runs Vigía as an unprivileged user, with a read-only filesystem except for `data/`, and restarts it if it crashes.

## macOS (always-on Mac)

Edit the paths in `deploy/net.vigia.plist`, then:

```bash
cp deploy/net.vigia.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/net.vigia.plist
sudo pmset -a sleep 0
```

## Exposing the dashboard (optional)

Only needed if you want to open the dashboard remotely, acknowledge from your phone, or **install the dashboard as an app**, since browsers only install apps served over HTTPS.

- Put Vigía behind a reverse proxy with HTTPS. With [Caddy](https://caddyserver.com) this is one line: `vigia.example.com { reverse_proxy 127.0.0.1:4848 }`.
- Set `DASH_PASS` so that the dashboard requires a login.
- Set `PUBLIC_URL` and `ACK_SECRET` to enable signed acknowledge links (see [alerts.md](alerts.md#acknowledging-from-the-phone)).

Alternatives without opening ports: Tailscale (private network), Tailscale Funnel or a Cloudflare Tunnel.

## Updating

```bash
cd /opt/vigia && docker compose pull && docker compose up -d   # VPS kit
docker compose pull && docker compose up -d   # Docker (published image)
git pull && sudo systemctl restart vigia      # systemd
```

Read the [CHANGELOG](../CHANGELOG.md) before upgrading: entries marked **Breaking** need a configuration change. 0.9, for example, requires `DASH_PASS` in Docker and per-asset keys on your servers.

`data/state.json` keeps alerts, acknowledgements, baselines and history across restarts and upgrades. It is written atomically with fsync, so neither a crash nor a power cut can leave half a file.

## Backups

Back up the whole `data/` folder:

| File | Contains | If lost |
|---|---|---|
| `inventory.json` | Your clients and what they run | **Your source of truth: restore it** |
| `inventory-history/` | The last 20 versions of `inventory.json`, one per edit from the dashboard | Only past versions are lost |
| `state.json` | Alerts, acknowledgements, accepted baselines (DNS, scripts, registrar…), incident history and availability | Vigía starts over: every asset is onboarded again, accepted changes are forgotten, and **past months can no longer be reported** |
| `pushed.json` | Inventories pushed by servers | Rebuilt by the next push |
| `wordfence.json` | Wordfence feed cache | Downloaded again |
| `reports/` | Monthly reports already written | Regenerate with `node server.mjs report all YYYY-MM` while the history is still in `state.json` |
