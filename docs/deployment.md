# Deployment

Two rules:

1. **Run Vigía somewhere that is always on.** A laptop that sleeps is not monitoring.
2. **Run it outside the infrastructure it watches.** If it shares a server, provider or network with your clients' sites, the outage that takes them down takes it down too. A small VPS at a different provider is ideal.

Whatever you choose, configure `HEARTBEAT_URL` so that you hear about it when Vigía itself stops.

## Docker Compose (recommended)

```bash
git clone https://github.com/aulafy/vigia.git && cd vigia
cp .env.example .env && nano .env
docker compose up -d
docker compose logs -f
```

State and inventory live in `./data` on the host. The dashboard is published on `127.0.0.1:4848` only. Reach it through an SSH tunnel:

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
git pull && docker compose up -d --build      # Docker
git pull && sudo systemctl restart vigia      # systemd
```

`data/state.json` keeps alerts, acknowledgements and seen KEV entries across restarts and upgrades. It is written atomically, so a crash cannot corrupt it.

## Backups

Back up `data/inventory.json`, since it is your source of truth. `data/pushed.json` (inventories pushed by servers) and `data/wordfence.json` (feed cache) are rebuilt by the next push and download. `data/state.json` can be deleted at any time. Vigía rebuilds it, but the next scan treats every asset as new and sends an onboarding summary again.
