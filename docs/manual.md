# Vigía — technician's quick manual

> Everything in depth (architecture, protocols, API, hardening): [technical guide](technical-guide.md).

One page to get Vigía running, add clients, and know what to do when it pages you. Each section links to the full reference.

**Contents:** [1. Set up](#1-set-up-15-minutes) · [2. Add a client](#2-add-a-client) · [3. Connect servers](#3-connect-servers-optional-recommended) · [4. When Vigía pages you](#4-when-vigía-pages-you) · [5. Routine](#5-routine) · [6. Troubleshooting](#6-troubleshooting) · [7. Cheat sheet](#7-cheat-sheet)

---

## 1. Set up (15 minutes)

Run Vigía on an always-on machine **outside** your clients' infrastructure, such as a small VPS at a different provider. Requirements: Node.js 20+ or Docker. About 150 MB of RAM, or 1 GB if you enable WordPress checks.

```bash
git clone https://github.com/aulafy/vigia.git && cd vigia
cp .env.example .env
```

Edit `.env`. These are the settings that matter on day one:

| Setting | Why | How |
|---|---|---|
| `NTFY_TOPIC` | Push alerts to your phone | Install the ntfy app and subscribe to a long random topic, e.g. `vigia-7f3c9a2e5b1d` |
| `DASH_PASS` | Dashboard password, **required with Docker** | Any strong password; the user is `vigia` |
| `HEARTBEAT_URL` | Someone tells you when Vigía itself dies | Free check at healthchecks.io; paste its ping URL |
| `CHECKIN_SECRET` | Master secret for backups and inventory pushes | `openssl rand -hex 32` |
| `VIGIA_LANG` | Alerts and dashboard in `en` or `es` | |
| `PUBLIC_URL` + `ACK_SECRET` | "Acknowledge" button inside notifications (needs HTTPS) | Your public URL and `openssl rand -hex 32` |
| `WORDFENCE_API_KEY` | WordPress plugin and theme vulnerabilities | Free key at wordfence.com/products/wordfence-intelligence |
| `OLLAMA_MODEL` | Optional: **Explain** and **Draft for the client** buttons on every alert | `ollama pull qwen3.5:9b`, then `OLLAMA_MODEL=qwen3.5:9b` ([ai.md](ai.md)) |

Start it:

```bash
docker compose up -d          # pulls ghcr.io/aulafy/vigia; dashboard on 127.0.0.1:4848 (ssh -L 4848:127.0.0.1:4848 you@vps)
# or
npm start                     # without Docker
```

Then:

1. Open the dashboard, go to **Settings → Send test alert**. Your phone must ring. If it doesn't, see [troubleshooting](#6-troubleshooting).
2. In the ntfy app, allow the topic to **override Do Not Disturb** for urgent messages. This is what wakes you at night.
3. Want to look around first? `npm run demo` shows three fictional clients without touching `data/`.

To install the dashboard as a phone app, Vigía must be served over HTTPS (Caddy: `vigia.example.com { reverse_proxy 127.0.0.1:4848 }`). Full details: [deployment.md](deployment.md).

## 2. Add a client

**From the dashboard:** **Clients → Add asset** (or **Add asset** on a client's page). The form has the same fields as below, checks them as you type, and proposes the ID. From a client's page you can also **Edit**, **Pause** and delete each asset. Every save keeps the previous `inventory.json` in `data/inventory-history/`.

**Or by hand:** clients live in `data/inventory.json`. Vigía picks up changes without a restart, and a typo never empties it: the last valid copy stays in use and you get a P2. If you edit the file while a form is open in the dashboard, saving the form warns you instead of overwriting your edit.

**Minimum: one site.**

```json
{ "id": "acme-shop", "client": "ACME Ltd", "name": "Online shop", "domain": "shop.acme.example", "criticality": "high" }
```

This alone gives you uptime, TLS, domain expiry, DNS hijack detection, SPF/DMARC and page tampering checks. The domain checks need `domain`; add `url` when the page to probe is not the home page (with only a `url`, you get uptime, TLS and page checks, but no domain, DNS or e-mail checks). `criticality: "high"` turns downtime and serious findings into P1s that wake you up; use `medium` or `low` for brochure sites.

**Typical: site + software + firewall + backups.**

```json
{
  "id": "acme-shop", "client": "ACME Ltd", "name": "Online shop",
  "domain": "shop.acme.example", "url": "https://shop.acme.example/checkout", "expect": "Add to cart", "criticality": "high",
  "contact": "Laura Gil +34 600 111 222",
  "stack": [
    { "wp": "core", "version": "6.4.3" },
    { "wp": "plugin", "slug": "woocommerce", "version": "8.5.1" },
    { "product": "php", "version": "8.1.27", "eol": "php" }
  ],
  "allowedHosts": ["stripe.com", "googletagmanager.com"], "strictScripts": true,
  "edge": [{ "type": "fortigate", "name": "Office FortiGate", "version": "7.2.5", "management": "https://203.0.113.10:4443" }],
  "backups": [{ "id": "db", "rpoHours": 24, "restoreTestDays": 30 }]
}
```

| You want to watch | Add | Reference |
|---|---|---|
| That the right page loads, not just "200 OK" | `expect`: a text that must appear | [inventory.md](inventory.md) |
| Software versions against vulnerabilities | `stack` entries (or let the server push them, §3) | [inventory.md](inventory.md#stack-entries) |
| The client's firewall / VPN / remote-access box | `edge` with `type`, `version`, `management` | [edge.md](edge.md) |
| Backup jobs | `backups` with `rpoHours` | [backups.md](backups.md) |
| A `.es` domain's expiry (no public RDAP) | `"domainExpires": "2027-03-01"` | [inventory.md](inventory.md#domain-dns-and-content-checks) |
| Legitimate third-party scripts and redirects | `allowedHosts` | [inventory.md](inventory.md) |
| A migration without noise | a **maintenance window** (client page → Maintenance), or `"paused": true` for longer breaks | [alerts.md](alerts.md#maintenance-windows) |

A new asset's first scan sends **one summary** ("12 findings · P1: 1 · P2: 3 · P3: 8"), not twelve alerts. Work through it from the dashboard.

## 3. Connect servers (optional, recommended)

Declaring versions by hand goes stale. Let servers report what they really run, and let backup jobs report in. Each server gets **its asset's own key**, never the master secret:

```bash
node server.mjs key acme-shop                       # on the Vigía host (Docker: docker compose exec vigia node server.mjs key acme-shop)
```

On the client's server, with `VIGIA_URL` and `VIGIA_CHECKIN_SECRET=<that key>` set:

```bash
# daily inventory (cron): WordPress, OS and runtimes; add --npm / --composer / --cyclonedx as needed
deploy/vigia-collect.sh acme-shop --wp /var/www/html --os --runtimes --dry-run   # check the output first
deploy/vigia-collect.sh acme-shop --wp /var/www/html --os --runtimes

# at the end of every backup job
deploy/vigia-checkin.sh acme-shop db success "{\"bytes\":$(wc -c < /backups/db.sql.gz)}"   # or: … db fail '{"message":"…"}'
deploy/vigia-checkin.sh acme-shop db restore                                                # after a test restore
```

Both scripts need only `sh`, `openssl` and `curl`. Details: [inventory-push.md](inventory-push.md), [backups.md](backups.md).

### Client portal and client e-mails

**Clients → the client → Client portal and notices**: **Create link** gives a read-only page for the client (their status, issues, computers, reports), and the e-mail field sends them their own notices. Details: [portal.md](portal.md).

### Computers (PCs, Macs, office servers)

**Clients → the client → Add computers → Create install line**, then run the line on each computer: the terminal line on Linux and macOS (with `sudo`), the PowerShell line on Windows (as Administrator). Each computer appears under the client and reports daily: OS, antivirus, installed software, listening ports, last update. Vigía must be reachable from them (`PUBLIC_URL`, ideally HTTPS) and `CHECKIN_SECRET` must be set. Details: [computers.md](computers.md).

## 4. When Vigía pages you

| Priority | Means | You get |
|---|---|---|
| **P1** | Act now, night included | Push that repeats every 10 min until acknowledged |
| **P2** | Act within hours | One push |
| **P3** | Plan it | Daily digest only |

Not sure what an alert means, or how to tell the client? With local AI on, press **Explain** or **Draft for the client** under it. You get a draft built from Vigía's facts; check it before using it.

**Acknowledge** = "I'm on it": stops the repeats; the alert stays open until the problem is gone. **Accept change** (on change alerts) = "this change was mine": the new value becomes the baseline. Never accept a change you don't recognise. If an open alert gets worse, it pages again even if you acknowledged it.

### Playbook

| Alert | What it means | First action |
|---|---|---|
| **… is DOWN** | Failed N probes in a row | Open the site; check hosting, DNS, certificate. A burst of many sites at once usually means one server or provider. |
| **certificate expires in N d** | TLS renewal is failing | Check the ACME/certbot job or the hosting panel. |
| **CVE-… EXPLOITED (KEV)** | A product the client runs is being attacked right now | Check the declared version against the advisory link; patch or mitigate today. On edge devices: patch **and** check for compromise. |
| **GHSA-… / CVE-… in package@version** | A dependency version is vulnerable (OSV) | Update the package; the alert closes by itself on the next scan or push. |
| **WordPress / plugin … — title** | Wordfence match on core, plugin or theme | Update to the fixed version in the alert; if there is none, remove or replace the plugin. Inactive plugins count too. |
| **… is EXPLOITABLE FROM THE INTERNET** | Exposed management **and** an exploited flaw on the same device | Restrict management to VPN/known IPs immediately, patch, then check for compromise. |
| **management interface … reachable** | The firewall's admin page answers from the Internet | Restrict it to your VPN or known IPs. |
| **attackers are scanning for …** | A scanning wave against that product type (GreyNoise and others) | Confirm the device is patched and its management is not exposed. |
| **NS records … changed** / **does NOT RESOLVE** | Possible domain hijack, or a domain that expired | Check the registrar account. Accept the change only if you made it. |
| **domain … expires / suspended / transfer lock removed / registrar changed** | Registration risk | Renew or re-lock at the registrar; verify any change with the client. |
| **can be spoofed by email** (P3) | SPF/DMARC missing or weak | Add `v=spf1 … -all` and DMARC `p=quarantine` or `p=reject`. |
| **redirects to … / looks DEFACED / new third-party script / form now submits to …** | Page tampering, phishing or a card skimmer | Inspect the page source; if not yours, take the site offline and investigate. Accept only known changes. |
| **backup … FAILED / overdue / much smaller / restore test overdue** | Backups are not protecting the client | Run the job by hand, check its log, check the size; schedule a test restore. |
| **inventory … out of date** | A server stopped pushing its inventory | Check the cron and `vigia-collect.sh` output on that server. |
| **Vigía: cannot check … / feed … not updating** | A blind spot: a check keeps failing | Read the error in the alert (DNS, firewall, rate limit); it closes when the check works again. |
| **alert channel … failing / weekly test** | The path to your phone is broken / the weekly proof that it works | Fix the channel; acknowledge the weekly test within 24 h. |
| **Vigía cannot save its state** (P1) | Disk full or permissions | Free space or fix permissions on `data/` now. |

## 5. Routine

| When | What |
|---|---|
| **Every morning** | Open **Today**. Clear P1s, then plan P2s. The 09:00 digest lists open P2s and new P3s. |
| **Weekly** | Acknowledge the weekly test alert. Review **Devices**: anything without an exploited-flaw alert but on old firmware? |
| **When you patch a firewall** | Update its `version` in the inventory, or add `"checked": "YYYY-MM-DD"`. Otherwise Vigía asks after 60 days. |
| **Monthly (day 1)** | Reports are ready under **Reports**. Open each client's, print to PDF and send it. |
| **Before planned work** (updates, migrations, hardware swaps) | Schedule a **maintenance window** on the client's page: no pages during the work, downtime not counted against availability, and anything still broken afterwards is sent when it ends. |
| **When you add a client** | Add it to the inventory, connect its servers (§3), and work through its onboarding summary. |
| **Before upgrading Vigía** | Read the [CHANGELOG](../CHANGELOG.md): **Breaking** entries need a config change. Back up `data/`. |

## 6. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Test alert: *no alert channel configured* | No `NTFY_TOPIC`, Telegram, webhook or email in `.env` | Set one and restart. |
| Install line: *invalid or expired* | The line is older than `ENROLL_DAYS` (7) | Create a new one in the dashboard. |
| Install line: *cannot reach* | The computer cannot reach `PUBLIC_URL` | Use an address the computer reaches (VPN, tunnel, reverse proxy with HTTPS). |
| Test alert: *no channel delivered it* | Wrong topic or token, or the network blocks the channel | Read the error in **Settings → Alert channels**. |
| The phone doesn't ring at night | ntfy is not allowed to bypass Do Not Disturb | Allow it in the ntfy app's topic settings. |
| Container exits: *Refusing to listen … without DASH_PASS* | Docker listens on all interfaces | Set `DASH_PASS` in `.env`. |
| Dashboard `421 host not allowed` | No password, and you open it by a hostname Vigía doesn't know | Set `DASH_PASS`, or add the name to `DASH_HOSTS`. |
| Dashboard `429` | 10 wrong passwords from your address | Wait 10 minutes. |
| "Session expired" banner | The browser lost the login | Reload the page. |
| Acknowledge link shows *expired* (`410`) | Link older than 7 days, or the alert already closed | Use the dashboard. |
| Check-in / push `401` | Wrong key, clock skew over 5 minutes, or the master secret used instead of the asset key | Use `node server.mjs key <asset>`; check the server clock (NTP). |
| Check-in / push `409` | Replayed or older than the last accepted call | Usually harmless after a retry; check that two jobs don't share one asset/job id. |
| Check-in `404` | The asset or job id is not in the inventory | Add `backups: [{ "id": … }]` to the asset. |
| `vigia-collect.sh` answers `400` | PHP printed notices into the WP-CLI JSON | Run with `--dry-run`, fix the notices or set `display_errors=Off` for the CLI. |
| P2 *inventory.json cannot be read* | JSON syntax error | Fix the file (or restore one from `data/inventory-history/`); Vigía keeps the last valid copy meanwhile. The dashboard editor is disabled until then. |
| Saving a form: *inventory.json changed meanwhile* | Someone edited the file, or saved another form | Your changes are kept: review them and save again. |
| No alerts from a client for a while | A maintenance window is still active | Check **Today** or **Settings → Maintenance**, and press **End now**. |
| Many alerts after adding a client | Expected: old software | Work through the onboarding summary; P3s only go to the digest. |
| No WordPress alerts at all | `WORDFENCE_API_KEY` not set (there is a P3 saying so) | Add the free key. |
| High memory use | The Wordfence feed is parsed every 6 h | Give the host 1 GB, or leave WordPress checks off. |

## 7. Cheat sheet

```bash
npm start                                    # run
npm run demo                                 # try with fictional clients
npm test                                     # run the test suite
node server.mjs key <asset-id>               # per-asset key for check-ins and pushes
node server.mjs report "<client>" 2026-10 > report.html   # one monthly report
node server.mjs report all 2026-10           # every client into data/reports/
curl -s localhost:4848/healthz               # liveness
docker compose pull && docker compose up -d  # update (Docker; pin a version with image: ghcr.io/aulafy/vigia:0.10)
docker compose logs -f                       # logs (Docker)
journalctl -u vigia -f                       # logs (systemd)
```

**Reference:** [inventory](inventory.md) · [alerts & on-call](alerts.md) · [edge devices](edge.md) · [backups](backups.md) · [inventory push & WordPress](inventory-push.md) · [reports](reports.md) · [dashboard](dashboard.md) · [deployment](deployment.md) · [security](../SECURITY.md)
