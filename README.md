# Vigía

**24/7 watch over every website you are responsible for. It wakes you up only when something actually affects one of your assets.**

[![CI](https://github.com/aulafy/vigia/actions/workflows/ci.yml/badge.svg)](https://github.com/aulafy/vigia/actions/workflows/ci.yml)
![Node ≥ 20](https://img.shields.io/badge/node-%E2%89%A520-339933)
![Zero dependencies](https://img.shields.io/badge/dependencies-0-blue)
[![MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

If you run IT for many small companies, you cannot read every CVE, advisory and release note that comes out. You also cannot miss the one that hits a client's shop at 3 a.m. Vigía turns this around. You describe what each client runs, and Vigía keeps watching public vulnerability sources and the sites themselves. It sends a phone alert only when **a new problem matches something you actually run**.

```text
 Public sources                     Your inventory                  You
 ─────────────────                  ──────────────────              ─────────────────────
 CISA KEV (exploited CVEs) ─┐       client / site / criticality
 OSV (npm, PyPI, Packagist…)┼──▶    product + exact version   ──▶  P1 → push that rings, repeated
 endoflife.date ────────────┘       domain / URL / contact          every 10 min until you ack
 HTTP + TLS probes every 60 s ─────────────────────────────▶       P2 → push
 RDAP + DNS + page content ── compared with a baseline ────▶       P3 → daily digest
```

## What it checks

| Every | Check | Alert |
|---|---|---|
| 60 s | **Uptime:** HTTP status and, optionally, an expected text on the page. Needs 2 failures in a row, so one blip does not page you. | High criticality: **P1**, otherwise P2. Recovery message when the site is back. |
| 1 h | **TLS certificate** expiry | < 3 days: **P1** · < 14 days: P2 |
| 5 min | **DNS:** nameservers and mail servers compared with a baseline (A/AAAA if you opt in). A changed nameserver is the classic sign of a hijacked domain. | NS changed or domain does not resolve: **P1** on high criticality · MX changed: P2 |
| 15 min | **Page content:** redirects to a foreign domain, defacement or SEO-spam text, and **new third-party scripts**, which is how card skimmers get into shops | High criticality: **P1**, otherwise P2 (new scripts: P2, or P1 with `strictScripts`) |
| 6 h | **Domain registration** through RDAP: expiry, suspension (hold, redemption), removed transfer lock, changed registrar | Expires < 7 days or suspended: **P1** · < 30 days: P2 · lock removed: P2 · registrar changed: P1 on high criticality |
| 15 min | **[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)**: CVEs confirmed exploited in the wild, matched against the products in your inventory | High criticality: **P1**, otherwise P2 |
| 30 min | **[OSV](https://osv.dev)**: known vulnerabilities in the exact versions of your dependencies (npm, Packagist, PyPI, Go, Maven, RubyGems, crates.io, Debian, Ubuntu, Alpine…) | In KEV, or critical on a high-criticality asset: **P1** · critical/high: P2 · other: P3 |
| 6 h | **[endoflife.date](https://endoflife.date)**: runtimes, OSes and databases that lost, or are about to lose, security support | Already end-of-life: P2/P3 · within 90 days: P3 |
| 60 s | **Self-health:** stale feeds, plus an outgoing heartbeat to an external service | P2, or the external service pages you |
| daily | **Digest** of open P2s and new P3s | one message |

## Why it stays quiet

An alert tool that pages you for everything ends up ignored. Vigía is built to stay quiet:

- **It matches before it alerts.** A new CVE only matters if it hits a product and version you run.
- **Priorities follow criticality.** The same finding is P1 on a client's payment site and P2 on a brochure site.
- **Onboarding sends a summary.** When you add a site that runs old software, its first scan sends one message ("20 findings · P1: 0 · P2: 9 · P3: 11") instead of 20 separate alerts. P1s still ring.
- **Alerts deduplicate and close themselves.** A finding is reported once. Once you upgrade the dependency, the next scan closes the alert.
- **Change alerts learn.** The first time Vigía sees a site's nameservers, registrar or third-party scripts, it saves them as the baseline. When something differs, you get an alert with an **Accept change** button. If the change was yours, one tap makes it the new baseline. A DNS change has to show up twice in a row before it alerts, so a flaky resolver does not page you.
- **Only P1s repeat.** They come back every 10 minutes until you acknowledge them, from the dashboard or straight from the notification on your phone.
- **The watcher is watched.** If Vigía crashes, the machine goes off or the network drops, its heartbeat stops and an external service (healthchecks.io, Better Stack…) pages you. If a vulnerability feed stops updating, you get a P2 about that blind spot.

## Quick start

Requires Node.js 20 or newer. There is nothing to install.

```bash
git clone https://github.com/aulafy/vigia.git
cd vigia
cp .env.example .env              # set at least NTFY_TOPIC
npm start                         # dashboard on http://localhost:4848
```

1. Install the **[ntfy](https://ntfy.sh)** app (iOS/Android) and subscribe to the topic you put in `NTFY_TOPIC`. Pick a long random name: anyone who knows a topic on the public ntfy.sh server can read it.
2. Open the dashboard and press **Send test alert**. Your phone should ring.
3. On the first run Vigía copies `inventory.example.json` to `data/inventory.json`. Edit that file to describe your clients (see below). Vigía re-reads it on every cycle, so there is no need to restart.
4. Create a free check on [healthchecks.io](https://healthchecks.io) and put its ping URL in `HEARTBEAT_URL`.
5. Deploy it somewhere that is always on and **is not one of the servers it watches**. See [docs/deployment.md](docs/deployment.md).

## The inventory

Everything depends on the inventory. Without it you would get hundreds of CVEs a day with no way to know which ones matter. With it, Vigía alerts only on the ones that affect you.

```json
[
  {
    "id": "acme-shop",
    "client": "ACME Ltd",
    "name": "Online shop",
    "domain": "example.com",
    "url": "https://example.com/health",
    "expect": "OK",
    "criticality": "high",
    "contact": "Jane Doe +34 600 000 000",
    "stack": [
      { "product": "wordpress", "version": "6.4.3" },
      { "product": "php", "version": "8.1.27", "eol": "php" },
      { "product": "apache", "kev": ["apache http server"], "version": "2.4.58" },
      { "ecosystem": "npm", "name": "lodash", "version": "4.17.15" },
      { "ecosystem": "Packagist", "name": "guzzlehttp/guzzle", "version": "7.4.0" }
    ]
  }
]
```

Each `stack` entry can feed one or more checks:

| Fields | Used by | Meaning |
|---|---|---|
| `product` (+ optional `kev`) | CISA KEV | Matched as a whole word against the KEV vendor and product. `php` matches *PHP* but not *phpMyAdmin*. Use `kev` for exact phrases such as `"apache http server"` or `"fortios"`. |
| `ecosystem` + `name` + `version` | OSV | An exact package version. `ecosystem` uses OSV names: `npm`, `Packagist`, `PyPI`, `Go`, `Maven`, `RubyGems`, `crates.io`, `NuGet`, `Debian:12`, `Ubuntu:22.04`, `Alpine:v3.19`… |
| `eol` + `version` | endoflife.date | The product id on endoflife.date (`php`, `nodejs`, `ubuntu`, `debian`, `mysql`, `postgresql`, `nginx`, `wordpress`…). |

The domain, DNS and content checks need nothing in `stack`, because they work from `domain` and `url`. Useful options on the asset itself:

| Field | Example | Meaning |
|---|---|---|
| `domainExpires` | `"2027-03-01"` | Expiry date for TLDs without public RDAP, such as **`.es`**. Vigía reminds you to set it. |
| `dnsWatch` | `["A", "AAAA"]` | Also watch the site's IP addresses. Leave it off behind a CDN that rotates IPs. |
| `allowedHosts` | `["stripe.com", "googletagmanager.com"]` | Foreign domains the page may redirect to or load scripts from. |
| `strictScripts` | `true` | A new third-party script is a P1. Use it on checkout pages. |
| `ignoreKeywords` | `["hacked by"]` | Defacement phrases that are legitimate on this site. |
| `skip` | `["content", "dns", "domain"]` | Turn individual checks off for this asset. |

Every field, including `paused`, `failThreshold` and `timeoutMs`, is documented in **[docs/inventory.md](docs/inventory.md)**, along with tips for generating the inventory from lockfiles and SBOMs.

## Alert channels

| Channel | Setup | Notes |
|---|---|---|
| **ntfy** | `NTFY_TOPIC` | Recommended. Priority 5 breaks through Do Not Disturb if you allow it. Has an **Acknowledge** button. |
| **Telegram** | `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | Includes an acknowledge link. |
| **Webhook** | `WEBHOOK_URL` | Sends JSON `{prio, title, body, key, ackUrl}`. Use it to connect PagerDuty, Better Stack, Opsgenie or Twilio for **phone calls and escalation to a second person**. |

Setup for each channel, phone acknowledgement and on-call escalation are covered in **[docs/alerts.md](docs/alerts.md)**.

## Configuration

All settings are environment variables, which can live in `.env`:

| Variable | Default | Purpose |
|---|---|---|
| `VIGIA_LANG` | `en` | Language of alerts and dashboard: `en` or `es` |
| `NTFY_TOPIC`, `NTFY_SERVER`, `NTFY_TOKEN` | — , `https://ntfy.sh`, — | ntfy channel |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | — | Telegram channel |
| `WEBHOOK_URL` | — | Generic JSON webhook |
| `HEARTBEAT_URL` | — | Pinged every minute (dead man's switch) |
| `PUBLIC_URL`, `ACK_SECRET` | — | Enable signed acknowledge links in P1 notifications |
| `HOST`, `PORT` | `127.0.0.1`, `4848` | Dashboard bind address |
| `DASH_PASS` | — | HTTP Basic auth for the dashboard (user `vigia`) |
| `DIGEST_HOUR`, `DIGEST_TZ` | `9`, `Europe/Madrid` | When to send the daily digest |
| `DNS_SERVERS` | `1.1.1.1,8.8.8.8` | Resolvers for the DNS check. Public resolvers avoid stale local caches and split-horizon answers. |
| `VIGIA_INV`, `VIGIA_STATE` | `data/inventory.json`, `data/state.json` | File locations |

## HTTP endpoints

| Endpoint | Auth | Description |
|---|---|---|
| `GET /` | dashboard | Web dashboard |
| `GET /api/state` | dashboard | Inventory, status, alerts and feed timestamps as JSON |
| `POST /api/ack?key=…` | dashboard | Acknowledge an alert. For a change alert, this also accepts the new value as the baseline. |
| `GET/POST /api/ack?key=…&sig=…` | signed link | Acknowledge from a notification. GET shows a confirmation button, so link previews cannot acknowledge by accident. |
| `POST /api/test` | dashboard | Send a test P1 to every channel |
| `GET /healthz` | none | Liveness check for Docker or your load balancer |

## What Vigía is not

Be honest with your clients about what is covered:

- **It does not make phone calls by itself.** For a real on-call rotation with calls and escalation, send the webhook to PagerDuty, Better Stack or Grafana OnCall. One person is not a sustainable 24/7 rota.
- **WordPress and PrestaShop plugins** are only matched by name against KEV. OSV covers them poorly. Dedicated databases such as Wordfence Intelligence or WPScan fill that gap (on the roadmap).
- **It is not a SIEM, EDR or WAF.** Logs, file integrity, malware and intrusion detection belong to tools like Wazuh, CrowdSec or Cloudflare. Vigía complements them.
- **It does not check backups.** Monitor them, and test a restore regularly.
- **The content check reads the HTML the server sends.** Scripts injected later by JavaScript, for example through a tag manager, or code that only shows up for some visitors (cloaking), are invisible to it. It catches the common cases, but it is not a full malware scanner.

## Development

```bash
npm test          # unit tests (node:test, no dependencies)
```

- `server.mjs` holds the scheduler, the checks, the notifications and the HTTP server.
- `lib.mjs` holds the pure logic: matching, priorities, validation and signatures. It is unit tested.
- `i18n.mjs` holds the alert texts in English and Spanish.
- `index.html` is the dashboard: one file, no build step.

Contributions are welcome, see [CONTRIBUTING.md](CONTRIBUTING.md). To report a security issue, see [SECURITY.md](SECURITY.md).

## Roadmap

- WordPress plugin and theme vulnerabilities (Wordfence Intelligence / WPScan)
- New certificates in Certificate Transparency logs (as P3)
- SPF/DMARC audit when a client is added
- Importing the inventory from SBOMs (CycloneDX/SPDX) and lockfiles
- Built-in PagerDuty Events v2 and Twilio call integrations
- Vendor advisory RSS feeds (INCIBE-CERT, Ubuntu USN, Debian DSA)
- Maintenance windows and per-client quiet hours

## License

[MIT](LICENSE) © 2026 Aulafy
