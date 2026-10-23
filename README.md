# Vigía

**24/7 watch over your clients' websites, firewalls, domains, backups and computers. It wakes you up only when something actually affects one of them.**

[![CI](https://github.com/aulafy/vigia/actions/workflows/ci.yml/badge.svg)](https://github.com/aulafy/vigia/actions/workflows/ci.yml)
![Node ≥ 20](https://img.shields.io/badge/node-%E2%89%A520-339933)
![Zero dependencies](https://img.shields.io/badge/dependencies-0-blue)
[![MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

![Vigía dashboard](docs/img/dashboard.jpg)

If you run IT for many small companies, you cannot read every CVE, advisory and release note that comes out. You also cannot miss the one that hits a client's shop at 3 a.m. Vigía turns this around. You describe what each client runs, and Vigía keeps watching public vulnerability sources and the sites themselves. It sends a phone alert only when **a new problem matches something you actually run**.

```text
 Public sources                     Your inventory                  You
 ─────────────────                  ──────────────────              ─────────────────────
 CISA KEV (exploited CVEs) ─┐       client / site / criticality
 OSV (npm, PyPI, Packagist…)┤       product + exact version         P1 → push that rings, repeated
 Wordfence (WordPress) ─────┼──▶    (declared, or pushed daily ──▶       every 10 min until you ack
 endoflife.date ────────────┤        by each server)
 Vendor + research advisories ┘
 HTTP + TLS probes every 60 s ─────────────────────────────▶       P2 → push
 RDAP + DNS + page content ── compared with a baseline ────▶       P3 → daily digest
```

## What it checks

| Every | Check | Alert |
|---|---|---|
| 60 s | **Uptime:** HTTP status and, optionally, an expected text on the page. Needs 2 failures in a row, so one blip does not page you. | High criticality: **P1**, otherwise P2. Recovery message when the site is back. |
| 1 h | **TLS certificate** expiry | < 3 days: **P1** · < 14 days: P2 |
| 5 min | **DNS:** nameservers and mail servers compared with a baseline (A/AAAA if you opt in). A changed nameserver is the classic sign of a hijacked domain. | NS changed or domain does not resolve: **P1** on high criticality · MX changed: P2 |
| 5 min | **Email spoofing protection:** SPF and DMARC compared with a baseline, plus an audit of what is missing | Protection weakened (DMARC lowered or removed, SPF removed or `+all`): P2 · missing at onboarding: P3 |
| 15 min | **Page content:** redirects to a foreign domain, defacement or SEO-spam text, **new third-party scripts** (the way card skimmers get into shops), **forms that submit to a new foreign domain** (phishing), new foreign iframes | Redirect, defacement or hijacked form: **P1** on high criticality · new script: P2 (P1 with `strictScripts`) · new iframe: P2 |
| on check-in | **Backups:** each backup job reports in with a signed call; Vigía alerts when a run fails, the RPO passes without a success, the backup shrinks suddenly or a restore test is overdue | Failed or overdue: **P1** on high criticality · shrunk or no restore test: P2 |
| 6 h | **Domain registration** through RDAP: expiry, suspension (hold, redemption), removed transfer lock, changed registrar | Expires < 7 days or suspended: **P1** · < 30 days: P2 · lock removed: P2 · registrar changed: P1 on high criticality |
| 15 min | **[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)**: CVEs confirmed exploited in the wild, matched against the products in your inventory | High criticality: **P1**, otherwise P2 |
| 30 min | **[OSV](https://osv.dev)**: known vulnerabilities in the exact versions of your dependencies (npm, Packagist, PyPI, Go, Maven, RubyGems, crates.io, Debian, Ubuntu, Alpine…) | In KEV, or critical on a high-criticality asset: **P1** · critical/high: P2 · other: P3 |
| 15 min | **Firewalls, VPN and remote access** you declare (FortiGate, Palo Alto, Cisco ASA, Ivanti, NetScaler, SonicWall, BeyondTrust…): CISA KEV, vendor advisories (Fortinet, Palo Alto and Cisco PSIRT, INCIBE-CERT), researchers (Volexity, watchTowr, GreyNoise, Rapid7), scanning waves against the product, administration interface reachable from the Internet, portal certificate | KEV or exploited: **P1** · exposed *and* exploited: **P1** · critical/high or scanning wave: P2 · exposed management: P2 |
| 2 h | **EPSS early warning**: probability of exploitation in the next 30 days for the CVEs in your open alerts | ≥ 50 %: raised to **P1** · ≥ 10 %: P3 raised to P2 |
| 30 min | **WordPress core, plugins and themes** against [Wordfence Intelligence](https://www.wordfence.com/products/wordfence-intelligence/) (free API key), with exact version ranges | KEV, or CVSS ≥ 9 unauthenticated or on a high-criticality asset: **P1** · CVSS ≥ 7: P2 · lower: P3 |
| on push | **Pushed inventory:** each server reports what it really runs (WP-CLI, `package-lock.json`, `composer.lock`, CycloneDX/SPDX SBOM, OS, runtimes) with a signed call | No push within the expected window: P2 |
| daily | **Computers and servers** added with one install line (Windows, Linux, macOS): operating system, antivirus, installed software, ports the machine listens on, last update. Nothing is scanned: each computer reports on itself. | Windows without active antivirus: P2 · no updates for 90 days: P2 (45: P3) · risky service listening on the network (RDP, databases, VNC…): P3 · exploited program installed (KEV): as above |
| 6 h | **[endoflife.date](https://endoflife.date)**: runtimes, OSes and databases that lost, or are about to lose, security support | Already end-of-life: P2/P3 · within 90 days: P3 |
| 60 s | **Self-health:** stale feeds, checks that keep failing for one asset or feed (coverage), alert channels, disk, and an outgoing heartbeat to an external service | P2 (disk: P1), or the external service pages you |
| daily | **Digest** of open P2s and new P3s | one message |
| any time | **Maintenance windows** for an asset, a client or everything | Alerts are kept but not sent; still-open ones go out when the window ends |

## Why it stays quiet

An alert tool that pages you for everything ends up ignored. Vigía is built to stay quiet:

- **It matches before it alerts.** A new CVE only matters if it hits a product and version you run.
- **Priorities follow criticality.** The same finding is P1 on a client's payment site and P2 on a brochure site.
- **Onboarding sends a summary.** When you add a site that runs old software, its first scan sends one message ("20 findings · P1: 0 · P2: 9 · P3: 11") instead of 20 separate alerts. P1s still ring.
- **Alerts deduplicate and close themselves.** A finding is reported once. Once you upgrade the dependency, the next scan closes the alert.
- **Change alerts learn.** The first time Vigía sees a site's nameservers, registrar or third-party scripts, it saves them as the baseline. When something differs, you get an alert with an **Accept change** button. If the change was yours, one tap makes it the new baseline. A DNS change has to show up twice in a row before it alerts, so a flaky resolver does not page you.
- **Only P1s repeat.** They come back every 10 minutes until you acknowledge them, from the dashboard or straight from the notification on your phone. P2s are sent once, and resent only if no channel confirmed delivery.
- **The front door first.** The firewall or VPN gateway is where most small-business breaches start, so for declared edge devices a KEV match is always P1 and vendor advisories arrive before KEV catches up. See [docs/edge.md](docs/edge.md).
- **Nothing is lost on the way.** Every P1/P2 keeps its delivery status until a channel confirms it, and undelivered ones are retried. An alert that gets worse pages again. A check that keeps failing for one asset or feed becomes a P2 ("cannot check…"), because a blind spot is a problem too.
- **Bursts are grouped.** When one check produces more than 3 messages at once, for example 30 sites on the same server going down, you get one summary instead of 30 pages. If Vigía's own connection drops, it notices and skips the uptime round instead of reporting every site as down.
- **The watcher is watched.** If Vigía crashes, the machine goes off or the network drops, its heartbeat stops and an external service (healthchecks.io, Better Stack…) pages you. If a vulnerability feed stops updating, you get a P2 about that blind spot.
- **So is the alert chain.** Each channel is retried and checked for real delivery. If one fails, the others tell you. If all fail, Vigía sends `/fail` to the heartbeat service, which reaches you by email or SMS. Once a week a **canary** alert asks you to acknowledge it. If nobody does, Vigía treats the chain as broken, because "the push was sent" does not prove that anyone saw it.

## Quick start

> In a hurry? The **[technician's quick manual](docs/manual.md)** covers setup, daily use and troubleshooting on one page.

Requires Node.js 20 or newer. There is nothing to install.

```bash
# Docker (published image, amd64 and arm64)
mkdir vigia && cd vigia
curl -fsSLO https://raw.githubusercontent.com/aulafy/vigia/main/docker-compose.yml
curl -fsSL https://raw.githubusercontent.com/aulafy/vigia/main/.env.example -o .env   # set NTFY_TOPIC and DASH_PASS
docker compose up -d                                                                 # dashboard on 127.0.0.1:4848

# or from source (Node 20+, nothing to install)
git clone https://github.com/aulafy/vigia.git && cd vigia
cp .env.example .env && npm start
npm run demo                      # try it first with demo clients (nothing is written to data/)
```

1. Install the **[ntfy](https://ntfy.sh)** app (iOS/Android) and subscribe to the topic you put in `NTFY_TOPIC`. Pick a long random name: anyone who knows a topic on the public ntfy.sh server can read it.
2. Open the dashboard and press **Send test alert**. Your phone should ring.
3. Add your clients from the dashboard (**Clients → Add asset**), or edit `data/inventory.json` directly (see below). Vigía picks up every change without a restart.
4. Create a free check on [healthchecks.io](https://healthchecks.io) and put its ping URL in `HEARTBEAT_URL`.
5. Deploy it somewhere that is always on and **is not one of the servers it watches**. See [docs/deployment.md](docs/deployment.md).

## The inventory

Everything depends on the inventory. You can fill it in from the dashboard, write it by hand, let each server **push** what it runs ([docs/inventory-push.md](docs/inventory-push.md)), or both. Without it you would get hundreds of CVEs a day with no way to know which ones matter. With it, Vigía alerts only on the ones that affect you.

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
| `wp` + `slug` + `version` | Wordfence | A WordPress component: `"wp": "core"`, or `"plugin"`/`"theme"` with the directory name as `slug`. |
| `eol` + `version` | endoflife.date | The product id on endoflife.date (`php`, `nodejs`, `ubuntu`, `debian`, `mysql`, `postgresql`, `nginx`, `wordpress`…). |

The domain, DNS and content checks need nothing in `stack`, because they work from `domain` and `url`. Useful options on the asset itself:

| Field | Example | Meaning |
|---|---|---|
| `domainExpires` | `"2027-03-01"` | Expiry date for TLDs without public RDAP, such as **`.es`**. Vigía reminds you to set it. |
| `dnsWatch` | `["A", "AAAA"]` | Also watch the site's IP addresses. Leave it off behind a CDN that rotates IPs. |
| `allowedHosts` | `["stripe.com", "googletagmanager.com"]` | Foreign domains the page may redirect to or load scripts from. |
| `strictScripts` | `true` | A new third-party script is a P1. Use it on checkout pages. |
| `ignoreKeywords` | `["hacked by"]` | Defacement phrases that are legitimate on this site. |
| `skip` | `["content", "dns", "mail", "domain"]` | Turn individual checks off for this asset. |
| `backups` | `[{ "id": "db", "rpoHours": 24, "restoreTestDays": 30 }]` | Backup jobs that report in. See **[docs/backups.md](docs/backups.md)**. |
| `edge` | `[{ "type": "fortigate", "version": "7.2.5", "management": "https://203.0.113.10:4443" }]` | Firewalls, VPN and remote-access devices. See **[docs/edge.md](docs/edge.md)**. |
| `inventoryMaxAgeHours` | `24` | Expect a pushed inventory at least this often (default 48 h once the asset has pushed). |

Every field, including `paused`, `failThreshold` and `timeoutMs`, is documented in **[docs/inventory.md](docs/inventory.md)**, along with tips for generating the inventory from lockfiles and SBOMs.

## Dashboard

A web app you can install on your phone, in light or dark mode, with seven sections: **Today, Alerts, Clients, Devices, Backups, Reports, Settings**. Acknowledge a P1 from the phone, open a client to see everything about it, **add and edit assets, devices and backup jobs without touching JSON**, schedule **maintenance windows**, and print the monthly report. Try it with `npm run demo`. See **[docs/dashboard.md](docs/dashboard.md)**.

## Local AI (optional)

With [Ollama](https://ollama.com) and `OLLAMA_MODEL` set, every alert gets **Explain** (what happens, the risk, steps, how to check) and **Draft for the client** (a plain-language message to copy). The model gets only the facts Vigía has about that alert, so it does not invent providers or versions. Everything runs on your machine, and the AI never decides, acknowledges or sends anything. See **[docs/ai.md](docs/ai.md)**.

## Computers and servers

**Clients → a client → Add computers** gives you one line for Linux and macOS and one for Windows. Run it on each computer: it joins that client and reports every day what it runs, which antivirus is active, when it was last updated and which ports it listens on. The line expires, each computer gets its own key, and nothing is scanned. See **[docs/computers.md](docs/computers.md)**.

## Monthly client reports

One printable page per client and month: availability, incidents, response times, backups, edge devices and recommended actions. Open it from the dashboard, or let Vigía write all of them when the month ends. See **[docs/reports.md](docs/reports.md)**.

## Alert channels

| Channel | Setup | Notes |
|---|---|---|
| **ntfy** | `NTFY_TOPIC` | Recommended. Priority 5 breaks through Do Not Disturb if you allow it. Has an **Acknowledge** button. |
| **Telegram** | `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | Includes an acknowledge link. |
| **Webhook** | `WEBHOOK_URL` | Sends JSON `{prio, title, body, key, ackUrl}`. Use it to connect PagerDuty, Better Stack, Opsgenie or Twilio for **phone calls and escalation to a second person**. |
| **Email** | `SMTP_HOST`, `SMTP_USER`, `SMTP_PASS`, `MAIL_TO` | Built-in SMTP client (TLS or STARTTLS), to one or more addresses, with the acknowledge link. |

Setup for each channel, phone acknowledgement and on-call escalation are covered in **[docs/alerts.md](docs/alerts.md)**.

## Configuration

All settings are environment variables, which can live in `.env`:

| Variable | Default | Purpose |
|---|---|---|
| `VIGIA_LANG` | `en` | Language of alerts and dashboard: `en` or `es` |
| `NTFY_TOPIC`, `NTFY_SERVER`, `NTFY_TOKEN` | — , `https://ntfy.sh`, — | ntfy channel |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | — | Telegram channel |
| `WEBHOOK_URL` | — | Generic JSON webhook |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE` | —, `587`, auto (`true` on 465) | Email channel: SMTP server. STARTTLS is used when offered, and required before sending a password (except to `localhost`) |
| `SMTP_ALLOW_PLAIN` | `false` | Allow sending without TLS to a remote relay that offers none (never with a password). Not recommended: alerts carry client names and acknowledge links |
| `SMTP_USER`, `SMTP_PASS`, `MAIL_FROM`, `MAIL_TO` | —, —, `SMTP_USER`, — | Email credentials, sender, and recipients (comma-separated). Email is on when `SMTP_HOST` and `MAIL_TO` are set |
| `HEARTBEAT_URL` | — | Pinged every minute (dead man's switch). Receives `/fail` when the alert chain is broken. |
| `HEARTBEAT_FAIL_URL` | `HEARTBEAT_URL` + `/fail` | Failure URL, for services that use a different one |
| `CANARY_DAYS`, `CANARY_ACK_HOURS` | `7`, `24` | Weekly test alert that must be acknowledged. `0` turns it off. |
| `CHECKIN_SECRET` | — | Master secret for backup check-ins, inventory pushes and computer install lines. Servers never get it: they get per-asset keys (`node server.mjs key <asset>`) |
| `ENROLL_DAYS` | `7` | How long an install line for computers stays valid |
| `WORDFENCE_API_KEY` | — | Free Wordfence Intelligence key, enables WordPress checks |
| `WORDFENCE_HOURS`, `WORDFENCE_URL` | `6`, the v3 production feed | How often to refresh the feed, and from where (a mirror, for example) |
| `PUBLIC_URL`, `ACK_SECRET` | — | Enable signed, expiring acknowledge links in P1/P2 notifications |
| `HOST`, `PORT` | `127.0.0.1`, `4848` | Dashboard bind address |
| `DASH_PASS` | — | HTTP Basic auth for the dashboard (user `vigia`). Required when listening beyond localhost, Docker included |
| `DIGEST_HOUR`, `DIGEST_TZ` | `9`, `Europe/Madrid` | When to send the daily digest |
| `EPSS_P1`, `EPSS_P2` | `0.5`, `0.1` | EPSS thresholds for escalating alerts |
| `ADVISORY_FEED_URLS` | — | `name=url,…` to replace or add advisory feeds |
| `REPORT_BRAND` | — | Your company name on client reports |
| `OLLAMA_MODEL`, `OLLAMA_URL`, `OLLAMA_TIMEOUT_S` | —, `http://127.0.0.1:11434`, `120` | Optional local AI for explanations and client drafts ([docs/ai.md](docs/ai.md)) |
| `CONNECTIVITY_URLS` | Cloudflare trace, `1.1.1.1` | Probed before each uptime round. If none answers, Vigía is the one offline: the round is skipped instead of paging for every site. |
| `CHECKIN_ALLOW_MASTER` | `false` | Servers sign with their asset's key (`node server.mjs key <asset>`). Set `true` only while migrating from versions before 0.9 |
| `ALLOW_NO_PASSWORD` | `false` | Vigía refuses to listen beyond localhost without `DASH_PASS`, unless this is `true` |
| `ACK_LINK_DAYS` | `7` | Acknowledge links in notifications expire after this |
| `EDGE_VERSION_DAYS`, `ADVISORY_MAX_AGE_DAYS` | `60`, `45` | Ask to confirm a firmware version after this; ignore older advisories and posts |
| `DASH_HOSTS` | — | Extra host names allowed to open the dashboard when `DASH_PASS` is not set |
| `DNS_SERVERS` | `1.1.1.1,8.8.8.8` | Resolvers for the DNS check. Public resolvers avoid stale local caches and split-horizon answers. |
| `VIGIA_INV`, `VIGIA_STATE`, `VIGIA_PUSHED`, `VIGIA_WORDFENCE` | `data/…` | File locations |

## HTTP endpoints

| Endpoint | Auth | Description |
|---|---|---|
| `GET /` | dashboard | Web dashboard (installable app; its static files are public, the data is not) |
| `GET /api/state` | dashboard | Inventory, status, alerts and feed timestamps as JSON |
| `POST /api/ack?key=…` | dashboard | Acknowledge an alert. For a change alert, this also accepts the new value as the baseline. |
| `GET/POST /api/ack?key=…&f=…&e=…&sig=…` | signed link | Acknowledge from a notification. The link is bound to one alert (or one burst summary) and expires; an invalid one answers `410`. GET shows a confirmation button, so link previews cannot acknowledge by accident. |
| `POST /api/backup/<asset>/<job>?status=…` | HMAC signature | Backup check-in, see [docs/backups.md](docs/backups.md#check-in-protocol) |
| `POST /api/inventory/<asset>` | HMAC signature | Inventory push, see [docs/inventory-push.md](docs/inventory-push.md#protocol) |
| `POST /api/enroll-token` | dashboard | Create an install line for a client: `{client}` → `{token, expires, commands: {unix, windows}}` |
| `POST /api/enroll` | install-line token | A computer registers: `{token, host, machineId}` → `{asset, key}`. Ten bad tokens block the address for 10 minutes |
| `GET /agent/install.sh`, `/agent/vigia-collect.sh`, `/agent/vigia-agent.ps1` | none | The agent scripts, so the install line needs only Vigía's address |
| `GET /api/reports` | dashboard | Clients and months available for reports |
| `GET /report?client=…&month=YYYY-MM` | dashboard | Monthly client report (HTML, printable) |
| `GET /api/inventory`, `POST /api/assets`, `PUT/DELETE /api/assets/<id>`, `POST /api/assets/<id>/pause` | dashboard | Edit the inventory. Every write sends the revision it started from (`409` if the file changed meanwhile) and keeps a copy in `data/inventory-history/` |
| `GET/POST /api/maintenance`, `DELETE /api/maintenance/<id>` | dashboard | Maintenance windows |
| `POST /api/ai/explain\|client?key=…` | dashboard | Local AI explanation or client draft for one alert (never sent anywhere) |
| `POST /api/test` | dashboard | Send a test P1 to every channel. Answers `400` with no channel configured and `502` if none delivered it |
| `GET /healthz` | none | Liveness check for Docker or your load balancer |

## What Vigía is not

Be honest with your clients about what is covered:

- **Its AI is not an analyst.** The optional local model only explains and drafts, from Vigía's facts. Read what it writes before using it.
- **It does not make phone calls by itself.** For a real on-call rotation with calls and escalation, send the webhook to PagerDuty, Better Stack or Grafana OnCall. One person is not a sustainable 24/7 rota.
- **PrestaShop, Joomla and Drupal modules** are not covered by a dedicated feed yet: only through OSV (Composer packages) and KEV. WordPress is covered through Wordfence.
- **It does not scan networks or fingerprint devices.** Firewalls and VPNs are declared by you; Vigía only checks whether the management address you declared answers. Computers report on themselves through the agent you install: which ports *they* listen on, not what is reachable from the Internet.
- **It is not a SIEM, EDR or WAF.** Logs, file integrity, malware and intrusion detection belong to tools like Wazuh, CrowdSec or Cloudflare. Vigía complements them.
- **It only knows about backups that report in.** It cannot see inside your backup tool. A job that never calls `vigia-checkin.sh` is invisible, and a "success" is only as honest as the script that sends it. Real restore tests remain your job: Vigía only reminds you.
- **The content check reads the HTML the server sends.** Scripts injected later by JavaScript, for example through a tag manager, or code that only shows up for some visitors (cloaking), are invisible to it. It catches the common cases, but it is not a full malware scanner.

## Development

```bash
npm test          # unit and HTTP integration tests (node:test, no dependencies)
```

- `server.mjs` holds the scheduler, the checks, the notifications and the HTTP server.
- `lib.mjs` holds the pure logic: matching, priorities, validation and signatures. It is unit tested.
- `alerts.mjs` holds the alert lifecycle (raise, escalate, group, deliver, retry), with the transport injected and the lifecycle tested without a network.
- `i18n.mjs` holds the alert texts in English and Spanish.
- `report.mjs` renders the monthly client report (pure functions).
- `ai.mjs` builds the grounded prompts for the optional local AI (pure functions).
- `smtp.mjs` is the email channel: a small SMTP client (TLS, STARTTLS, AUTH PLAIN/LOGIN), tested against a local fake server.
- `deploy/` holds the agents: `vigia-install.sh` and `vigia-collect.sh` (Linux, macOS), `vigia-agent.ps1` (Windows), `vigia-checkin.sh` (backups).
- `public/` holds the dashboard: an installable web app with no build step (`app.js`, `model.js`, `icons.js`, `app.css`, `sw.js`). See [docs/dashboard.md](docs/dashboard.md).
- `scripts/demo.mjs` runs the demo, and `scripts/make-icons.mjs` draws the app icons.

New to Vigía? Start with the **[technician's quick manual](docs/manual.md)**.

Contributions are welcome, see [CONTRIBUTING.md](CONTRIBUTING.md). To report a security issue, see [SECURITY.md](SECURITY.md).

## Roadmap

- New certificates in Certificate Transparency logs (as P3)
- PrestaShop/Drupal module feeds
- A read-only portal per client (their own alerts and report), and per-client email recipients
- Optional URL reputation through Google Web Risk
- More vendor PSIRT feeds (SonicWall, Ivanti and Citrix publish no usable RSS today; INCIBE-CERT covers them)
- Monthly report delivery by email
- Built-in PagerDuty Events v2 and Twilio call integrations
- Ubuntu USN and Debian DSA advisory feeds
- Lower memory use for the Wordfence feed, and faster uptime rounds beyond 1,000 assets
- Importing monitors from Uptime Kuma
- Per-client quiet hours (recurring maintenance windows)

## Data sources

CISA KEV (public domain), FIRST EPSS, vendor PSIRT feeds (Fortinet, Palo Alto Networks, Cisco), INCIBE-CERT, research blogs (Volexity, watchTowr Labs, GreyNoise, Rapid7; titles and links only), OSV.dev (each record under its source's licence), endoflife.date (MIT), IANA RDAP bootstrap, and Wordfence Intelligence (free for personal and commercial use under Wordfence's terms, cited as the source in every WordPress alert).

## License

[MIT](LICENSE) © 2026 Aulafy
