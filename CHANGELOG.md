# Changelog

## 0.11.0 — 2026-10-23

### Added
- **Local AI (optional, Ollama):** two buttons on every alert. **Explain** covers what is happening, the real risk, numbered steps and how to check the fix. **Draft for the client** writes a short, jargon-free message to copy into an e-mail or WhatsApp. Both are marked as an AI draft. Nothing is sent, and the AI never changes priorities or acknowledges anything.
- **Grounded prompts** (`ai.mjs`): the model gets only what Vigía knows about that alert (registrar, DNS and SPF/DMARC records, component version, device, backup run, site status, EPSS…). Every unknown fact is listed as unknown, so the model does not fill gaps: without the registrar it had suggested "GoDaddy or Cloudflare" for a NameCheap domain; with it, it said NameCheap. Feed text is fenced as data.
- One generation at a time, a cache per alert text, and a time limit. **Settings** shows whether the model is installed and reachable. The configuration is `OLLAMA_MODEL` (enables it), `OLLAMA_URL` and `OLLAMA_TIMEOUT_S`.
- `POST /api/ai/explain` and `POST /api/ai/client`.

### Fixed
- Tests and `npm run demo` no longer read your own `.env`. They could send test alerts to your real channels (`VIGIA_ENV_FILE` selects the file).

## 0.10.0 — 2026-10-23

### Added
- **Edit clients from the dashboard.** Add, edit, pause and delete assets with their software, firewalls/VPNs and backup jobs, with no JSON involved. The form validates as you type, with the same rules the server enforces (`public/validate.js`, shared), and proposes an ID from the client and name. Every save checks the revision the form started from, so a hand edit of `inventory.json` in the meantime is never overwritten: you get a warning and your changes are kept. The previous file is kept in `data/inventory-history/` (last 20), writes are atomic, and an unreadable `inventory.json` cannot be edited from the dashboard until it is fixed. IDs cannot change, because alerts and history use them.
- **Maintenance windows** for an asset, a whole client or everything, from the client page or Settings: 1/2/4/8 hours, until 08:00 tomorrow, or custom (up to 7 days). During a window, alerts for those assets are recorded but not sent, P1s do not repeat, and planned downtime does not count against availability. Whatever is still wrong when the window ends is sent then, marked "(after maintenance)", and what got fixed during the window is closed quietly. Windows appear on Today and in the client's monthly report.
- **Docker image on GHCR** for amd64 and arm64: `ghcr.io/aulafy/vigia`, tagged `latest`, `0.10` and `0.10.0`. `docker-compose.yml` now uses it. **Releases**: every version tag runs the tests, publishes the image and creates a GitHub release with the notes from this changelog.
- API: `GET /api/inventory`, `POST /api/assets`, `PUT|DELETE /api/assets/<id>`, `POST /api/assets/<id>/pause`, `GET|POST /api/maintenance`, `DELETE /api/maintenance/<id>`.

### Changed
- Dashboard actions with `PUT` and `DELETE` require the `x-vigia-ui` header too (CSRF).
- The client page lists every asset, device-only ones included, with Edit and Pause buttons.
- Focus and cursor survive redraws in every text field, not only in search.

## 0.9.0 — 2026-10-23

Driven by two external reviews: a code review by Codex (bugs, scale, security, UX) and research by Grok (how edge zero-days actually surface).

### ⚠️ Breaking
- **The master `CHECKIN_SECRET` is no longer accepted** for backup check-ins and inventory pushes. Each server must use its asset's key (`node server.mjs key <asset-id>`). To migrate gradually, set `CHECKIN_ALLOW_MASTER=true` temporarily.
- **Vigía refuses to listen beyond localhost without `DASH_PASS`**, and that includes Docker, where it listens on `0.0.0.0` inside the container. Set `DASH_PASS` in `.env`, or `ALLOW_NO_PASSWORD=true` if a proxy in front already authenticates.
- **Acknowledge links** in notifications are now bound to the alert instance and expire (`ACK_LINK_DAYS`, 7 by default). Links sent by older versions stop working.

### Fixed: alerts that could go unnoticed
- **A worse priority now re-pages** (for example TLS from P2 to P1, a domain under 7 days, or a vulnerability that turns out to be in KEV) and resets the acknowledgement. Before, the first priority stayed frozen.
- **Delivery is tracked per alert.** A P2 that never reached a channel, because of a crash, a restart or an outage, is retried every 10 minutes until one confirms it.
- **Bursts can be acknowledged from the phone:** the summary carries a group link that acknowledges every alert in it.
- **Onboarding findings** of a scan that failed half-way are no longer silenced: they join the next summary, and the health loop announces any left behind after an hour.
- **Daily digest:** uses a cursor instead of "last 24 h", so P3s from before the first digest or from an outage are no longer lost. It retries if sending failed.
- **The test alert** reports an error when no channel delivered it.
- **OSV:** follows `next_page_token` instead of silently truncating at 1,000 vulnerabilities per package.
- **A push during a busy scan** triggers another scan when it ends, instead of being dropped.
- **Coverage alerts:** RDAP, DNS, page content or an advisory feed failing 3 times in a row for one asset or feed raises a P2 ("cannot check…"). Before, one success anywhere marked the whole run healthy.
- **Monthly reports** are written atomically. The month is marked done only after every file is written, file names no longer collide (`A&B` and `A B`), and months follow `DIGEST_TZ` (DST included) instead of UTC.
- **Page bodies** are read up to 3 MB and the rest is dropped, so a huge page can no longer exhaust memory.
- **State files** are written with fsync. A disk error raises a P1 instead of crashing.
- KEV alerts close when their component disappears. Per-device and per-asset records of removed assets are cleaned up. A failed end-of-life lookup is no longer repeated for every component. An inventory push over 20,000 components says so and raises a P2.
- **TLS** is checked on the URL's own port. The dashboard shows a site as down only once the failure threshold is reached, matching the alerts.
- "Not known to be exploited in the wild" and its Spanish equivalents are no longer read as exploitation.
- XML entities outside Unicode no longer break a feed.

### Added: earlier warning on edge devices
- **Research feeds** for every declared firewall/VPN: Volexity, watchTowr Labs, GreyNoise and Rapid7. Posts older than `ADVISORY_MAX_AGE_DAYS` (45) are ignored.
- **Reconnaissance alerts (P2)**: GreyNoise-style "scanning spike against SonicWall…" posts. Attackers looking for your device type is the earliest signal there is.
- **Exposed and exploited is one P1**: when a device's management interface answers from the Internet *and* it has an exploited vulnerability, the exposure alert becomes P1 "EXPLOITABLE FROM THE INTERNET".
- **"Patch and check for compromise"**: exploitation often starts weeks before the advisory (BeyondTrust: about 47 days), so exploited edge alerts include compromise-assessment guidance.
- **Firmware version freshness:** a declared version not confirmed for `EDGE_VERSION_DAYS` (60) raises a P3. Add `"checked": "YYYY-MM-DD"` to a device after verifying it.
- Severity understands research wording: "0-day exploitation" is P1 and "pre-auth RCE" is P2.

### Security
- Signed check-ins and pushes must move forward in time per asset and endpoint: an A, B, A replay inside the 5-minute window is rejected.
- 10 failed logins from one address in 10 minutes → blocked for 10 minutes (429).
- `Cache-Control: no-store` on data, reports and acknowledge pages. The CSP no longer allows inline scripts.

### Dashboard
- Redraws only when something changed, and keeps keyboard focus across refreshes. Expandable texts are keyboard-accessible (`aria-expanded`, Enter/Space).
- P1/P2/P3 tags meet 4.5:1 contrast in both themes. There is a skip link, the search box has an accessible label, and touch targets on phones are at least 44 px.
- Refreshes cannot overlap, and a slow answer never overwrites a newer one. Errors are told apart: expired session, server error and offline (with or without data already shown).

### Internal
- The alert lifecycle moved to `alerts.mjs` with the transport injected. It is covered by `test/alerts.test.mjs`, and `test/server.test.mjs` starts the real server for HTTP integration tests. 81 tests in total.

## 0.8.0 — 2026-10-23

### Added
- **New dashboard**, an installable web app (manifest, service worker and icons) in the style of REM-L: graphite sidebar on computers, bottom tab bar on phones, and automatic, light or dark theme. Seven sections: **Today** (overall status, urgent list, channel and feed health), **Alerts** (filters by state, priority, client and text, acknowledge or accept change), **Clients** (per-client detail with sites, devices, backups, alerts and reports), **Devices**, **Backups**, **Reports** and **Settings** (theme, language, channels, feeds, configuration, test alert). Spanish and English.
- `npm run demo`: three fictional clients with local sites, devices and backups, in a temporary folder.
- `npm run icons`: draws the PNG app icons with no dependencies.
- `/api/state` now includes each asset's edge devices and monthly availability, the version and configuration flags.

### Changed
- The dashboard moved from `index.html` to `public/`. Static files are public (they hold no data). The page itself still asks for `DASH_PASS`, and the data stays behind authentication.
- The dashboard holds its 10-second redraw briefly after a tap, so clicks are never lost.
- The Docker image now copies `public/` and `package.json`.

## 0.7.0 — 2026-10-22

### Added
- **Edge devices** (`edge` on any asset: FortiGate, Palo Alto, Cisco ASA/IOS XE, Ivanti, NetScaler, SonicWall, Sophos, Check Point, WatchGuard, Zyxel, MikroTik, BeyondTrust, ScreenConnect, OPNsense, or custom). For each one: CISA KEV (always P1), vendor advisories, end-of-life firmware, whether the declared **management** address is reachable from the Internet (P2), and the **portal** certificate, self-signed included. Assets can be made of edge devices only.
- **Vendor advisories:** Fortinet, Palo Alto and Cisco PSIRT RSS plus INCIBE-CERT, matched by product (not vendor) and deduplicated by CVE across feeds. Exploited in the wild is P1, critical/high is P2. `ADVISORY_FEED_URLS` replaces or adds feeds.
- **EPSS early warning:** every 2 h, open vulnerability alerts with EPSS ≥ `EPSS_P1` (0.5) are raised to P1 and their acknowledgement is reset, and P3s with EPSS ≥ `EPSS_P2` (0.1) become P2.
- **Monthly client reports:** a printable HTML page per client and month (availability, incidents, MTTA/MTTR, recommended actions, sites, edge devices, backups, history), via `/report`, the dashboard, `node server.mjs report`, and written automatically to `data/reports/` when a month ends. Alert history and monthly availability are now recorded.
- KEV alerts link the vendor advisory from the KEV notes.

## 0.6.1 — 2026-10-22 (code review)

### Fixed: silent failures
- An unreadable `inventory.json` no longer empties the inventory or deletes every alert. Vigía keeps the last valid copy and raises a P2. While the inventory has errors, no alert or baseline is deleted as an orphan.
- Unacknowledged P1s now repeat every 10 minutes whatever check raised them. KEV, domain and WordPress P1s used to repeat only when their check ran again.
- New assets and newly reported products are matched against the last 90 days of CISA KEV. Before, only entries added after the asset existed were checked.
- A feed that has never succeeded since startup now goes stale and alerts.
- One failed OSV detail request no longer aborts the whole scan. Details are fetched in parallel and refreshed weekly.
- Request bodies are decoded as bytes. A UTF-8 character split across chunks broke check-in and push signatures.
- `.env` values in quotes are unquoted (`NTFY_TOPIC="x"` used to keep the quotes).
- Assets with only an `https://` url now get a TLS check, on the host they actually serve.
- An endoflife.date scan where every lookup failed counts as failed, not clean.
- An unreadable `state.json` is kept as `state.json.corrupt-<time>` instead of being silently overwritten.

### Fixed: scale
- Bounded parallelism: uptime 25, DNS 10, content 8, OSV details 8.
- The inventory is cached until `inventory.json` changes or a push arrives.
- `/api/state` returns at most 6 stack items per asset.
- The OSV cache expires after 30 days. State of removed assets (baselines, scans, pushed inventories) is cleaned up.
- When Vigía's own connection is down (connectivity probe, `CONNECTIVITY_URLS`), the uptime round is skipped instead of marking every site down.
- **Grouping:** when one run produces more than 3 messages, a single summary goes out instead.

### Fixed: security
- Per-asset check-in keys (`node server.mjs key <asset>`), with `CHECKIN_ALLOW_MASTER=false` to reject the master secret.
- CSRF: dashboard POSTs require an `x-vigia-ui` header.
- DNS rebinding: without `DASH_PASS`, only known host names may open the dashboard (`DASH_HOSTS`).
- Constant-time Basic auth comparison. `/healthz` no longer exposes feed errors, which contained client domains. Security headers added: frame-ancestors none, no-referrer, nosniff, CSP.
- Notification titles and bodies are clipped to the channels' size limits.

## 0.6.0 — 2026-10-22

### Added
- **Pushed inventory:** signed `POST /api/inventory/<asset>` plus `deploy/vigia-collect.sh`, which collects WordPress core, plugins and themes (WP-CLI), `package-lock.json`, `composer.lock`, CycloneDX and SPDX SBOMs (purls mapped to OSV ecosystems, including Debian, Ubuntu and Alpine), OS and runtime versions. Pushed components are merged with the declared stack and feed KEV, OSV, endoflife.date and Wordfence. A first push is treated as onboarding, and checks run right after each push.
- **Inventory freshness:** a P2 when an asset has not pushed within `inventoryMaxAgeHours` (default 48 h once it has pushed).
- **WordPress vulnerabilities** through the Wordfence Intelligence v3 production feed (`WORDFENCE_API_KEY`): exact version ranges, with P1 for KEV or CVSS ≥ 9 unauthenticated or on high-criticality assets. Alerts include the fixed version, and inactive plugins are flagged. The feed is cached and indexed in `data/wordfence.json`, and a cached copy stays in use for 24 h if a download fails.
- Version comparison for WordPress-style versions (`1.0 = 1.0.0`, `beta < rc < release`).

### Changed
- OSV is queried once per unique package version across all assets, in batches of 500.
- The dashboard shortens long stacks and shows each asset's inventory age.

## 0.5.0 — 2026-10-22

### Added
- **Alert-chain self-check:** every channel is retried (3 attempts) and checked for real delivery (ntfy message id, Telegram `ok:true`, webhook 2xx). One failing channel raises a P2 through the others. When all fail, Vigía calls `HEARTBEAT_URL/fail` (or `HEARTBEAT_FAIL_URL`) and keeps retrying with a "delivery restored" message.
- **Weekly canary:** a test alert that must be acknowledged within `CANARY_ACK_HOURS`. If it is not, Vigía raises a P1 and the heartbeat gets `/fail`.
- **Backup check-ins:** signed `POST /api/backup/<asset>/<job>` (HMAC-SHA256, 5-minute window, replay protection) and `deploy/vigia-checkin.sh`. Alerts for failed runs, missed RPO, shrunk backups and overdue restore tests. The dashboard gets a backups section.
- **SPF and DMARC:** an audit of missing or weak records (P3) and a baseline where a weakening change is P2.
- **Forms and iframes:** a `<form action>` posting to a new foreign domain (P1 on high criticality) and new foreign `<iframe>` hosts (P2).
- Acknowledge links on P2 alerts too, so the canary can be acknowledged from the phone.

### Changed
- The TLS check retries once before reporting an unreadable certificate.
- A fresh install skips its first daily digest. Canary alerts are left out of the digest.

## 0.4.0 — 2026-10-22

### Added
- **Domain registration check (RDAP, every 6 h):** expiry (< 7 days or expired = P1, < 30 days = P2), suspension (hold, redemption, pending delete = P1), removed transfer lock (P2) and changed registrar (P1 on high criticality). For TLDs without public RDAP, such as `.es`, use `domainExpires`.
- **DNS baseline (every 5 min):** NS and MX of the registrable domain, plus A/AAAA if listed in `dnsWatch`. A change has to show up twice in a row before it alerts. NXDOMAIN raises a P1.
- **Content check (every 15 min):** redirects to a foreign domain (HTTP or meta refresh), defacement and SEO-spam text, and new third-party `<script src>` hosts (the card-skimmer pattern).
- **Accept change:** acknowledging a change alert makes the new value the baseline.
- Asset options: `registrableDomain`, `domainExpires`, `dnsWatch`, `allowedHosts`, `strictScripts`, `ignoreKeywords`, `skip`.
- `DNS_SERVERS` setting. The new feeds also report when they go stale.

### Changed
- An onboarding scan that finds only P3s no longer sends a push. The findings wait for the daily digest.

## 0.3.0 — 2026-10-22

First public release: uptime and TLS checks, CISA KEV, OSV and endoflife.date matched against the inventory, P1/P2/P3 alerts over ntfy, Telegram and webhook, signed acknowledge links, onboarding summaries, heartbeat and stale-feed alerts, daily digest, English and Spanish.
