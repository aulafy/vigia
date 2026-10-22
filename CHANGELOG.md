# Changelog

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
