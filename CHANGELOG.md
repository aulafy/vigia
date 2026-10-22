# Changelog

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
