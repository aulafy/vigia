# Inventory reference

The inventory is a JSON array in `data/inventory.json` (or the file set in `VIGIA_INV`). Each element is one **asset**: usually a website, but it can be any HTTPS endpoint, such as an API, a client portal or a VPN login page.

Vigía re-reads the file on every cycle. Invalid entries are skipped and reported in the log, and the rest keep working.

## Asset fields

| Field | Required | Example | Description |
|---|---|---|---|
| `id` | yes | `"acme-shop"` | Unique, stable identifier. Alerts are keyed on it, so do not rename it casually. |
| `client` | recommended | `"ACME Ltd"` | Shown at the start of every alert. |
| `name` | recommended | `"Online shop"` | Human-readable name. |
| `domain` | one of `domain`/`url` | `"example.com"` | Used for the TLS check, and for the uptime check when there is no `url`. |
| `url` | one of `domain`/`url` | `"https://example.com/health"` | Exact URL for the uptime check. Redirects are followed. |
| `expect` | no | `"Add to cart"` | Text that must appear in the response. Catches broken pages that still return 200, such as a white screen, a database error or a defaced homepage. |
| `criticality` | no (`medium`) | `"high"` | `high`, `medium` or `low`. A high asset turns downtime, KEV matches and critical CVEs into **P1**. |
| `contact` | no | `"Jane +34 600…"` | Included in downtime alerts so you know who to call. |
| `stack` | no | `[…]` | Software the asset runs (see below). |
| `paused` | no | `true` | Skip every check, for example during a migration. Existing alerts are kept. |
| `failThreshold` | no (`2`) | `3` | Consecutive failed probes before raising a downtime alert. |
| `timeoutMs` | no (`10000`) | `20000` | HTTP timeout for the uptime probe. |
| `registrableDomain` | no | `"empresa.com.es"` | The domain as registered, for the RDAP and NS/MX checks. Vigía works it out from `domain` and knows common suffixes such as `com.es` and `co.uk`. Set it when the guess is wrong. |
| `domainExpires` | no | `"2027-03-01"` | Expiry date for TLDs without public RDAP (`.es` and others). Without it, Vigía cannot warn you before the domain expires, and says so in the daily digest. |
| `dnsWatch` | no | `["A", "AAAA"]` | Also watch the host's IP addresses. NS and MX are always watched. |
| `allowedHosts` | no | `["stripe.com"]` | Foreign domains the page may redirect to or load scripts from. Subdomains are included. |
| `strictScripts` | no | `true` | A new third-party script becomes P1 instead of P2. |
| `ignoreKeywords` | no | `["hacked by"]` | Defacement phrases that are legitimate on this site. |
| `skip` | no | `["content"]` | Checks to turn off for this asset: `domain`, `dns`, `mail`, `content`. |
| `inventoryMaxAgeHours` | no | `24` | Expect a pushed inventory at least this often (see [inventory-push.md](inventory-push.md#freshness)). |
| `edge` | no | `[{ "type": "fortigate", "version": "7.2.5" }]` | Firewalls, VPN and remote-access devices (see [edge.md](edge.md)). An asset may have only `edge` devices and no `url`/`domain`. |
| `backups` | no | `[{ "id": "db", "rpoHours": 24 }]` | Backup jobs that report to Vigía. Fields and setup are in [backups.md](backups.md). |

The legacy Spanish field names `cliente`, `criticidad` (`alta`/`media`/`baja`) and `contacto` are also accepted.

## Stack entries

A stack entry describes one piece of software. Which fields you fill decides which checks apply to it:

```json
{ "product": "wordpress", "version": "6.4.3" }
```
*KEV.* `product` is matched as a whole word against the vendor and product of each newly added KEV entry.

```json
{ "product": "apache", "kev": ["apache http server"], "version": "2.4.58" }
```
*KEV with explicit phrases.* Use `kev` when the product name alone is ambiguous: "apache" alone would also match Apache OFBiz, Struts, Tomcat… You can list several phrases.

```json
{ "ecosystem": "npm", "name": "lodash", "version": "4.17.15" }
```
*OSV.* An exact package version. Vigía asks OSV which advisories affect *that* version, so you are never alerted about a bug that was fixed before your version.

```json
{ "product": "php", "version": "8.1.27", "eol": "php" }
```
*End-of-life* (see below). This entry is also checked against KEV, because it has a `product`.

```json
{ "wp": "plugin", "slug": "contact-form-7", "version": "5.9" }
```
*WordPress.* Matched against Wordfence Intelligence. Use `"wp": "core"` (no slug needed) for WordPress itself, and `"theme"` for themes. See [inventory-push.md](inventory-push.md#wordpress-vulnerabilities-wordfence-intelligence).
*End-of-life.* `eol` is the product id on [endoflife.date](https://endoflife.date). The version is matched to the most specific release cycle (`8.1.27` belongs to cycle `8.1`). This entry is also checked against KEV, because it has a `product`.

### OSV ecosystems

Common values: `npm`, `Packagist` (Composer), `PyPI`, `Go`, `Maven`, `RubyGems`, `crates.io`, `NuGet`, `Hex`, `Pub`. For OS packages: `Debian:12`, `Ubuntu:22.04`, `Ubuntu:24.04`, `Alpine:v3.19`, `Rocky Linux:9`. The full list is in the [OSV schema](https://ossf.github.io/osv-schema/#affectedpackage-field).

## How alerts are prioritised

| Finding | high | medium / low |
|---|---|---|
| Site down (≥ `failThreshold` failures) | P1 | P2 |
| TLS expires < 3 days / < 14 days | P1 / P2 | P1 / P2 |
| TLS unreadable while the site answers | P2 | P2 |
| New KEV entry matches a stack product | P1 | P2 |
| OSV advisory that is also in KEV | P1 | P1 |
| OSV advisory, critical | P1 | P2 |
| OSV advisory, high | P2 | P2 |
| OSV advisory, moderate/low/unknown | P3 | P3 |
| Software already end-of-life | P2 | P3 |
| Software end-of-life within 90 days | P3 | P3 |
| Domain expires < 7 days, expired, or suspended (hold, redemption, pending delete) | P1 | P1 |
| Domain expires < 30 days | P2 | P2 |
| Domain transfer lock removed | P2 | P2 |
| Domain registrar changed | P1 | P2 |
| TLD without RDAP and no `domainExpires` | P3 | P3 |
| Nameservers (NS) changed | P1 | P2 |
| Domain does not resolve (NXDOMAIN, twice in a row) | P1 | P1 |
| MX, A or AAAA records changed | P2 | P2 |
| Page redirects to a foreign domain (HTTP or meta refresh) | P1 | P2 |
| Defacement or SEO-spam text on the page | P1 | P2 |
| New third-party script on the page | P2 (P1 with `strictScripts`) | P2 |
| A form now submits to a new foreign domain | P1 | P2 |
| New foreign iframe on the page | P2 | P2 |
| SPF or DMARC changed and protection got weaker | P2 | P2 |
| SPF or DMARC changed otherwise | P3 | P3 |
| SPF/DMARC missing, `+all`, `p=none` or duplicated (audit) | P3 | P3 |
| Backup failed, or no success within the RPO | P1 | P2 |
| Backup much smaller than usual, or restore test overdue | P2 | P2 |
| WordPress: KEV, or CVSS ≥ 9 and unauthenticated | P1 | P1 |
| WordPress: CVSS ≥ 9 (authenticated) | P1 | P2 |
| WordPress: CVSS ≥ 7 | P2 | P2 |
| WordPress: lower or unscored | P3 | P3 |
| Pushed inventory older than its window | P2 | P2 |
| Edge device: product in CISA KEV | P1 | P1 |
| Edge device: vendor advisory, exploited in the wild | P1 | P1 |
| Edge device: vendor advisory, critical or high | P2 | P2 |
| Edge device: management interface reachable from the Internet | P2 | P2 |
| Any vulnerability alert whose CVE has EPSS ≥ 50 % | P1 | P1 |

## Domain, DNS and content checks

These three checks need no `stack` entries. They work from `domain` and `url`, and compare against a **baseline**: the first value Vigía sees for that asset.

**Domain (RDAP, every 6 h).** Vigía finds the registry's RDAP server through the [IANA bootstrap file](https://data.iana.org/rdap/dns.json) and reads the expiry date, the status codes and the registrar. RDAP covers all generic TLDs (`.com`, `.net`, `.org`, `.shop`…) and many country TLDs. **`.es` has no public RDAP**, so for `.es` domains set `domainExpires` by hand. Vigía lists every asset where this is missing in the daily digest.

**DNS (every 5 min).** Vigía asks the public resolvers in `DNS_SERVERS` for the NS and MX records of the registrable domain and, if you add `dnsWatch`, for the A/AAAA records of the host. A difference must show up in **two consecutive checks** before it alerts. If the records return to the baseline, the alert closes.

**Email spoofing (with the DNS check).** Vigía reads the SPF record of the registrable domain and the DMARC record at `_dmarc.<domain>`. It does two things with them:
- An **audit** (P3, daily digest) lists what makes the domain easy to spoof: no SPF, `+all`, several SPF records, no DMARC, `p=none` or several DMARC records. Domains that send no mail need these too: `v=spf1 -all` and `p=reject` stop anyone from sending in their name.
- A **baseline**: a change that weakens protection (DMARC lowered from `reject` to `quarantine` or `none` or removed, SPF removed or switched to `+all`) is a P2. Other changes, such as adding an include for a new mail provider, are P3. Turn the check off with `"skip": ["mail"]`.

**Content (every 15 min).** Vigía downloads the page at `url` (or `https://domain`) and looks for:
- the final URL after redirects, and any `<meta http-equiv="refresh">`, pointing to a foreign domain;
- typical defacement and SEO-spam phrases ("hacked by", "defaced by", pharma spam, Indonesian gambling spam such as "slot gacor"), HTML comments included;
- `<script src>` hosts that belong to another domain and were not in the baseline;
- `<form action>` hosts that belong to another domain and were not in the baseline. A login or payment form that suddenly posts elsewhere is phishing or skimming;
- `<iframe src>` hosts that belong to another domain and were not in the baseline.

Point `url` at the page that matters most, such as `/checkout` or `/login`. Add the same site again with another `id` and `url` to watch more pages.

The content check is skipped while the site is down, since the downtime alert already covers it. It only sees the HTML the server sends, not scripts injected later in the browser.

**Accepting a change.** Change alerts (registrar, lock, DNS, SPF/DMARC, redirect, scripts, forms, iframes) show an **Accept change** button in the dashboard and in the phone link. Pressing it makes the new value the baseline and closes the alert. If the change was not yours, do not accept it: investigate.

On the very first run, Vigía records the whole KEV catalogue but alerts only on entries added in the last 14 days. After that, every newly added entry is checked.

## Building the inventory quickly

Writing the inventory by hand works for a dozen sites. Beyond that, **let the servers push it**: [inventory-push.md](inventory-push.md) covers `vigia-collect.sh`, which reads WP-CLI, lockfiles, SBOMs, the OS and runtimes. To build a static inventory instead:

- **Node projects:** `npm ls --all --json` or the `package-lock.json`. Every package with a version becomes `{ "ecosystem": "npm", "name": …, "version": … }`.
- **PHP projects:** `composer show --format=json` or `composer.lock`, with `"ecosystem": "Packagist"`.
- **Containers and servers:** `trivy fs --format cyclonedx` or `syft <image> -o cyclonedx-json` produce an SBOM. Each component's `purl` maps directly to an OSV ecosystem, name and version.
- **WordPress:** `wp core version`, `wp plugin list --format=json` and `wp theme list --format=json` through WP-CLI over SSH.

Keep only the dependencies that are actually deployed. Including dev dependencies creates noise.
