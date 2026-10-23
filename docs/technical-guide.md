# Vigía — technical guide

For IT staff who deploy, run and extend Vigía. It covers what the system does, how it does it, and how to operate it. Every interval, key format and limit here comes from the code. The other documents in `docs/` go deeper on single topics and are linked from each section.

---

## 1. What it is

Vigía is a single Node.js process (≥ 20, **zero runtime dependencies**) that monitors the websites, domains, firewalls, computers and backups of many small clients. It matches public vulnerability data against what each client actually runs, and pages the technician only when a finding applies to one of them.

Design rules that explain most decisions:

| Rule | Consequence |
|---|---|
| Zero dependencies | Node standard library only: own SMTP client, own JSON-file storage, no build step. Nothing to audit in `node_modules`. |
| Match before alerting | A CVE is news only if it hits a product (and, where data allows, the version) in the inventory. |
| Quiet by default | Every check defines what is P1, P2 or P3. Grouping, onboarding summaries, baselines and maintenance windows keep the pager meaningful. |
| No scanning | Vigía never sweeps networks or fingerprints devices. Devices are declared, and computers report on themselves. The only probes go to targets you declared or that a computer reported about itself. |
| Fail loudly about blindness | A feed, a check, a channel or the disk that keeps failing becomes an alert. Vigía itself is watched by an external heartbeat. |
| AI outside the alerting path | The optional local model explains and drafts; it never decides, acknowledges or sends. |

---

## 2. Architecture

```text
                    ┌──────────────────────────── server.mjs ─────────────────────────────┐
 public sources ──▶ │ scheduler (every)  → checks → raise/resolve ─▶ alerts.mjs ─▶ notify │ ─▶ ntfy / Telegram / webhook / SMTP
 sites, DNS, RDAP ◀─│ uptime, TLS, DNS, RDAP, content, KEV, OSV, Wordfence, EOL, edge,     │ ─▶ client e-mails (batched)
 agents (signed) ──▶│ EPSS, backups, inventory, machines, exposure, health, digest         │
 dashboard (PWA) ◀─▶│ HTTP API (auth + CSRF header) · portal (signed links) · agent files  │
                    └───── data/: inventory.json · state.json · pushed.json · clients.json ┘
```

| Module | Role | Tested in |
|---|---|---|
| `server.mjs` | Configuration, scheduler, all checks, notifications, HTTP server, CLIs | `test/server.test.mjs` (spawns the real server) |
| `lib.mjs` | Pure logic: matching, priorities, parsing (lockfiles, SBOM, feeds, RDAP), signatures, machine findings, exposure, enrolment | `test/lib.test.mjs` |
| `alerts.mjs` | Alert lifecycle with injected transport: raise, escalate, resolve, acknowledge, group, onboard, sweep, client events | `test/alerts.test.mjs` |
| `smtp.mjs` | SMTP client: implicit TLS / STARTTLS, AUTH PLAIN/LOGIN, RFC 2047 headers, base64 bodies | `test/smtp.test.mjs` (fake server, real TLS) |
| `portal.mjs` | Client portal page and its signed links | `test/lib.test.mjs` |
| `report.mjs` | Monthly client report (HTML, printable) | `test/report.test.mjs` |
| `ai.mjs` | Grounded prompts for the optional local model | `test/ai.test.mjs` |
| `i18n.mjs` | Alert texts, English and Spanish (`VIGIA_LANG`); a test checks both have the same keys | |
| `public/` | Dashboard PWA: `app.js` (router, screens), `model.js` (view logic, tested), `editor.js`, `validate.js` (shared with the server), `sw.js` | `test/model.test.mjs`, `test/validate.test.mjs` |
| `deploy/` | Agents and units: `vigia-install.sh`, `vigia-collect.sh`, `vigia-agent.ps1`, `vigia-checkin.sh`, `vigia.service`, `net.vigia.plist` | |

### Files on disk (`data/`)

| File | Content | Written | Back it up? |
|---|---|---|---|
| `inventory.json` (`VIGIA_INV`) | Assets: what to watch | By you or the dashboard editor; atomic, revision-checked, last 20 copies in `inventory-history/` | Yes |
| `state.json` (`VIGIA_STATE`) | Alerts, history, baselines (DNS, scripts, ports), backup records, availability, feed timestamps, maintenance windows, replay counters | After every scheduled run; atomic with fsync | Yes. Deleting it loses history and baselines, and replays the onboarding of every asset |
| `pushed.json` (`VIGIA_PUSHED`) | Inventories pushed by agents (components, machine data) | On every push | Optional (agents push again) |
| `clients.json` (`VIGIA_CLIENTS`) | Per-client e-mail recipients and portal link versions | From the dashboard | Yes |
| `wordfence.json` (`VIGIA_WORDFENCE`) | Cached Wordfence feed | Every `WORDFENCE_HOURS` | No |
| `reports/` | Monthly client reports written at month end | Monthly | Optional |

A `state.json` that does not parse is moved aside as `state.json.corrupt-<ts>` and Vigía starts empty instead of crashing. A write error is a **P1** (`vigia:disk`).

### Scheduler

Each job runs inside `alerts.run()`: its messages are flushed together at the end and grouped when there are more than 3. A job that is still running when its next tick comes is re-run once afterwards, not dropped. Each successful run stamps `state.feeds.<job>`; the health job turns a stale stamp into a P2.

| Job | Every | First run | Stale after |
|---|---|---|---|
| `uptime` (HTTP + TLS hourly) | 60 s | start | 5 min |
| `dns` (NS, MX, SPF, DMARC, opt. A/AAAA) | 5 min | +5 s | 20 min |
| `kev` | 15 min | start | 1 h |
| `osv` | 30 min | +15 s | 2 h |
| `content` | 15 min | +20 s | 1 h |
| `wordpress` | 30 min | +25 s | 2 h |
| `eol` (incl. macOS behind) | 6 h | +30 s | 24 h |
| `edge` (advisories, management exposure) | 15 min | +35 s | 1 h |
| `domain` (RDAP) | 6 h | +40 s | 24 h |
| `epss` | 2 h | +90 s | 6 h |
| `exposure` | 15 min (each address:port at most every `EXPOSURE_HOURS`) | start | — |
| `backups` | 5 min, and on each check-in | start | — |
| `inventory` (push freshness + machine findings) | 15 min, and on each push | start | — |
| `health` (stale feeds, repeats, retries, canary, heartbeat, reports, cleanup) | 60 s | start | — |
| `digest` | checks every 5 min, sends once a day at `DIGEST_HOUR` in `DIGEST_TZ` | | |
| `ai` (model reachable) | 10 min, only with `OLLAMA_MODEL` | | |

Before each uptime round, Vigía probes `CONNECTIVITY_URLS`. If none answers, Vigía is the one offline: the round is skipped instead of reporting every site down. The stale uptime feed and the missing heartbeat then raise the alarm.

---

## 3. Deploy

### Requirements and sizing

- Node 20, 22 or 24 (CI runs all three), or Docker (amd64, arm64).
- Memory: ~70 MB base (measured on 0.14 with a small inventory). With `WORDFENCE_API_KEY`, the feed index takes **350–700 MB** while loaded.
- Network out: HTTPS to the data sources, your sites, the alert channels and the SMTP server. For the exposure check, outbound TCP to your clients' public addresses.
- Network in: only if agents, phones (acknowledge links) or clients (portal) must reach it. Put it behind HTTPS.

### Docker (published image)

```bash
docker pull ghcr.io/aulafy/vigia:latest        # also :0.14 and :0.14.0
cp .env.example .env                           # set DASH_PASS (required off localhost) and a channel
docker compose up -d                           # docker-compose.yml: port 4848, ./data mounted
docker compose exec vigia node server.mjs key acme-shop
```

### From source

```bash
git clone https://github.com/aulafy/vigia && cd vigia
cp .env.example .env && $EDITOR .env
node server.mjs                                # or: npm start
```

Service units: `deploy/vigia.service` (systemd, with hardening options) and `deploy/net.vigia.plist` (launchd). Vigía exits with code 1 if asked to listen beyond localhost without `DASH_PASS` (`ALLOW_NO_PASSWORD=true` only behind an authenticating proxy).

### Reverse proxy (HTTPS)

Only these paths need to be public. Everything else can stay on a VPN.

| Path | Who calls it | Auth |
|---|---|---|
| `/api/inventory/<asset>`, `/api/backup/<asset>/<job>` | agents, backup jobs | HMAC signature |
| `/api/enroll`, `/agent/*` | computers running the install line | install-line token / none (static scripts) |
| `/api/ack?…&sig=…` | your phone, from a notification | signed link |
| `/portal/<token>…` | clients | signed link |
| `/healthz` | load balancer, Docker | none (reveals nothing) |

Caddy example:

```text
vigia.example.com {
  reverse_proxy 127.0.0.1:4848
}
```

Set `PUBLIC_URL=https://vigia.example.com`. If the proxy is the only way in, `TRUST_PROXY=true` makes the exposure check read the computer's address from `X-Forwarded-For`. Enable it only when the proxy overwrites that header.

### Minimal production `.env`

```bash
VIGIA_LANG=en
HOST=127.0.0.1                    # behind the proxy
PORT=4848
PUBLIC_URL=https://vigia.example.com
DASH_PASS=<long random>
CHECKIN_SECRET=<openssl rand -hex 32>
ACK_SECRET=<openssl rand -hex 32>
NTFY_TOPIC=vigia-<random>
HEARTBEAT_URL=https://hc-ping.com/<uuid>
SMTP_HOST=smtp.example.com
SMTP_USER=alerts@example.com
SMTP_PASS=<app password>
MAIL_TO=oncall@example.com
DIGEST_TZ=Europe/Madrid
```

The full variable list is in the [README](../README.md#configuration).

---

## 4. Inventory model

`data/inventory.json` is an array of **assets**. One asset is one thing you watch for one client: a site, a domain, a set of edge devices, or a computer. Field reference: [inventory.md](inventory.md).

```json
{
  "id": "acme-shop", "client": "ACME Ltd", "name": "Online shop", "criticality": "high",
  "url": "https://shop.acme.example/health", "domain": "shop.acme.example", "expect": "Add to cart",
  "contact": "Laura Gil +34 600 111 222",
  "stack": [
    { "ecosystem": "npm", "name": "lodash", "version": "4.17.15" },
    { "product": "php", "eol": "php", "version": "8.1.27" },
    { "wp": "plugin", "slug": "contact-form-7", "version": "5.9" }
  ],
  "edge": [{ "type": "fortigate", "name": "Office FortiGate", "version": "7.2.5", "management": "https://203.0.113.10:4443" }],
  "backups": [{ "id": "db", "rpoHours": 24, "restoreTestDays": 30 }],
  "inventoryMaxAgeHours": 24
}
```

- **Targets.** An asset needs at least one of `url`, `domain`, `edge` or `machine`.
- **Stack entries.** Four kinds:
  - `ecosystem` + `name` + `version`: OSV (npm, Packagist, PyPI, Go, Maven, RubyGems, crates.io, NuGet, Hex, Pub, Debian, Ubuntu, Alpine).
  - `product` (+ optional `kev` phrases): CISA KEV, name-only.
  - `eol` + `version`: endoflife.date.
  - `wp`: Wordfence.
  Pushed inventories are merged in and deduplicated.
- **Validation.** `public/validate.js` runs in the browser and on the server, returning error codes the UI translates. An inventory that does not parse never empties the watch list: the last good copy stays in use and a P2 says so.
- **Editing.** Changes are read live: the file is re-read when its mtime changes. The dashboard editor sends the revision it started from, and a hand edit in between makes the save fail with `409`. IDs are immutable, because alerts and history are keyed on them.
- **Criticality.** It drives priorities: a high asset turns downtime, KEV matches and critical CVEs into **P1**.

---

## 5. Checks reference

| Check | How | Raises | Closes |
|---|---|---|---|
| **Uptime** | `GET url` (redirects followed, `timeoutMs`), optional `expect` text in the first 3 MB. `failThreshold` (2) failures in a row | `down:<id>`: P1 high, else P2 | first success, with recovery message |
| **TLS** | TLS handshake to the served host (port from `url`), hourly, one retry | `tls:<id>`: < 3 d P1, < 14 d P2; unreadable P2 | renewed |
| **DNS** | NS/MX of the registrable domain (+A/AAAA with `dnsWatch`) via `DNS_SERVERS`; baseline on first sight, change confirmed twice | `dns:<id>:NS` (P1 high), MX P2, `dns:nx` P1 after 2 NXDOMAIN | back to baseline, or acknowledge = accept |
| **SPF / DMARC** | TXT lookups; audit what is missing (P3); compare with baseline | weakened protection P2 | as DNS |
| **Domain (RDAP)** | IANA bootstrap → registry RDAP; `domainExpires` for TLDs without RDAP | < 7 d or hold/redemption P1, < 30 d P2, transfer lock removed P2, registrar changed P1 high | |
| **Content** | One fetch: foreign redirect / meta refresh, defacement phrases, new foreign `<script src>`, `<form action>`, `<iframe src>` hosts against baseline + `allowedHosts` | redirect/defacement/form P1 high, script P2 (`strictScripts` P1), iframe P2 | acknowledge = accept the host |
| **CISA KEV** | Full catalogue every 15 min. New entries against all assets; new assets/products against the last 90 days. Whole-word match on vendor+product | `kev:<cve>:<id>`: P1 high/edge, P2 else; `kevPrio` P3 for self-updating software | product removed from the asset |
| **OSV** | `querybatch` (paginated, deduplicated across assets), details cached 7 days | in KEV or critical+high asset P1, critical/high P2, else P3 | dependency updated/removed |
| **Wordfence** | v3 production feed (`WORDFENCE_API_KEY`), exact version ranges for core/plugins/themes | KEV or CVSS ≥ 9 unauth/high asset P1, ≥ 7 P2, else P3 | |
| **End of life** | endoflife.date cycles; Windows by its own cycle ids (`11-24h2-w`, `10-22h2`, `2012-r2`) | past EOL P2 high / P3, < 90 d P3; macOS behind latest of its cycle P3 | |
| **Edge devices** | Declared only. KEV + vendor PSIRT RSS (Fortinet, Palo Alto, Cisco), INCIBE-CERT, research feeds; negation-aware severity parsing; TCP/TLS handshake to the declared management URL | KEV/exploited P1, exposed+exploited P1, critical/scanning wave P2, management reachable P2; version older than `EDGE_VERSION_DAYS` asks to confirm | [edge.md](edge.md) |
| **EPSS** | FIRST EPSS for CVEs in open alerts | ≥ `EPSS_P1` → P1, ≥ `EPSS_P2` P3→P2 | |
| **Backups** | Signed check-ins judged against `rpoHours`, `graceMinutes`, `restoreTestDays`, size history | failed/overdue P1 high else P2; shrunk or restore test overdue P2 | next success |
| **Pushed inventory freshness** | `inventoryMaxAgeHours` (48 h once an asset has pushed) | P2 | next push |
| **Computers** | See §8 | | |
| **Exposure** | See §8 | | |
| **Self-health** | stale jobs, coverage (same check failing 3 times for one asset), channels, disk, inventory errors | P2 (disk P1) | |

Alert keys are stable strings (`kind:asset[:detail]`), so a finding is reported once and closed when a later complete scan no longer finds it.

---

## 6. Priorities and the alert lifecycle

| | Meaning | Delivery |
|---|---|---|
| **P1** | Act now | Every channel, ntfy priority 5; **repeats every 10 min** until acknowledged |
| **P2** | Act within hours | Every channel, once; resent every 10 min only while no channel confirmed delivery |
| **P3** | Plan it | Dashboard and the daily digest only |

Lifecycle rules (`alerts.mjs`):

- **Raise** deduplicates by key. A worse priority re-pages and clears the acknowledgement ("(worse) …"). Priorities are never lowered automatically.
- **Resolve** sends a recovery message for P1/P2 that were sent, unless the check closes it quietly.
- **Group**: more than 3 messages from one run become one summary. Its `group:<id>` key acknowledges every alert in it.
- **Onboarding**: the first scan of a kind for a new asset stores findings and sends one summary ("12 findings · P1: 1 · P2: 3 · P3: 8"). P1s never wait more than 10 minutes for it.
- **Change alerts** carry an `accept` path. Acknowledging applies it to the baseline (DNS records, script hosts, listening ports, exposed ports).
- **Maintenance windows** (asset, client or all; at most 7 days). Alerts are recorded but not sent, and planned downtime does not count against availability. Still-open ones go out when the window ends, marked "(after maintenance)".
- **Delivery tracking**: `deliveredAt` is set only when a channel confirms (ntfy id, Telegram `ok`, HTTP 2xx, SMTP 250). If every channel fails, Vigía calls `HEARTBEAT_URL/fail`.
- **Canary**: a weekly P2 that must be acknowledged within `CANARY_ACK_HOURS`; if not, a P1 and `/fail`.
- **Digest**: open unacknowledged P2s and new P3s once a day.
- **History**: every alert's open, acknowledge and resolve times, kept 400 days, used by reports (MTTA, MTTR).

---

## 7. Channels

| Channel | Variables | Payload / behaviour |
|---|---|---|
| ntfy | `NTFY_TOPIC`, `NTFY_SERVER`, `NTFY_TOKEN` | JSON publish; P1 priority 5, else 4; an **Acknowledge** HTTP action when acknowledge links are on |
| Telegram | `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | `sendMessage` with the acknowledge link |
| Webhook | `WEBHOOK_URL` | `POST {prio, title, body, key, ackUrl}`: wire it to PagerDuty, Better Stack, Opsgenie, Twilio for calls and escalation |
| Email | `SMTP_HOST`, `SMTP_PORT` (587; 465 = TLS), `SMTP_USER`, `SMTP_PASS`, `MAIL_FROM`, `MAIL_TO` | STARTTLS required off localhost (`SMTP_ALLOW_PLAIN` only for password-less relays); certificate verified; `X-Priority: 1` for P1 |
| Heartbeat | `HEARTBEAT_URL`, `HEARTBEAT_FAIL_URL` | GET every minute; `/fail` when the alert chain is broken |

Each channel is retried (2 s, 8 s). A failing channel raises a P2 through the others.

**Acknowledge links** (`PUBLIC_URL` + `ACK_SECRET`):

```text
/api/ack?key=<alert key>&f=<alert first-seen ms>&e=<expiry ms>&sig=<HMAC-SHA256(ACK_SECRET, "key|f|e")[0:32]>
```

They are bound to one alert instance (a new alert with the same key is not covered) and expire after `ACK_LINK_DAYS`. `GET` shows a confirmation button, so link previews cannot acknowledge; `POST` acknowledges.

---

## 8. Agents, signatures and computers

### Signed calls

Backup check-ins and inventory pushes use the same scheme:

```text
key       = HMAC-SHA256(CHECKIN_SECRET, "vigia-asset:" + assetId)          # node server.mjs key <assetId>
signature = hex(HMAC-SHA256(key, ts + "." + path_with_query + "." + body))
headers   : x-vigia-timestamp: <unix seconds>   x-vigia-signature: <hex>
```

- The timestamp must be within ±300 s.
- Timestamps must move forward per asset and endpoint, so a captured call cannot be replayed (A-B-A included).
- The master secret itself is refused unless `CHECKIN_ALLOW_MASTER=true` (migration only).
- Inventory bodies are limited to 16 MB and 20,000 components; above that, a P2 says what is not being checked.

### Collector (`deploy/vigia-collect.sh`, POSIX sh + curl + openssl)

```bash
vigia-collect.sh acme-shop --wp /var/www/html --os --runtimes --npm /srv/app/package-lock.json
vigia-collect.sh --all            # with /etc/vigia/agent.env (installed by the install line)
vigia-collect.sh srv1 --all --dry-run
```

| Option | Part sent | Source |
|---|---|---|
| `--wp DIR` | `wp` | WP-CLI core/plugin/theme lists |
| `--npm`, `--composer`, `--cyclonedx`, `--spdx FILE` | lockfile / SBOM | file contents |
| `--os` | `os` | `/etc/os-release`, `sw_vers` |
| `--runtimes` | `runtime` | php, node, nginx, apache, mysql/mariadb, postgresql, redis, openssl on PATH |
| `--listening` | `listening` | `ss -Hltnp`, busybox/`netstat -ltn`, `lsof -iTCP -sTCP:LISTEN` |
| `--av` | `av` | ClamAV, mdatp, CrowdStrike, SentinelOne, Sophos, ESET, Bitdefender, XProtect |
| `--software` | `software` | dpkg / rpm / apk, `/Applications` (max 3,000) |
| `--publicip` | `network` | `VIGIA_IP_URL` (default `https://api.ipify.org`, `off` to skip) |
| `--all` | all six machine parts | |

Tested on macOS, Debian (dash, mawk, iproute2) and Alpine (busybox). The protocol and the JSON of each part are in [inventory-push.md](inventory-push.md#protocol).

### Install line (enrolment)

```text
token = base64url(client) "." expirySeconds "." HMAC-SHA256(CHECKIN_SECRET, "vigia-enroll|" + client + "|" + exp)[0:32]
```

1. The dashboard (`POST /api/enroll-token`) builds the token and two commands. The address in them is `PUBLIC_URL`, or the request origin only when it is a plain URL.
2. The computer computes `machineId = sha256(/etc/machine-id | IOPlatformUUID | MachineGuid)`, then calls `POST /api/enroll {token, host, machineId, platform}` and receives `{asset, key}`.
3. Vigía creates the asset as `{ id: suggestId(client, host), client, name, machine, machineId, criticality: "medium", inventoryMaxAgeHours: 72 }`. The same `machineId` and client reuse the asset; a different computer with the same name gets `-2`.
4. The installer stores the key and schedules the daily run:

   | | Key file | Schedule |
   |---|---|---|
   | Linux, macOS (as root) | `/etc/vigia/agent.env`, mode 600 | systemd timer, `/etc/cron.d` or LaunchDaemon |
   | Linux, macOS (no root) | `~/.config/vigia/agent.env` | crontab or LaunchAgent |
   | Windows | `C:\ProgramData\Vigia\agent.json` (SYSTEM + Administrators, owner Administrators, link refused) | Scheduled task "Vigia inventory" running as SYSTEM |

5. It sends the first inventory.

Plain HTTP is refused outside private ranges unless `VIGIA_INSECURE=1`. Bad tokens: 10 per address per 10 minutes. Each day's new computers are listed in one P3 per client. Details: [computers.md](computers.md).

### Machine findings (`lib.machineFindings`)

| Key | Rule | Priority |
|---|---|---|
| `mach:av` | Windows with no product that is enabled with real-time protection | P2 |
| `mach:avold` | enabled product with signatures > 7 days or reported out of date | P3 |
| `mach:patch` | Windows newest `Get-HotFix` > 45 days / > 90 days | P3 / P2 |
| `mach:risky` | RDP, SMB (not on Windows), FTP, Telnet, VNC, MySQL, PostgreSQL, SQL Server, MongoDB, Redis, Elasticsearch, memcached on a non-loopback address | P3 (Docker API 2375: P2) |
| `mach:port:<id>:tcp/N` | new non-loopback listener vs first inventory | P3, acknowledge = accept |
| `kev:…` on `software` | 37 product patterns mapped to KEV names (WinRAR, 7-Zip, AnyDesk, ScreenConnect, Veeam, PaperCut, MOVEit, FortiClient…) | as KEV; browsers, Office, Zoom P3 |

A push that lacks a part (no `--av`, say) never closes that part's alerts.

### Exposure to the Internet (`checkExposure`)

1. **Address.**
   - Candidates in order:
     1. the last `X-Forwarded-For` entry, only with `TRUST_PROXY=true` and a private peer;
     2. the push's TCP peer;
     3. the agent's `network.publicIp`.
   - The first **global** address wins (`lib.isPublicIp`: no RFC 1918, loopback, link-local, 100.64/10, documentation, benchmarking, multicast, reserved, ULA, 6to4).
   - Addresses are canonicalised with `net.isIP` and the URL parser; hostnames are never accepted.
   - An agent-only address waits until Vigía knows its own, and more than 3 addresses per computer per day stops the check for that computer.
2. **Ports.** Only the TCP ports that computer reports listening on beyond loopback, at most 50.
3. **Probe.** `net.connect`, 4 s timeout, closed on connect.
   - Ten at a time, at most 500 per round. Each `address:port` at most every `EXPOSURE_HOURS`.
   - Results are `open` / `closed` (refused or dropped) / `unknown` (no route: retried, never raises or closes), kept 7 days, 20,000 at most.
   - Computers sharing a NAT address share the results, and the alert names the others listening on that port.
4. **Same network.** Skipped when the address equals Vigía's own (from `PUBLIC_IP_URL`, refreshed every 6 h), because of hairpin NAT.
5. **Alerts.** `expo:<id>:<port>`:
   - risky service P2, or P1 on high criticality;
   - Docker API P1;
   - other ports P3.

   Acknowledging adds `tcp/<port>` to `state.machines[id].exposedOk`. When Vigía sees the port closed, the alert closes with a message; if the computer stopped listening, it closes quietly.

`EXPOSURE_CHECK=false` disables the probe entirely.

---

## 9. Clients: portal, e-mails and reports

| | Mechanism |
|---|---|
| Portal link | `/portal/base64url(client).v.HMAC-SHA256(HMAC(CHECKIN_SECRET or ACK_SECRET, "vigia-portal-key"), "vigia-portal|client|v")[0:32]` |
| Revocation | `v` and `on` live in `clients.json`; a new link bumps `v`, so old links answer 404 at once |
| What it shows | only that client's assets and alerts, minus internal keys (`cover:`, `inv:`, `enroll:`, `canary`, `channel:`, `feed:`, `vigia:`, `inventory:`); titles without the client prefix; no scripts; `no-store`, `noindex`, `no-referrer` |
| Abuse | only wrong links are counted: 10 per address per 10 minutes |
| Client e-mails | `onEvent` hook: new, worse, after-maintenance, and resolution of what they were told; never repeats; batched (60 s), one e-mail per client per 5 min max, 20 items max, come-and-go problems dropped |
| Reports | `/report?client=&month=` (dashboard) and `/portal/<token>/report?month=` (client copy without internal alerts); written for every client at month end into `data/reports/` |

Details: [portal.md](portal.md), [reports.md](reports.md).

---

## 10. HTTP API

All dashboard endpoints need Basic auth (`vigia` / `DASH_PASS`) when a password is set. Without one, they need an allowed `Host` (anti DNS-rebinding). Every non-GET also needs the header `x-vigia-ui: 1` (anti-CSRF). Responses are `no-store` with a strict CSP.

```bash
B="-u vigia:$DASH_PASS -H x-vigia-ui:1"
curl -s $B https://vigia.example.com/api/state | jq '.alerts[] | {prio,title}'
curl -s $B -X POST "https://vigia.example.com/api/ack?key=down:acme-shop"
curl -s $B -X POST https://vigia.example.com/api/test
curl -s $B -X POST https://vigia.example.com/api/enroll-token -H 'content-type: application/json' -d '{"client":"ACME Ltd"}' | jq -r .commands.unix
curl -s $B -X POST "https://vigia.example.com/api/clients/ACME%20Ltd/portal" -H 'content-type: application/json' -d '{}' | jq -r .url
```

The full table of endpoints is in the [README](../README.md#http-endpoints).

### CLIs

```bash
node server.mjs key <asset-id>                 # per-asset key for agents and backup jobs
node server.mjs report "<client>"|all [YYYY-MM] # write reports to data/reports/
npm run demo                                    # throw-away demo on :4848 (never reads your .env)
npm test                                        # 116 tests, no network needed except loopback
```

---

## 11. Security model and hardening

| Asset | Protection |
|---|---|
| Dashboard | `DASH_PASS` (required off localhost), 10 failed logins → 10 min block, Host allowlist without password, CSRF header, CSP without inline scripts, `X-Frame-Options: DENY` |
| Agent calls | per-asset HMAC keys, ±300 s window, monotonic replay protection, size limits |
| Install lines | expiring signed tokens, own rate limit, URL validation, HTTPS required off private ranges, locked-down install paths |
| Portal | signed versioned links, per-client filtering, wrong-link rate limit |
| Outbound probes | only declared targets or self-reported ports at global addresses |
| Secrets | `.env` and `data/` git-ignored; `CHECKIN_SECRET` never leaves the server; rotating it invalidates every agent key, install line and (without `ACK_SECRET` fallback) portal link |
| Email | TLS required, certificates verified, addresses validated before SMTP commands and headers |
| Feeds and AI | feed text treated as data; AI prompts fence it and the output is never acted on |

Checklist:

1. HTTPS in front, with `PUBLIC_URL` set.
2. `DASH_PASS`, `CHECKIN_SECRET`, `ACK_SECRET` from `openssl rand -hex 32`.
3. Dashboard on a VPN if possible, with only the public paths of §3 exposed.
4. `HEARTBEAT_URL` set, and the weekly canary acknowledged.
5. `data/` backed up and kept private: it maps your clients' weak spots.

Report vulnerabilities as described in [SECURITY.md](../SECURITY.md).

---

## 12. Operations

| Task | How |
|---|---|
| Is it alive? | `curl -s localhost:4848/healthz` → `{"ok":true,"uptimeAt":…}` |
| Logs | stdout (`journalctl -u vigia`, `docker compose logs -f`); one line per alert sent, every error with its source |
| Alerts reach me? | Settings → **Send test alert** (`POST /api/test` answers 400 without channels, 502 if none delivered) |
| A check keeps failing | Today → Vigía health (feed timestamps and errors), and the coverage P2 that names the asset |
| Upgrade | `docker compose pull && docker compose up -d`, or `git pull && systemctl restart vigia`. State files are forward-compatible; read the CHANGELOG for breaking changes |
| Move to a new host | copy `.env` and `data/`, start, run **Send test alert** |
| Rotate `CHECKIN_SECRET` | re-run `node server.mjs key` for every server and the install line on every computer; create new portal links |
| Remove a computer | `install.sh --uninstall` / `VIGIA_UNINSTALL=1`, then delete the asset in the dashboard |
| Scale | Tested with hundreds of assets; uptime runs 25 sites in parallel; OSV is deduplicated across assets. Beyond ~1,000 sites or with Wordfence on a small VPS, watch memory and round duration |

---

## 13. Limits

- KEV has no versions: matching for products and installed programs is by name, and by the last 90 days for newly added assets.
- Content checks read server HTML, not what JavaScript injects later.
- "Listening on the network" and "open from the Internet" are different findings. The second needs Vigía outside the client's network.
- Windows Server has no Security Center: only Defender is reported there. The last update is the newest `Get-HotFix` entry.
- Alert texts, client e-mails and the portal use one language per instance (`VIGIA_LANG`).
- One person is not a 24/7 rota. Use the webhook with an on-call service for escalation.
