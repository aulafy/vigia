# Backup check-ins

"Backup completed" in a log nobody reads protects nothing. Backups fail silently: a full disk, an expired cloud credential, a cron job that stopped after a server migration, or ransomware that quietly encrypts the source, so every new backup is useless. Vigía watches backups the only way that works without agents: **each backup job reports to Vigía, and Vigía alerts when a report is missing, failed or looks wrong.**

## How it works

```text
backup job ── signed POST ──▶ Vigía ── RPO exceeded / failure / shrunk / no restore test ──▶ alert
   (cron)     start / success / fail / restore
```

1. You declare the jobs in the inventory, with the maximum age you accept for a backup (the **RPO**).
2. At the end of each run, the job calls `deploy/vigia-checkin.sh`, a tiny script that needs only `sh`, `openssl` and `curl`.
3. Every 5 minutes, and on every check-in, Vigía compares what it received with what it expects.

| Finding | Priority |
|---|---|
| The job reported `fail` and has not succeeded since | P1 on high criticality, otherwise P2 (override with `priority`) |
| No success within `rpoHours` + `graceMinutes` (including a job that never reported) | P1 on high criticality, otherwise P2 |
| Size below `minRatio` (default 50 %) of the median of the previous runs (needs 3 previous runs) | P2 |
| No restore test within `restoreTestDays` | P2 |

When the next successful run arrives, the alert closes with a **RECOVERED** message.

## 1. Declare the jobs

```json
{
  "id": "acme-shop",
  "client": "ACME Ltd",
  "name": "Online shop",
  "domain": "shop.example.com",
  "criticality": "high",
  "backups": [
    { "id": "db",    "rpoHours": 24, "graceMinutes": 90, "restoreTestDays": 30 },
    { "id": "files", "rpoHours": 168, "minRatio": 0.7 }
  ]
}
```

| Field | Default | Meaning |
|---|---|---|
| `id` | required | Job name, unique within the asset. Use letters, digits and dashes: it goes into the URL. |
| `rpoHours` | `24` | Maximum acceptable age of the last good backup. |
| `graceMinutes` | `60` | Extra margin before alerting, for jobs that sometimes run long. |
| `restoreTestDays` | — | Require a recorded restore test at least this often. |
| `minRatio` | `0.5` | Alert if a backup is smaller than this fraction of the usual size. |
| `priority` | by criticality | Force `P1` or `P2` for failed and overdue alerts. |

A job that has never reported starts its RPO clock when it first appears in the inventory. If you add it and the first check-in never arrives, you hear about it.

## 2. Configure the secret

On the Vigía server, set a random `CHECKIN_SECRET` in `.env`. This is the master secret: the keys for each asset are derived from it (see below).

```bash
openssl rand -hex 32
```

The backup hosts must reach Vigía over HTTPS, behind a reverse proxy, Tailscale or a Cloudflare Tunnel (see [deployment.md](deployment.md#exposing-the-dashboard-optional)). Check-ins do not need the dashboard password: the signature authenticates them.

## 3. Call it from the job

Copy `deploy/vigia-checkin.sh` to the backup host and set two variables:

> **Give each server its own key, not the master secret.** On the Vigía host, run `node server.mjs key <asset-id>` and use the result as `VIGIA_CHECKIN_SECRET` on that asset's servers. A key only works for its own asset, so a compromised server cannot fake backups or inventories for other clients. Once every server has its own key, set `CHECKIN_ALLOW_MASTER=false`.


```bash
export VIGIA_URL=https://vigia.example.com
export VIGIA_CHECKIN_SECRET=<the same CHECKIN_SECRET>
```

Wrap the backup command:

```sh
#!/bin/sh
OUT=/backups/shop-$(date +%F).sql.gz
vigia-checkin.sh acme-shop db start
if mysqldump --single-transaction shop | gzip > "$OUT"; then
  vigia-checkin.sh acme-shop db success "{\"bytes\":$(wc -c < "$OUT")}"
else
  vigia-checkin.sh acme-shop db fail '{"message":"mysqldump failed"}'
fi
```

Restic, Borg, rclone, Veeam post-job scripts, `pg_dump`, a NAS task: anything that can run a shell command works the same way.

### Restore tests

A backup is only proven by restoring it. After a test restore (a scheduled one, or one you did by hand), record it:

```bash
vigia-checkin.sh acme-shop db restore
```

You can also report it with the successful run: `{"bytes": 123, "restoreTest": true}`, or `"restoreTest": "2026-10-01"` for a test done earlier.

## Check-in protocol

For use without the script, from PowerShell, Python or a backup tool's webhook:

```text
POST /api/backup/<assetId>/<jobId>?status=start|success|fail|restore
x-vigia-timestamp: <unix time in seconds>
x-vigia-signature: <hex HMAC-SHA256 of "<timestamp>.<path and query>.<body>" with CHECKIN_SECRET>
content-type: application/json

{"bytes": 123456, "objects": 42, "durationS": 310, "restoreTest": true, "message": "…"}
```

- The body is optional. Every field in it is optional too.
- The signature covers the timestamp, the exact path with its query and the body. A check-in cannot be moved to another job, edited, or replayed later. Signatures expire after 5 minutes, and the same signature is accepted only once (a replay gets `409`).
- Responses: `200` accepted, `401` bad or expired signature, `404` unknown job, `400` invalid status or body.
