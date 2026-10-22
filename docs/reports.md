# Monthly client reports

Vigilance that nobody sees is hard to charge for. Vigía can prepare a **monthly report for each client** in plain language: what was watched, what happened, how fast it was handled, and what is still pending. It is a single HTML page designed to be printed or saved as PDF from the browser, and it needs no extra software.

## What it contains

- **Summary:** availability over the month, number of incidents (P1/P2), open issues now, and median time to acknowledge and to resolve.
- **Recommended actions:** the open P1 and P2 issues, most urgent first. This is the list to discuss with the client.
- **Sites and services:** availability per site, its criticality and when the server last reported its inventory.
- **Firewalls, VPN and remote access:** each declared device with its version and open alerts.
- **Backups:** last good backup and last restore test per job, with any problem.
- **Planned maintenance** of the month, when there was any: when, what it covered and why. Probes during maintenance are not counted in availability.
- **Open issues** and **what happened this month**: every incident with when it opened, when it closed and how. It can be resolved, acknowledged, or closed as an accepted change.

Availability counts the uptime probes of the month. Rounds skipped because Vigía itself was offline are not counted, so they cannot lower the figure. P3 findings stay out of the incident counts, because they are maintenance, not incidents.

## Getting the reports

**Dashboard:** the *Monthly reports* section links every client's report for this month (so far) and last month. Add `&lang=es` or `&lang=en` to the URL to choose the language.

**Automatically:** when a month ends (in `DIGEST_TZ`), Vigía writes every client's report into `data/reports/<client>-<hash>-<YYYY-MM>.html` (the short hash keeps clients such as "A&B" and "A B" apart) and sends one P2: "Monthly reports for 2026-10 are ready". On a fresh install this starts from the next month change.

**Command line:**

```bash
node server.mjs report "ACME Ltd" 2026-10 > acme-2026-10.html   # one client
node server.mjs report all 2026-10                              # every client, into data/reports/
```

## Settings

| Variable | Purpose |
|---|---|
| `REPORT_BRAND` | Your company name, shown as "Prepared by". |
| `VIGIA_LANG` | Default language of the reports: `en` or `es`. |
| `DIGEST_TZ` | Time zone for dates and for deciding when a month ends. |

The `client` field of each asset groups assets into one report. Write it the same way on every asset of the same client.

Months are counted in `DIGEST_TZ`, daylight-saving changes included: an incident at 00:30 on 1 October in Madrid belongs to October. History is kept for 400 days and availability for about 13 months, so you can still regenerate last year's reports.
