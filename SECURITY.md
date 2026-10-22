# Security policy

Please **do not open a public issue** for security problems. Report them privately through [GitHub Security Advisories](https://github.com/aulafy/vigia/security/advisories/new).

We aim to acknowledge reports within 72 hours.

## Hardening notes for operators

- The dashboard binds to `127.0.0.1` by default. If you expose it, use HTTPS and set `DASH_PASS`.
- `data/inventory.json` describes your clients' infrastructure, which is valuable to an attacker. Keep it out of public repositories (it is in `.gitignore`) and restrict file permissions.
- Use a long random ntfy topic, or a protected topic with `NTFY_TOKEN`. Alert texts reveal client names and their vulnerabilities.
- `CHECKIN_SECRET` is the master secret for backup check-ins and inventory pushes. Do not copy it to servers. Give each server the key of its own asset (`node server.mjs key <asset-id>`), which cannot sign for any other asset, and set `CHECKIN_ALLOW_MASTER=false`. Rotating the master rotates every derived key.
- Without `DASH_PASS`, the dashboard only answers to `localhost`, `HOST`, the `PUBLIC_URL` host and `DASH_HOSTS`. This blocks DNS-rebinding pages from reading your inventory. Dashboard actions (acknowledge, accept change, test) require an `x-vigia-ui` header that cross-site forms cannot send.
- `/healthz` is unauthenticated and reveals only that Vigía is alive.
- `ACK_SECRET` signs acknowledge links. Rotating it invalidates every link already sent.
