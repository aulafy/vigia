# Security policy

Please **do not open a public issue** for security problems. Report them privately through [GitHub Security Advisories](https://github.com/aulafy/vigia/security/advisories/new).

We aim to acknowledge reports within 72 hours.

## Hardening notes for operators

- The dashboard binds to `127.0.0.1` by default. If you expose it, use HTTPS and set `DASH_PASS`.
- `data/inventory.json` describes your clients' infrastructure, which is valuable to an attacker. Keep it out of public repositories (it is in `.gitignore`) and restrict file permissions.
- Use a long random ntfy topic, or a protected topic with `NTFY_TOKEN`. Alert texts reveal client names and their vulnerabilities.
- `CHECKIN_SECRET` authenticates backup check-ins and inventory pushes. Anyone holding it can report a fake "backup OK" or a fake inventory, so keep it on the servers that need it and rotate it if a server is compromised.
- `ACK_SECRET` signs acknowledge links. Rotating it invalidates every link already sent.
