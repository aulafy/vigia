# Client portal and client e-mails

Your clients can see, and be told about, their own services, without an account and without access to your dashboard.

## The portal

**Clients → a client → Client portal and notices → Create link.** Send the link to the client. It opens a read-only page with:

- a one-line status: "Everything is working", or "2 open issues. Your IT team has been notified and is on it";
- their open issues in plain words (Urgent, Important, Notice), and whether you are already on it (acknowledged);
- their websites (working or down, availability this month, certificate), computers and servers (system, antivirus, last update), firewalls and VPN, and backups;
- their monthly reports, this month and last.

It shows **only that client's** assets and alerts, and never Vigía's own housekeeping (feed status, coverage, enrolment notes, the weekly test). It has no scripts, refreshes itself every 5 minutes, works in light and dark mode and on a phone, and tells search engines not to index it.

The link does not expire, so the client can bookmark it. **New link** creates another one and retires the previous one at once; **Turn off** retires it without a replacement. A retired or forged link answers *Not found*, and ten wrong links from one address are blocked for 10 minutes.

The link is signed with a key derived from `CHECKIN_SECRET` (or `ACK_SECRET` if there is no check-in secret). Changing that secret retires every portal link. The address in the link is `PUBLIC_URL`, so the client must be able to reach it, typically over HTTPS behind a reverse proxy. Only `/portal/…` needs to be public: the dashboard stays behind `DASH_PASS`.

## E-mails to the client

In the same section, **Who gets their notices by e-mail**: one or more addresses at the client, and which notices (urgent only, or urgent and important). It needs the SMTP settings of the [email channel](alerts.md#email); `MAIL_TO` is not needed for this.

What the client receives, compared with you:

| | You (the technician) | The client |
|---|---|---|
| New problem | yes | yes, from the priority they chose |
| Got worse (e.g. certificate from 10 days to 2) | yes | yes |
| P1 repeated every 10 minutes until acknowledged | yes | **no** |
| Resolved | yes (some quietly) | yes ("[Resolved] …"), for every problem they were told about |
| Still open after a maintenance window | yes | yes |
| Daily digest, weekly test, Vigía's own alerts | yes | no |
| Acknowledge link | yes | no: the portal link instead |

Notices for one client are **batched for a minute**, so a burst (a server with five sites going down) is one e-mail, not five. A client gets **at most one e-mail every 5 minutes**, a problem that appears and clears within the same batch is not sent at all, and one e-mail lists at most 20 items. Each e-mail says that their IT team has been notified, and links to the portal when it is on. **Send test** checks the addresses. If an e-mail to a client fails, you get a P2 (*E-mail to … could not be sent*), and the section shows the last result.

The sender is `MAIL_FROM` (or `SMTP_USER`): always your own address, never one made up from the client's domain.

E-mails and the portal use Vigía's language (`VIGIA_LANG`), the language the alert texts are written in.

## Good to know

- A client that disappears from the inventory (its last asset deleted) loses its link and recipients. A new client with the same name starts clean.
- History follows the asset: if you move an asset to another client, its past alerts appear in the new client's report.
- The portal's copy of the monthly report leaves out Vigía's internal alerts, like the portal.

## Where it is kept

`data/clients.json` (or `VIGIA_CLIENTS`): per client, the e-mail addresses, the chosen priority and the portal link's version. It holds client e-mail addresses, so it stays out of git like the rest of `data/`.

```json
{
  "Clínica Dental Sol": { "emails": ["gerencia@clinica-sol.example"], "minPrio": "P2", "portal": { "v": 2, "on": true, "at": "2026-10-23T09:00:00.000Z" } }
}
```

## API

| Endpoint | Auth | |
|---|---|---|
| `PUT /api/clients/<client>` | dashboard | `{ emails: "a@x.es, b@x.es" \| [...], minPrio: "P1" \| "P2" }` (up to 10 addresses) |
| `POST /api/clients/<client>/portal` | dashboard | `{}` creates a new link (retiring the old one) · `{ action: "revoke" }` turns it off → `{ url }` |
| `POST /api/clients/<client>/test` | dashboard | Sends a test e-mail to the client's addresses |
| `GET /portal/<token>` | the link | The portal page |
| `GET /portal/<token>/report?month=YYYY-MM` | the link | That client's monthly report |

`GET /api/state` includes `clients: { <client>: { emails, minPrio, portal: url | null, mail: { ok, at, err } } }`.
