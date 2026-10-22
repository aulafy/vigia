# Alerts, acknowledgement and on-call

## Priorities and behaviour

| Priority | Meaning | What you receive |
|---|---|---|
| **P1** | Act now, even at night: a critical site is down, a vulnerability exploited in the wild matches your stack, a certificate expires within days | Push at maximum priority, **repeated every 10 minutes until acknowledged** |
| **P2** | Act within hours: a high-severity vulnerability applies, software is out of support, a feed or check is not working | One push (resent only if no channel confirmed it) |
| **P3** | Plan it: moderate vulnerabilities, upcoming end-of-life | Only in the daily digest and the dashboard |

**Change alerts** (DNS records, registrar, transfer lock, redirects, new third-party scripts) compare against a baseline. Acknowledging one also **accepts the new value as the baseline**, so the same change does not alert again. The dashboard labels that button **Accept change**. Accept only changes you recognise.

When a site comes back or a certificate is renewed, you receive a **RECOVERED** message.

**Getting worse pages again.** If an open alert's priority rises (a certificate goes from 10 days to 2, a domain drops under 7 days, an OSV finding turns out to be in KEV, or EPSS jumps), you are paged again and an earlier acknowledgement no longer counts.

**Delivery is tracked.** Every P1/P2 remembers whether a channel confirmed it. P1s repeat every 10 minutes until acknowledged anyway. P2s that never got through, because of an outage, a restart or a crash, are retried every 10 minutes until one does.

**Bursts.** When one check produces more than 3 messages, you get a single summary. Its acknowledge link (and button) acknowledges every alert in the summary at once. When a dependency is upgraded and OSV no longer reports it, the alert closes on its own. That closure is silent, except for P1s.

## ntfy (recommended)

[ntfy](https://ntfy.sh) is a free, open-source push service with iOS and Android apps.

1. Install the app and subscribe to a topic with a long random name, for example `vigia-7f3c9a2e5b1d`. Topics on the public server are not private: anyone who knows the name can read them.
2. Set `NTFY_TOPIC=vigia-7f3c9a2e5b1d` in `.env`.
3. In the app's notification settings for that topic, allow it to **override Do Not Disturb** for priority 5 (urgent) messages. This is what wakes you up.
4. Press **Send test alert** in the dashboard.

For more privacy, [self-host ntfy](https://docs.ntfy.sh/install/), or use a protected topic and set `NTFY_SERVER` and `NTFY_TOKEN`.

## Telegram

1. Create a bot with [@BotFather](https://t.me/BotFather) and copy the token into `TELEGRAM_BOT_TOKEN`.
2. Send any message to your bot, then open `https://api.telegram.org/bot<TOKEN>/getUpdates` and copy `chat.id` into `TELEGRAM_CHAT_ID`. A group chat id also works, so a whole team can receive the alerts.

Telegram cannot bypass silent mode the way ntfy can. Use it as a second channel, not the only one.

## Webhook: phone calls and escalation

`WEBHOOK_URL` receives a `POST` with this JSON body for every P1 and P2:

```json
{
  "prio": "P1",
  "title": "ACME Ltd: Online shop is DOWN",
  "body": "ENOTFOUND (2 consecutive failures) — https://example.com. Contact: Jane +34 600…",
  "key": "down:acme-shop",
  "ackUrl": "https://vigia.example.com/api/ack?key=down%3Aacme-shop&f=1792700000000&e=1793304800000&sig=…"
}
```

Use it to connect a real on-call platform, which calls you, escalates to a second person when you do not answer, and keeps the rota:

- **PagerDuty / Better Stack / Opsgenie / Grafana OnCall:** create an incoming-webhook integration and point `WEBHOOK_URL` at it, with a small relay if the platform needs a different payload. Use `key` as the deduplication key. Burst summaries carry a `group:…` key that acknowledges every alert they contain.
- **Twilio:** a Twilio Studio flow triggered over HTTP can place a voice call that reads `title` out loud.
- **n8n / Make / Zapier:** fan the alert out to email, tickets or chat.

> If you promise 24/7 coverage to many clients, one person is not a rota. Plan for at least two people, or a night-time MDR/SOC, and write the scope, hours and escalation path into each contract.

## Acknowledging from the phone

By default you acknowledge a P1 in the dashboard. To do it straight from the notification:

1. Make Vigía reachable over **HTTPS**, for example behind Caddy or Nginx, a Cloudflare Tunnel or Tailscale Funnel.
2. Set `PUBLIC_URL=https://vigia.example.com`.
3. Set `ACK_SECRET` to a random value: `openssl rand -hex 32`.

P1 and P2 notifications then include an **Acknowledge** button in ntfy and a link in Telegram and the webhook. Each link is signed with HMAC-SHA256 for that alert only. It acknowledges that alert (or every alert of one burst summary) and nothing else, and it works without the dashboard password. Opening the link with GET shows a confirmation button, so Telegram previews or link scanners cannot acknowledge an alert by accident.

Each link is bound to that alert instance and expires after `ACK_LINK_DAYS` (7): an old link cannot acknowledge a new occurrence of the same problem. An expired or invalid link answers `410`; use the dashboard instead.

## Watching the watcher

A monitor that dies quietly is worse than none, because you believe you are covered. A monitor whose alerts never reach your phone is just as bad, and much harder to notice. Vigía checks both.

### The alert chain

- **Real delivery, with retries.** Each channel is tried 3 times (after 2 s and 8 s). Success means real delivery, not just an HTTP 200: ntfy must return a message id, Telegram must answer `"ok": true`, and a webhook must answer 2xx.
- **One channel down:** a P2 goes out through the channels that still work, and it closes on its own when the channel recovers. This is a good reason to configure two channels.
- **All channels down:** Vigía calls `HEARTBEAT_URL` + `/fail` (healthchecks.io and Better Stack both support it). The heartbeat service then alerts you by its own means, such as email, SMS or a phone call. Vigía keeps sending `/fail` instead of the normal ping every minute, and every 10 minutes it tries to deliver a "delivery restored, some alerts may have been lost" message. Once one gets through, the heartbeat goes back to normal. For a service with a different failure URL, set `HEARTBEAT_FAIL_URL`.
- **No channel configured:** the heartbeat receives `/fail` from the start, so a forgotten `.env` cannot pass for a working setup.

### The weekly canary

The channels can all work and you can still miss alerts: the app was uninstalled, notifications were muted, or the phone changed. To catch that, every `CANARY_DAYS` (default 7) Vigía sends a P2 **"weekly test: please acknowledge"**. Acknowledge it from the notification or the dashboard. If nobody does within `CANARY_ACK_HOURS` (default 24), Vigía raises a P1 and reports the chain as broken to the heartbeat service. Set `CANARY_DAYS=0` to turn it off.

### The process

- **Heartbeat:** set `HEARTBEAT_URL` to a ping URL from [healthchecks.io](https://healthchecks.io) (free tier) or a Better Stack heartbeat, and configure that service to alert you. Vigía calls it every minute. If the process crashes, the machine powers off or the network drops, the pings stop and the external service pages you.
- **Stale feeds:** a check that has not completed for about three cycles raises a P2 with the last error: uptime 5 min, DNS 20 min, KEV/content/edge 1 h, OSV/WordPress 2 h, EPSS 6 h, endoflife.date/RDAP 24 h. A feed that never worked since start counts from the start.
- **Coverage:** RDAP, DNS, page content or an advisory feed failing 3 times in a row *for one asset or feed* raises a P2 "cannot check…", even when the rest of the run is fine. It closes when the check works again.
- **Disk:** if `state.json` cannot be written, Vigía raises a P1. Alerts and acknowledgements would otherwise be lost on restart.
- **`/healthz`:** an unauthenticated liveness endpoint for Docker, systemd watchdogs or a load balancer.

## Daily digest

Every day at `DIGEST_HOUR` (time zone `DIGEST_TZ`), Vigía sends one message listing the open P2s you have not acknowledged and the P3s created since the last digest that went out. If there is nothing, it sends nothing; if sending fails, it tries again a few minutes later. A fresh install skips its first day, so it does not open with a digest, but what it finds from its first minute is in the next one.
