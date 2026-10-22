# Firewalls, VPN and remote access (edge devices)

Most small-business breaches don't start at the website. They start at the **front door**: the firewall, the VPN gateway or the remote-support tool facing the Internet. These devices are attacked within hours of a vulnerability becoming public, and often before a patch exists. Recent examples include FortiOS SSL-VPN, PAN-OS GlobalProtect, Ivanti Connect Secure, Citrix NetScaler and BeyondTrust Remote Support.

Vigía watches the devices **you declare**. It does not scan networks or fingerprint devices. It uses what you tell it, plus public advisories.

## Declaring devices

Add an `edge` list to any asset. An asset can also consist of edge devices only, such as a client's office network:

```json
{
  "id": "acme-net",
  "client": "ACME Ltd",
  "name": "Office network",
  "criticality": "high",
  "edge": [
    { "type": "fortigate", "name": "Madrid FortiGate", "version": "7.2.5",
      "portal": "https://vpn.acme.example", "management": "https://203.0.113.10:4443" },
    { "type": "beyondtrust", "name": "Remote support", "version": "24.2" }
  ]
}
```

| Field | Meaning |
|---|---|
| `type` | One of the known types below, or any name of your own together with `kev` / `adv` phrases. |
| `name` | How the device appears in alerts and reports. |
| `version` | The firmware or software version. It is included in alerts, so you can see at a glance whether an advisory applies, and it drives the end-of-life check. |
| `portal` | The public VPN or login page. Vigía checks its certificate, self-signed ones included. |
| `management` | The **administration** address. Vigía checks whether it is reachable from the Internet, which it should never be. |
| `kev`, `adv`, `feeds` | Your own phrases for matching KEV entries and advisories, and which feeds to read (for `type`s not in the table). |

### Known types

Every device, whatever its type, also reads the research feeds of **Volexity, watchTowr Labs, GreyNoise and Rapid7**. The table lists the vendor feeds on top of those.

| `type` | Device | Advisory feeds | End-of-life |
|---|---|---|---|
| `fortigate` | FortiGate (FortiOS, FortiProxy) | Fortinet PSIRT, INCIBE-CERT | ✓ |
| `paloalto` | Palo Alto PAN-OS / GlobalProtect | Palo Alto PSIRT, INCIBE-CERT | ✓ |
| `cisco-asa` | Cisco ASA / Firepower Threat Defense | Cisco PSIRT, INCIBE-CERT | |
| `cisco-iosxe` | Cisco IOS XE | Cisco PSIRT, INCIBE-CERT | ✓ |
| `ivanti` | Ivanti Connect Secure / Policy Secure | INCIBE-CERT | |
| `netscaler` | Citrix NetScaler ADC / Gateway | INCIBE-CERT | |
| `sonicwall` | SonicWall SonicOS / SMA | INCIBE-CERT | |
| `sophos` | Sophos Firewall | INCIBE-CERT | |
| `checkpoint` | Check Point Quantum | INCIBE-CERT | |
| `watchguard` | WatchGuard Firebox | INCIBE-CERT | |
| `zyxel` | Zyxel firewalls and VPN | INCIBE-CERT | |
| `mikrotik` | MikroTik RouterOS | INCIBE-CERT | ✓ |
| `beyondtrust` | BeyondTrust Remote Support / PRA | INCIBE-CERT | |
| `screenconnect` | ConnectWise ScreenConnect | INCIBE-CERT | |
| `opnsense` | OPNsense | INCIBE-CERT | ✓ |

## What Vigía checks

| Check | Every | Alert |
|---|---|---|
| **CISA KEV**: the device's product has a vulnerability that is being exploited | 15 min | **Always P1**, whatever the asset's criticality: this is the front door. A new device is checked against the last 90 days of KEV. |
| **Vendor advisories** from the Fortinet, Palo Alto and Cisco PSIRT feeds, plus INCIBE-CERT for every vendor | 15 min | Exploited in the wild (or a "0-day exploitation" post): **P1** · critical, high, CVSS ≥ 7 or pre-auth RCE: P2 · other: P3 |
| **Researchers** for every device: Volexity, watchTowr Labs, GreyNoise, Rapid7 | 15 min | Same rules. A **scanning or reconnaissance wave** against the product (GreyNoise) is P2: attackers are looking for devices like yours, often before the vulnerability is public. |
| **Management reachable from the Internet** (TCP/TLS handshake at the `management` address, from Vigía) | 15 min | P2 until it is closed · **P1** "exploitable from the Internet" while the device also has an exploited vulnerability (KEV or advisory) |
| **Firmware version freshness** | 15 min | P3 when the declared `version` has not changed or been confirmed (`"checked": "YYYY-MM-DD"`) for `EDGE_VERSION_DAYS` (60) |
| **Portal certificate** | 15 min | < 3 days: P1 · < 14 days: P2 |
| **End-of-life firmware** (endoflife.date) | 6 h | Like any other software |

Advisories are matched by **product**, not by vendor. A Fortinet bulletin about FortiSIEM, or "impact of the PHP vulnerability on our products", does not alert for a FortiGate. When the same CVE appears in several feeds, for example Fortinet's and INCIBE-CERT's, you get one alert, not two.

Advisories and posts older than `ADVISORY_MAX_AGE_DAYS` (45) are ignored, so a device added today is not flooded with last year's research.

**Patch and check for compromise.** Edge flaws are often exploited for weeks before anyone publishes them (BeyondTrust Remote Support: about 47 days; Ivanti Connect Secure: about 10). So every alert about an *exploited* edge vulnerability says it plainly: patching closes the door, but you also need to check whether someone already came in. Look at the vendor's integrity tool or IOCs, unknown admin accounts and unexpected configuration changes.

KEV entries and advisories carry no exact version ranges in a form that can be matched reliably, so these alerts show **your declared version** next to the link to the vendor advisory. Check the "affected versions" table there. If you are not affected, acknowledge the alert.

The management check sees what the Internet sees **from Vigía's location**. If your firewall allows Vigía's IP to reach the administration page (for instance, because Vigía runs inside your VPN), the result is not representative. Run Vigía outside, as recommended in [deployment.md](deployment.md).

## Early warning: EPSS

KEV lists what is already being exploited. [EPSS](https://www.first.org/epss/) (Exploit Prediction Scoring System, by FIRST) estimates the **probability that a CVE will be exploited in the next 30 days**, and it is updated daily for every CVE.

Every 2 hours, Vigía looks up the EPSS score of the CVEs in your open vulnerability alerts (OSV, WordPress, KEV and vendor advisories):

| EPSS | Effect |
|---|---|
| ≥ `EPSS_P1` (default 0.5 = 50 %) | Raised to **P1**, and an earlier acknowledgement no longer counts |
| ≥ `EPSS_P2` (default 0.1 = 10 %) | A P3 is raised to P2 |

EPSS never lowers a priority. The score is shown in the alert title: "(EPSS 91 %: likely to be exploited soon)".

## Settings

| Variable | Default | Purpose |
|---|---|---|
| `EPSS_P1`, `EPSS_P2` | `0.5`, `0.1` | Escalation thresholds |
| `EPSS_URL` | FIRST API | Override, for a mirror |
| `EDGE_VERSION_DAYS` | `60` | Ask to confirm a declared firmware version after this |
| `ADVISORY_MAX_AGE_DAYS` | `45` | Ignore advisories and research posts older than this |
| `ADVISORY_FEED_URLS` | — | `name=url,name=url`. Replaces or adds advisory feeds, for a mirror or your national CERT. A custom feed name is used by devices that list it in `feeds`. |
