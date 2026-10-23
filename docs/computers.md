# Computers and servers: one line to add them

Websites and firewalls are watched from the outside. For the computers of a client (the front-desk PC, the boss's Mac, the file server), Vigía needs them to tell it what they run. One command line on each computer does that:

1. **Dashboard → Clients → a client → Add computers → Create install line.**
2. Copy the line for the system and run it on the computer:

   ```bash
   # Linux and macOS (terminal)
   curl -fsSL https://vigia.example.com/agent/install.sh | sudo sh -s -- https://vigia.example.com <token>
   ```

   ```powershell
   # Windows (PowerShell as Administrator)
   $env:VIGIA_URL='https://vigia.example.com'; $env:VIGIA_TOKEN='<token>'; irm https://vigia.example.com/agent/vigia-agent.ps1 | iex
   ```

3. The computer appears under the client a few seconds later, and reports again every day.

The same line works on any number of computers of that client for 7 days (`ENROLL_DAYS`). Running it again on a computer that is already registered updates it instead of adding a duplicate.

## What it reports

The agent looks only at **the computer it runs on**. It does not scan the network, other devices or ports of other machines.

| | Windows | Linux | macOS |
|---|---|---|---|
| Operating system | Edition, version (24H2…), build | `/etc/os-release` | `sw_vers` |
| Antivirus | Microsoft Defender (state, real-time protection, signature age) and any product registered in Windows Security | ClamAV, Microsoft Defender for Endpoint, CrowdStrike, SentinelOne, Sophos, ESET, Bitdefender | XProtect, Defender, and the agents above |
| Installed software | Programs and features (registry) | Installed packages (dpkg, rpm, apk) | Applications in `/Applications` |
| Listening ports | `Get-NetTCPConnection` | `ss` (or `netstat`) | `lsof` |
| Updates | Date of the last installed update | — | Compared with the latest release of its version |
| Runtimes | — | PHP, Node.js, nginx, Apache, MySQL/MariaDB, PostgreSQL, Redis, OpenSSL | the same, if installed |

## What it alerts on

| Finding | Priority |
|---|---|
| Windows with **no active antivirus** (none reported, or real-time protection off) | P2 |
| Antivirus signatures older than 7 days, or reported out of date | P3 |
| Windows without updates for **more than 45 days** / **more than 90 days** | P3 / P2 |
| Risky services listening on the network: RDP, SMB (not on Windows, where it is always on), FTP, Telnet, VNC, databases (MySQL, PostgreSQL, SQL Server, MongoDB, Redis, Elasticsearch, memcached) | P3 |
| The Docker API (2375) open on the network: anyone who reaches it is root | P2 |
| A **new** service listening on the network since the first inventory (acknowledge to accept it) | P3 |
| A port the computer listens on **answers from the Internet** at its public address (see below) | Risky service: P2 (P1 on high criticality) · Docker API: P1 · anything else: P3 |
| Operating system at or near end of life (Windows 10, old macOS, old Linux releases…), from endoflife.date | as for any end-of-life software |
| macOS behind the latest release of its version | P3 |
| A program attackers go after (WinRAR, 7-Zip, AnyDesk, TeamViewer, ScreenConnect, Veeam, PaperCut, MOVEit, FortiClient, Acrobat, Java…) gets a new entry in **CISA KEV** | as for any KEV match. Browsers, Office and Zoom update themselves: P3 |
| The computer stops reporting for 72 hours | P2 |
| A computer was added today (one note per client and day) | P3 |

"Listening on the network" is not the same as "reachable from the Internet": behind a router with NAT, it may not be. The alert says so. It is still worth knowing that the reception PC answers on RDP.

## Exposure to the Internet

"Listening on the network" does not say whether the Internet can reach it. So Vigía checks, from where it runs:

1. **Which address.** The public address the inventory arrived from, when it is a public one. If Vigía is inside the same network or behind a proxy, the address the agent looked up (`--publicip`, from `VIGIA_IP_URL`, default `https://api.ipify.org`). Behind a reverse proxy, `TRUST_PROXY=true` makes Vigía use the first `X-Forwarded-For` address. Only global addresses are ever used: private, loopback, link-local, carrier-grade NAT, documentation and multicast ranges are refused, so a computer cannot point Vigía at an internal network.
2. **Which ports.** Only the TCP ports **that computer reports listening on** beyond loopback, at most 50. Nothing else is tried.
3. **How.** A plain TCP handshake from Vigía to `address:port`, closed at once: no banner grab, no payload. At most once per address and port every `EXPOSURE_HOURS` (6), 10 at a time.
4. **Shared addresses.** Computers behind the same office router share one public address, and each pair of address and port is checked once. An open port means the router forwards it *somewhere*: the alert says the computer listening on it is the likely target.
5. **Same network as Vigía.** From inside the network that is being checked, the router may answer for itself (hairpin NAT), so the answer means nothing. When the computer's public address is Vigía's own (looked up from `PUBLIC_IP_URL`), the check is skipped and the dashboard says so. Run Vigía outside the client's network (a small VPS) to get this check.

6. **Limits.** At most 500 probes per round and 20,000 remembered results. A connection Vigía could not even attempt (no route from Vigía's own network) counts as unknown: it neither raises nor closes an alert. An address reported only by the agent waits until Vigía knows its own address, and a computer that reports more than 3 different addresses in a day is not checked. When several computers behind one address listen on the same port, the alert names the others: the forward reaches one of them.

Behind a proxy, only the **last** `X-Forwarded-For` entry counts (the one your proxy appended), and only when the connection comes from a private address. A computer can only make Vigía attempt a handshake on its own listening ports at one address. It cannot prove that address is really its own, which is why such alerts say "reported by the computer itself". Dual-stack networks are checked on one address family (usually IPv4).

Acknowledging an exposure alert accepts that port for that computer (a VPN port, a web server you publish on purpose). It does not come back unless you delete the computer. When a port stops answering, the alert closes with a *no longer answers from the Internet* message. `EXPOSURE_CHECK=false` turns the whole check off.

## Security

- **The install line** holds a token that names the client and expires. It is signed with `CHECKIN_SECRET`, so nothing is stored. Anyone with the line can add computers to that client until it expires, and each one shows up in the dashboard and in a P3 note. If you do not recognise one, delete it and create a new line.
- **Each computer gets its own key** (derived from `CHECKIN_SECRET`, like servers with `vigia-collect.sh`). It is stored readable only by root / SYSTEM and Administrators: `/etc/vigia/agent.env` (Linux, macOS) or `C:\ProgramData\Vigia\agent.json` (Windows). Every inventory is signed with it and protected against replay.
- **Use HTTPS.** The key travels when the computer registers, and the agent runs as root / SYSTEM. Over plain HTTP the installers accept only private addresses (10.x, 172.16–31.x, 192.168.x, localhost) and refuse anything else unless `VIGIA_INSECURE=1`. The dashboard warns you.
- On Windows the installer takes ownership of `C:\ProgramData\Vigia` for Administrators, removes inherited permissions and refuses a folder that is a link, so a normal user cannot plant a script the SYSTEM task would run.
- **Vigía must be reachable** from the computers: set `PUBLIC_URL` to that address (behind a reverse proxy, a tunnel or a VPN). With Vigía on `localhost`, the dashboard warns that the line will not work on other computers.
- The installer is a short shell or PowerShell script served by your own Vigía (`/agent/install.sh`, `/agent/vigia-agent.ps1`). Read it before running it: [deploy/vigia-install.sh](../deploy/vigia-install.sh), [deploy/vigia-agent.ps1](../deploy/vigia-agent.ps1).

## Where it lives on the computer

| | Linux / macOS (with sudo) | Without sudo | Windows |
|---|---|---|---|
| Program | `/usr/local/bin/vigia-collect` | `~/.local/bin/vigia-collect` | `C:\ProgramData\Vigia\vigia-agent.ps1` |
| Key | `/etc/vigia/agent.env` | `~/.config/vigia/agent.env` | `C:\ProgramData\Vigia\agent.json` |
| Daily run | systemd timer `vigia-collect.timer`, `/etc/cron.d/vigia-collect` or `/Library/LaunchDaemons/net.vigia.collect.plist` | your crontab or a LaunchAgent | Scheduled task "Vigia inventory" (SYSTEM) |
| Last result | `journalctl -u vigia-collect` or the cron log | — | `C:\ProgramData\Vigia\last.log` |

Without sudo it still works, but `lsof` and `ss` only see that user's processes.

**Try without installing:** `sh vigia-collect.sh test --all --dry-run` (Linux, macOS) or `$env:VIGIA_DRYRUN='1'; irm …/agent/vigia-agent.ps1 | iex` (Windows) print what would be sent.

**Remove:** `curl -fsSL https://vigia.example.com/agent/install.sh | sudo sh -s -- --uninstall`, or on Windows `$env:VIGIA_UNINSTALL='1'; irm …/agent/vigia-agent.ps1 | iex`. Then delete the computer in the dashboard.

## Limits

- The Windows agent does not see Windows Security products on **Windows Server** (it has no Security Center): only Defender is reported there.
- KEV matching for installed programs is by product name, not by version (KEV has no versions). For browsers and Office, which update themselves, it is a P3 heads-up.
- The last Windows update is the newest entry in `Get-HotFix`. Feature updates installed as a new build do not always appear there.
- XProtect (macOS) updates on Apple's schedule, so its age is not judged.
- Servers that already push with `vigia-collect.sh` (see [inventory-push.md](inventory-push.md)) can add `--listening --av --software`, or simply `--all`.
