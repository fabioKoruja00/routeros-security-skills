# Scripts, scheduler, files and containers checks

Severity scale: CRITICAL / HIGH / MEDIUM / LOW. Every command is read-only. Method and output format: `routeros-audit-method`.

## 1. Script, scheduler and fetch

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Secret inside a script | `/system script print detail` | password, bot token, API key or connection string in the `source` field — any user with read access extracts it | CRITICAL |
| Export with secrets inside a script | `/system script print detail` and `/system scheduler print detail` | call to `export` with `show-sensitive`: the file comes out with **PPP, wireless and tunnel passwords in cleartext** — and the routine usually mails or FTPs it | CRITICAL |
| Backup leaving by an insecure path | same commands | routine using `mode=ftp` or a destination that is not the approved repository | CRITICAL |
| Script not requiring permissions | `/system script print detail` | `dont-require-permissions=yes`: a user in a restricted group triggers an action their group would not allow | HIGH |
| Broad script permission | `/system script print detail` (`policy`) | a simple routine with `policy` containing `password`, `sensitive` or `policy` | HIGH |
| Fetch without certificate validation | `/system script print detail` and `/system scheduler print detail` | `/tool fetch` call without `check-certificate`: **the official default is `no`, even over HTTPS** — whoever sits on the path swaps the downloaded content and nothing complains | HIGH |
| Fetch over plain HTTP | same | `url="http://..."` downloading a blocklist, a script or a configuration | HIGH |
| Unknown schedule | `/system scheduler print detail` | task nobody recognises, `on-event` calling a removed script, or `start-time=startup` with strange content | CRITICAL |
| Orphan script | `/system script print detail` (`last-started`, `run-count`) | script with a high `run-count` and no visible scheduler — called by another path | HIGH |

Scheduler and script are where an intruder's persistence lives. A finding here is **never** LOW.

## 2. Files, backup and storage

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Exported config sitting on disk | `/file print detail` | `.rsc` file on the device: `export` without `hide-sensitive` writes PPP, IPsec and wireless passwords in cleartext | CRITICAL |
| Binary backup without password | `/file print detail` and `/system backup ...` | `.backup` generated without `password` — restorable by whoever downloads the file | HIGH |
| Cloud backup without password | `/ip cloud print` | `backups-enabled=yes` without a backup password set | HIGH |
| DDNS on without use | `/ip cloud print` | `ddns-enabled=yes` publishing the device's public IP without need | MEDIUM |
| SMB exposed | `/ip smb print` and `/ip smb shares print detail` | `enabled=yes` with `interfaces=all` or a share without authentication | CRITICAL |
| Unplanned disk/partition | `/disk print detail` and `/partitions print` | mounted media that is not in the inventory | MEDIUM |
| Degraded RAID | `/disk raid print` | array in degraded mode: the next failure takes the data with it, and nothing warns | HIGH |
| ROSE installed without use | `/system package print` and `/disk print detail` | `rose-storage` package present on a device that only routes — file-service surface for no reason | MEDIUM |

`export` without `hide-sensitive` is the most common way to leak the wireless and PPPoE
password — the file stays in `/file` and nobody remembers it.

## 3. Container (v7)

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Container active without being planned | `/container print detail` | container running on a network device nobody declared | CRITICAL |
| No RAM ceiling | `/container print detail` | `ram-limit` empty: a memory leak kills the router by OOM | HIGH |
| Running on the internal flash | `/container print detail` (`root-dir`) | `root-dir` on the internal NAND — constant writes destroy the device's flash | HIGH |
| veth with access to management | `/interface veth print detail` and `/interface bridge port print detail` | container interface in the same bridge as management, without a filter | CRITICAL |
| Untrusted image source | `/container print detail` (`remote-image`) | image pulled from a public registry without pinning the digest | HIGH |
| `container` enabled without use | `/system device-mode print` | `container=yes` on a device that runs none | MEDIUM |
