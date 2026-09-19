# Automation, storage and observability checks

Severity scale: CRITICAL / HIGH / MEDIUM / LOW. Every command is read-only.

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

## 4. Log and time

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Log only in memory | `/system logging print detail` and `/system logging action print detail` | no `remote` action: a reboot erases everything, and whoever breaks in reboots | HIGH |
| Critical topic not logged | `/system logging print detail` | absence of `account`, `critical`, `error`, `warning` (and `firewall` where a rule has `log=yes`) | HIGH |
| Remote log not arriving | `/system logging action print detail` + count on the collector | `remote` action configured pointing to an IP that no longer receives — **the system lies about its own state** | CRITICAL |
| NTP off | `/system ntp client print` and `/system clock print` | `enabled=no` or clock out of time: invalidates TLS certificates, breaks RPKI/DNSSEC and makes the log useless for forensics | HIGH |
| Open NTP server | `/system ntp server print` and `/ip firewall filter print detail` | `enabled=yes` reachable from the WAN — amplification vector | HIGH |
| Debug on permanently | `/system logging print detail where topics~"debug\|packet\|raw"` | debug/packet/raw topic logging non-stop: leaks traffic content and fills the disk | HIGH |
| E-mail without TLS or with a credential | `/tool e-mail print proplist=address,port,tls,from,vrf` | `tls=no`, or an SMTP password stored and reachable by anyone with read access | HIGH |
| Evidence never handled | `/log print without-paging where topics~"account\|critical\|error\|warning"` | serial failed logins, unexpected reboot or configuration change recorded and never looked at | HIGH |
| Netwatch with broad action | `/tool netwatch print detail` | `on-down`/`on-up` running a script with more permission than needed | MEDIUM |

## 5. SNMP and monitoring

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Default community | `/snmp community print detail` | `public` or `private` still present and enabled | CRITICAL |
| No source restriction | `/snmp community print detail` | `addresses=0.0.0.0/0` (or `::/0`, which is the factory value) — the MIB hands out interfaces, IPs, clients, traffic and topology | HIGH |
| Write enabled | `/snmp community print detail` | `write-access=yes`: **the device can be reconfigured over SNMP**, and with a default community that is open administrative access | CRITICAL |
| Unprotected trap | `/snmp print` | `trap-version=1` or `2`, with a default community, leaving the management network | MEDIUM |
| v1/v2c on an untrusted network | `/snmp print` and `/snmp community print detail` | `security=none` outside an isolated management network | HIGH |
| Trap to the wrong destination | `/snmp print` (`trap-target`) | trap leaving to an IP that is not the current collector | MEDIUM |

## 6. AAA and RADIUS

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Weak RADIUS secret | `/radius print proplist=disabled,address,service,protocol,src-address,timeout,require-message-auth` | `secret` short, generic or repeated on every NAS | HIGH |
| RADIUS without Message-Authenticator | same command | `require-message-auth` off on RADIUS over UDP: forgeable reply, authentication accepted without the server having said anything | HIGH |
| CoA / incoming open | `/radius incoming print` | `accept=yes` without source restriction: anyone drops or re-authorises a subscriber session | CRITICAL |
| Single RADIUS, no pair | `/radius print detail` and `/radius monitor [find] once` | one server only: a RADIUS outage locks administrative login too, if AAA depends on it | HIGH |
| AAA default group | `/user aaa print` | `default-group=full` — whoever RADIUS authenticates enters with full power | CRITICAL |
| RADIUS over an untrusted network | `/radius print detail` | server reached over the Internet or a third party's link without IPsec | HIGH |
| `accounting` off | `/radius print detail` | no accounting: no record of who connected and when | MEDIUM |
| PPP user with a weak password | `/ppp secret print detail` | password short, equal to the user name, or a sample | HIGH |
| PPP profile without cipher | `/ppp profile print detail` | `use-encryption=no` on a profile that crosses a public network | HIGH |
| Weak PPP authentication | `/ppp aaa print` and `/interface <type>-server server print` | `authentication` accepting `pap` (user and password in cleartext) | HIGH |
| User Manager exposed | `/user-manager router print detail` | weak shared secret, or the User Manager web interface reachable from outside | HIGH |

## 7. Certificates

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Expired on an active service | `/certificate print detail` | `invalid-after` in the past on a certificate used by `www-ssl`, `api-ssl`, SSTP, OVPN or CAPsMAN | HIGH |
| Short key | `/certificate print detail` | `key-size` below 2048 | HIGH |
| Private key missing | `/certificate print detail` | flags without `K`: the certificate cannot serve the server role and the service drops when it needs it | MEDIUM |
| ACME renewal stalled | `/certificate print detail` | ACME certificate near expiry without renewal, or DNS no longer pointing to the IP | MEDIUM |
| Test CA in production | `/certificate print detail` | self-signed CA generated in a lab serving external access | MEDIUM |

## 8. Procedure during an incident

Not a configuration check — how to look without making it worse.

| Situation | What to use | What NOT to use |
|---|---|---|
| Suspected flood | `/ip firewall connection print count-only`, then `/system resource print` | **Torch and `/tool profile` on a device already at 100% CPU**: both cost CPU and can take the device down for good |
| Finding the source | `/ip firewall connection print where protocol=... and dst-port=...` | active scanning from the device itself |
| Confirming state exhaustion | `/ip firewall connection tracking print` (compare usage and ceiling) | raising `max-entries` without treating the source — only postpones the exhaustion |
| Wireless | `/interface wireless registration-table print` | `scan` and `snooper` without `background=yes` — **they drop the radio's clients** |

## 9. Nuances that generate false positives

- **A script without a scheduler is not suspicious by itself** — it may be called by Netwatch, a
  DHCP lease script, PPP `on-up` or the mode button. Find the caller before accusing.
- **An `.rsc` in `/file` may be the team's legitimate restore routine.** The finding survives if
  the file has a secret inside: check with `export hide-sensitive` whether the equivalent content
  hides something.
- **Log only in memory is the factory default.** The finding is "nobody configured the shipping",
  not "someone disabled it" — that changes the wording and the severity.
- **The automatic blacklist catches whoever monitors.** The brute-force ladder lists whoever
  fails the password a few times in a row — including the administrator — and the scan detector
  (`psd`) catches the inventory tool and the NMS. Before recommending, check the management
  network is exempted **above** those rules; without that the recommendation is a scheduled outage.
- **A per-source connection limit takes a whole office behind one public IP down.** Count how
  many users leave through that address before suggesting the value.
