---
name: routeros-audit-automation
description: "Read-only security audit of what runs by itself inside a MikroTik RouterOS device, what it stores and what it tells the outside: scripts, scheduler and fetch (secrets in source, export with show-sensitive, unverified HTTPS), files and backups left on disk, containers (v7), logging and NTP, SNMP communities and write access, AAA/RADIUS (Message-Authenticator, CoA, default group), PPP secrets, certificates, plus the safe procedure to look at a device during an incident without making it worse. This skill should be used when auditing persistence, credential exposure and observability on a RouterOS device without changing configuration."
---

# RouterOS security audit — automation, storage and observability

What runs on its own inside the device, what it keeps, and what it reports outward. In this area
the typical finding is **a credential sitting in cleartext**, not an open port.

## Rules

- Read-only. Never `set`, `add`, `remove`, `enable`, `disable`, `reboot`.
- **Secrets never enter the report.** `/system script print detail` shows the `source` — read it
  to *detect* a credential, never copy it. `/radius`, `/snmp community`, `/ppp secret` and
  `/tool e-mail`: use `proplist` with the non-secret fields only. The finding is "credential in
  script X", not the value.
- Connect with a `read`-group user. Audit only the devices that were named.
- Scheduler and scripts are where an intruder's persistence lives. A finding here is **never** LOW.

## Severity

CRITICAL / HIGH / MEDIUM / LOW — in doubt, the lower. A secret inside a script, an `export
show-sensitive` sent by e-mail or FTP, an `.rsc` on disk with PPP/wireless/IPsec passwords, an
unknown scheduled task, `public`/`private` SNMP community, SNMP write access, RADIUS CoA open to
any source, or remote logging pointing to a collector that no longer receives are CRITICAL.

## Checks

[references/checks.md](references/checks.md) — sections: script, scheduler and fetch (1); files,
backup and storage (2); container (3); log and time (4); SNMP and monitoring (5); AAA and
RADIUS (6); certificates (7); procedure during an incident (8); false-positive nuances (9).

## Output

One document per device with findings: what is wrong, the read command that proves it, what is
at stake, and the possible fixes with the risk of each. Path, not recipe: no write command ready
to paste. A script that nobody recognises is a possible compromise — recommend investigation
before removal, and removal only after the caller is found.

## Traps

- **`/tool fetch` does not verify certificates by default** (`check-certificate=no`, even over
  HTTPS). Whoever sits on the path swaps the downloaded content and nothing complains.
- **`export` without `hide-sensitive` is the most common way to leak the wireless and PPPoE
  passwords** — the file stays in `/file` and nobody remembers it.
- **Log only in memory is the factory default.** The finding is "nobody configured remote
  logging", not "someone disabled it" — that changes the wording and the severity.
- **Remote logging configured to a dead collector is worse than none:** the system lies about its
  own state. Confirm reception on the collector side, not just the action on the device.
- **A script without a scheduler is not suspicious by itself** — it may be called by Netwatch, a
  DHCP lease script, PPP `on-up` or the mode button. Find the caller before accusing.
- **The automatic blacklist catches the monitoring itself.** The brute-force ladder lists whoever
  fails the password a few times in a row — including the administrator — and the port-scan
  detector catches the inventory tool and the NMS. Check the management network is exempted
  **above** those rules before recommending; otherwise the recommendation is a scheduled outage.
- **A per-source connection limit takes a whole office behind one public IP down.** Count how
  many users leave through that address before suggesting the value.
