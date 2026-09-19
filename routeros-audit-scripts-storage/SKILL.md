---
name: routeros-audit-scripts-storage
description: "Read-only audit of persistence and storage on MikroTik RouterOS: secrets inside scripts, export with show-sensitive in routines, backups leaving over FTP, scripts that do not require permissions or hold broad policies, fetch without certificate validation or over plain HTTP, unknown scheduler entries and orphan scripts, .rsc and unencrypted .backup files on disk, cloud backup and DDNS, SMB, unplanned disks, degraded RAID, ROSE, and containers (limits, root-dir on flash, veth on the management bridge, unpinned images). This skill should be used when auditing what runs by itself inside a RouterOS device and what it keeps, without changing configuration."
---

# RouterOS security audit — scripts, scheduler, files and containers

Scheduler and scripts are where an intruder's persistence lives, and `/file` is where credentials get forgotten in cleartext. A finding in the script/scheduler section is **never** LOW.

## Rules

Read-only: `print`, `get`, `export`, `monitor` only — never `set`, `add`, `remove`, `enable`, `disable`, `reboot`. Connect with a dedicated least-privilege audit account; do not assume the built-in `read` group is strictly read-only. Audit only the devices that were named. Secrets never enter the report (use `proplist` on areas that store credentials). Method, severity scale (CRITICAL / HIGH / MEDIUM / LOW — in doubt, the lower), output format and the collection order live in `routeros-audit-method`; factory values in `routeros-factory-defaults`. Read the RouterOS version first: v6 and v7 menus differ, and a command in the wrong menu returns empty.

## Checks

[references/checks.md](references/checks.md)

## Traps

- **`/tool fetch` does not verify certificates by default** (`check-certificate=no`, even over HTTPS).
- **Current RouterOS hides sensitive values in normal exports.** The dangerous cases are an explicit `show-sensitive`, manually embedded credentials, or scripts that write secret-bearing content to `/file`. Never use `show-sensitive` during normal AI-assisted collection.
- **A script without a scheduler is not suspicious by itself** — it may be called by Netwatch, a DHCP lease script, PPP `on-up` or the mode button. Find the caller before accusing.
- **An `.rsc` in `/file` may be the team's legitimate restore routine.** The finding survives only if the file has a secret inside.
- **A script that nobody recognises is a possible compromise:** recommend investigation before removal.
