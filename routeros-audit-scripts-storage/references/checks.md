# Scripts, scheduler, files and containers checks

Severity scale: CRITICAL / HIGH / MEDIUM / LOW. Every command is read-only. Method and output format: `routeros-audit-method`.

## 1. Script, scheduler and fetch

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Secret inside a script | normal audit: `/system script print proplist=name,owner,policy,dont-require-permissions,last-started,run-count`; optional sensitive review only with explicit operator authorization | script source may contain passwords, tokens or connection strings. Do not read `source` into the agent context during normal collection; if a sensitive review is authorized, report only that a secret exists, never its value | CRITICAL |
| Export with secrets inside a script | optional sensitive review only with explicit operator authorization | a script or scheduler action invoking `export show-sensitive` can write credentials into an `.rsc` file. Normal metadata-only collection cannot prove this safely | CRITICAL |
| Backup leaving by an insecure path | optional sensitive review only with explicit operator authorization | inline script/scheduler actions may disclose destinations or credentials; inspect only when the operator accepts that sensitive content may enter the review context | CRITICAL |
| Script not requiring permissions | `/system script print detail` | `dont-require-permissions=yes`: a user in a restricted group triggers an action their group would not allow | HIGH |
| Broad script permission | `/system script print detail` (`policy`) | a simple routine with `policy` containing `password`, `sensitive` or `policy` | HIGH |
| Fetch without certificate validation | optional sensitive review only with explicit operator authorization | detect `/tool fetch` calls and verify certificate validation only when script source review is authorized; do not read script source during the normal pass | HIGH |
| Fetch over plain HTTP | optional sensitive review only with explicit operator authorization | a script downloading executable/configuration content over plain HTTP is unsafe; inspect only in the sensitive pass | HIGH |
| Unknown schedule | `/system scheduler print proplist=name,start-time,interval,policy,run-count,next-run` | unknown or unexpected task, especially startup jobs. Inspect `on-event` only in the optional sensitive pass because it can contain inline secrets | CRITICAL |
| Orphan script | `/system script print detail` (`last-started`, `run-count`) | script with a high `run-count` and no visible scheduler — called by another path | HIGH |

Scheduler and script are where an intruder's persistence lives. A finding here is **never** LOW.

## 2. Files, backup and storage

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Exported config sitting on disk | `/file print detail` | `.rsc` file on the device is not automatically a secret leak: current RouterOS exports hide sensitive values by default. Escalate when provenance shows `show-sensitive`, manual secret insertion, or another process that wrote credentials into the file | HIGH |
| Binary backup without password | `/file print detail` and `/system backup ...` | `.backup` generated without `password` — restorable by whoever downloads the file | HIGH |
| Cloud backup without password | `/ip cloud print` | `backups-enabled=yes` without a backup password set | HIGH |
| DDNS on without use | `/ip cloud print` | `ddns-enabled=yes` publishing the device's public IP without need | MEDIUM |
| SMB exposed | `/ip smb print` and `/ip smb shares print detail` | `enabled=yes` with `interfaces=all` or a share without authentication | CRITICAL |
| Unplanned disk/partition | `/disk print detail` and `/partitions print` | mounted media that is not in the inventory | MEDIUM |
| Degraded RAID | `/disk raid print` | array in degraded mode: the next failure takes the data with it, and nothing warns | HIGH |
| ROSE installed without use | `/system package print` and `/disk print detail` | `rose-storage` package present on a device that only routes — file-service surface for no reason | MEDIUM |

`export` hides sensitive values by default on current RouterOS releases. The dangerous case is an explicit `show-sensitive` export, manually embedded credentials, or another routine that writes secrets into a file.

## 3. Container (v7)

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Container active without being planned | `/container print detail` | container running on a network device nobody declared | CRITICAL |
| No RAM ceiling | `/container print detail` | `ram-limit` empty: a memory leak kills the router by OOM | HIGH |
| Running on the internal flash | `/container print detail` (`root-dir`) | `root-dir` on the internal NAND — constant writes destroy the device's flash | HIGH |
| veth with access to management | `/interface veth print detail` and `/interface bridge port print detail` | container interface in the same bridge as management, without a filter | CRITICAL |
| Untrusted image source | `/container print detail` (`remote-image`) | image pulled from a public registry without pinning the digest | HIGH |
| `container` enabled without use | `/system device-mode print` | `container=yes` on a device that runs none | MEDIUM |
