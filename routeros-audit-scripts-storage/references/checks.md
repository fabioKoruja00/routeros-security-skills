# Scripts, scheduler, files and containers checks

Severity scale: CRITICAL / HIGH / MEDIUM / LOW. Every command is read-only. Method and output format: `routeros-audit-method`.

## 1. Script, scheduler and fetch

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Potential secret-bearing script | `/system script print proplist=name,owner,policy,dont-require-permissions,last-started,run-count` | script source may contain passwords, tokens or connection strings, therefore the agent must never read `source`. Assess owner, permissions, execution history and whether the script is expected | HIGH |
| Risky export routine | metadata only; never read script source or scheduler `on-event` | not directly agent-verifiable. A trusted local scanner may return only a sanitized boolean such as `unsafe_export=true`; raw source must never be sent to the agent | HIGH |
| Backup exfiltration path | metadata only; never read inline script/scheduler source | destination/security details embedded in source are not agent-verifiable. Use only sanitized metadata or a trusted local scanner result; never send raw source, URLs with credentials, tokens or passwords to the agent | HIGH |
| Script not requiring permissions | `/system script print proplist=name,owner,policy,dont-require-permissions,last-started,run-count` | `dont-require-permissions=yes`: a user in a restricted group triggers an action their group would not allow | HIGH |
| Broad script permission | `/system script print proplist=name,owner,policy,dont-require-permissions,last-started,run-count` | a simple routine with `policy` containing `password`, `sensitive` or `policy` | HIGH |
| Fetch certificate validation in scripts | metadata only; never read script source | not agent-verifiable when embedded in script source. A trusted local scanner may return only a boolean such as `fetch_without_cert_validation=true`; never send command text containing credentials or tokens | HIGH |
| Fetch over plain HTTP in scripts | metadata only; never read script source | not agent-verifiable directly. A trusted local scanner may return only a sanitized protocol classification such as `scheme=http`; never send the raw URL if it can contain credentials or tokens | HIGH |
| Unknown schedule | `/system scheduler print proplist=name,start-time,interval,policy,run-count,next-run` | unknown or unexpected task, especially startup jobs. Never read `on-event` because it can contain inline secrets | CRITICAL |
| Orphan script | `/system script print proplist=name,owner,policy,dont-require-permissions,last-started,run-count` | script with a high `run-count` and no visible scheduler — called by another path. Never read `source` to investigate it in the agent | HIGH |

Scheduler and script are where an intruder's persistence lives. A finding here is **never** LOW.

## 2. Files, backup and storage

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Exported config sitting on disk | `/file print proplist=name,type,size,creation-time,last-modified` | `.rsc` presence is a handling risk, not proof of a secret leak. Never open it in the agent to inspect credentials; use provenance or a trusted local scanner that returns only a boolean `contains_secret` result | MEDIUM |
| Binary backup without password | `/file print detail` and `/system backup ...` | `.backup` generated without `password` — restorable by whoever downloads the file | HIGH |
| Cloud backup without password | `/ip cloud print` | `backups-enabled=yes` without a backup password set | HIGH |
| DDNS on without use | `/ip cloud print` | `ddns-enabled=yes` publishing the device's public IP without need | MEDIUM |
| SMB exposed | `/ip smb print` and `/ip smb shares print detail` | `enabled=yes` with `interfaces=all` or a share without authentication | CRITICAL |
| Unplanned disk/partition | `/disk print detail` and `/partitions print` | mounted media that is not in the inventory | MEDIUM |
| Degraded RAID | `/disk raid print` | array in degraded mode: the next failure takes the data with it, and nothing warns | HIGH |
| ROSE installed without use | `/system package print` and `/disk print detail` | `rose-storage` package present on a device that only routes — file-service surface for no reason | MEDIUM |

`export` hides sensitive values by default on v7; on v6 it shows them unless `hide-sensitive` is given. The dangerous cases are a v6 export without `hide-sensitive`, a v7 `export show-sensitive`, manually embedded credentials, or another routine that writes secrets into a file.

## 3. Container (v7)

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Container active without being planned | `/container print detail` | container running on a network device nobody declared | CRITICAL |
| No RAM ceiling | `/container print detail` | `ram-limit` empty: a memory leak kills the router by OOM | HIGH |
| Running on the internal flash | `/container print detail` (`root-dir`) | `root-dir` on the internal NAND — constant writes destroy the device's flash | HIGH |
| veth with access to management | `/interface veth print detail` and `/interface bridge port print detail` | container interface in the same bridge as management, without a filter | CRITICAL |
| Untrusted image source | `/container print detail` (`remote-image`) | image pulled from a public registry without pinning the digest | HIGH |
| `container` enabled without use | `/system device-mode print` | `container=yes` on a device that runs none | MEDIUM |
