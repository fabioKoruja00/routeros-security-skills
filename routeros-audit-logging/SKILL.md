---
name: routeros-audit-logging
description: "Read-only audit of observability on MikroTik RouterOS: logging only in memory, critical topics not logged, remote logging to a dead collector, NTP client off or clock wrong, open NTP server, permanent debug topics, e-mail without TLS or with a stored credential, evidence never handled, Netwatch actions, SNMP communities (default, unrestricted, write-enabled), trap protection and destinations, v1/v2c on untrusted networks. This skill should be used when assessing whether a RouterOS device would tell anyone that something happened, without changing configuration."
---

# RouterOS security audit — logging, time and SNMP

What the device tells the outside, and whether anyone is listening. The worst state is a remote logging action pointing to a collector that no longer receives: the system lies about its own observability.

## Rules

Read-only: `print`, `get`, `export`, `monitor` only — never `set`, `add`, `remove`, `enable`, `disable`, `reboot`. Connect with a `read`-group user and audit only the devices that were named. Secrets never enter the report (use `proplist` on areas that store credentials). Method, severity scale (CRITICAL / HIGH / MEDIUM / LOW — in doubt, the lower), output format and the collection order live in `routeros-audit-method`; factory values in `routeros-factory-defaults`. Read the RouterOS version first: v6 and v7 menus differ, and a command in the wrong menu returns empty.

## Checks

[references/checks.md](references/checks.md)

## Traps

- **Log only in memory is the factory default.** The finding is "nobody configured remote logging", not "someone disabled it".
- **Confirm reception on the collector side**, not just the action on the device.
- **SNMP `write-access=yes` with a default community is open administrative access.**
- **A wrong clock invalidates TLS, RPKI and DNSSEC and makes the log useless for forensics.**
