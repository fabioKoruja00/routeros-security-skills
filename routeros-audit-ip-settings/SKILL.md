---
name: routeros-audit-ip-settings
description: "Read-only audit of the MikroTik RouterOS IP stack settings that only show in print and never in export: reverse path filter, ICMP redirect acceptance and sending, source routing, forwarding on L2-only devices, ARP neighbor limits, kernel ICMP rate limit — each compared against the factory default so that a shipped value is not accused as somebody's insecure choice. This skill should be used when reviewing /ip settings on a RouterOS device without changing them."
---

# RouterOS security audit — IP stack settings

`/ip settings print` is the only way to see these; an audit done on `/export` alone approves a device with the stack open. Most "wrong" values here are factory defaults — compare with `routeros-factory-defaults` before writing a finding.

## Rules

Read-only: `print`, `get`, `export`, `monitor` only — never `set`, `add`, `remove`, `enable`, `disable`, `reboot`. Connect with a dedicated least-privilege audit account; do not assume the built-in `read` group is strictly read-only. Audit only the devices that were named. Secrets never enter the report (use `proplist` on areas that store credentials). Method, severity scale (CRITICAL / HIGH / MEDIUM / LOW — in doubt, the lower), output format and the collection order live in `routeros-audit-method`; factory values in `routeros-factory-defaults`. Read the RouterOS version first: v6 and v7 menus differ, and a command in the wrong menu returns empty.

## Checks

[references/checks.md](references/checks.md)

## Traps

- **`accept-redirects=yes` and `accept-source-route=yes` are deviations from default** — somebody enabled them. `send-redirects=yes` is default and vendor-recommended.
- **`rp-filter=strict` on a multihomed device kills legitimate traffic** — recommend `loose`.
