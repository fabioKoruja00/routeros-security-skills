---
name: routeros-audit-dhcp
description: "Read-only audit of DHCP on MikroTik RouterOS: rogue-server alerts, pool exhaustion and starvation, static leases for infrastructure, add-arp without reply-only ARP, lease scripts with broad permission, and DHCP clients that trust the segment (peer DNS and default route on non-approved interfaces). This skill should be used when assessing DHCP server and client exposure on a RouterOS device without changing configuration."
---

# RouterOS security audit — DHCP

Small area, two classic traps: a protection that exists halfway (`add-arp=yes` without `arp=reply-only`) and a DHCP client on the wrong interface that lets whoever answers first become the device's DNS and gateway.

## Rules

Read-only: `print`, `get`, `export`, `monitor` only — never `set`, `add`, `remove`, `enable`, `disable`, `reboot`. Connect with a `read`-group user and audit only the devices that were named. Secrets never enter the report (use `proplist` on areas that store credentials). Method, severity scale (CRITICAL / HIGH / MEDIUM / LOW — in doubt, the lower), output format and the collection order live in `routeros-audit-method`; factory values in `routeros-factory-defaults`. Read the RouterOS version first: v6 and v7 menus differ, and a command in the wrong menu returns empty.

## Checks

[references/checks.md](references/checks.md)

## Traps

- **`add-arp=yes` without `arp=reply-only` on the interface is worth nothing** — the client still picks its own IP.
- **A /24 pool empties in seconds under starvation.** Random MACs in the lease table are the evidence.
- DHCP snooping and trusted ports are audited in `routeros-audit-layer2`.
