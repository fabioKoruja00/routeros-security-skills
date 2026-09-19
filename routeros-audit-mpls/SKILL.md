---
name: routeros-audit-mpls
description: "Read-only audit of MPLS on MikroTik RouterOS: LDP on untrusted interfaces, transport address, label filters and ranges, targeted sessions, MTU, TTL propagation, unsupported architectures, VPLS (vpls-id, horizon, control word, BGP-VPLS site-id), L3VPN isolation (RD, import RT, route leaking, management by VRF), traffic engineering, and the control plane under saturation (BFD, loopback exposure, priority queues). This skill should be used when a RouterOS device is an LSR/PE or terminates VPLS/L3VPN and its isolation must be assessed without changing configuration."
---

# RouterOS security audit — MPLS, VPLS and L3VPN

Isolation between customers is the whole point, and it breaks silently: a duplicated `vpls-id`, an import RT matching another customer's export, a static route with gateway `@main` inside a VRF, LDP forming adjacencies on a customer port.

## Rules

Read-only: `print`, `get`, `export`, `monitor` only — never `set`, `add`, `remove`, `enable`, `disable`, `reboot`. Connect with a `read`-group user and audit only the devices that were named. Secrets never enter the report (use `proplist` on areas that store credentials). Method, severity scale (CRITICAL / HIGH / MEDIUM / LOW — in doubt, the lower), output format and the collection order live in `routeros-audit-method`; factory values in `routeros-factory-defaults`. Read the RouterOS version first: v6 and v7 menus differ, and a command in the wrong menu returns empty.

## Checks

[references/checks.md](references/checks.md)

## Traps

- **The router cannot be managed from within a VRF** — services answer through the main table. A policy assuming otherwise protects nothing.
- **L2MTU below the MPLS MTU discards packets silently** when the next header is not IP.
- **`bandwidth` on a TE tunnel only accounts the reservation**; `bandwidth-limit` is what limits.
- **MPLS does not exist on `smips` on v7.**
