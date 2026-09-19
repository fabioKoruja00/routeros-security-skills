---
name: routeros-audit-ospf
description: "Read-only audit of OSPF on MikroTik RouterOS (v6/v7): neighborship authentication and passive interfaces, templates that match every interface, unexpected neighbors, network types and DR election (including the priority default change between v6 and v7), instance, areas, redistribution and filter order, no-summaries and NSSA traps, the PPPoE /32 route flood, and the originate-default nuance. This skill should be used when a RouterOS device runs OSPF and its routing security must be assessed without changing configuration."
---

# RouterOS security audit — OSPF

An unauthenticated adjacency on a shared segment hands the routing table to whoever is on the wire. The rest of the area is about what the topology does under stress: /32 floods from PPPoE, a default announced without an exit, an ABR that isolates its own area.

## v6 vs v7 menu map

| Area | v6 | v7 |
|---|---|---|
| OSPF interface | `/routing ospf interface print` | `/routing ospf interface-template print` |
| OSPF resolved | — | `/routing ospf interface print` (what the template generated) |
| BGP peer | `/routing bgp peer print` | `/routing bgp connection print` |
| BGP instance | `/routing bgp instance print` | `/routing bgp template print` |
| Route filter | `/routing filter print` | `/routing filter rule print` |
| Router-id | `/routing ospf instance print` | `/routing id print` |
| Virtual-link | own menu | `network-type=virtual-link` on the interface-template |
| BGP aggregation | `/routing bgp aggregate print` | **does not exist** — redo with filters |
| RPKI | does not exist | `/routing rpki print` |


## Rules

Read-only: `print`, `get`, `export`, `monitor` only — never `set`, `add`, `remove`, `enable`, `disable`, `reboot`. Connect with a dedicated least-privilege audit account; do not assume the built-in `read` group is strictly read-only. Audit only the devices that were named. Secrets never enter the report (use `proplist` on areas that store credentials). Method, severity scale (CRITICAL / HIGH / MEDIUM / LOW — in doubt, the lower), output format and the collection order live in `routeros-audit-method`; factory values in `routeros-factory-defaults`. Read the RouterOS version first: v6 and v7 menus differ, and a command in the wrong menu returns empty.

## Checks

[references/checks.md](references/checks.md)

## Traps

- **Route filters only reach external routes** — they do not filter intra-area prefixes.
- **`originate-default=if-installed` may stop announcing** on a router whose default comes from PPPoE or DHCP. Check the origin of the default before recommending a change.
- **The OSPF priority default changed from 1 (v6) to 128 (v7)**: the election changes on its own after an upgrade.
- **On v7 every area, including the backbone, is created by hand.**
