---
name: routeros-audit-bgp
description: "Read-only audit of BGP on MikroTik RouterOS (v6/v7): session hardening (MD5 presence, GTSM, prefix limits, listen with empty remote AS, loopback peering, next-hop-self), input/output filters and route leaks, attribute handling (local-pref, MED, weight, communities, blackhole), private AS and redistribution, route reflection and confederations, RPKI validation, and the AS-path regex, filter syntax and discard/reject traps that silently change policy between versions. This skill should be used when a RouterOS device runs BGP and its routing security must be assessed without changing configuration."
---

# RouterOS security audit — BGP and RPKI

On v7 a session without an output filter announces **every connected network by default**. The other CRITICALs: no input filter on a transit peer, a transit-to-transit leak, a third party's blackhole community accepted for a prefix that is not theirs.

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

- **AS-path regex differs between v6 and v7** (`_200_` vs `".*_200_.*"`); a copied filter matches another set with no syntax error.
- **Filter syntax copied between versions is not applied and does not complain.**
- **A rejected route shows as inactive** — not a backup route.
- **A fallen RPKI cache session triggers nothing:** the filter stays active and stops rejecting.
- **Multihomed nuances:** `drop connection-state=invalid` may be absent on purpose with asymmetric routing; an asymmetric path is not a failure by itself but breaks conntrack and IPsec; ECMP between primary and backup may be an accident of equal cost.
