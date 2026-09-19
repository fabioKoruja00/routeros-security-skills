---
name: routeros-audit-routing
description: "Read-only security audit of dynamic routing on MikroTik RouterOS (v6/v7): OSPF neighborship, network types and DR election, areas and redistribution, the PPPoE /32 flood problem, BGP sessions (MD5, GTSM, prefix limits), BGP filters, attributes and route leaks, route reflection and confederations, RPKI, MPLS/LDP, VPLS and L3VPN isolation, traffic engineering, and the control plane under saturation. Includes the v6-vs-v7 menu map and the AS-path regex, filter syntax and discard/reject traps that silently change policy after an upgrade. This skill should be used when a RouterOS device runs OSPF, BGP, MPLS or VPLS and its routing security must be assessed without changing configuration."
---

# RouterOS security audit — dynamic routing

Applies only to devices running a dynamic protocol. On an access router without OSPF/BGP: skip
this skill and state in the report that it does not apply.

## Rules

- Read-only. `print`, `get`, `monitor` only. Never `set`, `add`, `remove`, `enable`, `disable`.
- Connect with a `read`-group user. Audit only the devices that were named.
- **Check the version before any command** (`/system resource print`): the v6 menu does not
  exist on v7 and vice versa. A command in the wrong menu returns empty, and empty looks like
  "not configured".
- Secrets never enter the report: for `tcp-md5-key` and OSPF `auth-key`, check **presence**,
  never the value.

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

## Severity

CRITICAL / HIGH / MEDIUM / LOW — in doubt, the lower. An unauthenticated OSPF adjacency on a
shared segment, a BGP session without an output filter on v7 (every connected network is
announced by default), LDP on a customer interface, a duplicated `vpls-id` or an open import RT
are CRITICAL: they hand routing or another customer's L2 to whoever is on the wire.

## Checks

[references/checks.md](references/checks.md) — sections: OSPF neighborship (1), network type and
election (2), instance/area/redistribution (3), OSPF + PPPoE /32 (4), BGP session (5), BGP
filters/attributes/leaks (6), reflection and confederation (7), RPKI (8), MPLS/LDP (9), VPLS and
L3VPN (10), traffic engineering (11), control plane under saturation (12), false-positive
nuances (13).

## Output

One document per device with findings: what is wrong, the read command that proves it, what is
at stake, and the possible fixes with the risk of each — a route filter applied in the wrong
order or a `no-summaries` on the wrong router isolates an area. Path, not recipe.

## Silent traps (no syntax error, different behaviour)

- **AS-path regex (v6 vs v7).** On v7 `_200_` matches ASN 200 in the middle of the path; on v6
  the same pattern matches **any ASN of at least 6 characters containing `200`**. The v6
  equivalent is `".*_200_.*"`. A filter copied from one to the other matches another set.
- **Filter syntax.** v6 is field by field (`action=discard set-bgp-communities=no-export`); v7 is
  a script (`rule="if (bgp-communities equal 100:501) {reject;}"`). Configuration copied between
  versions **is not applied and does not complain** — the policy simply ceases to exist.
- **`discard` vs `reject`.** On v6, `discard` stops updating the route; `reject` keeps it in
  memory and allows `refresh`. On v7 `discard` does not exist. A rejected route shows as
  **inactive** — do not confuse it with a backup route.
- **OSPF priority default changed** from 1 on v6 to 128 on v7: a priority that was "rigid" on v6
  stops counting after the upgrade and the election changes on its own.
- **`/routing bgp aggregate` does not exist on v7.** A migrated device counting on it leaks every
  specific route.
- **The v7 route-reflector field is `no-client-to-client-reflection`** and reflection is
  automatic: whoever looks for the v6 name concludes "the RR is not active", and whoever ticks
  the box inverts the whole policy.
- **A fallen RPKI cache session triggers nothing.** The filter rule stays active and stops
  rejecting. State the device does not report = CRITICAL.
