---
name: routeros-audit-ipv6
description: "Read-only IPv6 security audit of MikroTik RouterOS: stack state, Router Advertisement and Neighbor Discovery, the IPv6 firewall (ICMPv6 by type, link-local and multicast, bogons, RAW), DHCPv6 and prefix delegation, IPv6 routing (BGP, OSPFv3), transition mechanisms (6to4, protocol 41, Teredo, GRE6/IPIPv6/EoIPv6), addressing plan and extension headers, plus the nuances that generate false positives. This skill should be used when a RouterOS device has IPv6 enabled (the v7 default) and its exposure must be assessed without changing configuration."
---

# RouterOS security audit — IPv6

IPv6 is enabled by default on RouterOS v7, but the firewall baseline depends on the product and how it was initialized. Devices that received the standard `defconf` include an IPv6 firewall; CCR, some switch/CAP/IP-only profiles, devices reset with `no-defaults=yes`, or devices whose defaults were removed may not. IPv6 does not rely on NAT for protection: globally routed hosts become directly addressable only when routing reaches the prefix and the firewall permits the traffic.

Golden rule when recommending: a generic ICMPv6 block **breaks the whole IPv6 network**. ND, DAD, SLAAC and PMTUD depend on it. Filter by type, never by protocol.

## Rules

Read-only: `print`, `get`, `export`, `monitor` only — never `set`, `add`, `remove`, `enable`, `disable`, `reboot`. Connect with a dedicated least-privilege audit account; do not assume the built-in `read` group is strictly read-only. Audit only the devices that were named. Secrets never enter the report (use `proplist` on areas that store credentials). Method, severity scale (CRITICAL / HIGH / MEDIUM / LOW — in doubt, the lower), output format and the collection order live in `routeros-audit-method`; factory values in `routeros-factory-defaults`. Read the RouterOS version first: v6 and v7 menus differ, and a command in the wrong menu returns empty.

## Checks

[references/checks.md](references/checks.md)

## Traps

- **`accept-router-advertisements` with `forward=yes` is already protected by the default** (`yes-if-forwarding-disabled`). Read both before accusing.
- **Mirroring the IPv4 policy into IPv6 without the ICMPv6 and link-local accepts kills the network.**
- **Do not treat IPv6 NAT as the security boundary.** If NAT66/masquerade exists, removing it before the `forward` policy is ready can change reachability; fix the firewall policy first.
- **`no-dad=yes` is legitimate on an anycast address.**
- **A rule against next-header `50`/`51` "to filter extension headers" kills IPsec** — those are ESP and AH.
