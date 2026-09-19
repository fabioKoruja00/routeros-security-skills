---
name: routeros-audit-ipv6
description: "Read-only IPv6 security audit of MikroTik RouterOS: stack state, Router Advertisement and Neighbor Discovery, the IPv6 firewall (ICMPv6 by type, link-local and multicast, bogons, RAW), DHCPv6 and prefix delegation, IPv6 routing (BGP, OSPFv3), transition mechanisms (6to4, protocol 41, Teredo, GRE6/IPIPv6/EoIPv6), addressing plan and extension headers. Every check carries the read command, what characterises a failure and a suggested severity, plus the nuances that generate false positives. This skill should be used when a RouterOS device has IPv6 enabled (the v7 default) and its exposure must be assessed without changing configuration."
---

# RouterOS security audit — IPv6

**The stack ships enabled on v7 and the v6 firewall ships empty.** That combination is the most
common and most serious finding in this area: IPv4 protected, IPv6 open, and **with no NAT in
the path every internal host is reachable directly from the Internet**.

Golden rule when recommending: a generic ICMPv6 block **breaks the whole IPv6 network**. ND, DAD,
SLAAC and PMTUD depend on it. Filter by type, never by protocol.

## Rules

- Read-only. Every command in the reference is `print`, `get` or `monitor`. Never `set`, `add`,
  `remove`, `enable`, `disable`.
- Connect with a `read`-group user. Audit only the devices that were named.
- Read `/system resource print` first — v6 and v7 differ in DHCPv6 (v6 is delegation-only) and in
  routing menus.
- Read `/ipv6 settings print` **and** `/ipv6 address print` before anything else: a device with no
  IPv6 address and `disable-ipv6=yes` ends the audit in one line.
- Secrets never enter the report (`tcp-md5-key`: check presence, never the value).

## Severity

CRITICAL / HIGH / MEDIUM / LOW — in doubt, the lower. An empty IPv6 firewall on a device with a
global address is CRITICAL. Anything that only hardens today's risk is LOW.

**Absence of a rule is not automatically a failure.** Check `disabled`, order in the chain, the
interface list it matches and the packet counter before accusing.

## Checks

[references/checks.md](references/checks.md) — sections: stack state (1), RA and ND (2), IPv6
firewall (3), DHCPv6 and prefix delegation (4), IPv6 routing (5), transition and tunnels (6),
addressing plan (7), extension headers and what IPv6 does NOT have (8), false-positive nuances (9).

Factory defaults for `/ipv6 settings` live in the `routeros-factory-defaults` skill:
`accept-router-advertisements=yes-if-forwarding-disabled` already protects a router with
`forward=yes` — read both properties together before accusing.

## Output

One document per device with findings. Each finding: what is wrong, the read command that proves
it, what is at stake, and the possible ways to fix it with the risk of each — including losing
access to the device. Path, not recipe: no write command ready to paste.

## Traps that took networks down

- Mirroring the IPv4 policy into IPv6 without the ICMPv6 and link-local accepts kills the network.
  The direct copy is the classic mistake.
- Removing IPv6 NAT before the `forward` chain is ready exposes what was hidden. Order matters.
- Disabling `add-default-route` on the DHCPv6 client cuts transit if that is the only default.
- `no-dad=yes` is legitimate on an anycast address. Re-enabling DAD there takes the service down.
- Discarding IPv6 fragments can cut legitimate traffic (DNSSEC over UDP, some tunnels). Measure the
  real volume before recommending.
- A rule written against next-header `50`/`51` "to filter extension headers" is filtering ESP and
  AH — it **kills IPsec**.
