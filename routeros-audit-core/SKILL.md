---
name: routeros-audit-core
description: "Read-only security audit of MikroTik RouterOS (v6/v7) — the core checklist: exposed services and administrative access, auxiliary services nobody remembers to disable, firewall chain policy, RAW table and flood defence, ICMP by type, layer 2 / MNDP / bridge / VLAN, DHCP, the IP stack settings that only show in print, tunnels and ciphers (PPTP, L2TP, SSTP, OVPN, IPsec, WireGuard, VXLAN, ZeroTier, EoIP), and QoS with security effect. Every check carries the read command, what characterises a failure, and a suggested severity. This skill should be used when asked to audit, review, harden or assess the security of a RouterOS device without changing its configuration."
---

# RouterOS security audit — core

Read-only assessment of a RouterOS device. Every command in the reference is a `print`, `get`,
`export` or `monitor`. The skill diagnoses; it never fixes.

## Rules that cannot be broken

- **No write command, under any circumstance.** No `set`, `add`, `remove`, `enable`, `disable`,
  `move`, `reset`, `upgrade`, `reboot`. An audit that touches the configuration stops being an
  audit and becomes an incident.
- **Do not restrict Winbox as a recommendation** on its own: it is the recovery path of the
  device. Recommend restricting its *source* (`address`), never removing the service.
- **Secrets never enter the report.** When reading an area that stores credentials, use
  `proplist` to bring only what matters — `/radius print proplist=address,service,timeout`,
  `/user print proplist=name,group,address`, `/certificate print proplist=name,invalid-after,expired`.
  Never paste a PSK, PPP password, private key or SNMP community into a document, a chat or an
  agent prompt. The finding is "weak password on X", not the value.
- **Connect with a user of group `read`** over SSH or the API. Reading production is still
  touching it: it creates a session, a log line and competes for CPU with the device's own work.
  Audit only the devices that were named, when they were named.

## Before judging any item

1. **Read the version.** `/system resource print` and `/system package print`. Menus differ
   between v6 and v7 (BGP, OSPF, route filters, wireless vs wifi). A command in the wrong menu
   returns empty, and empty looks like "not configured" — the audit then accuses the absence of
   something that exists.
2. **Read the factory default.** Use the `routeros-factory-defaults` skill (or the vendor docs).
   A value equal to the default is not somebody's insecure choice: it changes the severity and
   the wording ("nobody enabled the protection" vs "someone disabled it").
3. **Read the role of the device.** Edge router, concentrator, switch, AP and multihomed core do
   not accept the same list. A good recommendation on one is an outage on the other.

## Collection order

One topic per connection. Start with what depends on nothing (`/ip service`, `/ip settings`,
`/tool mac-server`), then the areas that require walking rule lists (`/ip firewall/*`). The
bulk read-only sequence is at the end of [references/checks.md](references/checks.md).

`/export verbose hide-sensitive` **complements, never replaces** the prints: `/ip settings`,
the per-service `address` ("Available From"), `Protected RouterBOOT`, `device-mode` and the
connection-tracking timeouts only appear in the `print` of their own menu.

## How to classify

Severity is a suggestion. Reclassify when the measurement on the device contradicts it, and say
so. When in doubt between two levels, pick the lower — inflated severity turns the whole report
into noise.

- **CRITICAL** — an access breach open right now (administrative service with no source
  restriction on the WAN, default credential, input chain with no final drop), or the device
  lies about its own state.
- **HIGH** — protection missing on a production device that talks to the Internet.
- **MEDIUM** — debt with a known trap (MNDP on a customer interface, btest enabled).
- **LOW** — hardening that does not change today's risk.

**Absence of a rule is not automatically a failure.** Before accusing: check `disabled`, the
ORDER in the chain (a rule after the drop never runs), the interface/list it matches and the
packet counter. An existing rule with a zero counter on an edge device deserves suspicion, not
approval.

## Output

One document per device **with findings** — clean devices appear only on the summary line.
Each finding carries: what is wrong, the read command that proves it, what is at stake, and
**the possible ways to fix it with the risk of each one** — including the risk of losing access
to the device. No write command ready to paste: a path, not a recipe.

A finding repeated across several devices becomes **one** item with the list of affected
devices, not one item per device.

## Checks

[references/checks.md](references/checks.md) — sections: administrative access (1), auxiliary
services (2), firewall chain policy (3), RAW and flood (4), ICMP by type (5), layer 2 and
bridge (6), DHCP (7), IPv6 summary (8), IP stack (9), crypto and tunnels (10), QoS (11), bulk
collection (12). Read the section before auditing the area — the list is long and memory of it
ages.

Companion skills for the other areas: `routeros-audit-ipv6`, `routeros-audit-routing`,
`routeros-audit-wireless`, `routeros-audit-automation`.

## Measured traps

- **`/export` does not show everything.** `/ip/settings`, the per-service `Available From`,
  `Protected RouterBOOT`, `device-mode` and the connection-tracking timeouts only appear in the
  `print` of the area. An audit done only on the export approves a device with the IP stack open.
- **A rule in `bridge filter` does not run on a port with hardware offload.** The packet never
  reaches the CPU. The rule stays on screen, the counter stays at zero, and the policy never
  existed.
- **On a device that only bridges, `/ip firewall` does not see the traffic** while
  `use-ip-firewall=no` (the default). The whole policy may be decorative.
- **The audit itself can take the target down.** Wireless `scan` and `snooper` without
  `background=yes` disconnect the clients; Torch and `profile` cost CPU on a device already
  saturated. Read state, do not provoke it.
- **Fasttrack skips firewall, conntrack and queues.** Rules and queues that come after do not
  apply to the accelerated connection — and the UI keeps showing both as if they did.
- **A closed IPv4 firewall does not close IPv6.** The classic case is udp/53: blocked in
  `/ip firewall`, forgotten in `/ipv6 firewall`, and the open resolver stays up on the other
  protocol.
- **`drop connection-state=invalid` may be absent on purpose** on a multihomed device with
  asymmetric routing — there the rule kills legitimate traffic. Count the active exits before
  accusing.
- **`log=yes` on a drop rule without `limit` is a DoS the device applies to itself:** under
  attack the log saturates CPU, disk and the collector.
- **`device-mode` with `flagged=yes`** means somebody tried to unlock a feature without the
  physical confirmation. Treat as a possible compromise, not as a configuration backlog.
- **`device-mode` (7.1x+) blocks `scheduler` and `script`** and only releases them with physical
  access: treat as unsupported, not as a device failure.
- **A sample password from training material is not a recommendation.** A short, generic value
  (`demo`, `test`, a digit sequence) found in production is a critical finding, not a reference
  configuration.
