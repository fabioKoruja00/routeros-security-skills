---
name: routeros-audit-method
description: "How to run a read-only security audit on MikroTik RouterOS without changing or knocking down the device: the rules that cannot be broken (no write command, secrets never enter agent context or report, dedicated least-privilege audit account, named targets only), what to read before judging (version, factory default, device role), collection order and the bulk read-only sequence, the severity scale (CRITICAL / HIGH / MEDIUM / LOW) and how to classify, the output format per device, the traps measured in the field, and the safe procedure during an incident. This skill should be used first, before any routeros-audit-* skill, and whenever a finding needs to be classified or reported."
---

# RouterOS security audit — method

The shared method behind every `routeros-audit-*` skill. Every command in those skills is a
`print`, `get`, `export` or `monitor`. The audit diagnoses; it never fixes.

## Rules that cannot be broken

- **No write command, under any circumstance.** No `set`, `add`, `remove`, `enable`, `disable`,
  `move`, `reset`, `upgrade`, `reboot`. An audit that touches the configuration stops being an
  audit and becomes an incident.
- **Do not restrict Winbox as a recommendation** on its own: it is the recovery path of the
  device. Recommend restricting its *source* (`address`), never removing the service.
- **Secrets never enter the agent context, prompt, logs, artifacts or report.** This rule has no exception. When reading credential-bearing areas, use an explicit `proplist` that excludes all secret values. Never retrieve PSKs, passwords, PPP secrets, RADIUS secrets, SNMP community strings, WireGuard preshared keys, private keys, tokens, API keys, SMTP passwords or script bodies that may contain credentials. Do not perform secret-strength analysis inside the agent. Presence or absence of a secret may be tested with a filter that prints only a number — `print count-only where <field>=""` — never with a print that shows the field. Report only metadata that can be proven without reading the secret, such as whether a credential-backed feature is enabled, its authentication mode, source restriction, transport protection and privilege scope.
- **Use a dedicated least-privilege audit account** over SSH or the API. Do not assume the built-in `read` group is strictly read-only: it also carries policies such as `reboot`, `test`, `sniff`, `sensitive`, API access and others. Build a custom group with only the login method and read capabilities required for the approved collection. Add any extra permission only for a named check that requires it. Reading production is still touching it: it creates a session, a log line and competes for CPU with the device's own work. Audit only the devices that were named, when they were named.

## Before judging any item

1. **Read the version.** `/system resource print` and `/system package print`. Menus differ
   between v6 and v7 (BGP, OSPF, route filters, wireless vs wifi). A command in the wrong menu
   returns empty, and empty looks like "not configured" — the audit then accuses the absence of
   something that exists.
2. **Read the factory default.** Use the `routeros-factory-defaults` skill.
   A value equal to the default is not somebody's insecure choice: it changes the severity and
   the wording ("nobody enabled the protection" vs "someone disabled it").
3. **Read the role of the device.** Edge router, concentrator, switch, AP and multihomed core do
   not accept the same list. A good recommendation on one is an outage on the other.

## Collection order

One topic per connection. Start with what depends on nothing (`/ip service`, `/ip settings`,
`/tool mac-server`), then the areas that require walking rule lists (`/ip firewall/*`). The
bulk read-only sequence is in [references/collection.md](references/collection.md); the safe
procedure during an incident is in [references/incident.md](references/incident.md).

`/export verbose` **complements, never replaces** the prints. Sensitive values are hidden by default on v7 (`show-sensitive` is the flag that reveals them); on v6 the default is the opposite and `hide-sensitive` must be given explicitly. **Never use `show-sensitive` (v7) or omit `hide-sensitive` (v6) in any agent-assisted collection. There is no sensitive-review mode.** `/ip settings`,
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

## Measured traps

- **`/export` does not show everything.** `/ip/settings`, the per-service `Available From`,
  `Protected RouterBOOT`, `device-mode` and the connection-tracking timeouts only appear in the
  `print` of the area. An audit done only on the export approves a device with the IP stack open.
- **Do not assume a `bridge filter` protects traffic that stays fully hardware-offloaded.** Whether the packet reaches the CPU depends on platform, switch chip and forwarding path. Confirm CPU punt or hardware ACL/switch-chip enforcement on the installed model before judging the policy.
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
- **Do not inspect password/PSK/community values to judge strength.** Secret quality must be validated outside the agent with a trusted local process if operations requires it. The agent may only state that secret strength was not assessed because secret values are intentionally excluded.

## Domain skills

| Skill | Domain |
|---|---|
| `routeros-factory-defaults` | factory values to read before judging |
| `routeros-audit-access` | administrative access, users, device-mode |
| `routeros-audit-services` | auxiliary services (DNS, proxy, SOCKS, UPnP, mac-server, RoMON) |
| `routeros-audit-firewall` | filter/NAT/mangle chain policy |
| `routeros-audit-flood-defense` | RAW, flood, brute force, ICMP by type |
| `routeros-audit-layer2` | MNDP, bridge, VLAN, STP |
| `routeros-audit-dhcp` | DHCP server and client |
| `routeros-audit-ip-settings` | /ip settings (print-only values) |
| `routeros-audit-vpn` | tunnels, PPP, IPsec, WireGuard, overlays |
| `routeros-audit-qos` | queues with a security effect |
| `routeros-audit-ipv6` | IPv6 stack, firewall, RA/ND, DHCPv6, transition |
| `routeros-audit-ospf` | OSPF |
| `routeros-audit-bgp` | BGP and RPKI |
| `routeros-audit-mpls` | MPLS, LDP, VPLS, L3VPN, TE |
| `routeros-audit-wireless` | wireless interfaces (legacy and wifi-qcom) |
| `routeros-audit-capsman` | CAPsMAN |
| `routeros-audit-scripts-storage` | scripts, scheduler, files, containers |
| `routeros-audit-logging` | logging, NTP, SNMP |
| `routeros-audit-aaa` | RADIUS, PPP secrets, User Manager |
| `routeros-audit-certificates` | certificate store |
