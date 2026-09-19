---
name: routeros-audit-firewall
description: "Read-only audit of the MikroTik RouterOS IPv4 firewall chain policy: input and forward chains (final drop, established/related, invalid, WAN new connections, dstnat), bogon and anti-spoof lists, TCP flag combinations, interface lists as zones, counters and disabled rules, fasttrack exceptions, NAT (permissive dst-nat, masquerade without interface, IPsec bypass, undocumented redirects), ALG helpers, FQDN address-lists, mangle marks capturing management, drop logging. This skill should be used when reviewing the filter, NAT and mangle tables of a RouterOS device without changing them."
---

# RouterOS security audit — firewall chain policy

The policy as written versus the policy as it runs. Order, `disabled`, interface lists and counters decide more than the rule text — a protection rule after the drop, or with a zero counter on an edge device, is a finding, not a pass.

## Rules

Read-only: `print`, `get`, `export`, `monitor` only — never `set`, `add`, `remove`, `enable`, `disable`, `reboot`. Connect with a dedicated least-privilege audit account; do not assume the built-in `read` group is strictly read-only. Audit only the devices that were named. Secrets never enter the report (use `proplist` on areas that store credentials). Method, severity scale (CRITICAL / HIGH / MEDIUM / LOW — in doubt, the lower), output format and the collection order live in `routeros-audit-method`; factory values in `routeros-factory-defaults`. Read the RouterOS version first: v6 and v7 menus differ, and a command in the wrong menu returns empty.

## Checks

[references/checks.md](references/checks.md)

## Traps

- **Absence of a rule is not automatically a failure.** Check `disabled`, the order in the chain, the interface/list it matches and the packet counter before accusing.
- **`drop connection-state=invalid` may be absent on purpose** on a multihomed device with asymmetric routing — see the nuances in `routeros-audit-bgp`.
- **Fasttrack skips firewall, conntrack and queues.** Rules after it do not apply to the accelerated connection, and the UI keeps showing both as if they did.
- **`log=yes` on a drop without `limit`** is a DoS the device applies to itself.
- **On a device that only bridges, `/ip firewall` does not see the traffic** while `use-ip-firewall=no`. The whole policy may be decorative.
