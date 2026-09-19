---
name: routeros-audit-layer2
description: "Read-only audit of layer 2 on MikroTik RouterOS: MNDP discovery scope, neighbor table, bridge DHCP snooping and trusted ports, RA Guard, horizon isolation, BPDU guard and STP, loop protect, ARP mode, bridge filters and hardware offload, use-ip-firewall on bridged devices, VLAN filtering, PVID and frame types, MAC limits and MAC flapping. This skill should be used when assessing the switching and bridging side of a RouterOS device — especially where customer and management traffic share a bridge — without changing configuration."
---

# RouterOS security audit — layer 2, discovery and bridge

Where the segmentation is only nominal: a bridge carrying customer and management VLANs with `vlan-filtering=no`, a customer port marked trusted, a bridge filter that never runs because the port is offloaded to hardware.

## Rules

Read-only: `print`, `get`, `export`, `monitor` only — never `set`, `add`, `remove`, `enable`, `disable`, `reboot`. Connect with a dedicated least-privilege audit account; do not assume the built-in `read` group is strictly read-only. Audit only the devices that were named. Secrets never enter the report (use `proplist` on areas that store credentials). Method, severity scale (CRITICAL / HIGH / MEDIUM / LOW — in doubt, the lower), output format and the collection order live in `routeros-audit-method`; factory values in `routeros-factory-defaults`. Read the RouterOS version first: v6 and v7 menus differ, and a command in the wrong menu returns empty.

## Checks

[references/checks.md](references/checks.md)

## Traps

- **A rule in `bridge filter` does not run on a port with hardware offload.** The packet never reaches the CPU; the counter stays at zero; the policy never existed.
- **`use-ip-firewall=no` (the default) on a bridging device** means `/ip firewall` rules written for that traffic are decorative.
- **MNDP recommendation is `none`**, not a management list.
- **Same MAC on two ports or in another customer's VLAN** is a loop, a spoof or a leak between domains — never noise.
