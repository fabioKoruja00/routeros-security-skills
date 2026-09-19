# routeros-security-skills

Read-only security audit skills for MikroTik RouterOS (v6/v7), packaged for AI coding agents
(Claude Code and compatible skill loaders). One folder per theme; each skill is self-contained
and installable on its own.

[Leia em português](README.pt-BR.md)

## What is in here

| Skill | Covers |
|---|---|
| [`routeros-factory-defaults`](routeros-factory-defaults/) | Factory values of `/ip settings`, `/ipv6 settings`, connection tracking, device-mode, the default firewall (defconf) per chain, the bogon lists from the official advanced-firewall guide, and the services the vendor tells you to disable. Read before opening any finding. |
| [`routeros-audit-core`](routeros-audit-core/) | Administrative access and exposed services, auxiliary services, firewall chain policy, RAW and flood defence, ICMP by type, layer 2 / MNDP / bridge / VLAN, DHCP, IP stack, tunnels and ciphers, QoS with security effect, bulk collection sequence. |
| [`routeros-audit-ipv6`](routeros-audit-ipv6/) | Stack state, RA/ND, IPv6 firewall, DHCPv6 and prefix delegation, IPv6 routing, transition mechanisms, addressing plan, extension headers. |
| [`routeros-audit-routing`](routeros-audit-routing/) | OSPF, BGP (session, filters, attributes, leaks, reflection), RPKI, MPLS/LDP, VPLS and L3VPN isolation, traffic engineering, control plane under saturation, v6↔v7 menu map and silent syntax traps. |
| [`routeros-audit-wireless`](routeros-audit-wireless/) | Legacy driver vs `wifi-qcom`, authentication and ciphers, who can read the PSK, client admission, operating modes, CAPsMAN trust/segmentation/versions, regulatory and RF, evidence from the registration table. |
| [`routeros-audit-automation`](routeros-audit-automation/) | Scripts, scheduler and fetch, files and backups on disk, containers, logging and NTP, SNMP, AAA/RADIUS, certificates, safe procedure during an incident. |

Every check is a table row with: the **read command**, **what characterises a failure**, and a
**suggested severity** (CRITICAL / HIGH / MEDIUM / LOW). Every file ends with the nuances that
generate false positives — what *looks* like a finding and is not.

## Principles

- **Read-only.** `print`, `get`, `export`, `monitor`. Never `set`, `add`, `remove`, `enable`,
  `disable`, `reboot`. An audit that changes the device is an incident.
- **Read the version and the factory default before judging.** v6 and v7 menus differ; a command
  in the wrong menu returns empty, and empty looks like "not configured". A value equal to the
  factory default is not somebody's insecure choice.
- **Read the role of the device.** Edge, concentrator, switch, AP and multihomed core do not
  accept the same list.
- **Secrets never enter the report.** Use `proplist` on areas that store credentials. The finding
  is "weak password on X", not the value.
- **In doubt between two severities, the lower.** Inflated severity turns the report into noise.
- **Absence of a rule is not automatically a failure.** Check `disabled`, order in the chain, the
  interface list and the packet counter first.
- **The audit itself can take the target down.** Wireless `scan`/`snooper` without
  `background=yes`, Torch and `profile` on a saturated CPU. Read state, do not provoke it.

## Install

Copy the folders you want into your agent's skills directory:

```bash
git clone https://github.com/fabioKoruja00/routeros-security-skills
cp -r routeros-security-skills/routeros-* ~/.claude/skills/
```

Or per project: `<repo>/.claude/skills/`.

## Output the skills produce

One document per device **with findings**. Each finding: what is wrong, the read command that
proves it, what is at stake, and the possible ways to fix it with the risk of each — including
the risk of losing access to the device. A path, not a paste-ready recipe.

## Scope and disclaimer

Independent material based on public RouterOS documentation and field experience. Not
affiliated with, endorsed by or certified by MikroTik. Commands, menus and defaults change
between RouterOS releases — confirm on the installed version before acting on any finding.

## License

MIT — see [LICENSE](LICENSE).
