# routeros-security-skills

Read-only security audit skills for MikroTik RouterOS (v6/v7), packaged for AI coding agents
(Claude Code, ChatGPT Skills and compatible skill loaders). One folder per domain (21 skills). Domain skills share two base dependencies: `routeros-audit-method` and `routeros-factory-defaults`.

[Leia em português](README.pt-BR.md)

## What is in here

| Skill | Domain |
|---|---|
| [`routeros-audit-method`](routeros-audit-method/) | How to run the audit: unbreakable rules, what to read before judging, collection order, severity scale, output format, field traps, incident procedure. **Read first.** |
| [`routeros-factory-defaults`](routeros-factory-defaults/) | Factory values of `/ip settings`, `/ipv6 settings`, connection tracking, device-mode, the default firewall per chain, the official bogon lists, and the services the vendor tells you to disable. |
| [`routeros-audit-access`](routeros-audit-access/) | Administrative access: services and their source restriction, SSH, users/groups/keys, RouterBOOT, device-mode, AAA default group, physical button, supout, graphs, version. |
| [`routeros-audit-services`](routeros-audit-services/) | Auxiliary services: mac-server, MNDP, bandwidth test, DNS cache, DoH, proxy, SOCKS, UPnP, cloud/DDNS, RoMON. |
| [`routeros-audit-firewall`](routeros-audit-firewall/) | Filter/NAT/mangle chain policy: input/forward, bogons, anti-spoof, TCP flags, zones, counters, fasttrack, NAT, ALG, FQDN lists, drop logging. |
| [`routeros-audit-flood-defense`](routeros-audit-flood-defense/) | RAW table, SYN flood, DDoS detection, amplification, port scan, brute-force blacklists, conntrack exhaustion, ICMP by type. |
| [`routeros-audit-layer2`](routeros-audit-layer2/) | MNDP, neighbor table, DHCP snooping, RA Guard, horizon, BPDU guard, STP, bridge filters and hardware offload, VLAN filtering, PVID, MAC limits. |
| [`routeros-audit-dhcp`](routeros-audit-dhcp/) | DHCP server alerts, pool exhaustion, static leases, add-arp, lease scripts, DHCP client trust. |
| [`routeros-audit-ip-settings`](routeros-audit-ip-settings/) | `/ip settings` values that only show in print: rp-filter, redirects, source route, forwarding, ARP limits, ICMP rate. |
| [`routeros-audit-vpn`](routeros-audit-vpn/) | PPTP, L2TP/IPsec, PPP, PPPoE, Quick Set and Back To Home, SSTP, OVPN, IPsec, WireGuard, VXLAN, ZeroTier, EoIP, port knocking. |
| [`routeros-audit-qos`](routeros-audit-qos/) | Queues with a security effect: management priority, guarantees, PCQ, dead queues, dynamic queues, bufferbloat. |
| [`routeros-audit-ipv6`](routeros-audit-ipv6/) | IPv6 stack, RA/ND, IPv6 firewall, DHCPv6/PD, IPv6 routing, transition, addressing, extension headers. |
| [`routeros-audit-ospf`](routeros-audit-ospf/) | OSPF neighborship, network types, areas, redistribution, PPPoE /32 flood, v6↔v7 menu map. |
| [`routeros-audit-bgp`](routeros-audit-bgp/) | BGP sessions, filters, attributes, leaks, reflection, confederation, RPKI, silent v6↔v7 traps. |
| [`routeros-audit-mpls`](routeros-audit-mpls/) | LDP, VPLS, L3VPN isolation, traffic engineering, control plane under saturation. |
| [`routeros-audit-wireless`](routeros-audit-wireless/) | Wireless interfaces (legacy and wifi-qcom): ciphers, PSK exposure, client admission, modes, regulatory, registration table. |
| [`routeros-audit-capsman`](routeros-audit-capsman/) | CAPsMAN: CAP–controller trust, discovery, provisioning, datapaths, versions, automatic CA. |
| [`routeros-audit-scripts-storage`](routeros-audit-scripts-storage/) | Scripts, scheduler, fetch, files and backups on disk, SMB, disks, containers. |
| [`routeros-audit-logging`](routeros-audit-logging/) | Logging, NTP, e-mail, Netwatch, SNMP. |
| [`routeros-audit-aaa`](routeros-audit-aaa/) | RADIUS, CoA, AAA default group, PPP secrets, User Manager. |
| [`routeros-audit-certificates`](routeros-audit-certificates/) | Certificate store and its use by services. |

Every check is a table row with: the **read command**, **what characterises a failure**, and a
**suggested severity** (CRITICAL / HIGH / MEDIUM / LOW). Every file ends with the nuances that
generate false positives — what *looks* like a finding and is not.

## Principles

- **Read-only workflow.** `print`, `get`, `export`, `monitor`. Never `set`, `add`, `remove`, `enable`, `disable`, `reboot`. Use a dedicated least-privilege audit account; do not assume the built-in RouterOS `read` group is strictly read-only.
- **Read the version and the factory default before judging.** v6 and v7 menus differ; a command
  in the wrong menu returns empty, and empty looks like "not configured". A value equal to the
  factory default is not somebody's insecure choice.
- **Read the role of the device.** Edge, concentrator, switch, AP and multihomed core do not
  accept the same list.
- **Secrets do not enter normal AI-assisted collection.** Use safe `proplist` selections on credential-bearing areas. Secret-strength checks require a separately authorized sensitive review; never include the secret value in the report. Never use `show-sensitive` in normal collection.
- **In doubt between two severities, the lower.** Inflated severity turns the report into noise.
- **Absence of a rule is not automatically a failure.** Check `disabled`, order in the chain, the
  interface list and the packet counter first.
- **The audit itself can take the target down.** Wireless `scan`/`snooper` without
  `background=yes`, Torch and `profile` on a saturated CPU. Read state, do not provoke it.

## Base dependencies

Install `routeros-audit-method` and `routeros-factory-defaults` together with any domain skill. The method defines collection/severity/output behavior; factory-defaults prevents false positives caused by comparing every platform to a home-router baseline.

## Install

Clone once, then expose the same skill folders to the agent you use:

```bash
git clone https://github.com/fabioKoruja00/routeros-security-skills
```

- **Claude Code**: copy or symlink the selected `routeros-*` folders into `~/.claude/skills/` or `<repo>/.claude/skills/`.
- **Codex**: copy or symlink them into `$HOME/.agents/skills/` or `<repo>/.agents/skills/`.
- **Google Antigravity**: copy or symlink them into `~/.gemini/config/skills/` globally or `<repo>/.agents/skills/` for a project.
- **ChatGPT Skills**: each skill already includes `agents/openai.yaml` UI metadata in addition to the common `SKILL.md`.

Do not maintain separate copies of the skill logic for each agent. Keep this repository as the single source of truth and use symlinks where practical.

See [COMPATIBILITY.md](COMPATIBILITY.md) for installation patterns and notes.

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
