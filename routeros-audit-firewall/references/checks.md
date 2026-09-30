# Firewall chain policy checks

Severity scale: CRITICAL / HIGH / MEDIUM / LOW. Every command is read-only. Method and output format: `routeros-audit-method`.

## 1. Firewall — chain policy

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Input chain without final drop | `/ip firewall filter print detail where chain=input` | no `action=drop` at the end of input, or one after a broad `accept`. Follow `jump` chains and per-interface drops before accusing; on an L2 switch with management reachable only from an isolated VLAN, HIGH | CRITICAL |
| Management allow missing | `/ip firewall filter print detail` | final drop without a prior `accept` for the management address-list — locking yourself out | HIGH |
| Established/related at the top | `/ip firewall filter print detail where chain=input` | no `accept connection-state=established,related,untracked` at the beginning. Stateful checks only apply when `/ip firewall connection tracking` is enabled — cores often run with it off | MEDIUM |
| Invalid not dropped | `/ip firewall filter print detail` | missing `drop connection-state=invalid` in input and forward. **Real exception:** multihomed device with asymmetric routing — see the nuances in `routeros-audit-bgp` | HIGH |
| Permissive forward chain | `/ip firewall filter print detail where chain=forward` | on a device that NATs a protected LAN: no drop of `in-interface-list=WAN connection-state=new connection-nat-state=!dstnat`. Not applicable to border and core routers that forward routed customer traffic without NAT — there the rule would drop legitimate traffic | CRITICAL |
| Inbound traffic without destination NAT | `/ip firewall filter print detail` | WAN drop written without `connection-nat-state=!dstnat`: also kills legitimate port forwarding, or (inverted) lets through what was not forwarded | HIGH |
| Bogons not filtered | `/ip firewall raw print detail` and `/ip firewall address-list print count-only where list=<name>` per list referenced (never a full address-list print: it can hold tens of thousands of entries) | no address-list equivalent to `bad_ipv4`/`not_global_ipv4` applied on WAN ingress | HIGH |
| Invalid source/destination | `/ip firewall raw print detail` | no drop of `bad_src_ipv4` (multicast as source, `255.255.255.255`) and `bad_dst_ipv4` | MEDIUM |
| Invalid source address on the LAN | `/ip firewall raw print detail` | no drop of sources outside the LAN range on the inside interface (anti-spoof) | MEDIUM |
| Invalid TCP flag combinations | `/ip firewall raw print detail` | no chain handling `fin,syn`, `fin,rst`, `fin,!ack`, `fin,urg`, `syn,rst`, `rst,urg` and `!fin,!syn,!rst,!ack` | MEDIUM |
| Zone interface lists | `/interface list print` and `/interface list member print detail` | rules written per loose interface instead of a list: a new interface is born unprotected | LOW |
| Counters | `/ip firewall filter print stats` | protection rule with `packets=0` on an edge device — it may never match, sit in the wrong order, or simply have seen no such traffic. A lead to investigate | LOW |
| Disabled rule | `/ip firewall filter print detail where disabled=yes` | existing protection with `disabled=yes` — worse than absent, because it looks covered | HIGH |
| Fasttrack without exception | `/ip firewall filter print detail where action=fasttrack-connection` | fasttrack before a rule that needs to see the packet (QoS marking, accounting, IPsec): the connection skips everything that comes after | MEDIUM |
| Permissive NAT | `/ip firewall nat print detail` | `dst-nat`/`netmap` inward without source restriction. It may be an intentional publication: confirm the service and the filter before raising it | MEDIUM |
| Masquerade without interface | `/ip firewall nat print detail where action=masquerade` | no `out-interface-list=WAN` nor `out-interface`: masks traffic between internal networks and breaks traceability. On CGNAT the translation is usually `src-nat` with an address range — read that too | HIGH |
| Masquerade eating IPsec | `/ip firewall nat print detail where chain=srcnat` + `/ip ipsec policy print count-only` | only where IPsec policies exist: missing `ipsec-policy=out,none` (or an `accept` before) for the tunnel's pair of networks — traffic leaves masqueraded and the policy does not apply | HIGH |
| Undocumented redirect | `/ip firewall nat print detail where action=redirect` | DNS/HTTP redirect nobody declared, or one that also catches the management network and the VPN. DNS redirect for overdue customers or court blocking is common at ISPs — confirm with the operation | MEDIUM |
| Helper/ALG enabled without use | `/ip firewall service-port print detail` | `sip`, `ftp`, `pptp`, `h323`, `tftp` enabled without need: each helper opens dynamic ports from the inside | MEDIUM |
| Address-list by FQDN | `/ip firewall address-list print count-only where list=<name>` per list used in an `accept`, then that list only | static entry whose `address` is a domain name (it generates dynamic IP entries) in a list used by an `accept` rule: whoever controls DNS chooses who gets in | HIGH |
| Allowlist too broad | the management list only (`/ip firewall address-list print where list=<management list>`) | management list with a large prefix (`/16`, `0.0.0.0/0`) or a third party's IP | HIGH |
| Mangle mark capturing management | `/ip firewall mangle print detail stats` + `/routing rule print detail` and `/ip vrf print` (v7) / `/ip route rule print detail` and `/ip route vrf print` (v6) | routing mark or VRF catching management or VPN traffic: silent blackhole | HIGH |
| Mark shared between QoS and PBR | `/ip firewall mangle print detail` | the same `connection-mark` feeding both the `packet-mark` of a queue **and** the `routing-mark` of a route policy: touching one changes the other. (`packet-mark` alone does not route) | MEDIUM |
| Drop log without limit | `/ip firewall filter print detail stats where log=yes`, and separately `/ip firewall raw print detail where log=yes` | drop rule with `log=yes` and no `limit`: under attack the log itself saturates CPU, disk and syslog — a DoS the device applies to itself | HIGH |
| Critical drop without evidence | same commands | no relevant drop with `log=yes` where the policy requires intrusion evidence. Common and acceptable on a core | LOW |
