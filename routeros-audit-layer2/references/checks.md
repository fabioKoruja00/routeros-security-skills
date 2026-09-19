# Layer 2, discovery and bridge checks

Severity scale: CRITICAL / HIGH / MEDIUM / LOW. Every command is read-only. Method and output format: `routeros-audit-method`.

## 1. Layer 2, discovery and bridge

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| MNDP on an untrusted interface | `/ip neighbor discovery-settings print` | `discover-interface-list=all` or a list containing WAN/customer. Official recommendation: `none` | HIGH |
| Broad discovery list | `/interface list member print detail` | discovery list with more interfaces than the management ones | HIGH |
| Inflated neighbor table | `/ip neighbor print count-only` and `/ip neighbor print detail` | thousands of entries, or a neighbor with platform/identity outside the inventory | HIGH |
| DHCP snooping off | `/interface bridge print detail` | `dhcp-snooping=no` on a segment with customers: a rogue DHCP server gets through | HIGH |
| Wrong trusted port | `/interface bridge port print detail` | customer port with `trusted=yes`, or legitimate uplink without trust | CRITICAL |
| RA Guard absent | `/interface bridge port print detail` | `ra-guard=no` on a customer port: a rogue RA injects an IPv6 gateway and does MITM without touching IPv4 | HIGH |
| No isolation between customers | `/interface bridge port print detail` | customer ports with `horizon=none` on a provider/guest network | MEDIUM |
| BPDU guard absent | `/interface bridge port print detail` | access port without `bpdu-guard=yes`: a customer switch takes over the STP root | MEDIUM |
| STP off | `/interface bridge print detail` | `protocol-mode=none` on a bridge with more than one physical port | MEDIUM |
| Loop protect | `/interface ethernet print detail` | `loop-protect=off` on an access port | LOW |
| Unrestricted ARP where DHCP rules | `/interface ethernet print detail` and `/interface bridge print detail` | `arp=enabled` on a DHCP-controlled segment with static leases — the client picks its own IP | MEDIUM |
| Bridge without filter | `/interface bridge filter print detail stats` | segment that should carry only one protocol (e.g. PPPoE) without a specific `accept` + final `drop` | MEDIUM |
| Bridge filter the traffic never sees | `/interface bridge port print detail` (`hw`) and `/interface bridge settings print` | policy written in `bridge filter` while the port has hardware offload: the packet never reaches the CPU and **the rule never matches, with no error** | HIGH |
| IP firewall that does not see bridged traffic | `/interface bridge settings print` | device in bridge mode with `use-ip-firewall=no` (the default) and `/ip firewall filter` rules written to filter that traffic: **the whole policy is decorative** | HIGH |
| Transport link without L2 filter | `/interface bridge filter print detail stats` | segment that should only carry PPPoE without `accept mac-protocol=pppoe-discovery` + `pppoe-session` + final `drop` | MEDIUM |
| VLAN filtering off | `/interface bridge print detail` and `/interface bridge vlan print detail` | `vlan-filtering=no` on a bridge carrying customer VLANs together with management: the separation is only nominal | CRITICAL |
| Wrong PVID and frame types | `/interface bridge port print proplist=bridge,interface,pvid,frame-types,ingress-filtering` | access port accepting tagged, trunk accepting untagged, or `ingress-filtering=no` — VLAN hopping | CRITICAL |
| Bridge port without MAC limit | `/interface bridge port print detail` and `/interface bridge host print` | access port learning many MACs without a limit: enables DHCP starvation | HIGH |
| MAC flapping between ports | `/interface bridge host print detail` | same MAC switching ports or appearing in another customer's VLAN: loop, spoof or leak between domains | HIGH |
