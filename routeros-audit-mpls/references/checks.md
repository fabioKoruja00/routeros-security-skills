# MPLS, VPLS and L3VPN checks

Severity scale: CRITICAL / HIGH / MEDIUM / LOW. Every command is read-only. Method and output format: `routeros-audit-method`.

## 1. MPLS and LDP

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| LDP on an untrusted interface | `/mpls ldp interface print detail` | LDP active on a customer or WAN interface: **anyone on the L2 forms an adjacency (hello UDP/646, session TCP/646) and injects bindings** | CRITICAL |
| Transport address on a physical interface | `/mpls ldp print detail` (v6) / `/mpls ldp instance print detail` (v7) | `transport-address`/`lsr-id` off the loopback — penultimate hop popping breaks | HIGH |
| No label filter | `/mpls ldp accept-filter print` and `/mpls ldp advertise-filter print` | no filter: announces and accepts labels for the whole table, including `0.0.0.0/0` | MEDIUM |
| Unexpected targeted session | `/mpls ldp neighbor print detail` | neighbor flagged `targeted` for an address outside the core | HIGH |
| LDP neighbor outside the inventory | same command | unplanned dynamic neighbor, or with addresses outside the core ranges | HIGH |
| Colliding label range | `/mpls print` (v6) / `/mpls settings print` (v7) | `dynamic-label-range` overlapping a static binding, or including 0-15 (reserved) — forwarding to the wrong destination | HIGH |
| Orphan static binding | `/mpls local-bindings print`, `/mpls remote-bindings print`, `/mpls forwarding-table print` | label pointing to a next-hop outside the MPLS domain | MEDIUM |
| Insufficient MTU on the path | `/mpls interface print detail` + `/interface print detail` (`l2mtu`) | L2MTU smaller than the required MPLS MTU: if the next header is not IP, **the packet is discarded silently** — intermittent failure that never shows in a log | HIGH |
| TTL propagated | `/mpls settings print` (v7) / `/mpls print` (v6) | `propagate-ttl=yes`: a traceroute from outside enumerates the core IPs | LOW |
| Unsupported architecture (v7) | `/system resource print` | `smips` device planned as LSR/PE — **MPLS does not exist on that architecture on v7** | HIGH |

## 2. VPLS and L3VPN

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| VPLS over public transport without cipher | `/interface vpls print detail` | customer L2 tunnel crossing the Internet or a third party's link without IPsec/WireGuard underneath | CRITICAL |
| Duplicated `vpls-id` | `/interface vpls print detail` and `/interface vpls monitor <n>` | same id on different pairs: **two customers in the same L2 domain** | CRITICAL |
| VPLS bridge without horizon | `/interface bridge port print detail` (`horizon`) | VPLS ports on the same bridge without horizon and without STP: loop and broadcast storm crossing the tunnel | CRITICAL |
| Management port in the customer's bridge | `/interface bridge port print detail` | provider uplink or management inside the VPN bridge | CRITICAL |
| Divergent control word | `/interface vpls print detail` | enabled on one side only: frames reassembled wrong or the tunnel does not come up | MEDIUM |
| Repeated RD | `/ip route vrf print detail` (v6) / `/ip vrf print detail` (v7) | same route-distinguisher on different VRFs: VPNv4 prefixes stop being unique | CRITICAL |
| Open import RT | `/routing bgp vpn print detail` (v7) | import matching another customer's export: **one customer's route enters another's VRF** | CRITICAL |
| Duplicated `site-id` in BGP-VPLS | `/interface vpls bgp-vpls print detail` | dynamic tunnel created for a peer that does not belong to the VPN — and it **joins the bridge on its own** | CRITICAL |
| Redistribution of connected in the VRF | `/routing bgp vpn print detail` | PE-CE links and the management network entering the customer's VPN | HIGH |
| Route leaking to the global table | `/ip route print detail` filtered by VRF | static route with gateway `@main` in a customer VRF: punches through the isolation | CRITICAL |
| Management by VRF assumed | `/ip service print detail` + `/ip vrf print detail` | **the router cannot be managed from within a VRF** — the service answers through the main table. A policy written assuming otherwise protects nothing | HIGH |

## 3. Traffic engineering

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| TE on an edge interface | `/mpls traffic-eng interface print detail` | TE enabled outside the core: opaque LSAs with backbone topology and bandwidth leaving the trusted domain | HIGH |
| Path with loose hops | `/mpls traffic-eng tunnel-path print detail` and `/interface traffic-eng monitor <n>` | too many `loose` hops — the LSP may cross a third party's equipment. The recorded path proves where it went | MEDIUM |
| Reservation exhausted | `/mpls traffic-eng interface print` | remaining bandwidth at zero: no new tunnel comes up, **including the protection ones** | MEDIUM |
| No secondary path | `/interface traffic-eng print detail` | critical service without an alternative: a link failure takes it down with no automatic failover | HIGH |
| `bandwidth` mistaken for a limit | `/interface traffic-eng print detail` | operator believes `bandwidth` limits the rate — **it only accounts the reservation**; `bandwidth-limit` is what limits | MEDIUM |
| Next-hop diverted to TE | `/routing filter rule print detail` | global `use-te-nexthop=yes`: BGP traffic diverted through a tunnel without the policy saying so | MEDIUM |

## 4. Control plane under saturation

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Control traffic without priority | `/ip firewall mangle print detail` and `/queue tree print detail` | no marking and priority queue for OSPF, BGP, BFD and the management port: a saturated link kills the routing session **and** access to the device together | HIGH |
| BFD without authentication | `/routing bfd configuration print detail` | session on a shared segment without authentication — taking BFD down takes the route down | MEDIUM |
| Loopback announced too far | `/ip address print detail` + `/routing ospf interface-template print` | loopback (identity of LDP, iBGP and TE) reachable from a customer or from the Internet | HIGH |
