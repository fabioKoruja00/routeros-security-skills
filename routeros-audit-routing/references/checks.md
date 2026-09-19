# Dynamic routing checks — OSPF, BGP, RPKI, MPLS

Severity scale: CRITICAL / HIGH / MEDIUM / LOW. Every command is read-only. Check the version
first: v6 and v7 menus differ (map in SKILL.md).

## 1. OSPF — neighborship

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Adjacency without authentication | `/routing ospf interface-template print detail` (v7) / `/routing ospf interface print detail` (v6) | `auth` empty: **any host on the segment becomes a neighbor and injects LSAs** | CRITICAL |
| Cleartext authentication | same command | `auth=simple` | HIGH |
| Customer interface active | same command (`passive`) | `passive=no` on an interface that does not talk to another OSPF router | HIGH |
| Generic template without exception | `/routing ospf interface-template print detail` + `/routing ospf interface print` | template `interfaces=all` without reviewing what it resolved to: **a new interface joins OSPF on its own**. Read the resolved list, not the template | MEDIUM |
| Unexpected neighbor | `/routing ospf neighbor print detail` and `/routing ospf lsa print` | unknown router-id adjacent | CRITICAL |
| Flapping adjacency | `/routing ospf neighbor print detail` (state-change counter) and `/log print where topics~"ospf"` | counter climbing, or neighbor stuck in `ExStart`/`2-way` — usually MTU, authentication or network type | MEDIUM |
| Static neighbor outside the domain | `/routing ospf static-neighbor print detail` | NBMA pointing to a third party's IP | MEDIUM |
| Duplicated or dynamic router-id | `/routing id print detail` (v7) / `/routing ospf instance print` (v6) | id repeated in the area, or dynamic election (`any`/`lowest`) instead of a fixed loopback | HIGH |

## 2. OSPF — network type and election

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Point-to-point link as broadcast | `/routing ospf interface-template print detail` (`network-type`) | `broadcast` (the default) on a two-router link across a radio, media converter or L2 fibre. **When the L2 drops with the ports still UP, both sides become DR and the adjacency does not come back on its own** | HIGH |
| Priority inherited from an upgrade | same command (`priority`) | the default changed from **1 on v6 to 128 on v7**: a priority that was "rigid" on v6 stops counting after the upgrade and the election changes on its own | HIGH |
| Weak device eligible as DR | same command | `priority` above 0 on small hardware | MEDIUM |
| Different timers between sides | same command (hello/dead) | divergent values — the adjacency does not close | MEDIUM |
| NBMA without neighbor list | `/routing ospf interface-template print detail` + `/routing ospf static-neighbor print` | `network-type=nbma` without a matching static neighbor | MEDIUM |

## 3. OSPF — instance, area and redistribution

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Default announced without an exit | `/routing ospf instance print detail` | `originate-default=always` on something that is not the real border: announces default **even without a route** and pulls the area's traffic into a hole | CRITICAL |
| Redistribution without filter | same command (`redistribute`, `out-filter`) | `connected`/`static` marked with an empty output filter | HIGH |
| Filter assumed to cover everything | `/routing filter rule print detail` | **route filters only reach external routes** — they do not filter intra-area prefixes. A policy written assuming otherwise does not exist | HIGH |
| Order of the filter rules | same command | `accept 0.0.0.0/0` before the specific `reject`: the specific never runs | HIGH |
| Area without type | `/routing ospf area print detail` | leaf area as `default`, receiving external LSAs it does not need | MEDIUM |
| `no-summaries` in the wrong place | same command | set on the ABR (should be only on the internal routers): **the area is left without a route to the rest of the network** | HIGH |
| NSSA without translator | same command | `nssa-translator=no` on every ABR of the NSSA | MEDIUM |
| Missing backbone | same command | no area `0.0.0.0`. On **v7 every area, including the backbone, is created by hand** — on v6 it came ready | MEDIUM |
| Permanent virtual-link | `/routing ospf interface-template print detail where network-type=virtual-link` | a patch became permanent, worse without authentication | HIGH |
| Missing summarisation | `/routing ospf area-range print detail` | internal prefix (backup network, management) announced to the backbone | MEDIUM |
| Instance in the wrong VRF | `/routing ospf instance print detail` (`vrf`, `routing-table`) | a customer VRF instance with `vrf=main`: leak between customers | HIGH |
| Growing LSA database | `/routing ospf lsa print count-only` | count climbing without a topology change | HIGH |

## 4. OSPF + PPPoE — the /32 problem

Every PPPoE session creates a `/32` route. Redistributed, they become an LSA flood across the
whole area.

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Subscriber /32 in OSPF | `/ip route print detail where dst-address~"/32"` and `/routing ospf lsa print` | dozens or hundreds of `/32` with OSPF origin | HIGH |
| Subscriber block in the area | `/routing ospf interface-template print detail` (`networks`) | the pool block listed — generates one LSA per session | HIGH |
| No aggregate with blackhole | `/ip route print detail where blackhole` | missing discard route of the aggregated block that replaces the /32s | HIGH |
| Blackhole competing with the real route | same command | `distance` too low: the blackhole wins over the good route and **swallows the traffic silently** | HIGH |
| Concentration area is not stub | `/routing ospf area print detail` | area with hundreds of sessions still `default` | MEDIUM |

## 5. BGP — session

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Session without MD5 | `/routing bgp connection print detail` (v7) / `/routing bgp peer print detail` (v6) — check **presence**, never the value | key empty on a session crossing a third party's network | HIGH |
| GTSM off | same command | `ttl-security=no` on a directly connected eBGP peer: a forged packet from afar reaches port 179 | MEDIUM |
| No prefix ceiling | same command | `max-prefix-limit` empty on an eBGP peer — a full-table leak exhausts RAM | HIGH |
| Peer accepting any ASN (v7) | `/routing bgp connection print detail` | `remote.as` empty with `listen` on: v7 discovers the ASN from the OPEN message and closes with whoever arrives | HIGH |
| Session on a physical address | same command | iBGP peer on a physical interface IP instead of loopback: a link drop kills the session | MEDIUM |
| Next-hop not adjusted on iBGP | same command (`nexthop-choice`) | border without `force-self`: the iBGP peers receive an external next-hop, the route stays inactive or forces carrying the external network in the IGP | HIGH |
| Port 179 open | `/ip firewall filter print detail where chain=input` | `dst-port=179` without `src-address` restricted to the peers | HIGH |

## 6. BGP — filters, attributes and leaks

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| No output filter | `/routing bgp connection print detail` + `/routing filter rule print` | `output.filter` empty: **on v7 every connected network is announced by default** — the internal network leaks without anyone asking | CRITICAL |
| No input filter | same | `input.filter` empty on a transit peer: accepts bogons, default and prefixes more specific than /24 | CRITICAL |
| Transit leak | `/routing filter rule print` | output filter letting a prefix learned from one transit through to another transit or to an IX | CRITICAL |
| `local-pref` accepted from outside | `/routing filter rule print` + `/ip route print detail` | attribute received from an external peer without normalisation in the input filter: **the neighbor starts deciding your AS's exit** | HIGH |
| `weight` as the only failover criterion | `/ip route print detail where bgp` | `weight` is local to the router and does not propagate — the policy does not replicate and the failover fails silently | MEDIUM |
| MED passed on | `/ip route print detail` | MED from one neighbor being announced to a third AS | MEDIUM |
| Origin `incomplete` announced | `/ip route print detail where bgp` | prefix with origin `incomplete` going out: that is redistribution entering BGP directly — an internal route leaking | HIGH |
| Private AS announced | `/routing bgp connection print detail` | `remove-private-as=no` on a session to the Internet | HIGH |
| Broad redistribution | same command (`out.redistribute`) | `connected,static,ospf` without filter: publishes the whole IGP | HIGH |
| Unconditional default route | same command | `default-originate=always` | MEDIUM |
| Community without scrubbing | `/routing filter rule print detail` | community received from a customer passed on — the customer triggers prepend or blackhole on your side | HIGH |
| Third-party blackhole accepted | same command | blackhole community accepted for a prefix that **does not belong** to the requester: a customer discards someone else's route | CRITICAL |
| Internal prefix without `no-export` | same command | internal network announced without the mark that pins it at the neighbor | HIGH |

**AS-path regex trap (v6 vs v7).** On v7 `_200_` matches ASN 200 in the middle of the path; on
v6 the same pattern matches **any ASN of at least 6 characters containing `200`**. The v6
equivalent is `".*_200_.*"`. A filter copied from one to the other matches another set — **with no
syntax error**.

**Filter syntax trap.** v6 uses field by field (`action=discard set-bgp-communities=no-export`);
v7 uses a script (`rule="if (bgp-communities equal 100:501) {reject;}"`). Configuration copied
between versions **is not applied and does not complain** — the policy simply stops existing.

**`discard` vs `reject` trap.** On v6, `discard` stops updating the route; `reject` keeps it in
memory and allows `refresh`. On v7 `discard` does not exist. A rejected route shows as
**inactive** — do not confuse it with a backup route.

## 7. BGP — reflection and confederation

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Reflection enabled on the client | `/routing bgp peer print detail where route-reflect=yes` (v6) | `route-reflect=yes` on a peer that is not a reflector: crossed reflection and iBGP loop | HIGH |
| Inverted option on v7 | `/routing bgp template print detail` and `/routing bgp connection print detail` | on v7 the field is **`no-client-to-client-reflection`** and reflection is automatic: whoever looks for the v6 name concludes "the RR is not active", and whoever ticks the box inverts the whole policy | HIGH |
| Incoherent cluster-id | `/routing bgp template print detail` (v7) / `/routing bgp instance print detail` (v6) | redundant RRs with different cluster-ids where they should be equal: loop or loss of the anti-loop protection | MEDIUM |
| Improper confederated sub-AS | `/routing bgp instance print detail` (v6) | an AS in the `confederation-peers` list that should not be there: the eBGP exchange starts being treated as iBGP and attributes cross the boundary | HIGH |
| Confederated AS-path leaking | `/ip route print detail where bgp` | parentheses in the as-path seen by an external peer | MEDIUM |
| Expected aggregate that does not exist (v7) | `/routing filter rule print` | device migrated from v6 counting on `/routing bgp aggregate`: **the menu does not exist on v7** and every specific route leaks | HIGH |
| Aggregate inheriting attributes | `/routing bgp aggregate print detail` (v6) | `inherit-attributes=yes` pulling `no-export` from the specifics — the aggregate stops being announced | MEDIUM |

## 8. RPKI (v7 only)

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| RPKI absent at the border | `/routing rpki print` and `/routing rpki-session print` | device with a full table and no cache configured | HIGH |
| Cache configured without use | `/routing filter rule print` | cache active and no rule testing the result — validates and ignores | HIGH |
| Cache session down | `/routing rpki-session print` | session not `established`: validation stops and **the filter stops rejecting anything, with no alarm** | HIGH |
| `invalid` accepted | `/routing filter rule print` | no rule rejecting `rpki-status=invalid` | HIGH |

## 9. MPLS and LDP

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

## 10. VPLS and L3VPN

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

## 11. Traffic engineering

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| TE on an edge interface | `/mpls traffic-eng interface print detail` | TE enabled outside the core: opaque LSAs with backbone topology and bandwidth leaving the trusted domain | HIGH |
| Path with loose hops | `/mpls traffic-eng tunnel-path print detail` and `/interface traffic-eng monitor <n>` | too many `loose` hops — the LSP may cross a third party's equipment. The recorded path proves where it went | MEDIUM |
| Reservation exhausted | `/mpls traffic-eng interface print` | remaining bandwidth at zero: no new tunnel comes up, **including the protection ones** | MEDIUM |
| No secondary path | `/interface traffic-eng print detail` | critical service without an alternative: a link failure takes it down with no automatic failover | HIGH |
| `bandwidth` mistaken for a limit | `/interface traffic-eng print detail` | operator believes `bandwidth` limits the rate — **it only accounts the reservation**; `bandwidth-limit` is what limits | MEDIUM |
| Next-hop diverted to TE | `/routing filter rule print detail` | global `use-te-nexthop=yes`: BGP traffic diverted through a tunnel without the policy saying so | MEDIUM |

## 12. Control plane under saturation

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Control traffic without priority | `/ip firewall mangle print detail` and `/queue tree print detail` | no marking and priority queue for OSPF, BGP, BFD and the management port: a saturated link kills the routing session **and** access to the device together | HIGH |
| BFD without authentication | `/routing bfd configuration print detail` | session on a shared segment without authentication — taking BFD down takes the route down | MEDIUM |
| Loopback announced too far | `/ip address print detail` + `/routing ospf interface-template print` | loopback (identity of LDP, iBGP and TE) reachable from a customer or from the Internet | HIGH |

## 13. Nuances that generate false positives

- **On a multihomed device, `drop connection-state=invalid` may be missing on purpose.** With two
  exits, a packet of the same connection enters through a different interface than it left,
  conntrack marks it `invalid` and the rule kills good traffic. Count the active exits before
  accusing; there the correct recommendation is handling it in RAW or disabling conntrack, not
  inserting the drop.
- **An asymmetric path is not a failure by itself** — but it breaks conntrack and IPsec. Compare
  the best path in **both directions** before concluding.
- **ECMP between the primary and the backup link may be an accident of equal cost**, not a
  decision. Read the cost before treating it as design.
- **`originate-default=if-installed` may stop announcing** on a router whose default comes from
  PPPoE or DHCP. Changing it without checking the origin of the default cuts the exit of the
  whole area.
