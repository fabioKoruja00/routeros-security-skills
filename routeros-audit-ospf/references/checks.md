# OSPF checks

Severity scale: CRITICAL / HIGH / MEDIUM / LOW. Every command is read-only. Method and output format: `routeros-audit-method`.

## 1. OSPF — neighborship

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Adjacency without authentication | `/routing ospf interface-template print proplist=interfaces,area,auth,auth-id,type,passive,cost,priority,hello-interval,dead-interval,disabled` (v7) / `/routing ospf interface print proplist=interface,authentication,authentication-key-id,network-type,passive,priority` (v6). Never `auth-key`/`authentication-key` | `auth` empty (v7) / `authentication=none` (v6) on a segment reachable by customers or untrusted L2: any host there with matching parameters becomes a neighbor and injects LSAs. On a closed point-to-point core link, HIGH | CRITICAL |
| Cleartext authentication | same command | `auth=simple` | HIGH |
| Customer interface active | same command (`passive`) | `passive=no` on an interface that does not talk to another OSPF router | HIGH |
| Generic template without exception | safe interface-template `proplist` + `/routing ospf interface print` | template `interfaces=all` without reviewing what it resolved to: **a new interface joins OSPF on its own**. Read the resolved list, not the template | MEDIUM |
| Unexpected neighbor | `/routing ospf neighbor print detail` and `/routing ospf lsa print` | unknown router-id adjacent | CRITICAL |
| Flapping adjacency | `/routing ospf neighbor print detail` (state-change counter) and `/log print where topics~"ospf"` | counter climbing, or neighbor stuck in `ExStart`, or in `2-way` where it should reach `Full` (between two DROthers `2-way` is normal) — usually MTU, authentication or network type | MEDIUM |
| Static neighbor outside the domain | `/routing ospf static-neighbor print detail` | NBMA pointing to a third party's IP | MEDIUM |
| Duplicated or dynamic router-id | `/routing id print detail` (v7) / `/routing ospf instance print` (v6) | id repeated in the area, or dynamic election (`any`/`lowest`) instead of a fixed loopback | HIGH |

## 2. OSPF — network type and election

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Point-to-point link as broadcast | safe interface-template `proplist` | `broadcast` (the default) on a two-router link across a radio, media converter or L2 fibre. **When the L2 drops with the ports still UP, both sides become DR and the adjacency does not come back on its own** | HIGH |
| Priority inherited from an upgrade | same command (`priority`) | the default changed from **1 on v6 to 128 on v7**: a priority that was "rigid" on v6 stops counting after the upgrade and the election changes on its own | HIGH |
| Weak device eligible as DR | same command | `priority` above 0 on small hardware | MEDIUM |
| Different timers between sides | same command (hello/dead) | divergent values — the adjacency does not close | MEDIUM |
| NBMA without neighbor list | safe interface-template `proplist` + `/routing ospf static-neighbor print` | `type=nbma` (v7) / `network-type=nbma` (v6) without a matching static neighbor | MEDIUM |

## 3. OSPF — instance, area and redistribution

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Default announced without an exit | `/routing ospf instance print detail` | `originate-default=always` (v7) / `distribute-default=always-as-type-1` or `always-as-type-2` (v6) on something that is not the real border: announces default **even without a route** and pulls the area's traffic into a hole | CRITICAL |
| Redistribution without filter | same command (`redistribute` and `out-filter-chain` on v7; `redistribute-connected`/`redistribute-static` and `out-filter` on v6) | `connected`/`static` marked with an empty output filter | HIGH |
| Filter assumed to cover everything | `/routing filter rule print detail` | **route filters only reach external routes** — they do not filter intra-area prefixes. A policy written assuming otherwise does not exist | HIGH |
| Order of the filter rules | same command | `accept 0.0.0.0/0` before the specific `reject`: the specific never runs | HIGH |
| Area without type | `/routing ospf area print detail` | leaf area as `default`, receiving external LSAs it does not need | MEDIUM |
| `no-summaries` misunderstood | `/routing ospf area print detail` | stub area where the operator expected type-3 summaries and the area is totally stubby (`no-summaries` set): internal routers only get the default from the ABR. It is set on the area; the ABR is the one that suppresses the summaries | MEDIUM |
| NSSA without translator | same command | `nssa-translator=no` on every ABR of the NSSA | MEDIUM |
| Missing backbone | same command | multi-area design with no area `0.0.0.0`. On **v7 every area, including the backbone, is created by hand** — on v6 it came ready. A single non-zero area on its own is not a failure | MEDIUM |
| Permanent virtual-link | `/routing ospf interface-template print proplist=interfaces,area,auth,auth-id,type,passive,cost,priority,hello-interval,dead-interval,disabled where type=virtual-link` (v7) / `/routing ospf virtual-link print` (v6) | a patch became permanent, worse without authentication | MEDIUM |
| Missing summarisation | `/routing ospf area range print detail` | internal prefix (backup network, management) announced to the backbone | MEDIUM |
| Instance in the wrong VRF | `/routing ospf instance print detail` (`vrf`, `routing-table` on v7; `routing-table` on v6) | a customer VRF instance on the main table: leak between customers | HIGH |
| Growing LSA database | `/routing ospf lsa print count-only` | count climbing without a topology change | HIGH |

## 4. OSPF + PPPoE — the /32 problem

Every PPPoE session creates a `/32` route. Redistributed, they become an LSA flood across the
whole area.

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Subscriber /32 in OSPF | `/routing ospf lsa print count-only` and `/ip route print count-only where ospf and dst-address~"/32"` (never a full route or LSA listing on a busy concentrator) | dozens or hundreds of `/32` with OSPF origin | HIGH |
| Subscriber block in the area | safe interface-template `proplist` including `networks` (v7) / `/routing ospf network print` (v6) | the pool block listed — generates one LSA per session | HIGH |
| No aggregate with blackhole | `/ip route print detail where blackhole` | missing discard route of the aggregated block that replaces the /32s | HIGH |
| Blackhole competing with the real route | same command | `distance` too low: the blackhole wins over the good route and **swallows the traffic silently** | HIGH |
| Concentration area is not stub | `/routing ospf area print detail` | area with hundreds of sessions still `default` | MEDIUM |
