# IPv6 checks

Severity scale: CRITICAL / HIGH / MEDIUM / LOW. Every command is read-only. Method and output format: `routeros-audit-method`.

## 1. Stack state

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| IPv6 active without use | `/ipv6 settings print` and `/ipv6 address print` | stack enabled on a network that neither uses nor manages IPv6 | HIGH |
| Empty v6 firewall | `/ipv6 firewall filter print detail stats` | empty list, or only disabled rules, with an active IPv6 address | CRITICAL |
| Restrictive v4 policy and loose v6 | `/ip firewall filter print` + `/ipv6 firewall filter print` | same box with tight rules on v4 and nothing on v6 | CRITICAL |
| RA acceptance on a router | `/ipv6 settings print` (`accept-router-advertisements`, `forward`) and `/ipv6 route print where dynamic` | acceptance active with `forward=yes` on an untrusted link: another device injects the default route | HIGH |
| ICMPv6 redirect | `/ipv6 settings print` | `accept-redirects` active on a router | MEDIUM |
| Inflated neighbor table | `/ipv6 neighbor print count-only` and `/ipv6 neighbor print where status=incomplete` | volume of `incomplete` far above the real hosts: scan of the /64 (ND exhaustion) | HIGH |
| Address in conflict | `/ipv6 address print detail` (flags) and `/log print where topics~"ipv6"` | address flagged as duplicate — can be a repeated IP **or** a DAD DoS (someone answering every NS) | HIGH |
| DAD off without being anycast | `/ipv6 address print detail where no-dad=yes` | `no-dad=yes` on an ordinary unicast address | MEDIUM |

## 2. RA and ND

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Advertisement on the wrong interface | `/ipv6 address print detail where advertise=yes` | `advertise=yes` on an uplink, transit or interface without clients | HIGH |
| RA scope open | `/ipv6 nd print detail` | entry with `interface=all`: advertises on every interface, **including the WAN and those added later** | HIGH |
| Incoherent M/O flags | `/ipv6 nd print detail` | `managed-address-configuration=yes` without a stateful DHCPv6 answering — the host is left without an address. With M set, the O flag is ignored and SLAAC is not used | MEDIUM |
| Strange prefix advertised | `/ipv6 nd prefix print detail` | prefix outside the plan, or a mask other than `/64` (SLAAC only works with /64) | HIGH |
| RA lifetime | `/ipv6 nd print detail` (`ra-lifetime`) | `0` on a LAN that should have a gateway (the router declares "I am not default"), or a lifetime far above the advertisement interval | MEDIUM |
| Rogue RA on the segment | `/ipv6 neighbor print detail`, `/ipv6 route print where dynamic`, `/ping ff02::2 interface=<lan>` | something that is not the gateway answers on `ff02::2`; dynamic default route learned on a customer port | CRITICAL |
| RA preference | `/ipv6 nd print detail` (`ra-preference`) | legitimate at `low` while a neighbor advertises `high` — but raising the preference is a palliative: the defence is filtering type 134 on the customer port | MEDIUM |
| RA Guard absent on the port | `/interface bridge port print detail` and `/interface ethernet switch rule print detail` | `ra-guard=no` on a customer port | HIGH |
| Router MAC advertised | `/ipv6 nd print detail` (`advertise-mac-address`) | enabled on a transit interface | LOW |
| DNS advertised without a v6 server | `/ipv6 nd print detail` + `/ip dns print` | `advertise-dns=yes` with `/ip dns servers` holding no IPv6 address: the client is left without v6 DNS and silently falls back to IPv4 | MEDIUM |

## 3. IPv6 firewall

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Forward without drop of new connections from the WAN | `/ipv6 firewall filter print where chain=forward` | no `drop connection-state=new in-interface-list=WAN`: **the whole LAN exposed**, without the NAT that "protected by accident" on v4 | CRITICAL |
| Invalid not dropped | `/ipv6 firewall filter print where chain=forward` | missing `drop connection-state=invalid` | HIGH |
| Established accept after the drop | `/ipv6 firewall filter print` (numbering) | the reply of outbound traffic dies on the way back | HIGH |
| Input without final drop | `/ipv6 firewall filter print where chain=input` | no drop, or a drop without `in-interface-list` (also kills management from the LAN) | CRITICAL |
| ICMPv6 blocked as a block | `/ipv6 firewall filter print where protocol=icmpv6` | generic `drop protocol=icmpv6`: kills ND, DAD, SLAAC and PMTUD | CRITICAL |
| ICMPv6 allowed without limit | same command | accept without `limit`: flood and tunnelling channel | HIGH |
| ND without `hop-limit` | same command | accept of types 133-136 without `hop-limit=equal:255` — a legitimate neighbor always arrives with 255; without the check, forged ND from afar is accepted | HIGH |
| Link-local and multicast not handled | `/ipv6 firewall filter print where chain=input` | no accept for `fe80::/10` and `ff00::/8` (source **and** destination) above the final drop: ND, DAD and OSPFv3 fall together when the drop lands | CRITICAL |
| Link-scope multicast from the WAN | same command | `ff02::1`/`ff02::2` accepted on an external interface: enumeration of link hosts | HIGH |
| DNS open only on v6 | `/ip dns print` + `/ipv6 firewall filter print where dst-port=53` | udp/tcp 53 blocked on v4 and **forgotten on v6** — the open resolver stays up | CRITICAL |
| Management exposed on v6 | `/ipv6 firewall filter print where dst-port=8291` + `/ip service print detail` | accept of a management port without a restricted `src-address`. Changing the port is **not** the control | HIGH |
| v6 bogons not filtered | `/ipv6 firewall raw print detail` and `/ipv6 firewall address-list print` | no list equivalent to `bad_ipv6`/`not_global_ipv6` | HIGH |
| RAW matching ICMPv6 without exception | `/ipv6 firewall raw print` | RAW rule catching 133-137: **in RAW there is no conntrack to save the session** | HIGH |
| v6 NAT in use | `/ipv6 firewall nat print` | v6 masquerade hiding topology and breaking end-to-end — remove only after `forward` is correct | MEDIUM |
| Referenced address-list is empty | `/ipv6 firewall address-list print` | list cited by an accept rule with no content: the rule never matches | MEDIUM |

## 4. DHCPv6 and prefix delegation

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Server on the wrong interface | `/ipv6 dhcp-server print detail` | `interface` is WAN/transit instead of the LAN bridge | HIGH |
| Unknown binding | `/ipv6 dhcp-server binding print detail` and `/ipv6 pool used print` | DUID nobody recognises, or delegated prefix outside the planned pool | HIGH |
| Delegated prefix longer than /64 | `/ipv6 pool print detail` | `prefix-length` above 64: the client's SLAAC stops working | MEDIUM |
| Client accepting route and DNS from the peer | `/ipv6 dhcp-client print detail` | `add-default-route=yes` or `use-peer-dns=yes` on an untrusted link: the peer picks the device's gateway and resolver | HIGH |
| Unexpected dynamic DNS | `/ip dns print` (`dynamic-servers`) | learned resolver that is not the operation's | HIGH |
| Lease too long | `/ipv6 dhcp-server print detail` | binding stuck to a client already gone — traceable, occupied address | LOW |
| PD pool swapped in PPP | `/ppp profile print detail` (`dhcpv6-pd-pool`, `remote-ipv6-prefix-pool`) | PD pointing to the pool of another customer class | MEDIUM |
| RA with M set on v6 without stateful | `/ipv6 nd print detail` + `/system resource print` | on RouterOS v6 DHCPv6 is **delegation only**: with the M flag the host waits for an address that never comes | HIGH |

## 5. IPv6 routing

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| v6 BGP without input filter | `/routing bgp connection print detail` (`input.filter`) | empty on a carrier session: accepts bogons, default and third-party prefixes | CRITICAL |
| v6 BGP without output filter | same (`output.filter`, `output.network`) | announcement backed only by an address-list — if the list grows, someone else's prefix is announced | HIGH |
| Dirty announcement address-list | `/ipv6 firewall address-list print where list=<announce list>` | entry that does not belong to the organisation | CRITICAL |
| Session without MD5 | `/routing bgp connection print detail` (presence of `tcp-md5-key`, never the value) | empty on a session crossing a third party's network | HIGH |
| Aggregate without blackhole | `/ipv6 route print where blackhole` | aggregated prefix announced without a local discard route: loop and sub-route leak | MEDIUM |
| Strange default | `/ipv6 route print where dst-address="::/0"` | more than one default, or an unplanned dynamic default | HIGH |
| Route volume out of the expected | `/ipv6 route print count-only where bgp` | session that should bring only default bringing a table | HIGH |
| OSPFv3 on a customer interface | `/routing ospf interface-template print detail` | template with empty `interfaces` (matches everything) or `passive=no` on a customer port: anyone forms an adjacency and injects routes | CRITICAL |
| OSPFv3 without authentication | same command (presence of `auth`) | open neighborship on an untrusted segment | HIGH |
| Redistribution on a concentrator | `/routing ospf instance print detail` | `redistribute` including `connected` on a PPPoE concentrator: injects one route per client | HIGH |
| PTP link as broadcast | `/routing ospf interface-template print detail` (`network-type`) | `broadcast` on point-to-point: allows DR election by an untrusted node on the segment | MEDIUM |

## 6. Transition and tunnels

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| 6to4 active without use | `/interface 6to4 print detail` | tunnel enabled where native IPv6 exists — unauthenticated path ending at a third-party relay | HIGH |
| Protocol 41 allowed | `/ip firewall filter print where protocol=ipv6-encap` | IPv6 entering inside IPv4, escaping the v6 policy | HIGH |
| Teredo in use | `/ipv6 route print where dst-address in 2001::/32` and `/ip firewall connection print where protocol=udp` (port 3544) | route or traffic to `2001::/32` on a network that does not use Teredo: an internal host punching through the egress policy | HIGH |
| v6 tunnel without cipher | `/interface gre6 print detail`, `/interface ipipv6 print detail`, `/interface eoipv6 print detail` | `ipsec-secret` empty: the traffic (including the IPv4 carried inside) travels in the clear | HIGH |
| Open endpoint | same commands + `/ipv6 firewall filter print where protocol=gre` | generic `remote-address`, or accept of GRE/IPIP without restricting the peer's source | HIGH |
| MSS not adjusted | `/interface gre6 print detail` | `clamp-tcp-mss=no` with a reduced MTU: TCP sessions hang intermittently and become a "ghost problem" | LOW |

## 7. Addressing plan with a security effect

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Block outside the plan | `/ipv6 address print`, `/ipv6 pool print`, `/ipv6 route print` | address in use outside the documented plan: **covered by no firewall rule and no announcement filter** | MEDIUM |
| Predictable address exposed | `/ipv6 address print` | service on `::1`/`::2` without source restriction. Not a reason to renumber — a reason to filter: "hard-to-find address" is not a control | MEDIUM |
| EUI-64 on an exposed service | `/ipv6 address print detail where eui-64=yes` | MAC embedded in the address: traceable and predictable | LOW |
| PTP with a public /64 | `/ipv6 address print` | point-to-point link occupying a whole /64 — unnecessary scanning surface | LOW |

## 8. Extension headers and what IPv6 does NOT have

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Routing header type 0 | `/ipv6 firewall filter print detail` and `/ipv6 firewall raw print detail` | no discard of routing header type 0 in forward — RH0 allows traffic reflection and was deprecated for that. RouterOS has its own matcher for extension headers (`headers`) and for the routing header type; **check the exact name on the installed version with `print detail` of an existing rule** before writing the recommendation | HIGH |
| Unlimited ICMPv6 echo from outside | `/ipv6 firewall filter print detail where protocol=icmpv6` | accept of echo request on the WAN `input` without `limit`: direct flood and amplification through `ff02::1` | MEDIUM |
| IPv6 fragment crossing the edge | `/ipv6 firewall filter print detail` (`Next Header 44`) | **only the source fragments in IPv6** — a fragment arriving from outside is anomalous, and serves to evade the filter by overlap | HIGH |
| Wrong header value in the filter | `/ipv6 firewall filter print detail` | rule written against `50`/`51` believing it filters extensions: those are ESP and AH — **kills IPsec** | MEDIUM |
| Control that only exists on IPv4 | `/ipv6 firewall filter print`, `/ipv6 firewall raw print` | policy written counting on NAT, hotspot, layer-7 filter or policy routing **on IPv6** — they do not exist. Audit as a gap, not as missing configuration | HIGH |
| Loopback with automatic MAC | `/interface bridge print detail` | bridge used as loopback with `auto-mac=yes`: the link-local changes with the MAC and **takes down adjacencies and routes that use that address as gateway** | MEDIUM |

## 9. Nuances that generate false positives

- **`accept-router-advertisements` with `forward=yes` is already protected by the default**
  (`yes-if-forwarding-disabled`). Read both properties together before accusing.
- **Disabling `add-default-route` on the DHCPv6 client cuts transit** if that is the only default.
  Check where the route comes from before recommending.
- **Removing v6 NAT without `forward` ready exposes what was hidden.** Order matters.
- **`no-dad=yes` is legitimate on an anycast address.** Re-enabling DAD there takes the service down.
- **Mirroring the v4 policy into v6 without the ICMPv6 and link-local accepts takes the network
  down.** The direct copy is the classic mistake.
- **Several addresses per MAC in the neighbor table is usually the privacy extension, not an
  attack.** Modern operating systems generate a new temporary address periodically. Compare with
  the number of real hosts before calling it exhaustion — and never tie a rule to a host
  address, only to a prefix.
- **Discarding IPv6 fragments can cut legitimate traffic** (DNSSEC over UDP, some tunnels).
  Measure the real volume before recommending.
