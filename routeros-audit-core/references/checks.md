# RouterOS security checks — core

Every command here is READ-ONLY. Severity is a suggestion: reclassify when the measurement on
the device contradicts it, and say that it was reclassified. In doubt between two levels, the lower.

**Read the factory defaults first** (`routeros-factory-defaults`). Half of the false positives in
this area are factory values being accused as somebody's insecure decision.

Sibling skills by area: `routeros-audit-ipv6` · `routeros-audit-routing` ·
`routeros-audit-wireless` · `routeros-audit-automation`.

Severity scale: CRITICAL / HIGH / MEDIUM / LOW.

## 1. Exposed services and administrative access

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Insecure service enabled | `/ip service print detail` | `telnet`, `ftp`, `www` or `api` with `disabled=no` | HIGH |
| Administrative service without source restriction | `/ip service print detail` | `winbox`/`ssh`/`www-ssl`/`api-ssl` with `address=""`. In Winbox this is the empty **Available From** column | CRITICAL |
| Default service port | `/ip service print detail` | `ssh` on 22 and `winbox` on 8291 exposed to the WAN. Changing the port is obfuscation: it does **not** replace `address` nor a filter — the official docs are explicit | LOW |
| www-ssl/api-ssl certificate | `/ip service print detail` + `/certificate print detail` | `certificate=none` on a TLS service, or an expired certificate in external use | MEDIUM |
| SSH with weak crypto | `/ip ssh print` | `strong-crypto=no`, `allow-none-crypto=yes`, or `host-key-size` below 2048 | MEDIUM |
| SSH forwarding enabled | `/ip ssh print` | `forwarding-enabled` other than `no` without a declared use: the device becomes a pivot into the network | HIGH |
| `admin` user active | `/user print detail` | user `admin` with `disabled=no`. Without password or with the default one: immediate CRITICAL | CRITICAL |
| User without source restriction | `/user print detail` | account in group `full`/`write` with `address=""` | HIGH |
| Group with too much permission | `/user group print detail` | monitoring-only group with `write`, `policy`, `sensitive` or `password` | HIGH |
| Orphan SSH key | `/user ssh-keys print detail` | public key registered that nobody recognises — access that survives a password change | CRITICAL |
| Unexpected active session | `/user active print` | session from an unknown origin, or `via=api` nobody recognises | HIGH |
| Unused interface enabled | `/interface print detail` | physical port or virtual interface without a function and `disabled=no` | MEDIUM |
| Protected RouterBOOT | `/system routerboard settings print` | `protected-routerboot=disabled` on a device with third-party physical access | HIGH |
| RouterBOOT firmware behind | `/system routerboard print` | `current-firmware` different from `upgrade-firmware` | MEDIUM |
| Permissive device-mode (v7.17+) | `/system device-mode print` | `container`, `socks`, `proxy`, `traffic-gen` or `partitions` enabled without a declared use | MEDIUM |
| Device-mode flagged | `/system device-mode print` | `flagged=yes`: there was a change attempt without physical confirmation. **Treat as a possible intrusion**, audit everything before clearing the state | CRITICAL |
| Flagging disabled | `/system device-mode print` | `flagging-enabled=no`: the device stops warning about the attempt — it loses the only signal it had | CRITICAL |
| Downgrade allowed | `/system device-mode print` and `/system package print detail` | `install-any-version=yes`, or installed version outside `allowed-versions`: allows going back to a version with a known flaw and reopening what was fixed | HIGH |
| Baseline of the model assumed | `/system default-configuration print` | auditing against the home-router defconf when the device is a CCR, IP-only, CAP or switch — **those lines do not receive the default firewall**, so "no rules" there is factory-normal, and the finding is another one: nobody built the policy | CRITICAL |
| Permissive alternate boot | `/system routerboard settings print` | `boot-device` accepting ethernet/Netinstall without a custody procedure | HIGH |
| AAA login with a broad group | `/user aaa print` | `default-group=full`: whoever RADIUS authenticates enters with full power, even without an attribute | CRITICAL |
| Password too old | `/user print proplist=name,group,address,last-logged-in,password-changed-before` | administrative account whose password has not changed since before the last staff turnover | MEDIUM |
| LCD without PIN | `/lcd print` and `/lcd pin print` | screen enabled, no PIN and no read-only mode on a device in a shared rack | MEDIUM |
| Physical button running a script | `/system routerboard button print` (or `/system routerboard mode-button print`) | button enabled with an `on-event` that brings up a tunnel or a service: **whoever reaches the device raises an exit path with no credential at all** | HIGH |
| Device snapshot on disk | `/file print where name~"supout"` | accumulated `supout.rif`/`autosupout.rif`: they contain the full configuration, log and state | MEDIUM |
| Public graphs | `/tool graphing interface print`, `/tool graphing resource print`, `/tool graphing queue print` + `/ip service print where name=www` | `allow-address=0.0.0.0/0` with `www` up: the `/graphs` page hands out interface names, queues, CPU and memory **without login** | HIGH |
| Unmaintained monitoring tool | `/dude print` | Dude server active — product discontinued by the vendor | MEDIUM |
| RouterOS version | `/system package update print` and `/system resource print` | version outside the long-term release approved by operations, or older than the fix of a known vulnerability | HIGH |

## 2. Auxiliary services nobody remembers to disable

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| mac-server open | `/tool mac-server print` | `allowed-interface-list=all`. The official recommendation is `none` | HIGH |
| mac-winbox open | `/tool mac-server mac-winbox print` | `allowed-interface-list=all` | HIGH |
| mac-ping | `/tool mac-server ping print` | `enabled=yes` in production | LOW |
| Bandwidth server | `/tool bandwidth-server print` | `enabled=yes`, worse with `authenticate=no` | MEDIUM |
| Open DNS cache | `/ip dns print` | `allow-remote-requests=yes` without a udp/53 filter at the edge: open resolver, DDoS amplifier | CRITICAL |
| DoH without certificate validation | `/ip dns print` | `use-doh-server` configured with `verify-doh-cert=no` | HIGH |
| Proxy enabled | `/ip proxy print` | `enabled=yes` without need | MEDIUM |
| Proxy listening on everything | `/ip proxy print detail` | `src-address=::`/`0.0.0.0` (the default) without the port filtered on the WAN: **open proxy**, relay for spam and third-party abuse | CRITICAL |
| Proxy cache without ceiling | `/ip proxy print detail` | `max-cache-size=unlimited` with cache in RAM: memory exhaustion and reboot — denial of service by configuration | HIGH |
| Proof of open proxy | `/ip proxy connections print` | active connection with a public/external `src-address` | CRITICAL |
| Disabled proxy rule | `/ip proxy access print` | blocking rule with `disabled=yes`, or `hits=0` for a long time — a control the operator believes active and is not. **End of list: what does not match is ALLOWED** | HIGH |
| Port-80 redirect without source | `/ip firewall nat print detail where action=redirect` | redirect to the proxy without `in-interface-list`/`src-address` of the LAN: turns the proxy open by an indirect route | HIGH |
| SOCKS | `/ip socks print` | `enabled=yes` without need — classic botnet relay vector | HIGH |
| UPnP | `/ip upnp print` | `enabled=yes` — a client opens ports in the NAT on its own | HIGH |
| UPnP taking down the WAN | `/ip upnp print` and `/ip upnp interfaces print` | `allow-disable-external-interface=yes`: **any LAN host can disable the external interface** | CRITICAL |
| Cloud / DDNS | `/ip cloud print` | `ddns-enabled=yes` or `update-time=yes` without need: publishes the device's public IP | MEDIUM |
| RoMON | `/tool romon print` and `/tool romon port print` | `enabled=yes` without `secrets`, or RoMON port active on an untrusted interface | HIGH |
| SNMP | `/snmp print` and `/snmp community print detail` | detailed in `routeros-audit-automation` | HIGH |
| Remote log and NTP | `/system logging action print` and `/system ntp client print` | detailed in `routeros-audit-automation` | HIGH |

## 3. Firewall — chain policy

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Input chain without final drop | `/ip firewall filter print detail where chain=input` | no `action=drop` at the end of input, or one after a broad `accept` | CRITICAL |
| Management allow missing | `/ip firewall filter print detail` | final drop without a prior `accept` for the management address-list — locking yourself out | HIGH |
| Established/related at the top | `/ip firewall filter print detail where chain=input` | no `accept connection-state=established,related,untracked` at the beginning | MEDIUM |
| Invalid not dropped | `/ip firewall filter print detail` | missing `drop connection-state=invalid` in input and forward. **Real exception:** multihomed device with asymmetric routing — see `routeros-audit-routing` §13 | HIGH |
| Permissive forward chain | `/ip firewall filter print detail where chain=forward` | no drop of `in-interface-list=WAN connection-state=new connection-nat-state=!dstnat` | CRITICAL |
| Inbound traffic without destination NAT | `/ip firewall filter print detail` | WAN drop written without `connection-nat-state=!dstnat`: also kills legitimate port forwarding, or (inverted) lets through what was not forwarded | HIGH |
| Bogons not filtered | `/ip firewall raw print detail` and `/ip firewall address-list print` | no address-list equivalent to `bad_ipv4`/`not_global_ipv4` applied on WAN ingress | HIGH |
| Invalid source/destination | `/ip firewall raw print detail` | no drop of `bad_src_ipv4` (multicast as source, `255.255.255.255`) and `bad_dst_ipv4` | MEDIUM |
| Invalid source address on the LAN | `/ip firewall raw print detail` | no drop of sources outside the LAN range on the inside interface (anti-spoof) | MEDIUM |
| Invalid TCP flag combinations | `/ip firewall raw print detail` | no chain handling `fin,syn`, `fin,rst`, `fin,!ack`, `fin,urg`, `syn,rst`, `rst,urg` and `!fin,!syn,!rst,!ack` | MEDIUM |
| Zone interface lists | `/interface list print` and `/interface list member print detail` | rules written per loose interface instead of a list: a new interface is born unprotected | MEDIUM |
| Counters | `/ip firewall filter print stats` | protection rule with `packets=0` on an edge device — either it never matches or it is in the wrong order | MEDIUM |
| Disabled rule | `/ip firewall filter print detail where disabled=yes` | existing protection with `disabled=yes` — worse than absent, because it looks covered | HIGH |
| Fasttrack without exception | `/ip firewall filter print detail where action=fasttrack-connection` | fasttrack before a rule that needs to see the packet (QoS marking, accounting, IPsec): the connection skips everything that comes after | MEDIUM |
| Permissive NAT | `/ip firewall nat print detail` | `dst-nat`/`netmap` inward without source restriction | HIGH |
| Masquerade without interface | `/ip firewall nat print detail where action=masquerade` | no `out-interface-list=WAN`: masks traffic between internal networks and breaks traceability | HIGH |
| Masquerade eating IPsec | `/ip firewall nat print detail where chain=srcnat` | missing `ipsec-policy=out,none` (or an `accept` before) for the tunnel's pair of networks: traffic leaves masqueraded and the policy does not apply | CRITICAL |
| Undocumented redirect | `/ip firewall nat print detail where action=redirect` | DNS/HTTP redirect nobody declared, or one that also catches the management network and the VPN | HIGH |
| Helper/ALG enabled without use | `/ip firewall service-port print detail` | `sip`, `ftp`, `pptp`, `h323`, `tftp` enabled without need: each helper opens dynamic ports from the inside | MEDIUM |
| Address-list by FQDN | `/ip firewall address-list print detail` | entry with a domain name in an `accept` rule: whoever controls DNS chooses who gets in | HIGH |
| Allowlist too broad | `/ip firewall address-list print detail` | management list with a large prefix (`/16`, `0.0.0.0/0`) or a third party's IP | HIGH |
| Mangle mark capturing management | `/ip firewall mangle print detail stats` + `/routing rule print detail` (v7) / `/ip route rule print detail` (v6) | routing mark or VRF catching management or VPN traffic: silent blackhole | HIGH |
| Mark shared between QoS and PBR | `/ip firewall mangle print detail` | same `connection-mark`/`packet-mark` serving a queue **and** a route policy: touching one changes the other | HIGH |
| Drop log without limit | `/ip firewall filter print detail stats where log=yes` and `/ip firewall raw print detail where log=yes` | drop rule with `log=yes` and no `limit`: under attack the log itself saturates CPU, disk and syslog — a DoS the device applies to itself | HIGH |
| Critical drop without evidence | same commands | no relevant drop with `log=yes`: no trace of intrusion attempts | MEDIUM |

## 4. RAW table and flood defence

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| RAW unused | `/ip firewall raw print detail stats` | empty table on an edge device: all junk enters connection tracking before being discarded | MEDIUM |
| SYN flood | `/ip firewall filter print detail` and `/ip firewall raw print detail` | no `limit` for `tcp-flags=syn connection-state=new`, nor an equivalent drop in RAW | HIGH |
| TCP SynCookies | `/ip settings print` | `tcp-syncookies=no` (default). Containment during an attack; enabling it alone does not replace rate limiting | MEDIUM |
| Rate-based DDoS detection | `/ip firewall filter print detail` and `/ip firewall address-list print` | no detection chain with `dst-limit=...,src-and-dst-addresses/10s` feeding attacker and target address-lists, and no matching drop in RAW | MEDIUM |
| udp/53 from the WAN | `/ip firewall raw print detail` | missing drop of `dst-port=53 protocol=udp dst-address-type=local` from the external interface list | CRITICAL |
| Internal DNS rate limit | `/ip firewall raw print detail` | udp/53 from the LAN without `limit` — an infected client becomes an amplifier from inside | MEDIUM |
| Amplification via udp/123 and udp/1900 | `/ip firewall filter print detail` and `/system ntp server print` | NTP server or SSDP reachable from the WAN | HIGH |
| Smurf / broadcast | `/ip firewall filter print detail` | missing drop of ICMP to `dst-address-type=broadcast` | MEDIUM |
| Port scan (PSD) | `/ip firewall raw print detail` or `/ip firewall filter print detail` | no `psd` feeding an address-list, and no drop of the list | MEDIUM |
| Staged brute force | `/ip firewall filter print detail` and `/ip firewall address-list print` | no progressive stages feeding a blacklist on the management ports, or a blacklist without `address-list-timeout` | HIGH |
| Blacklist without expiry | `/ip firewall address-list print detail` | dynamic entry without `timeout`: the list only grows and a false positive becomes a permanent block | MEDIUM |
| Connection tracking at the limit | `/ip firewall connection tracking print` and `/ip firewall connection print count-only` | usage close to `max-entries`: state exhaustion takes the device down before the link fills | HIGH |
| Fasttrack catching what it should not | `/ip firewall connection print proplist=src-address,dst-address,protocol,fasttrack where fasttrack=yes` | a connection with QoS marking, accounting, hotspot, PBR or IPsec showing as fasttracked — proof that the exception does not exist | HIGH |
| Fasttrack in the wrong state | `/ip firewall filter print detail where action=fasttrack-connection` | `connection-state` including `new`, `invalid` or `untracked`: the connection skips the firewall **from the start** | HIGH |
| Liberal TCP tracking | `/ip firewall connection tracking print` | `liberal-tcp-tracking=yes` — accepts out-of-sequence TCP flows as valid | MEDIUM |
| Defconf protection rule disabled | `/ip firewall filter print where chain=forward and action=drop` | the factory `drop all from WAN` marked `disabled` — the protection is on screen and does not run | CRITICAL |
| Loose TCP tracking | `/ip firewall connection tracking print` | `loose-tcp-tracking=yes` (default) on an edge device with a symmetric path — accepts half a handshake as established | LOW |

## 5. ICMP by type

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| ICMP without its own chain | `/ip firewall filter print detail where protocol=icmp` | ICMP allowed as a block (`accept protocol=icmp`) instead of a chain with a jump per type | MEDIUM |
| Echo without rate limit | `/ip firewall filter print detail` | `8:0` and `0:0` accepted without `limit` (the official docs use `limit=5,10:packet`) | MEDIUM |
| PMTUD broken | `/ip firewall filter print detail` | `3:4` (fragmentation needed) dropped — breaks MTU discovery and connections "hang without error" | HIGH |
| Traceroute/TTL | `/ip firewall filter print detail` | `11:0` and `3:3` dropped when diagnostics are an operational requirement | LOW |
| Obsolete types accepted | `/ip firewall filter print detail` | redirect (5), timestamp (13/14), address mask (17/18) and source quench (4) accepted | MEDIUM |
| ICMP final drop | `/ip firewall filter print detail` | ICMP chain without a `drop` at the end: a new type gets in by omission | MEDIUM |

## 6. Layer 2, discovery and bridge

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

## 7. DHCP

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| No rogue DHCP alert | `/ip dhcp-server alert print` | no alert configured on the customer segment: a rogue server only shows up through complaints | MEDIUM |
| Pool near exhaustion | `/ip pool print detail` and `/ip dhcp-server lease print detail` | pool without free addresses, leases with random MACs (a /24 empties in seconds under starvation) | HIGH |
| Static lease missing where it matters | `/ip dhcp-server lease print detail` | infrastructure equipment taking a dynamic IP | LOW |
| `add-arp` without restricted ARP | `/ip dhcp-server print detail` and `/interface ethernet print detail` | `add-arp=yes` without `arp=reply-only` on the interface: the protection exists halfway and is worth nothing | MEDIUM |
| Lease script with broad permission | `/ip dhcp-server print detail` (`lease-script`) | script fired on every lease with more permission than needed | HIGH |
| DHCP client trusting the segment | `/ip dhcp-client print proplist=interface,status,use-peer-dns,add-default-route,dhcp-server,primary-dns` | `use-peer-dns=yes` or `add-default-route=yes` on an interface that is not the approved WAN: whoever answers first becomes the device's DNS and gateway | HIGH |

## 8. IPv6 (summary — full list in `routeros-audit-ipv6`)

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| IPv6 active without use | `/ipv6 settings print` and `/ipv6 address print` | stack enabled (v7 default) on a network that neither uses nor manages IPv6 | HIGH |
| IPv6 without firewall | `/ipv6 firewall filter print detail stats` | interface with an IPv6 address and no policy equivalent to IPv4. **Without NAT in the path, every internal host is exposed directly** | CRITICAL |
| ICMPv6 blocked as a block | `/ipv6 firewall filter print detail where protocol=icmpv6` | generic ICMPv6 drop: kills Neighbor Discovery, DAD and PMTUD — the whole IPv6 network stops | CRITICAL |
| ND without `hop-limit` | `/ipv6 firewall filter print detail` | accept of 133-136 without `hop-limit=equal:255`: accepts a "neighbor" that came from far away | HIGH |
| External RA accepted | `/ipv6 settings print` and `/ipv6 nd print detail` | `accept-router-advertisements` active on the external interface of an edge router with a static address | MEDIUM |
| RA/ND advertised to the wrong client | `/ipv6 nd print detail` | `advertise-dns`/`advertise-mac-address` and prefix leaving through an interface that should not | HIGH |
| IPv6 bogons not filtered | `/ipv6 firewall raw print detail` and `/ipv6 firewall address-list print` | no list equivalent to `bad_ipv6`/`not_global_ipv6` | HIGH |
| DNS closed on v4 and open on v6 | `/ip dns print` + `/ipv6 firewall filter print detail where dst-port=53` | udp/tcp 53 blocked in the IPv4 firewall and **forgotten in IPv6**: the open resolver stays up on the other protocol | CRITICAL |
| Advertisement on the wrong interface | `/ipv6 address print proplist=address,interface,advertise,no-dad,dynamic,from-pool` | WAN address with `advertise=yes`, or a prefix other than `/64` serving SLAAC (does not work and nobody notices) | HIGH |
| Inflated IPv6 neighbor table | `/ipv6 neighbor print detail` | abnormal volume or oscillating entries: ND exhaustion — the /64 has plenty of room to scan | MEDIUM |
| Automatic tunnel active | `/interface 6to4 print detail` | 6to4/relay tunnel enabled without use — an entry path nobody monitors | HIGH |
| v6-in-v4 encapsulation allowed | `/ip firewall filter print detail where protocol=ipv6-encap` and `/ip firewall filter print detail where protocol=udp and dst-port=3544` | protocol 41 or Teredo passing without a requirement: IPv6 enters inside IPv4 and escapes the v6 policy | HIGH |
| Managed IPv6 tunnel without cipher | `/interface gre6 print detail`, `/interface ipipv6 print detail`, `/interface eoipv6 print detail` | unknown endpoint, or sensitive traffic without IPsec/WireGuard underneath | HIGH |

## 9. IP stack (only visible in print, not in export)

Compare against `routeros-factory-defaults` — most "wrong" values here are factory defaults.

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Reverse path filter | `/ip settings print` | `rp-filter=no` (default) on a device with a symmetric path. **On multihomed, `strict` kills legitimate traffic** — recommend `loose` | MEDIUM |
| Redirect acceptance | `/ip settings print` | `accept-redirects=yes` — **deviation from default**, somebody turned it on | HIGH |
| Source route | `/ip settings print` | `accept-source-route=yes` — deviation from default | HIGH |
| Redirect sending | `/ip settings print` | `send-redirects=yes` is default **and vendor-recommended**: only a finding on a customer segment where the redirect leaks topology | LOW |
| Forwarding on an L2 device | `/ip settings print` | `ip-forward=yes` on a device that only switches / serves as AP | MEDIUM |
| ARP neighbor limit | `/ip settings print` and `/ip arp print count-only` | ARP table near `max-neighbor-entries` | LOW |
| Kernel ICMP rate limit | `/ip settings print` | `icmp-rate-limit` raised to a high value while the firewall does not limit either | LOW |

## 10. Cryptography, certificates and tunnels

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| PPTP enabled | `/interface pptp-server server print` | `enabled=yes` — MS-CHAPv2 broken for years, no fix possible | CRITICAL |
| L2TP without IPsec | `/interface l2tp-server server print` | `use-ipsec=no`, or `use-ipsec=yes` with an empty `ipsec-secret` | CRITICAL |
| Cleartext PPP authentication | `/interface <type>-server server print` and `/ppp aaa print` | `authentication` accepting `pap`, or `mschap1` without need | HIGH |
| PPP session without cipher | `/ppp active print` | **empty** encoding column — the session came up unencrypted, even with the profile asking for it | HIGH |
| PPP profile not requiring cipher | `/ppp profile print detail` | `use-encryption=no` or `default` on a profile that crosses an untrusted network | HIGH |
| Multiple sessions per subscriber | `/interface pppoe-server server print detail` | `one-session-per-host=no`: one credential opens N sessions, drains the pool and the CPU | HIGH |
| Concentrator accepting empty service | same command | `accept-empty-service=yes` — a client that does not state the service name gets in | MEDIUM |
| Concentrator with an IP on the access interface | `/ip address print` crossed with `/interface pppoe-server server print` | the interface where PPPoE listens **must not have an IP address** | MEDIUM |
| PPPoE client without a fixed AC | `/interface pppoe-client print detail` | `ac-name` and `service-name` empty: connects to **the first concentrator that answers** — open door for a rogue concentrator | HIGH |
| Route and DNS dictated by the link | `/interface pppoe-client print detail` | `use-peer-dns=yes` and `add-default-route=yes` on an unapproved link | MEDIUM |
| Remote access created by the wizard | `/interface l2tp-server server print` + `/ppp secret print proplist=name,profile,service` + `/ip cloud print` | VPN raised by Quick Set: generic user, and the wizard itself leaves **`Firewall Router` unchecked** | CRITICAL |
| Home tunnel with the admin credential | `/ip cloud print`, `/interface wireguard peers print detail`, `/user print proplist=name,group` | Back To Home active: the app asks for **the administrative credential** to build the tunnel, and offers file access in full mode. Unknown peer in the list = remote access nobody registered | HIGH |
| Weak tunnel secret | `/ip ipsec identity print detail` and `/ppp secret print detail` | short, generic or sample-from-training `secret`/`password` | CRITICAL |
| Weak SSTP | `/interface sstp-server server print detail` | `certificate=none`, `force-aes=no`, or `tls-version=any` (accepts TLS 1.0) | HIGH |
| Weak OVPN | `/interface ovpn-server server print detail` | `auth=none`/`md5`/`sha1`, `cipher=null`/`blowfish128`, or `require-client-certificate=no` | HIGH |
| IPsec with weak algorithm | `/ip ipsec proposal print detail` and `/ip ipsec profile print detail` | `auth-algorithms=md5`/`sha1`, `enc-algorithms=des`/`3des`, `dh-group` below `modp2048` | HIGH |
| IKEv1 aggressive with PSK | `/ip ipsec profile print detail` and `/ip ipsec identity print detail` | `exchange-mode=aggressive` with `auth-method=pre-shared-key`: the hash goes over the air for offline cracking | CRITICAL |
| IPsec without PFS | `/ip ipsec profile print detail` | `pfs-group=none`: a compromised key opens all past traffic | MEDIUM |
| WireGuard with a broad peer | `/interface wireguard print detail` and `/interface wireguard peers print detail` | `allowed-address=0.0.0.0/0` outside a full-tunnel scenario; `listen-port` exposed without an input filter | HIGH |
| WireGuard without preshared-key | `/interface wireguard peers print detail` | peer without `preshared-key` where margin against future cryptanalysis is required | LOW |
| VXLAN without cipher | `/interface vxlan print detail`, `/interface vxlan vteps print` and `/interface vxlan fdb print` | VXLAN crossing the Internet without IPsec/WireGuard underneath (customer L2 in cleartext), VTEP/VNI outside the inventory, or udp/4789 reachable from any source | HIGH |
| ZeroTier | `/zerotier print`, `/zerotier interface print` and `/zerotier peer print` | network ID nobody recognises, `allow-default=yes` (the device's default route starts leaving through the overlay), `allow-global=yes`, or interface bridged with the LAN without segmentation | CRITICAL |
| EoIP without protection | `/interface eoip print detail` | EoIP over the Internet without `ipsec-secret`: an L2 bridge open to whoever forges the endpoint | HIGH |
| Badly built port knocking | `/ip firewall filter print detail` and `/ip firewall address-list print` | knock sequence without `address-list-timeout`, or the final port drop missing — the knock protects nothing | MEDIUM |
| Certificate | `/certificate print detail` | detailed in `routeros-audit-automation` | HIGH |

## 11. QoS with a security effect

A badly built queue is not just slowness: it is the path by which the device becomes
unreachable during an attack or a peak, and by which one customer eats everybody else's bandwidth.

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Management without priority | `/queue tree print detail stats` and `/ip firewall mangle print detail` | management and routing traffic without a priority queue: a full link takes access down with it | HIGH |
| Guarantee above capacity | `/queue tree print proplist=name,parent,limit-at,max-limit,priority` | sum of the children's `limit-at` greater than the parent's `max-limit`: the guarantee is a lie and distribution becomes luck | HIGH |
| PCQ classifying backwards | `/queue type print proplist=name,kind,pcq-classifier,pcq-rate,pcq-limit,pcq-total-limit` | upload without `src-address` or download without `dst-address`: the whole network is treated as one client | MEDIUM |
| Queue that never matches | `/queue tree print detail stats` and `/queue simple print detail stats` | `bytes=0` on a production queue — wrong parent, wrong packet-mark, or fasttrack passing in front | MEDIUM |
| Dynamic queues without ceiling | `/queue simple print count-only` | thousands of dynamic simple queues on small hardware: CPU pegged and the device stops answering | MEDIUM |
| Bufferbloat | `/queue type print detail` and `/queue interface print stats` | `pfifo`/`bfifo` with a high `limit`: latency climbs under load and management goes with it | MEDIUM |

## 12. Bulk collection

Read-only sequence to gather the baseline before judging any item:

```
/system identity print
/system resource print
/system package print
/system default-configuration print
/system routerboard print
/system routerboard settings print
/system device-mode print
/user print proplist=name,group,address,disabled,last-logged-in
/user group print detail
/user aaa print
/user ssh-keys print detail
/ip service print detail
/ip ssh print
/ip settings print
/ipv6 settings print
/ip neighbor discovery-settings print
/tool mac-server print
/tool mac-server mac-winbox print
/ip firewall filter print detail stats
/ip firewall raw print detail stats
/ip firewall nat print detail
/ip firewall connection tracking print
/ip firewall service-port print detail
/ipv6 firewall filter print detail stats
/interface list member print detail
/interface bridge print detail
/interface bridge port print detail
/system script print detail
/system scheduler print detail
/file print detail
```

`/export verbose hide-sensitive` complements, **does not replace**: what only appears in `print`
is listed in section 9 and in the factory-defaults reference.
