# RouterOS factory defaults

Values checked against the official documentation. Read BEFORE opening a finding.

## `/ip settings`

| Property | Default | Reading of the official docs |
|---|---|---|
| `ip-forward` | `yes` | forwarding between interfaces |
| `send-redirects` | `yes` | **MikroTik recommends KEEPING it on in a router** |
| `accept-redirects` | `no` | only makes sense on a host, not on a router |
| `secure-redirects` | `yes` | accepts redirects only from gateways in the default list |
| `accept-source-route` | `no` | SRR |
| `rp-filter` | `no` | `no` / `strict` / `loose` |
| `tcp-syncookies` | `no` | SYN flood containment |
| `allow-fast-path` | `yes` | |
| `route-cache` | `yes` | present up to 7.12; gone from 7.18 on (measured) |
| `arp-timeout` | `30s` | base of the reachable time |
| `icmp-rate-limit` | `10` | send ceiling for the types in `icmp-rate-mask` |
| `icmp-rate-mask` | `0x1818` | mask of rate-limited types |
| `max-neighbor-entries` | RAM-dependent | ARP table ceiling |

Source: <https://help.mikrotik.com/docs/spaces/ROS/pages/103841817/IP+Settings>

**Direct consequence for the audit:**
- `accept-redirects=yes` and `accept-source-route=yes` are **deviations from default** — somebody enabled them. Finding.
- `send-redirects=yes` and `secure-redirects=yes` are default **and vendor recommendation**.
  Flagging this alone is a false positive. It becomes a finding only with context (a customer
  segment where the redirect leaks topology), and then the severity is LOW.
- `rp-filter=no` and `tcp-syncookies=no` are default: the finding is "protection was not
  enabled", not "someone disabled it". The recommendation text changes.

## `/ipv6 settings`

| Property | Default |
|---|---|
| `disable-ipv6` | `no` — **the stack ships enabled on v7** |
| `forward` | `yes` |
| `accept-redirects` | `yes-if-forwarding-disabled` |
| `accept-router-advertisements` | `yes-if-forwarding-disabled` |
| `accept-router-advertisements-on` | `all` |
| `max-neighbor-entries` | RAM-dependent |
| `stale-neighbor-timeout` | `60` |
| `multipath-hash-policy` | `l3` |
| `disabled-link-local-address` | `no` |

`accept-router-advertisements` only accepts RA when forwarding is off — on a router with
`forward=yes` the default already protects. Flagging `accept-router-advertisements` without
reading `forward` alongside is a reading error.

## `/ip firewall connection tracking`

| Property | Default |
|---|---|
| `enabled` | `auto` |
| `loose-tcp-tracking` | `yes` |
| `tcp-syn-sent-timeout` | `5s` |
| `tcp-syn-received-timeout` | `5s` |
| `tcp-established-timeout` | `1d` |
| `tcp-close-wait-timeout` | `10s` |
| `tcp-fin-wait-timeout` | `10s` |
| `tcp-last-ack-timeout` | `10s` |
| `tcp-time-wait-timeout` | `10s` |
| `tcp-close-timeout` | `10s` |
| `udp-timeout` | `30s` |
| `udp-stream-timeout` | `3m` |
| `icmp-timeout` | `10s` |
| `generic-timeout` | `10m` |

Source: <https://help.mikrotik.com/docs/spaces/ROS/pages/130220087/Connection+tracking>

`loose-tcp-tracking=yes` (default) treats SYN,ACK and ACK without the initial SYN as
`established`. Turning it off makes that packet `invalid` — hardens, but **breaks asymmetric
routing**.

## `/system device-mode` (v7.17+)

Factory mode: `advanced` on CCR and the 1100 line, `home` on home routers, `basic` on the rest.
Before 7.17 every device behaved as `advanced`.

Features the mode restricts: `scheduler`, `socks`, `fetch`, `pptp`, `l2tp`, `bandwidth-test`,
`traffic-gen`, `sniffer`, `ipsec`, `romon`, `proxy`, `hotspot`, `smb`, `email`, `zerotier`,
`container`, `install-any-version`, `partitions`, `routerboard`.

`traffic-gen`, `install-any-version`, `partitions` and `routerboard` ship **disabled in every
mode**, including `advanced` — each has to be enabled one by one.

A change requires physical confirmation (reset/mode button or power cycle) inside the configured
window — default 5 min, adjustable from `00:00:10` to `1d`. Three unconfirmed attempts lock
further changes until a power cycle. **There is no way to apply it remotely.**

Source: <https://help.mikrotik.com/docs/spaces/ROS/pages/93749258/Device-mode>

## Default firewall (`defconf`) on v7

What the factory configuration already provides, per chain:

**IPv4 input:** accept `established,related,untracked`; drop `invalid`; accept ICMP;
accept from loopback (`dst-address=127.0.0.1`); drop everything not from the `LAN` list.

**IPv4 forward:** `fasttrack-connection` for `established,related`; accept
`established,related,untracked`; drop `invalid`; drop `connection-state=new` from
`in-interface-list=WAN` with `connection-nat-state=!dstnat`.

**IPv6 input:** accept `established,related,untracked`; drop `invalid`; accept `icmpv6`;
accept UDP traceroute `33434-33534`; accept DHCPv6-PD on `dst-port=546` from `fe80::/10`;
accept IKE `500,4500`; accept `ipsec-ah` and `ipsec-esp`; accept `ipsec-policy=in,ipsec`;
drop everything not from `LAN`.

**IPv6 forward:** `fasttrack6`; accept `established,related,untracked`; drop `invalid`;
drop source and destination in address-list `bad_ipv6`; drop `hop-limit=equal:1` for `icmpv6`
(RFC 4890); accept `icmpv6`; accept HIP (protocol 139); accept IKE, `ipsec-ah`, `ipsec-esp`,
`ipsec-policy=in,ipsec`; drop everything not from `LAN`.

**Address-list `bad_ipv6` of the defconf:** `::/128`, `::1/128`, `fec0::/10`,
`::ffff:0.0.0.0/96`, `::/96`, `100::/64`, `2001:db8::/32`, `2001:10::/28`, `3ffe::/16`.

A device that **lost** these rules (reset with `no-defaults=yes`, or somebody cleared them) has
nothing. A device that only has the defconf is protected against the basics, but has **no** RAW,
anti-spoof, ICMP rate limit or blacklist.

## Advanced firewall lists from the official docs

Not shipped from factory — they are the target on an edge device.

| List | Content |
|---|---|
| `bad_ipv4` | `127.0.0.0/8`, `192.0.0.0/24`, `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `240.0.0.0/4` |
| `not_global_ipv4` | `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `169.254.0.0/16`, `172.16.0.0/12`, `192.168.0.0/16`, `198.18.0.0/15`, `255.255.255.255/32` |
| `bad_src_ipv4` | `224.0.0.0/4`, `255.255.255.255/32` |
| `bad_dst_ipv4` | `0.0.0.0/8`, `224.0.0.0/4` |
| `bad_ipv6` | `::1/128`, `::ffff:0:0/96`, `2001::/23`, `2001:db8::/32`, `2001:10::/28`, `::/96` |
| `not_global_ipv6` | `100::/64`, `2001::/32`, `2001:2::/48`, `fc00::/7` |
| `bad_src_ipv6` | `::/128`, `ff00::/8` |
| `bad_dst_ipv6` | `::/128` |

Recommended ICMP rate limit: `limit=5,10:packet` for echo request/reply.
ND with `hop-limit=equal:255` — a discovery packet that came from far away is not a neighbor.

Source: <https://help.mikrotik.com/docs/spaces/ROS/pages/328513/Building+Advanced+Firewall>

## Services the vendor tells you to disable

`/tool mac-server set allowed-interface-list=none`,
`/tool mac-server mac-winbox set allowed-interface-list=none`,
`/tool mac-server ping set enabled=no`,
`/ip neighbor discovery-settings set discover-interface-list=none`,
`/tool bandwidth-server set enabled=no`,
`/ip dns set allow-remote-requests=no`,
`/ip proxy set enabled=no`, `/ip socks set enabled=no`, `/ip upnp set enabled=no`,
`/ip cloud set ddns-enabled=no update-time=no`,
`/ip ssh set strong-crypto=yes`, and disable every unused interface.

The official recommendation is `none`, not "management list" — whoever uses MAC-Winbox as a
rescue path accepts risk by choice, and that has to be written down, not assumed.

Source: <https://help.mikrotik.com/docs/spaces/ROS/pages/328353/Securing+your+router>
