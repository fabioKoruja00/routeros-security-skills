# Flood defence and ICMP checks

Severity scale: CRITICAL / HIGH / MEDIUM / LOW. Every command is read-only. Method and output format: `routeros-audit-method`.

## 1. RAW table and flood defence

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

## 2. ICMP by type

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| ICMP without its own chain | `/ip firewall filter print detail where protocol=icmp` | ICMP allowed as a block (`accept protocol=icmp`) instead of a chain with a jump per type | MEDIUM |
| Echo without rate limit | `/ip firewall filter print detail` | `8:0` and `0:0` accepted without `limit` (the official docs use `limit=5,10:packet`) | MEDIUM |
| PMTUD broken | `/ip firewall filter print detail` | `3:4` (fragmentation needed) dropped — breaks MTU discovery and connections "hang without error" | HIGH |
| Traceroute/TTL | `/ip firewall filter print detail` | `11:0` and `3:3` dropped when diagnostics are an operational requirement | LOW |
| Obsolete types accepted | `/ip firewall filter print detail` | redirect (5), timestamp (13/14), address mask (17/18) and source quench (4) accepted | MEDIUM |
| ICMP final drop | `/ip firewall filter print detail` | ICMP chain without a `drop` at the end: a new type gets in by omission | MEDIUM |
