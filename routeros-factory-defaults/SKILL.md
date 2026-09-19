---
name: routeros-factory-defaults
description: "Factory default values of MikroTik RouterOS v7 that a security review must know before judging any setting: /ip settings, /ipv6 settings, connection tracking timeouts, device-mode restrictions, the default firewall (defconf) per chain, the bogon address-lists from the official 'Building Advanced Firewall' guide, and the services the vendor tells you to disable. This skill should be used before opening a finding on a RouterOS device, to tell 'someone turned this on' apart from 'this is how it ships' — the severity and the wording change."
---

# RouterOS factory defaults

Read this before opening any finding. A value equal to the factory default is not an insecure
choice somebody made; it is what the device shipped with. That changes the severity and the
wording of the recommendation ("nobody enabled the protection" is different from "someone
disabled it").

## How to use

1. Read the setting on the device with the `print` of its own menu (`/ip settings print`,
   `/ipv6 settings print`, `/ip firewall connection tracking print`, `/system device-mode print`).
   These values do **not** appear in `/export` — an audit done on an export alone approves a
   device with an open IP stack.
2. Compare with the tables in [references/defaults.md](references/defaults.md).
3. Classify:
   - **Deviation from default** (`accept-redirects=yes`, `accept-source-route=yes`): somebody
     turned it on. Finding.
   - **Default and vendor recommendation** (`send-redirects=yes`, `secure-redirects=yes`):
     flagging this alone is a false positive. It becomes a finding only with context (a customer
     segment where redirects leak topology), and then the severity is LOW.
   - **Default but protection not enabled** (`rp-filter=no`, `tcp-syncookies=no`): the finding
     is "the protection was never enabled", not "someone disabled it".

## What the reference covers

| Section | Content |
|---|---|
| `/ip settings` | forwarding, redirects, source routing, rp-filter, syncookies, fast path, ARP timeout, ICMP rate limit |
| `/ipv6 settings` | stack enabled by default on v7, RA acceptance tied to `forward`, neighbor limits |
| Connection tracking | `enabled=auto`, `loose-tcp-tracking`, every TCP/UDP/ICMP timeout |
| Device-mode (v7.17+) | per-model factory mode, features each mode restricts, physical confirmation rule |
| Default firewall (`defconf`) | what the factory config provides per chain, IPv4 and IPv6, and the `bad_ipv6` list |
| Advanced firewall lists | `bad_ipv4`, `not_global_ipv4`, `bad_src_ipv4`, `bad_dst_ipv4` and their IPv6 counterparts |
| Services to disable | the vendor's own hardening list (mac-server, MNDP, bandwidth-server, DNS, proxy, SOCKS, UPnP, cloud, SSH crypto) |

## Traps

- `accept-router-advertisements` only accepts RA when forwarding is off (`yes-if-forwarding-disabled`).
  On a router with `forward=yes` the default already protects. Flagging it without reading
  `forward` alongside is a reading error.
- `loose-tcp-tracking=yes` (default) treats SYN,ACK and ACK without the initial SYN as
  `established`. Turning it off hardens, but **breaks asymmetric routing**.
- Devices that lost the defconf rules (reset with `no-defaults=yes`, or someone wiped them) have
  nothing. Devices that only have the defconf are protected against the basics but have **no**
  RAW, anti-spoof, ICMP rate limit or blacklist.
- CCR, IP-only, CAP and switch product lines do **not** receive the default firewall. "No rules"
  there is factory-normal, and the finding is a different one: nobody built the policy.
- The vendor's recommendation for `mac-server` and MNDP is `none`, not "management list". Using
  MAC-Winbox as a rescue path is an accepted risk by choice — it has to be written down as such,
  not assumed.
