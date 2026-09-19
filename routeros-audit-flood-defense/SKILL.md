---
name: routeros-audit-flood-defense
description: "Read-only audit of flood, DDoS and scan defence on MikroTik RouterOS: the RAW table, SYN flood and syncookies, rate-based DDoS detection, udp/53 and NTP/SSDP amplification, smurf, port-scan detection, staged brute-force blacklists and their expiry, connection-tracking exhaustion, fasttrack in the wrong state, liberal/loose TCP tracking, and ICMP handled by type (echo rate limit, PMTUD, traceroute, obsolete types, final drop). This skill should be used when assessing how a RouterOS device behaves under attack, without changing configuration."
---

# RouterOS security audit — flood defence and ICMP

What keeps the device up when the link is full of junk: RAW before conntrack, rate limits, staged blacklists, and ICMP filtered by type instead of as a block.

## Rules

Read-only: `print`, `get`, `export`, `monitor` only — never `set`, `add`, `remove`, `enable`, `disable`, `reboot`. Connect with a dedicated least-privilege audit account; do not assume the built-in `read` group is strictly read-only. Audit only the devices that were named. Secrets never enter the report (use `proplist` on areas that store credentials). Method, severity scale (CRITICAL / HIGH / MEDIUM / LOW — in doubt, the lower), output format and the collection order live in `routeros-audit-method`; factory values in `routeros-factory-defaults`. Read the RouterOS version first: v6 and v7 menus differ, and a command in the wrong menu returns empty.

## Checks

[references/checks.md](references/checks.md)

## Traps

- **The automatic blacklist catches whoever monitors.** The brute-force ladder lists the administrator who mistypes the password, and `psd` catches the inventory tool and the NMS. Check the management network is exempted **above** those rules before recommending.
- **A per-source connection limit takes a whole office behind one public IP down.** Count the users behind that address before suggesting the value.
- **Dropping `3:4` (fragmentation needed) breaks PMTUD** — connections hang without an error.
- **Enabling `tcp-syncookies` alone does not replace rate limiting.**
