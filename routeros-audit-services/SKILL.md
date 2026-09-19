---
name: routeros-audit-services
description: "Read-only audit of auxiliary services on MikroTik RouterOS that nobody remembers to disable: mac-server and MAC-Winbox, mac-ping, bandwidth server, DNS cache as open resolver, DoH without certificate check, web proxy (open proxy, unbounded cache, dead access rules, port-80 redirect), SOCKS, UPnP, cloud/DDNS, RoMON. This skill should be used when assessing the service surface of a RouterOS device beyond the administrative ones, without changing configuration."
---

# RouterOS security audit — auxiliary services

Services that ship enabled or get enabled once "for a test" and stay. The vendor's own hardening list says `none`/`no` for most of them (see `routeros-factory-defaults`).

## Rules

Read-only: `print`, `get`, `export`, `monitor` only — never `set`, `add`, `remove`, `enable`, `disable`, `reboot`. Connect with a dedicated least-privilege audit account; do not assume the built-in `read` group is strictly read-only. Audit only the devices that were named. Secrets never enter the report (use `proplist` on areas that store credentials). Method, severity scale (CRITICAL / HIGH / MEDIUM / LOW — in doubt, the lower), output format and the collection order live in `routeros-audit-method`; factory values in `routeros-factory-defaults`. Read the RouterOS version first: v6 and v7 menus differ, and a command in the wrong menu returns empty.

## Checks

[references/checks.md](references/checks.md)

## Traps

- **`allow-remote-requests=yes` without a udp/53 filter at the edge is an open resolver** — a DDoS amplifier, CRITICAL.
- **Proxy `src-address` defaults to everything**; without a WAN filter on its port it is an open proxy. `/ip proxy connections print` with a public source proves it.
- **UPnP `allow-disable-external-interface=yes`** lets any LAN host drop the WAN.
- The official recommendation for mac-server and MNDP is `none`, not a management list — using MAC-Winbox as rescue is an accepted risk that has to be written down.
