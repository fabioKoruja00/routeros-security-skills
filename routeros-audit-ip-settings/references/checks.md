# IP stack settings checks

Severity scale: CRITICAL / HIGH / MEDIUM / LOW. Every command is read-only. Method and output format: `routeros-audit-method`.

## 1. IP stack (only visible in print, not in export)

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
