# DHCP checks

Severity scale: CRITICAL / HIGH / MEDIUM / LOW. Every command is read-only. Method and output format: `routeros-audit-method`.

## 1. DHCP

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| No rogue DHCP alert | `/ip dhcp-server alert print` | no alert configured on the customer segment: a rogue server only shows up through complaints | MEDIUM |
| Pool near exhaustion | `/ip pool print detail` and `/ip dhcp-server lease print detail` | pool without free addresses, leases with random MACs (a /24 empties in seconds under starvation) | HIGH |
| Static lease missing where it matters | `/ip dhcp-server lease print detail` | infrastructure equipment taking a dynamic IP | LOW |
| `add-arp` without restricted ARP | `/ip dhcp-server print detail` and `/interface ethernet print detail` | `add-arp=yes` without `arp=reply-only` on the interface: the protection exists halfway and is worth nothing | MEDIUM |
| Lease script present | `/ip dhcp-server print count-only where lease-script!=""` | count above zero means a lease script exists. The agent must never retrieve its body; review ownership/intent from sanitized local metadata if needed | HIGH |
| DHCP client trusting the segment | `/ip dhcp-client print proplist=interface,status,use-peer-dns,add-default-route,dhcp-server,primary-dns` | `use-peer-dns=yes` or `add-default-route=yes` on an interface that is not the approved WAN: whoever answers first becomes the device's DNS and gateway | HIGH |
