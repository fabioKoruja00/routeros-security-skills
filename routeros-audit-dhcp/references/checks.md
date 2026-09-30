# DHCP checks

Severity scale: CRITICAL / HIGH / MEDIUM / LOW. Every command is read-only. Method and output format: `routeros-audit-method`.

## 1. DHCP

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| No rogue DHCP alert | `/ip dhcp-server alert print` | no alert configured on the customer segment: a rogue server only shows up through complaints. Lower still where DHCP snooping or L2 isolation already covers the segment | LOW |
| Pool near exhaustion | `/ip pool used print count-only` per pool, compared with the pool size in `/ip pool print` | pool without free addresses. Never `lease print detail` on a server with thousands of leases. Random MACs alone are normal on modern clients and do not prove starvation | HIGH |
| Static lease missing where it matters | `/ip dhcp-server lease print count-only where dynamic=yes` plus the infrastructure inventory | infrastructure equipment taking a dynamic IP. Needs the inventory to be judged | LOW |
| `add-arp` without restricted ARP | `/ip dhcp-server print proplist=name,interface,address-pool,lease-time,add-arp,authoritative,use-radius,disabled` and the `arp` setting of that server's interface (`/interface bridge`, `/interface vlan` or `/interface ethernet`) | `add-arp=yes` without `arp=reply-only` on the interface the server listens on: the protection exists halfway and is worth nothing | MEDIUM |
| Lease script present | `/ip dhcp-server print count-only where lease-script!=""` | count above zero means a lease script exists. The agent must never retrieve its body; review ownership/intent from sanitized local metadata if needed | LOW |
| DHCP client trusting the segment | `/ip dhcp-client print proplist=interface,status,disabled,use-peer-dns,add-default-route,dhcp-server,primary-dns` | only enabled clients with `status=bound`: `add-default-route=yes` on an interface that is not the approved WAN makes whoever answers first the device's gateway (HIGH); `use-peer-dns=yes` there makes it the resolver (MEDIUM) | HIGH |
