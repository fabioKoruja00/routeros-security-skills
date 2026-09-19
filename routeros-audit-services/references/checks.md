# Auxiliary services checks

Severity scale: CRITICAL / HIGH / MEDIUM / LOW. Every command is read-only. Method and output format: `routeros-audit-method`.

## 1. Auxiliary services

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
| SNMP | `/snmp print` and `/snmp community print detail` | detailed in `routeros-audit-logging` | HIGH |
| Remote log and NTP | `/system logging action print` and `/system ntp client print` | detailed in `routeros-audit-logging` | HIGH |
