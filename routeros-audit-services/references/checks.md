# Auxiliary services checks

Severity scale: CRITICAL / HIGH / MEDIUM / LOW. Every command is read-only. Method and output format: `routeros-audit-method`.

## 1. Auxiliary services

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| mac-server open | `/tool mac-server print` | `allowed-interface-list=all`. The official recommendation is `none` | HIGH |
| mac-winbox open | `/tool mac-server mac-winbox print` | `allowed-interface-list=all` | HIGH |
| mac-ping | `/tool mac-server ping print` | `enabled=yes` in production | LOW |
| Bandwidth server | `/tool bandwidth-server print` | `enabled=yes`, worse with `authenticate=no` | MEDIUM |
| Open DNS cache | `:put [/ip dns get allow-remote-requests]` + the input filter for udp/53 | `allow-remote-requests=yes` with udp/53 reachable from the WAN: open resolver, DDoS amplifier. Confirm the filter before rating it | CRITICAL |
| DoH without certificate validation | `:put [/ip dns get use-doh-server]` + `:put [/ip dns get verify-doh-cert]` | `use-doh-server` configured with `verify-doh-cert=no`: an on-path attacker can answer — no worse than plain DNS, but the DoH promise is void | MEDIUM |
| Proxy enabled | `/ip proxy print` | `enabled=yes` without need | MEDIUM |
| Open proxy | `/ip proxy print` (`enabled`, `port`) + `/ip proxy access print` + the input filter for the proxy port | proxy port reachable from the WAN with no `access` rule limiting clients: relay for spam and third-party abuse. `src-address` is only the address the proxy uses for its own outgoing connections — it does not restrict who connects | CRITICAL |
| Proxy cache without ceiling | `/ip proxy print` | `max-cache-size=unlimited` with cache in RAM (factory value is `none`): memory exhaustion and reboot | MEDIUM |
| Proof of open proxy | `/ip proxy connections print` | active connection from an external `src-address` — a strong lead; confirm with the filter and access rules | HIGH |
| Disabled proxy rule | `/ip proxy access print` | blocking rule with `disabled=yes`, or `hits=0` for a long time — a control the operator believes active and is not. **End of list: what does not match is ALLOWED** | HIGH |
| Port-80 redirect without source | `/ip firewall nat print detail where action=redirect` | redirect to the proxy without `in-interface-list`/`src-address` of the LAN: turns the proxy open by an indirect route | HIGH |
| SOCKS | `/ip socks print` | `enabled=yes` without need — classic botnet relay vector | HIGH |
| UPnP | `/ip upnp print` | `enabled=yes` — a client opens ports in the NAT on its own | HIGH |
| UPnP taking down the WAN | `/ip upnp print` and `/ip upnp interfaces print` | `allow-disable-external-interface=yes`: **any LAN host can disable the external interface** | CRITICAL |
| Cloud / DDNS | `:put [/ip cloud get ddns-enabled]` + `:put [/ip cloud get update-time]` + `:put [/ip cloud get public-address]` | `ddns-enabled=yes` or `update-time=yes` without need: publishes the device's public IP. Never use broad `/ip cloud print` in agent-assisted collection | MEDIUM |
| RoMON | `:put [/tool romon get enabled]` + `:put [:len [/tool romon get secrets]]` (settings menu: no `proplist`/`count-only`; `print` shows the secrets) + `/tool romon port print proplist=interface,forbid,cost` | `enabled=yes` without `secrets`, or RoMON port active on an untrusted interface | HIGH |
| SNMP | `:put [/snmp get enabled]` and `/snmp community print proplist=disabled,addresses,security,read-access,write-access` | detailed in `routeros-audit-logging` | HIGH |
| Remote log and NTP | `/system logging action print` and `/system ntp client print` | detailed in `routeros-audit-logging` | HIGH |
