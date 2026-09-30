# Fields that come and go between versions

A field missing from a `print` can be absent on that version, not "not configured". Measured on
real devices through the API — `/console/inspect` on v7 (argument names only, no values) and
`print` with `proplist` on v6 — before judging any check that reads these fields.

| Field or menu | Present | Absent |
|---|---|---|
| `/ip ssh` `allow-none-crypto` | v6 (6.48–6.49), 7.3, 7.12 | 7.18 and later |
| `/ip settings` `route-cache` | v6, 7.3, 7.12 | 7.18 and later |
| `/interface bridge` `ra-guard`, `/interface bridge port` `trusted-ra` | 7.23 | v6, 7.3–7.21 |
| `/radius` `require-message-auth` | 6.49.18, 7.18 and later | 7.3, 7.12 |
| `/tool netwatch` `name`, `type`, `test-script` | 7.12 and later | 7.3 (v6 has `host`, `up-script`, `down-script` only) |
| `/routing bgp connection` `output.remove-private-as` | 7.12 and later | 7.3 |
| `/routing bgp connection` `remote.ttl`, `tcp-md5-key`, `output.filter-chain` | v7 | — (v6 uses `/routing bgp peer`) |
| `/system device-mode` `flagged`, `flagging-enabled`, `install-any-version` | 7.23 | v6 (no device-mode) |
| `/system routerboard mode-button`, `reset-button`, `wps-button` | v6 and v7 | there is no `/system routerboard button` |
| `/user` `password-changed-before` | — | v6 and v7 (no password-age field exists) |
| `/ip ipsec profile` `disabled` | — | v7 |
| `/caps-man aaa` `radius-accounting` | — | v6 and v7 (it has `interim-update`) |
| `/interface wireless registration-table` `distance` | v6 | — |
| `/lcd` | only models with a screen | every other model |
| `/ipv6 firewall nat` | v7 | v6 |
| `/mpls traffic-eng`, `/mpls ldp accept-filter`/`advertise-filter` | v7 | — |

Default values confirmed in the official IP Settings page: `arp-timeout=30s`, `tcp-syncookies=no`,
`rp-filter=no`, `disable-ipv6=no`. OSPF `priority` on v7 interface templates defaults to 128
(templates migrated from v6 keep 1).
