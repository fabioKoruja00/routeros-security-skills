# Tunnels and cryptography checks

Severity scale: CRITICAL / HIGH / MEDIUM / LOW. Every command is read-only. Method and output format: `routeros-audit-method`.

## 1. Cryptography, certificates and tunnels

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| PPTP enabled | `/interface pptp-server server print` | `enabled=yes` — MS-CHAPv2 broken for years, no fix possible | CRITICAL |
| L2TP without IPsec | `/interface l2tp-server server print` | `use-ipsec=no`, or `use-ipsec=yes` with an empty `ipsec-secret` | CRITICAL |
| Cleartext PPP authentication | `/interface <type>-server server print` and `/ppp aaa print` | `authentication` accepting `pap`, or `mschap1` without need | HIGH |
| PPP session without cipher | `/ppp active print` | **empty** encoding column — the session came up unencrypted, even with the profile asking for it | HIGH |
| PPP profile not requiring cipher | `/ppp profile print detail` | `use-encryption=no` or `default` on a profile that crosses an untrusted network | HIGH |
| Multiple sessions per subscriber | `/interface pppoe-server server print detail` | `one-session-per-host=no`: one credential opens N sessions, drains the pool and the CPU | HIGH |
| Concentrator accepting empty service | same command | `accept-empty-service=yes` — a client that does not state the service name gets in | MEDIUM |
| Concentrator with an IP on the access interface | `/ip address print` crossed with `/interface pppoe-server server print` | the interface where PPPoE listens **must not have an IP address** | MEDIUM |
| PPPoE client without a fixed AC | `/interface pppoe-client print detail` | `ac-name` and `service-name` empty: connects to **the first concentrator that answers** — open door for a rogue concentrator | HIGH |
| Route and DNS dictated by the link | `/interface pppoe-client print detail` | `use-peer-dns=yes` and `add-default-route=yes` on an unapproved link | MEDIUM |
| Remote access created by the wizard | `/interface l2tp-server server print` + `/ppp secret print proplist=name,profile,service` + `/ip cloud print` | VPN raised by Quick Set: generic user, and the wizard itself leaves **`Firewall Router` unchecked** | CRITICAL |
| Home tunnel with the admin credential | `/ip cloud print`, `/interface wireguard peers print detail`, `/user print proplist=name,group` | Back To Home active: the app asks for **the administrative credential** to build the tunnel, and offers file access in full mode. Unknown peer in the list = remote access nobody registered | HIGH |
| Tunnel secret strength | normal audit: inspect only non-secret metadata with `proplist`; optional sensitive audit only with explicit operator authorization | secret strength cannot be proven without reading the value. Do not pull PSKs/passwords into the agent context during normal collection | HIGH |
| Weak SSTP | `/interface sstp-server server print detail` | `certificate=none`, `force-aes=no`, or `tls-version=any` (accepts TLS 1.0) | HIGH |
| Weak OVPN | `/interface ovpn-server server print detail` | `auth=none`/`md5`/`sha1`, `cipher=null`/`blowfish128`, or `require-client-certificate=no` | HIGH |
| IPsec with weak algorithm | `/ip ipsec proposal print detail` and `/ip ipsec profile print detail` | `auth-algorithms=md5`/`sha1`, `enc-algorithms=des`/`3des`, `dh-group` below `modp2048` | HIGH |
| IKEv1 aggressive with PSK | `/ip ipsec profile print detail` and `/ip ipsec identity print detail` | `exchange-mode=aggressive` with `auth-method=pre-shared-key`: the hash goes over the air for offline cracking | CRITICAL |
| IPsec PFS policy | `/ip ipsec proposal print detail` | inspect `pfs-group` in the Phase 2 proposal. `none` may be intentional for interoperability (including documented IKEv2 client cases); flag it only when the security policy explicitly requires PFS | MEDIUM |
| WireGuard with a broad peer | `/interface wireguard print detail` and `/interface wireguard peers print detail` | `allowed-address=0.0.0.0/0` outside a full-tunnel scenario; `listen-port` exposed without an input filter | HIGH |
| WireGuard without preshared-key | `/interface wireguard peers print detail` | peer without `preshared-key` where margin against future cryptanalysis is required | LOW |
| VXLAN without cipher | `/interface vxlan print detail`, `/interface vxlan vteps print` and `/interface vxlan fdb print` | VXLAN crossing the Internet without IPsec/WireGuard underneath (customer L2 in cleartext), VTEP/VNI outside the inventory, or udp/4789 reachable from any source | HIGH |
| ZeroTier | `/zerotier print`, `/zerotier interface print` and `/zerotier peer print` | network ID nobody recognises, `allow-default=yes` (the device's default route starts leaving through the overlay), `allow-global=yes`, or interface bridged with the LAN without segmentation | CRITICAL |
| EoIP without protection | `/interface eoip print detail` | EoIP over the Internet without `ipsec-secret`: an L2 bridge open to whoever forges the endpoint | HIGH |
| Badly built port knocking | `/ip firewall filter print detail` and `/ip firewall address-list print` | knock sequence without `address-list-timeout`, or the final port drop missing — the knock protects nothing | MEDIUM |
| Certificate | `/certificate print detail` | detailed in `routeros-audit-certificates` | HIGH |
