# Wireless interfaces checks

Severity scale: CRITICAL / HIGH / MEDIUM / LOW. Every command is read-only. Method and output format: `routeros-audit-method`.

## 1. Authentication and cipher

| Check | Read (legacy) | Read (wifi) | Characterises a failure | Sev. |
|---|---|---|---|---|
| `default` profile in production | `/interface wireless print detail` + `/interface wireless security-profiles print detail` | `/interface wifi print detail` + `/interface wifi security print detail` | interface pointing to the `default` profile, which **ships `mode=none`** — an open network nobody chose | CRITICAL |
| WEP / static key | `/interface wireless security-profiles print detail` | `/interface wifi security print detail` | `mode=static-keys-required` or `static-keys-optional` | CRITICAL |
| WPA1 still accepted | same | same | `authentication-types` with `wpa-psk` (without the `2`) — common "for compatibility", ticked together with WPA2 | HIGH |
| TKIP on unicast | same | same | `unicast-ciphers` with `tkip` | HIGH |
| TKIP only on group | same | same | `group-ciphers` with `tkip` while unicast is already AES: **the whole network's broadcast falls back to TKIP** | HIGH |
| PMF off | `management-protection=disabled` | `pmf` empty or `disabled` | management frames unprotected: mass deauthentication and AP cloning | HIGH |
| PMKID exposed | `/interface wireless security-profiles print detail` | same | `disable-pmkid=no` — PMKID capture allows offline cracking of the PSK without an associated client | MEDIUM |
| Group key renewal | same | same | `group-key-update` far above the 5-minute default | LOW |
| Weak / sample passphrase | same | same | passphrase short, digits only, equal to the SSID, or copied from training material. **The system accepts from 8 characters** | CRITICAL |
| EAP without certificate validation | same | same | `tls-mode=dont-verify-certificate` or `no-certificates` with `wpa2-eap` | HIGH |
| WPS enabled | `/interface wireless print detail` | `/interface wifi print detail` | `wps-mode` other than `disabled` | HIGH |
| WPA3/OWE available and unused | — | `/interface wifi security print detail` | hardware with `wifi-qcom` still WPA2 only | LOW |

`pmf=required` only counts with WPA3; with WPA2 the useful value is `allowed`. Requiring
`required` on a WPA2 network disconnects legacy clients — write that into the risk.

## 2. Who reads the key

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| PSK readable by monitoring-only users | `/user group print detail` and `/user print detail` | a group with `read` reaches `/interface wireless security-profiles`, `/radius` and the access-list: **PSK, PPSK and RADIUS secret appear in cleartext** | HIGH |
| PPSK in cleartext in the table | `/interface wireless access-list print detail` | per-client key short or digits only — and it shows as a visible column in Winbox | HIGH |

This is why collection in this skill uses `proplist`: `print detail` in these areas brings secrets.

## 3. Client admission

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Permissive final rule | `/interface wireless access-list print detail` | last entry **without** `mac-address`, with `authentication=yes forwarding=yes`: a catch-all that authenticates anyone | HIGH |
| Rule order | same command (the numbering is the evaluation order) | broad permissive rule before the restrictive one — the list stops at the first match | HIGH |
| Empty list with permissive default | `/interface wireless print detail` + access-list | `default-authentication=yes` and an empty list: only the password stands in the way | MEDIUM |
| MAC as the only control | `/interface wireless access-list print detail` | MAC filter without WPA2 underneath — a MAC is sniffed and cloned | HIGH |
| Allow by OUI | same command | `mac-mask` covering a whole vendor (e.g. `FF:FF:FF:00:00:00`) with `action=accept` | CRITICAL |
| Client talks to client | `/interface wireless print detail` or `/interface wifi datapath print detail` | `default-forwarding=yes` on a guest, hotspot or public SSID | HIGH |
| Time-based rule without a clock | access-list + `/system ntp client print` | rule with `time=` on a device with NTP off: the window opens or closes at the wrong time | LOW |
| Signal floor | `/interface wireless access-list print detail` | no `signal-range` on a façade AP — associates whoever is outside the building | LOW |
| Loose connect-list on the client | `/interface wireless connect-list print detail` | station without a `security-profile` bound: associates to a same-name AP (evil twin) | HIGH |

## 4. Operating mode and L2 bridging

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Dynamic WDS | `/interface wireless print detail` | `wds-mode=dynamic` with `wds-default-bridge` filled: a neighbouring AP forms an L2 bridge **on its own** | HIGH |
| Bridge mode on without use | same command | `bridge-mode=enabled` on an end-user access AP — enables `station-bridge` on the other side | MEDIUM |
| Station in pseudobridge | same command + `/interface bridge port print` | `station-pseudobridge`/`station-bridge` in the same bridge as the internal network: a third party's L2 glued to yours | HIGH |
| Virtual interface inheriting the open profile | `/interface wireless print detail where master-interface!=""` | virtual SSID with `security-profile=default` | CRITICAL |
| Radio VLAN in the management bridge | `/interface wireless print detail` (`vlan-mode`, `vlan-id`) + `/interface bridge port print detail` | `vlan-mode=no-tag` on a radio whose bridge also carries management | MEDIUM |
| NV2 without cipher | `/interface wireless print detail` | `wireless-protocol=nv2` with `nv2-security=disabled` — NV2 has its own cipher, independent of the profile | HIGH |
| Orphan profile from the repeater wizard | `/interface wireless security-profiles print detail` | profile generated by `Setup Repeater` still present, carrying the repeated network's key | MEDIUM |
| Radio on without a function | `/interface wireless print detail` | interface in `ap-bridge` on a device that should be a station, or a wlan enabled without use | MEDIUM |
| Interworking (802.11u) | same command | `interworking-profile` active without need: publishes network data to anyone who probes | LOW |

## 5. Regulatory and RF with a security effect

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Regulatory limit ignored | `/interface wireless print detail` | `frequency-mode=manual-txpower` or `superchannel`: power and channel outside the local rules | HIGH |
| Country not set | same + `/interface wireless info country-info <country>` | `country=no_country_set` or a country other than the one of operation | HIGH |
| Antenna gain not declared | `/interface wireless print detail` (`antenna-gain`) | `0` with an external antenna. Since 6.46 the field disappeared from the UI on fixed-antenna devices, **but stays changeable from the CLI** | HIGH |
| Manual power above the allowed | same (`tx-power-mode`, `tx-power`, `tx-chains`) | `all-rates-fixed`/`manual` above the EIRP. **Careful with the maths:** with 802.11n the chains add +3/+5/+6 dBm to the configured value | MEDIUM |
| Real channel different from the configured one | `/interface wireless monitor <if> once` | with DFS or `frequency=auto`, the `frequency` field **does not prove** the channel in use — the radio moves on its own on radar detection | MEDIUM |
| Basic rate too low | `/interface wireless print detail` (`basic-rates-*`) | 1/2 Mbps on 2.4 GHz: extends the usable range of the cell beyond the perimeter | LOW |
| Aggregation priority open | same (`ht-ampdu-priorities`) | priorities 4-7 enabled on a user network: a client marks its own traffic as voice and takes the medium | LOW |

## 6. Evidence and real state

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Associated client nobody knows | `/interface wireless registration-table print detail` or `/caps-man registration-table print detail` | MAC outside the inventory, `last-ip` outside the range, distance incompatible with the coverage, or a weak cipher in use — **the table proves the state; the profile only declares the intention** | HIGH |
| AP in the controller list that is not yours | `/caps-man remote-cap print detail` | unknown device in state `Run` | HIGH |
| Unprovisioned radio | `/caps-man radio print` | radio listed without the provisioned mark: does not radiate, and nobody notices | MEDIUM |
| Sniffer on | `/interface wireless sniffer print` | `streaming-enabled=yes` or `server` pointing to an unplanned host: network frames leaving over TZSP | HIGH |
| Wireless log missing | `/system logging print detail` | no rule with topic `wireless`: no evidence of mass deauthentication, DFS or authentication failure | MEDIUM |
| RADIUS accounting off | `/caps-man aaa print` and access-list | `radius-accounting` unticked: no record of who connected and when | MEDIUM |

## 7. Nuances that generate false positives

- **`default-forwarding=no` breaks legitimate use** (printers, Chromecast, mDNS). Only a finding on
  a guest/public SSID.
- **`default-authentication=no` with an empty access-list drops the whole fleet** — including
  the client you administer from. Never recommend without the list ready.
- **A signal floor drops edge clients** when there is no neighbouring AP to roam to.
- **The legacy driver does not deliver WPA3.** Accusing "no WPA3" on a device without `wifi-qcom`
  is demanding what the package does not have: the real finding is the version/package.
- **`hide-ssid=yes` is not protection** — and not a finding by itself either. The SSID goes out
  in the client's own probe. It becomes a finding only when documented as if it were a control.
- **Low CCQ and high retransmission may be interference, not an attack.** Measure with spectrum
  analysis before concluding.
