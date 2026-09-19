# CAPsMAN checks

Severity scale: CRITICAL / HIGH / MEDIUM / LOW. Every command is read-only. Method and output format: `routeros-audit-method`.

## 1. CAPsMAN — trust between CAP and controller

This is where the most serious finding of the area lives: **without a certificate there is no
authentication at all** between AP and controller, and the controller hands out the entire
configuration, **passphrase included**.

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Controller accepts any AP | `/caps-man manager print` or `/interface wifi capsman print` | `require-peer-certificate=no` — an unauthorised AP joins and receives SSID, VLAN and password | HIGH |
| No certificate on either side | same + `/interface wireless cap print` | `certificate=none` on the controller **and** on the CAP | HIGH |
| CAP closes with any controller | `/interface wireless cap print` | `caps-man-names`, `caps-man-addresses` and `caps-man-certificate-common-names` all empty: **an empty list means "any available manager"** | HIGH |
| CAP without name lock | same command | `lock-to-caps-man=no` with `locked-caps-man-common-name` empty | MEDIUM |
| Discovery on a customer interface | `/interface wireless cap print` (`discovery-interfaces`) and `/caps-man manager interface print` | discovery enabled on a customer bridge or the WAN. On the controller, absence of the `all forbid=yes` entry allowing only the management port | HIGH |
| Manager listening everywhere (v7) | `/interface wifi capsman print` | `interfaces` field empty | HIGH |
| Provisioning by MAC | `/caps-man provisioning print detail` or `/interface wifi provisioning print detail` | rule matching `radio-mac` without requiring a certificate — a cloned MAC inherits the configuration | HIGH |
| Catch-all at the top | same command (see the numbering) | rule `radio-mac=00:00:00:00:00:00` above the specific ones: the ones below **are never reached** | MEDIUM |
| Provisioning already enabled | same command | `action=create-dynamic-enabled` in a sensitive environment — a new radio joins and starts radiating without review | MEDIUM |
| Controller address only via DHCP | `/ip dhcp-server network print detail` (`caps-manager`) and `/ip dhcp-client print detail` on the CAP | CAP depending on option 138 on a segment without DHCP snooping: a rogue server points the AP to another controller | MEDIUM |
| Control port exposed | `/caps-man remote-cap print detail` (shows the port) + `/ip firewall filter print` | CAPWAP port reachable from the WAN or from the customer network | HIGH |
| L2 preferred over L3 | `/caps-man remote-cap print detail` (compare registration by MAC and by IP) | CAPs registered by MAC on a segment where any host can start a controller — **the L2 manager wins over the legitimate L3 one** | HIGH |

## 2. CAPsMAN — segmentation and data

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Guest in the internal bridge | `/caps-man datapath print detail` or `/interface wifi datapath print detail` | guest datapath with the same `bridge` as corporate and no `vlan-id` | HIGH |
| Tag configured without `vlan-mode` | same command | `vlan-id` filled with `vlan-mode` empty: the tag **is not applied** | HIGH |
| VLAN by MAC | `/caps-man access-list print detail` | privileged VLAN assignment matching `mac-address` — whoever clones the MAC lands in the good VLAN | MEDIUM |
| Local forwarding without filter | `/caps-man datapath print detail` | `local-forwarding=yes` on a remote CAP without its own firewall: client traffic exits on the AP's LAN, outside the controller's inspection | MEDIUM |
| Tunnel data in the clear | `/caps-man datapath print detail` + `/interface print` | CAP crossing an untrusted network with CAPWAP only — **only control is encrypted (DTLS), data is not** | MEDIUM |
| CAP management on the clients' network | `/ip address print` and `/interface bridge port print` on the CAP | AP management address inside the subnet handed out over Wi-Fi | HIGH |
| Bridge without horizon or STP | `/caps-man datapath print detail` (`bridge-horizon`) | several CAPs on the same bridge without loop protection | MEDIUM |

## 3. CAPsMAN — version and certificate

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Fleet on mixed versions | `/caps-man remote-cap print detail` (version column) + `/system resource print` | mixed versions. To reach 7.13+ **passing through 7.12 is mandatory**, otherwise the wireless package is not converted and the AP comes back without a radio | HIGH |
| Upgrade policy | `/caps-man manager print` (`upgrade-policy`, `package-path`) | `require-same-version` **does not provision** a CAP that fails the upgrade (left without a radio); `suggest-same-version` provisions it anyway (stays up on the old version). Choosing without knowing this is a trap | MEDIUM |
| Wrong package folder | same command + `/file print` | `package-path` non-existent or holding a package for another architecture: mass failed upgrade | MEDIUM |
| Automatic CA treated as PKI | `/certificate print detail` | CA generated by CAPsMAN itself: no renewal, no revocation, valid until 2038, and the CommonName derives from the MAC (guessable) | MEDIUM |
| Migration to the new stack | `/interface wireless print detail` | link using Nstreme/Nv2, `station-bridge`, or VLAN inside the wireless profile: **none of that exists on the new stack** — migrating without redoing it takes the link and the access to the remote device down | HIGH |
