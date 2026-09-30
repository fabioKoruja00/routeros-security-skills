# Administrative access checks

Severity scale: CRITICAL / HIGH / MEDIUM / LOW. Every command is read-only. Method and output format: `routeros-audit-method`.

## 1. Exposed services and administrative access

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Insecure service enabled | `/ip service print detail` | `telnet` or `ftp` with `disabled=no` (cleartext login) | HIGH |
| Cleartext management service | `/ip service print detail` | `www` or `api` with `disabled=no`: credentials travel in the clear. Lower when `address` limits it to a management network | MEDIUM |
| Administrative service without source restriction | `/ip service print detail` | `winbox`/`ssh`/`www-ssl`/`api-ssl` with `address=""`. In Winbox this is the empty **Available From** column | CRITICAL |
| Default service port | `/ip service print detail` | `ssh` on 22 and `winbox` on 8291 exposed to the WAN. Changing the port is obfuscation: it does **not** replace `address` nor a filter — the official docs are explicit | LOW |
| www-ssl/api-ssl certificate | `/ip service print detail` + `/certificate print proplist=name,common-name,subject-alt-name,issuer,serial-number,fingerprint,invalid-before,invalid-after,expired,revoked,trusted,private-key,key-type,key-size,signature-algorithm` (`private-key` returns only a presence flag) | `certificate=none` on a TLS service, or an expired certificate in external use | MEDIUM |
| SSH with weak crypto | `/ip ssh print` | `strong-crypto=no`, or `host-key-size` below 2048. `allow-none-crypto=yes` only exists on v6 (gone on v7) | MEDIUM |
| SSH forwarding enabled | `/ip ssh print` | `forwarding-enabled` other than `no` without a declared use: an authenticated user can pivot into the network | MEDIUM |
| `admin` user active | `/user print proplist=name,group,address,disabled,last-logged-in` | user `admin` with `disabled=no`. Password value/strength is deliberately not assessed by the agent | CRITICAL |
| User without source restriction | `/user print proplist=name,group,address,disabled,last-logged-in` | account in group `full`/`write` with `address=""` | HIGH |
| Group with too much permission | `/user group print detail` | a custom group meant for monitoring (its name or its users say so) with `write`, `policy`, `sensitive` or `password`. The built-in `full` group has them by design | HIGH |
| Unrecognised SSH key | `/user ssh-keys print proplist=user,bits,key-owner` | public key nobody recognises — access that survives a password change. The agent lists; a human confirms | HIGH |
| Unexpected active session | `/user active print` | session from an unknown origin, or `via=api` nobody recognises. The audit's own session shows up here — exclude it by source address | HIGH |
| Unused interface enabled | `/interface print proplist=name,type,disabled,running,comment` | physical port or virtual interface with no comment, no address, no bridge membership, `running=no` and `disabled=no`. `print detail` on a large CRS/CCR is heavy | MEDIUM |
| Protected RouterBOOT | `/system routerboard settings print` | `protected-routerboot=disabled` on a device with third-party physical access | HIGH |
| RouterBOOT firmware behind | `/system routerboard print` | `current-firmware` different from `upgrade-firmware` | MEDIUM |
| Permissive device-mode (v7.17+) | `/system device-mode print` | `container`, `socks`, `proxy`, `traffic-gen` or `partitions` enabled without a declared use | MEDIUM |
| Device-mode flagged | `/system device-mode print` | `flagged=yes`: there was a change attempt without physical confirmation. **Treat as a possible intrusion**, audit everything before clearing the state | CRITICAL |
| Flagging disabled | `/system device-mode print` | `flagging-enabled=no`: the device stops warning about the attempt — it loses the only signal it had | CRITICAL |
| Downgrade allowed | `/system device-mode print` and `/system package print detail` | `install-any-version=yes`, or installed version outside `allowed-versions`: allows going back to a version with a known flaw and reopening what was fixed | HIGH |
| Baseline of the model assumed | `/system resource print` (`board-name`) | auditing against the home-router defconf when the device is a CCR, IP-only, CAP or switch — **those lines do not receive the default firewall**, so "no rules" there is factory-normal, and the finding is another one: nobody built the policy. Do not print `/system default-configuration`: its custom script may carry credentials | MEDIUM |
| Permissive alternate boot | `/system routerboard settings print` | `boot-device` accepting ethernet/Netinstall without a custody procedure | HIGH |
| AAA login with a broad group | `/user aaa print` | `use-radius=yes` and `default-group=full`: whoever RADIUS authenticates enters with full power, even without an attribute | HIGH |
| Password too old | not agent-verifiable: `/user` has no password-age field on v6 or v7 | take it from the change record kept outside the device | — |
| LCD without PIN | `/lcd print` (menu present only on models with a screen) | screen enabled, no PIN and no read-only mode on a device in a shared rack | MEDIUM |
| Physical button running a script | `/system routerboard mode-button print proplist=enabled`, and the same on `reset-button` and `wps-button` (v6 and v7; there is no `button` menu). Never print `on-event` | button enabled with an action behind it: **whoever reaches the device raises an exit path with no credential at all**. Presence is the finding; the action body stays out of the agent | HIGH |
| Device snapshot on disk | `/file print where name~"supout"` | accumulated `supout.rif`/`autosupout.rif`: they contain the full configuration, log and state | MEDIUM |
| Public graphs | `/tool graphing interface print`, `/tool graphing resource print`, `/tool graphing queue print` + `/ip service print where name=www` | `allow-address=0.0.0.0/0` with `www` up: the `/graphs` page hands out interface names, queues, CPU and memory **without login** | HIGH |
| Unmaintained monitoring tool | `/dude print` (menu exists only with the `dude` package; an error means absent) | Dude server active — product discontinued by the vendor | MEDIUM |
| RouterOS version | `/system package update print` and `/system resource print` | version outside the long-term release approved by operations, or older than the fix of a known vulnerability | HIGH |
