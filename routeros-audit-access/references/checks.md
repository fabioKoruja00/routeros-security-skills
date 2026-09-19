# Administrative access checks

Severity scale: CRITICAL / HIGH / MEDIUM / LOW. Every command is read-only. Method and output format: `routeros-audit-method`.

## 1. Exposed services and administrative access

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Insecure service enabled | `/ip service print detail` | `telnet`, `ftp`, `www` or `api` with `disabled=no` | HIGH |
| Administrative service without source restriction | `/ip service print detail` | `winbox`/`ssh`/`www-ssl`/`api-ssl` with `address=""`. In Winbox this is the empty **Available From** column | CRITICAL |
| Default service port | `/ip service print detail` | `ssh` on 22 and `winbox` on 8291 exposed to the WAN. Changing the port is obfuscation: it does **not** replace `address` nor a filter — the official docs are explicit | LOW |
| www-ssl/api-ssl certificate | `/ip service print detail` + `/certificate print proplist=name,common-name,subject-alt-name,issuer,serial-number,fingerprint,invalid-before,invalid-after,expired,revoked,trusted,private-key,key-type,key-size,signature-algorithm` | `certificate=none` on a TLS service, or an expired certificate in external use | MEDIUM |
| SSH with weak crypto | `/ip ssh print` | `strong-crypto=no`, `allow-none-crypto=yes`, or `host-key-size` below 2048 | MEDIUM |
| SSH forwarding enabled | `/ip ssh print` | `forwarding-enabled` other than `no` without a declared use: the device becomes a pivot into the network | HIGH |
| `admin` user active | `/user print proplist=name,group,address,disabled,last-logged-in` | user `admin` with `disabled=no`. Password value/strength is deliberately not assessed by the agent | CRITICAL |
| User without source restriction | `/user print proplist=name,group,address,disabled,last-logged-in` | account in group `full`/`write` with `address=""` | HIGH |
| Group with too much permission | `/user group print detail` | monitoring-only group with `write`, `policy`, `sensitive` or `password` | HIGH |
| Orphan SSH key | `/user ssh-keys print detail` | public key registered that nobody recognises — access that survives a password change | CRITICAL |
| Unexpected active session | `/user active print` | session from an unknown origin, or `via=api` nobody recognises | HIGH |
| Unused interface enabled | `/interface print detail` | physical port or virtual interface without a function and `disabled=no` | MEDIUM |
| Protected RouterBOOT | `/system routerboard settings print` | `protected-routerboot=disabled` on a device with third-party physical access | HIGH |
| RouterBOOT firmware behind | `/system routerboard print` | `current-firmware` different from `upgrade-firmware` | MEDIUM |
| Permissive device-mode (v7.17+) | `/system device-mode print` | `container`, `socks`, `proxy`, `traffic-gen` or `partitions` enabled without a declared use | MEDIUM |
| Device-mode flagged | `/system device-mode print` | `flagged=yes`: there was a change attempt without physical confirmation. **Treat as a possible intrusion**, audit everything before clearing the state | CRITICAL |
| Flagging disabled | `/system device-mode print` | `flagging-enabled=no`: the device stops warning about the attempt — it loses the only signal it had | CRITICAL |
| Downgrade allowed | `/system device-mode print` and `/system package print detail` | `install-any-version=yes`, or installed version outside `allowed-versions`: allows going back to a version with a known flaw and reopening what was fixed | HIGH |
| Baseline of the model assumed | `/system default-configuration print` | auditing against the home-router defconf when the device is a CCR, IP-only, CAP or switch — **those lines do not receive the default firewall**, so "no rules" there is factory-normal, and the finding is another one: nobody built the policy | CRITICAL |
| Permissive alternate boot | `/system routerboard settings print` | `boot-device` accepting ethernet/Netinstall without a custody procedure | HIGH |
| AAA login with a broad group | `/user aaa print` | `default-group=full`: whoever RADIUS authenticates enters with full power, even without an attribute | CRITICAL |
| Password too old | `/user print proplist=name,group,address,last-logged-in,password-changed-before` | administrative account whose password has not changed since before the last staff turnover | MEDIUM |
| LCD without PIN | `/lcd print` and `/lcd pin print` | screen enabled, no PIN and no read-only mode on a device in a shared rack | MEDIUM |
| Physical button running a script | `/system routerboard button print` (or `/system routerboard mode-button print`) | button enabled with an `on-event` that brings up a tunnel or a service: **whoever reaches the device raises an exit path with no credential at all** | HIGH |
| Device snapshot on disk | `/file print where name~"supout"` | accumulated `supout.rif`/`autosupout.rif`: they contain the full configuration, log and state | MEDIUM |
| Public graphs | `/tool graphing interface print`, `/tool graphing resource print`, `/tool graphing queue print` + `/ip service print where name=www` | `allow-address=0.0.0.0/0` with `www` up: the `/graphs` page hands out interface names, queues, CPU and memory **without login** | HIGH |
| Unmaintained monitoring tool | `/dude print` | Dude server active — product discontinued by the vendor | MEDIUM |
| RouterOS version | `/system package update print` and `/system resource print` | version outside the long-term release approved by operations, or older than the fix of a known vulnerability | HIGH |
