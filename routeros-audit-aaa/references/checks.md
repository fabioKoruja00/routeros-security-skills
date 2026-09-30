# AAA and RADIUS checks

Severity scale: CRITICAL / HIGH / MEDIUM / LOW. Every command is read-only. Method and output format: `routeros-audit-method`.

## 1. AAA and RADIUS

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| RADIUS credential handling | `/radius print proplist=disabled,address,service,protocol,src-address,timeout,require-message-auth` | assess transport, source, Message-Authenticator and service exposure only. Secret strength is deliberately not assessed because the agent must never retrieve the secret | MEDIUM |
| RADIUS without Message-Authenticator | same command. `require-message-auth` exists on 6.49.18+ and 7.18+; it is absent on 7.3 and 7.12 (not applicable there, report the version instead) | `require-message-auth=no` on RADIUS over UDP: the device accepts replies without the attribute, so a forged reply can pass. It does not prove the server omits it | HIGH |
| CoA / incoming open | `/radius incoming print` + the input filter for udp/3799 | `accept=yes` and udp/3799 reachable from any source. `/radius incoming` only has `accept`, `port` and `vrf`: the source restriction lives in the firewall | HIGH |
| Single RADIUS, no pair | `/radius print proplist=disabled,address,service,protocol,src-address,timeout,require-message-auth` | one server per service: a RADIUS outage stops subscriber and RADIUS-based admin logins. Local users still log in | MEDIUM |
| AAA default group | `/user aaa print` | `use-radius=yes` and `default-group=full` — whoever RADIUS authenticates enters with full power | HIGH |
| RADIUS over an untrusted network | `/radius print proplist=disabled,address,service,protocol,src-address,timeout,require-message-auth` plus routing/interface context | server reached over the Internet or a third party's link without an approved protected transport | HIGH |
| `accounting` or interim update off | `/ppp aaa print` (`accounting`, `interim-update`) and `/caps-man aaa print` (`interim-update`) | no accounting where the policy requires session traceability; `interim-update=0` on a PPPoE concentrator leaves stale sessions on the billing side after a reboot | MEDIUM |
| PPP credential handling | `/ppp secret print count-only` first; then `/ppp secret print proplist=name,service,profile,disabled,caller-id` only when the count is small | assess account scope, service/profile use and exposure only. Password strength is deliberately not assessed. Local secrets on a concentrator that also has `use-radius=yes` are a bypass of the RADIUS policy worth listing | MEDIUM |
| PPP profile without cipher | `/ppp profile print proplist=name,use-encryption,only-one,local-address,remote-address` | `use-encryption=no` on a profile used by PPTP, L2TP or SSTP across an untrusted network. **Not applicable to PPPoE access:** MPPE is not used there and forcing it costs the concentrator's CPU | HIGH |
| Weak PPP authentication | `/ppp aaa print` and `/interface pppoe-server server print proplist=interface,service-name,authentication` (or the matching `l2tp`/`sstp`/`pptp` server) | `authentication` accepting `pap` on a tunnel across an untrusted network. On a PPPoE access segment it is often kept for old CPEs: record it, severity MEDIUM | HIGH |
| User Manager exposure | `/tool user-manager` (v6) or `/user-manager` (v7), always with an explicit non-secret `proplist` such as `name,group,disabled,shared-users` | verify reachability, transport and authorization scope. Shared-secret strength is deliberately not assessed because the secret must never enter agent context | HIGH |
