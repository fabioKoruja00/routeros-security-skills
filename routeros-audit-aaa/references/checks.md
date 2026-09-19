# AAA and RADIUS checks

Severity scale: CRITICAL / HIGH / MEDIUM / LOW. Every command is read-only. Method and output format: `routeros-audit-method`.

## 1. AAA and RADIUS

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| RADIUS credential handling | `/radius print proplist=disabled,address,service,protocol,src-address,timeout,require-message-auth` | assess transport, source, Message-Authenticator and service exposure only. Secret strength is deliberately not assessed because the agent must never retrieve the secret | MEDIUM |
| RADIUS without Message-Authenticator | same command | `require-message-auth` off on RADIUS over UDP: forgeable reply, authentication accepted without the server having said anything | HIGH |
| CoA / incoming open | `/radius incoming print` | `accept=yes` without source restriction: anyone drops or re-authorises a subscriber session | CRITICAL |
| Single RADIUS, no pair | `/radius print proplist=disabled,address,service,protocol,src-address,timeout,require-message-auth` and `/radius monitor [find] once` | one server only: a RADIUS outage locks administrative login too, if AAA depends on it | HIGH |
| AAA default group | `/user aaa print` | `default-group=full` — whoever RADIUS authenticates enters with full power | CRITICAL |
| RADIUS over an untrusted network | `/radius print proplist=disabled,address,service,protocol,src-address,timeout,require-message-auth` plus routing/interface context | server reached over the Internet or a third party's link without an approved protected transport | HIGH |
| `accounting` off | `/radius print proplist=disabled,address,service,protocol,src-address,timeout,require-message-auth` plus the relevant AAA/PPP accounting settings | no accounting where the operational policy requires session traceability | MEDIUM |
| PPP credential handling | `/ppp secret print proplist=name,service,profile,disabled,caller-id` | assess account scope, service/profile use and exposure only. Password strength is deliberately not assessed because the agent must never retrieve the password | MEDIUM |
| PPP profile without cipher | `/ppp profile print detail` | `use-encryption=no` on a profile that crosses a public network | HIGH |
| Weak PPP authentication | `/ppp aaa print` and `/interface <type>-server server print` | `authentication` accepting `pap` (user and password in cleartext) | HIGH |
| User Manager exposure | inspect only non-secret router/service metadata with explicit `proplist` fields | verify reachability, transport and authorization scope. Shared-secret strength is deliberately not assessed because the secret must never enter agent context | HIGH |
