# AAA and RADIUS checks

Severity scale: CRITICAL / HIGH / MEDIUM / LOW. Every command is read-only. Method and output format: `routeros-audit-method`.

## 1. AAA and RADIUS

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| RADIUS secret strength | normal audit: `/radius print proplist=disabled,address,service,protocol,src-address,timeout,require-message-auth`; optional sensitive review only with explicit operator authorization | the normal pass cannot prove secret strength without reading it. If sensitive review is authorized, evaluate locally and report only weak/adequate, never the value | HIGH |
| RADIUS without Message-Authenticator | same command | `require-message-auth` off on RADIUS over UDP: forgeable reply, authentication accepted without the server having said anything | HIGH |
| CoA / incoming open | `/radius incoming print` | `accept=yes` without source restriction: anyone drops or re-authorises a subscriber session | CRITICAL |
| Single RADIUS, no pair | `/radius print proplist=disabled,address,service,protocol,src-address,timeout,require-message-auth` and `/radius monitor [find] once` | one server only: a RADIUS outage locks administrative login too, if AAA depends on it | HIGH |
| AAA default group | `/user aaa print` | `default-group=full` — whoever RADIUS authenticates enters with full power | CRITICAL |
| RADIUS over an untrusted network | `/radius print proplist=disabled,address,service,protocol,src-address,timeout,require-message-auth` plus routing/interface context | server reached over the Internet or a third party's link without an approved protected transport | HIGH |
| `accounting` off | `/radius print proplist=disabled,address,service,protocol,src-address,timeout,require-message-auth` plus the relevant AAA/PPP accounting settings | no accounting where the operational policy requires session traceability | MEDIUM |
| PPP secret strength | normal audit: `/ppp secret print proplist=name,service,profile,disabled,caller-id`; optional sensitive review only with explicit operator authorization | the normal pass cannot prove password strength. If sensitive review is authorized, report only the assessment result, never the password | HIGH |
| PPP profile without cipher | `/ppp profile print detail` | `use-encryption=no` on a profile that crosses a public network | HIGH |
| Weak PPP authentication | `/ppp aaa print` and `/interface <type>-server server print` | `authentication` accepting `pap` (user and password in cleartext) | HIGH |
| User Manager shared-secret strength / exposure | normal audit: inspect non-secret router and service metadata only; optional sensitive review for secret strength | weak shared-secret strength cannot be proven without reading it. Separately verify whether the User Manager interface is reachable from an untrusted network | HIGH |
