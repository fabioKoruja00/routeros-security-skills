# AAA and RADIUS checks

Severity scale: CRITICAL / HIGH / MEDIUM / LOW. Every command is read-only. Method and output format: `routeros-audit-method`.

## 1. AAA and RADIUS

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Weak RADIUS secret | `/radius print proplist=disabled,address,service,protocol,src-address,timeout,require-message-auth` | `secret` short, generic or repeated on every NAS | HIGH |
| RADIUS without Message-Authenticator | same command | `require-message-auth` off on RADIUS over UDP: forgeable reply, authentication accepted without the server having said anything | HIGH |
| CoA / incoming open | `/radius incoming print` | `accept=yes` without source restriction: anyone drops or re-authorises a subscriber session | CRITICAL |
| Single RADIUS, no pair | `/radius print detail` and `/radius monitor [find] once` | one server only: a RADIUS outage locks administrative login too, if AAA depends on it | HIGH |
| AAA default group | `/user aaa print` | `default-group=full` — whoever RADIUS authenticates enters with full power | CRITICAL |
| RADIUS over an untrusted network | `/radius print detail` | server reached over the Internet or a third party's link without IPsec | HIGH |
| `accounting` off | `/radius print detail` | no accounting: no record of who connected and when | MEDIUM |
| PPP user with a weak password | `/ppp secret print detail` | password short, equal to the user name, or a sample | HIGH |
| PPP profile without cipher | `/ppp profile print detail` | `use-encryption=no` on a profile that crosses a public network | HIGH |
| Weak PPP authentication | `/ppp aaa print` and `/interface <type>-server server print` | `authentication` accepting `pap` (user and password in cleartext) | HIGH |
| User Manager exposed | `/user-manager router print detail` | weak shared secret, or the User Manager web interface reachable from outside | HIGH |
