---
name: routeros-audit-aaa
description: "Read-only audit of authentication backends on MikroTik RouterOS: RADIUS secret strength, Message-Authenticator requirement, CoA/incoming without source restriction, single RADIUS without a pair, AAA default group, RADIUS over untrusted networks, accounting, PPP secrets and profiles, PPP authentication methods, User Manager exposure. This skill should be used when assessing how a RouterOS device authenticates administrators and subscribers, without changing configuration."
---

# RouterOS security audit — AAA and RADIUS

The device trusts the RADIUS answer; the question is who else can produce one. `require-message-auth` off over UDP, CoA open to any source and `default-group=full` are the findings that turn a forged packet into administrative access.

## Rules

Read-only: `print`, `get`, `export`, `monitor` only — never `set`, `add`, `remove`, `enable`, `disable`, `reboot`. Connect with a `read`-group user and audit only the devices that were named. Secrets never enter the report (use `proplist` on areas that store credentials). Method, severity scale (CRITICAL / HIGH / MEDIUM / LOW — in doubt, the lower), output format and the collection order live in `routeros-audit-method`; factory values in `routeros-factory-defaults`. Read the RouterOS version first: v6 and v7 menus differ, and a command in the wrong menu returns empty.

## Checks

[references/checks.md](references/checks.md)

## Traps

- **`/radius print detail` shows the secret.** Use the `proplist` given in the table.
- **A single RADIUS locks administrative login too** when AAA depends on it — availability is a security finding here.
- PPP tunnel and PPPoE server hardening is in `routeros-audit-vpn`.
