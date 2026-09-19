---
name: routeros-audit-certificates
description: "Read-only audit of certificates on MikroTik RouterOS: expired certificates on active services (www-ssl, api-ssl, SSTP, OVPN, CAPsMAN), short keys, missing private keys, stalled ACME renewal, lab CAs serving production. This skill should be used when reviewing the certificate store of a RouterOS device and its use by services, without changing configuration."
---

# RouterOS security audit — certificates

`/certificate print detail` answers most of it: `invalid-after`, `key-size`, the `K` flag, and which service references the certificate. Never export a private key to prove anything.

## Rules

Read-only: `print`, `get`, `export`, `monitor` only — never `set`, `add`, `remove`, `enable`, `disable`, `reboot`. Connect with a `read`-group user and audit only the devices that were named. Secrets never enter the report (use `proplist` on areas that store credentials). Method, severity scale (CRITICAL / HIGH / MEDIUM / LOW — in doubt, the lower), output format and the collection order live in `routeros-audit-method`; factory values in `routeros-factory-defaults`. Read the RouterOS version first: v6 and v7 menus differ, and a command in the wrong menu returns empty.

## Checks

[references/checks.md](references/checks.md)

## Traps

- **A certificate without the `K` flag cannot serve the server role** — the service drops when it needs it.
- **The CAPsMAN automatic CA** is audited in `routeros-audit-capsman`.
