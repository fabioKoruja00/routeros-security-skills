# Certificates checks

Severity scale: CRITICAL / HIGH / MEDIUM / LOW. Every command is read-only. Method and output format: `routeros-audit-method`.

## 1. Certificates

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Expired on an active service | `/certificate print detail` | `invalid-after` in the past on a certificate used by `www-ssl`, `api-ssl`, SSTP, OVPN or CAPsMAN | HIGH |
| Short key | `/certificate print detail` | `key-size` below 2048 | HIGH |
| Private key missing | `/certificate print detail` | flags without `K`: the certificate cannot serve the server role and the service drops when it needs it | MEDIUM |
| ACME renewal stalled | `/certificate print detail` | ACME certificate near expiry without renewal, or DNS no longer pointing to the IP | MEDIUM |
| Test CA in production | `/certificate print detail` | self-signed CA generated in a lab serving external access | MEDIUM |
