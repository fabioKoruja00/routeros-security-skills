# Certificates checks

Severity scale: CRITICAL / HIGH / MEDIUM / LOW. Every command is read-only. Method and output format: `routeros-audit-method`.

## 1. Certificates

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Expired on an active service | `/certificate print proplist=name,common-name,subject-alt-name,issuer,serial-number,fingerprint,invalid-before,invalid-after,expired,revoked,trusted,private-key,key-type,key-size,signature-algorithm` | `invalid-after` in the past on a certificate used by `www-ssl`, `api-ssl`, SSTP, OVPN or CAPsMAN | HIGH |
| Short key | `/certificate print proplist=name,common-name,subject-alt-name,issuer,serial-number,fingerprint,invalid-before,invalid-after,expired,revoked,trusted,private-key,key-type,key-size,signature-algorithm` | `key-type=rsa` with `key-size` below 2048. ECDSA keys (`secp256r1`/`secp384r1`) are strong at their own sizes — do not compare them with the RSA threshold | HIGH |
| Private key missing | `/certificate print proplist=name,common-name,subject-alt-name,issuer,serial-number,fingerprint,invalid-before,invalid-after,expired,revoked,trusted,private-key,key-type,key-size,signature-algorithm` | flags without `K`: the certificate cannot serve the server role and the service drops when it needs it | MEDIUM |
| ACME renewal stalled | `/certificate print proplist=name,common-name,subject-alt-name,issuer,serial-number,fingerprint,invalid-before,invalid-after,expired,revoked,trusted,private-key,key-type,key-size,signature-algorithm` | ACME certificate near expiry without renewal, or DNS no longer pointing to the IP | MEDIUM |
| Test CA in production | `/certificate print proplist=name,common-name,subject-alt-name,issuer,serial-number,fingerprint,invalid-before,invalid-after,expired,revoked,trusted,private-key,key-type,key-size,signature-algorithm` | self-signed CA generated in a lab serving external access | MEDIUM |
