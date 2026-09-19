---
name: routeros-audit-capsman
description: "Read-only security audit of CAPsMAN on MikroTik RouterOS (legacy /caps-man and the wifi-qcom /interface wifi capsman): trust between CAP and controller (peer certificates, empty manager lists meaning any manager, discovery interfaces, provisioning by MAC, catch-all rules, DHCP option 138, CAPWAP exposure, L2 winning over L3), datapath segmentation (guest bridge, vlan-mode, VLAN by MAC, local forwarding, unencrypted data), fleet versions and upgrade policy, the automatic CA. This skill should be used when a CAPsMAN controller or a CAP must be assessed without changing configuration."
---

# RouterOS security audit — CAPsMAN

The most serious finding of the wireless area lives here: **without a certificate there is no authentication at all** between AP and controller, and the controller hands out the entire configuration, **passphrase included**. An empty `caps-man-names`/`caps-man-addresses`/`caps-man-certificate-common-names` on the CAP means "any available manager".

## Rules

Read-only: `print`, `get`, `export`, `monitor` only — never `set`, `add`, `remove`, `enable`, `disable`, `reboot`. Connect with a dedicated least-privilege audit account; do not assume the built-in `read` group is strictly read-only. Audit only the devices that were named. Secrets never enter the report (use `proplist` on areas that store credentials). Method, severity scale (CRITICAL / HIGH / MEDIUM / LOW — in doubt, the lower), output format and the collection order live in `routeros-audit-method`; factory values in `routeros-factory-defaults`. Read the RouterOS version first: v6 and v7 menus differ, and a command in the wrong menu returns empty.

## Checks

[references/checks.md](references/checks.md)

## Traps

- **A manager reachable over L2 wins over the legitimate one over L3.** CAPs registered by MAC on a segment where any host can start a controller are the exposed ones.
- **Only CAPWAP control is encrypted (DTLS); data is not** — a CAP across an untrusted network needs a tunnel underneath.
- **To reach 7.13+ the CAP must pass through 7.12.** `require-same-version` leaves a CAP that failed the upgrade without a radio; `suggest-same-version` keeps it up on the old version.
- **The automatic CA is not a PKI:** no renewal, no revocation, CommonName derived from the MAC.
