---
name: routeros-audit-vpn
description: "Read-only audit of tunnels and cryptography on MikroTik RouterOS: PPTP, L2TP without IPsec, PPP authentication and encryption, PPPoE server and client hardening, Quick Set and Back To Home remote access, weak tunnel secrets, SSTP and OVPN cipher settings, IPsec proposals, IKEv1 aggressive mode, PFS, WireGuard peers and preshared keys, VXLAN, ZeroTier, EoIP, port knocking. This skill should be used when assessing VPN and tunnel exposure on a RouterOS device without changing configuration."
---

# RouterOS security audit — tunnels and cryptography

Every tunnel is an entry path. The findings that matter: protocols broken beyond repair (PPTP, L2TP without IPsec, IKEv1 aggressive with PSK), tunnels raised by wizards that leave the firewall unchecked, and overlays (ZeroTier, VXLAN, EoIP) that glue a third party's L2 to yours.

## Rules

Read-only: `print`, `get`, `export`, `monitor` only — never `set`, `add`, `remove`, `enable`, `disable`, `reboot`. Connect with a dedicated least-privilege audit account; do not assume the built-in `read` group is strictly read-only. Audit only the devices that were named. Secrets never enter the report (use `proplist` on areas that store credentials). Method, severity scale (CRITICAL / HIGH / MEDIUM / LOW — in doubt, the lower), output format and the collection order live in `routeros-audit-method`; factory values in `routeros-factory-defaults`. Read the RouterOS version first: v6 and v7 menus differ, and a command in the wrong menu returns empty.

## Checks

[references/checks.md](references/checks.md)

## Traps

- **PPTP has no fix.** `enabled=yes` is CRITICAL regardless of context.
- **Masquerade eats IPsec** without `ipsec-policy=out,none` (or an accept before) for the tunnel's networks — audited in `routeros-audit-firewall`.
- **A PPPoE client with empty `ac-name`/`service-name` connects to the first concentrator that answers.**
- **Back To Home asks for the administrative credential** to build the tunnel. An unknown WireGuard peer is remote access nobody registered.
- Certificates used by SSTP/OVPN are audited in `routeros-audit-certificates`.
