---
name: routeros-audit-wireless
description: "Read-only security audit of wireless interfaces on MikroTik RouterOS: legacy driver (/interface wireless) versus the wifi-qcom stack (/interface wifi), authentication and ciphers (open default profile, WEP, WPA1, TKIP, PMF, PMKID, WPS, EAP), who can read the PSK, client admission (access-list order, MAC-only control, OUI masks, client isolation, evil twin), operating modes and L2 bridging (WDS, station-bridge, NV2), regulatory/RF with security effect, and evidence from the registration table. This skill should be used when a RouterOS access point or station must be assessed without changing configuration and without knocking clients off the air. CAPsMAN is covered by routeros-audit-capsman."
---

# RouterOS security audit — wireless interfaces

**Two drivers, two menus, and they do not coexist.** Up to 7.12 everything was `/interface wireless`. From 7.13 the `wireless` package became separate and conflicts with `wifi-qcom`/`wifi-qcom-ac`; an 802.11ax interface **requires** `wifi-qcom`. The wrong menu returns empty, and empty looks like "this device has no wireless". Check first: `/system package print` and `/interface wifi print`.

**The audit itself can take the site down.** `/interface wireless scan` and `snooper` drop the radio's connections — only with `background=yes`.

## Rules

Read-only: `print`, `get`, `export`, `monitor` only — never `set`, `add`, `remove`, `enable`, `disable`, `reboot`. Connect with a dedicated least-privilege audit account; do not assume the built-in `read` group is strictly read-only. Audit only the devices that were named. Secrets never enter the report (use `proplist` on areas that store credentials). Method, severity scale (CRITICAL / HIGH / MEDIUM / LOW — in doubt, the lower), output format and the collection order live in `routeros-audit-method`; factory values in `routeros-factory-defaults`. Read the RouterOS version first: v6 and v7 menus differ, and a command in the wrong menu returns empty.

## Checks

[references/checks.md](references/checks.md)

## Traps

- **`print detail` on security-profiles, access-list (PPSK) and `/radius` shows the keys.** Use `proplist`.
- **`default-authentication=no` with an empty access-list drops the whole fleet**, including the client you administer from.
- **`pmf=required` on a WPA2 network disconnects legacy clients**; with WPA2 the useful value is `allowed`.
- **The registration table proves the state; the profile only declares the intention.**
- **"No WPA3" on a device without `wifi-qcom`** is a finding about the package/version, not about wireless.
