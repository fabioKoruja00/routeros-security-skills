---
name: routeros-audit-wireless
description: "Read-only security audit of wireless on MikroTik RouterOS: legacy driver (/interface wireless) versus the wifi-qcom stack (/interface wifi), authentication and ciphers (open default profile, WEP, WPA1, TKIP, PMF, PMKID, WPS, EAP), who can read the PSK, client admission (access-list order, MAC-only control, OUI masks, client isolation), operating modes and L2 bridging (WDS, station-bridge, NV2), CAPsMAN trust between CAP and controller (certificates, discovery, provisioning, CAPWAP exposure), CAPsMAN segmentation and datapaths, versions and certificates, regulatory/RF with security effect, and evidence from the registration table. This skill should be used when a RouterOS access point, station, CAP or CAPsMAN controller must be assessed without changing configuration and without knocking clients off the air."
---

# RouterOS security audit — wireless

**Two drivers, two menus, and they do not coexist.** Up to 7.12 everything was
`/interface wireless`. From 7.13 the `wireless` package became separate and conflicts with
`wifi-qcom`/`wifi-qcom-ac`; an 802.11ax interface **requires** `wifi-qcom`. The wrong menu returns
empty, and empty looks like "this device has no wireless".

Check first: `/system package print` and `/interface wifi print`.

## Rules

- Read-only. Never `set`, `add`, `remove`, `enable`, `disable`.
- **The audit itself can take the site down.** `/interface wireless scan` and
  `/interface wireless snooper` **drop the radio's connections**. If a sweep is needed, only with
  `background=yes`, or `/caps-man interface scan`, which already runs in the background.
- **Secrets never enter the report.** `print detail` on `security-profiles`, `access-list`
  (PPSK) and `/radius` shows the PSK, per-client keys and RADIUS secret in cleartext. Use
  `proplist` to bring only the fields that matter (`mode`, `authentication-types`,
  `unicast-ciphers`, `group-ciphers`, `management-protection`, `disable-pmkid`), never the key.
  The finding is "weak passphrase on SSID X", not the value.
- Connect with a `read`-group user. Audit only the devices that were named.

## Severity

CRITICAL / HIGH / MEDIUM / LOW — in doubt, the lower. An interface on the `default` security
profile (which ships `mode=none`), WEP, an OUI-wide `mac-mask` accept, a passphrase from training
material, or a virtual SSID inheriting the open profile are CRITICAL. "No WPA3" on a device
without `wifi-qcom` is not a finding about wireless — it is about the package/version.

## Checks

[references/checks.md](references/checks.md) — sections: authentication and cipher (1), who
reads the key (2), client admission (3), operating mode and L2 bridging (4), CAPsMAN trust
between CAP and controller (5), CAPsMAN segmentation and data (6), CAPsMAN version and
certificate (7), regulatory and RF (8), evidence and real state (9), false-positive nuances (10).

Each table gives the read command for the legacy driver and for the `wifi` stack where they
differ.

## Output

One document per device with findings: what is wrong, the read command that proves it, what is
at stake, and the possible fixes with the risk of each — `default-authentication=no` with an
empty access-list drops the whole fleet including the client you administer from;
`pmf=required` on a WPA2 network disconnects legacy clients. Path, not recipe.

## Traps

- **Without a certificate there is no authentication at all** between CAP and controller, and the
  controller hands out the entire configuration, **passphrase included**. Empty
  `caps-man-names`/`caps-man-addresses`/`caps-man-certificate-common-names` on the CAP means
  "any available manager".
- **A manager reachable over L2 wins over the legitimate one over L3.** On a segment where any
  host can start a controller, CAPs registered by MAC are the exposed ones.
- **To reach 7.13+ the CAP must pass through 7.12**, otherwise the wireless package is not
  converted and the AP comes back without a radio. `require-same-version` does not provision a
  CAP that failed the upgrade; `suggest-same-version` provisions it anyway with the old version.
- **`hide-ssid` is not protection** — and not a finding by itself either. It becomes one only when
  documented as if it were a control.
- **The registration table proves the state; the profile only declares the intention.** A weak
  cipher in use, an unknown MAC or a `last-ip` outside the range is evidence; the profile is not.
