# Sensitive-parameter denylist

Use MikroTik's official **List of menus with sensitive parameters** as a normative denylist for agent-assisted audits.

Official reference:
https://help.mikrotik.com/docs/spaces/ROS/pages/380076066/List+of+menus+with+sensitive+parameters

## Rule

If a RouterOS menu can contain a sensitive field:

- do not use broad `print` or `print detail` in agent-assisted collection;
- do not use `show-sensitive`;
- do not export sensitive values;
- use an explicit non-secret `proplist` on list-style menus;
- if only presence/absence is needed, use `print count-only where <field>...` so the value is never printed;
- on single-value settings menus that do not support `proplist`/`count-only`, use `:put [/menu get <non-secret-field>]`; if only secret presence matters, return only `:len [/menu get <sensitive-field>]`, never the field value;
- if a check cannot be proven without retrieving the value, mark it **not agent-verifiable**;
- a trusted local scanner may return only sanitized booleans/classifications, never raw secret-bearing content.

## Important sensitive surfaces

The official list includes, among others:

- containers: password;
- PPP clients and PPP secrets: passwords, PINs and secrets;
- L2TP, EoIP, GRE, IPIP and related tunnels: IPsec secrets;
- IPsec: secrets, passwords, keys and passphrases;
- e-mail: password;
- User Manager: passwords, shared secrets and OTP secrets;
- WiFi/CAPsMAN/wireless: passphrases, PPSKs, WEP keys, NV2 preshared keys and EAP passwords;
- WireGuard client configuration: sensitive client configuration material;
- ZeroTier: identity;
- certificates: passphrases/PINs;
- RoMON: secrets;
- routing protocols where authentication keys are present, such as BGP MD5 and OSPF authentication keys;
- cloud/backup/storage features where private keys or passwords may be exposed;
- script-bearing fields such as scheduler actions, Netwatch actions and DHCP lease scripts because arbitrary code can embed credentials.

## Safe design principle

The audit should be **zero-secret by construction**, not merely rely on RouterOS masking behavior.

A command is acceptable only if its output schema is known not to include secret-bearing fields. When uncertain, prefer a narrow `proplist` or skip the check.
