---
name: routeros-audit-access
description: "Read-only audit of administrative access on MikroTik RouterOS: enabled services and their source restriction (Available From), SSH crypto and forwarding, users, groups, SSH keys and active sessions, Protected RouterBOOT, device-mode flags and downgrade, AAA default group, LCD, mode button, supout files, public graphs, RouterOS version. This skill should be used when assessing who can log into a RouterOS device and with what power, without changing configuration."
---

# RouterOS security audit — administrative access

Who can reach the device, from where, and with what power. The most common CRITICAL findings live here: an administrative service with an empty `address` ("Available From"), the `admin` user still enabled, an orphan SSH key, `device-mode` with `flagged=yes`.

## Rules

Read-only: `print`, `get`, `export`, `monitor` only — never `set`, `add`, `remove`, `enable`, `disable`, `reboot`. Connect with a dedicated least-privilege audit account; do not assume the built-in `read` group is strictly read-only. Audit only the devices that were named. Secrets never enter the report (use `proplist` on areas that store credentials). Method, severity scale (CRITICAL / HIGH / MEDIUM / LOW — in doubt, the lower), output format and the collection order live in `routeros-audit-method`; factory values in `routeros-factory-defaults`. Read the RouterOS version first: v6 and v7 menus differ, and a command in the wrong menu returns empty.

## Checks

[references/checks.md](references/checks.md)

## Traps

- **Changing the service port is obfuscation**, not a control: `address` and a filter are.
- **Do not recommend disabling Winbox** — it is the recovery path. Restrict its source.
- **`device-mode` with `flagged=yes`** is a possible compromise, not a configuration backlog.
- **CCR, IP-only, CAP and switch lines do not ship the default firewall.** "No rules" there is factory-normal; the finding is that nobody built the policy.
