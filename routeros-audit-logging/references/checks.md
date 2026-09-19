# Logging, time and SNMP checks

Severity scale: CRITICAL / HIGH / MEDIUM / LOW. Every command is read-only. Method and output format: `routeros-audit-method`.

## 1. Log and time

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Log only in memory | `/system logging print detail` and `/system logging action print detail` | no `remote` action: a reboot erases everything, and whoever breaks in reboots | HIGH |
| Critical topic not logged | `/system logging print detail` | absence of `account`, `critical`, `error`, `warning` (and `firewall` where a rule has `log=yes`) | HIGH |
| Remote log not arriving | `/system logging action print detail` + count on the collector | `remote` action configured pointing to an IP that no longer receives — **the system lies about its own state** | CRITICAL |
| NTP off | `/system ntp client print` and `/system clock print` | `enabled=no` or clock out of time: invalidates TLS certificates, breaks RPKI/DNSSEC and makes the log useless for forensics | HIGH |
| Open NTP server | `/system ntp server print` and `/ip firewall filter print detail` | `enabled=yes` reachable from the WAN — amplification vector | HIGH |
| Debug on permanently | `/system logging print detail where topics~"debug\|packet\|raw"` | debug/packet/raw topic logging non-stop: leaks traffic content and fills the disk | HIGH |
| E-mail without TLS | `:put [/tool e-mail get server]`, `:put [/tool e-mail get port]`, `:put [/tool e-mail get tls]` | `tls=no` on an untrusted path. SMTP password presence/strength is intentionally not assessed by the agent because the password field is sensitive | HIGH |
| Evidence never handled | `/log print without-paging where topics~"account\|critical\|error\|warning"` | serial failed logins, unexpected reboot or configuration change recorded and never looked at | HIGH |
| Netwatch actions present | `/tool netwatch print proplist=name,host,type,interval,timeout,status,disabled` + presence-only counts for `up-script`, `down-script` and `test-script` | action scripts exist but their bodies must never enter the agent. Assess only presence, target and schedule unless a trusted local scanner returns sanitized classifications | MEDIUM |

## 2. SNMP and monitoring

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Default community | `/snmp community print count-only where name=public` and `... where name=private` | count above zero: the well-known name is tested by filter, the value itself is never printed | CRITICAL |
| SNMP community exposure | `/snmp community print proplist=disabled,addresses,security,read-access,write-access,authentication-protocol,encryption-protocol` | assess scope, security mode and privileges only. Never retrieve the community string/name because it is a credential | HIGH |
| No source restriction | `/snmp community print proplist=disabled,addresses,security,read-access,write-access,authentication-protocol,encryption-protocol` | `addresses=0.0.0.0/0` or `::/0` on an enabled entry — the MIB may expose interfaces, IPs, clients, traffic and topology | HIGH |
| Write enabled | `/snmp community print proplist=disabled,addresses,security,read-access,write-access,authentication-protocol,encryption-protocol` | `write-access=yes`: the device can be reconfigured over SNMP. Do not retrieve the community credential to prove the risk | CRITICAL |
| Unprotected trap | `:put [/snmp get trap-version]` + `:put [/snmp get trap-target]` (settings menu: `print` shows `trap-community`, `get` of a named field does not) | `trap-version=1` or `2` leaving the management network without an approved protected transport. Do not retrieve the trap community value | MEDIUM |
| v1/v2c on an untrusted network | `:put [/snmp get enabled]` and `/snmp community print proplist=disabled,addresses,security,read-access,write-access,authentication-protocol,encryption-protocol` | `security=none` outside an isolated management network | HIGH |
| Trap to the wrong destination | `:put [/snmp get trap-target]` | trap leaving to an IP that is not the current collector | MEDIUM |
