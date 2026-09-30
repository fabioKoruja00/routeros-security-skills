# Bulk collection

Read-only sequence to gather the baseline before judging any item:

```
/system identity print
/system resource print
/system package print
/system routerboard print
/system routerboard settings print
/system device-mode print
/user print proplist=name,group,address,disabled,last-logged-in
/user group print detail
/user aaa print
/user ssh-keys print proplist=user,bits,key-owner
/ip service print detail
/ip ssh print
/ip settings print
/ipv6 settings print
/ip neighbor discovery-settings print
/tool mac-server print
/tool mac-server mac-winbox print
/ip firewall filter print detail stats
/ip firewall raw print detail stats
/ip firewall nat print detail
/ip firewall connection tracking print
/ip firewall service-port print detail
/ipv6 firewall filter print detail stats
/interface list member print detail
/interface bridge print detail
/interface bridge port print detail
/system script print proplist=name,owner,policy,dont-require-permissions,last-started,run-count
/system scheduler print proplist=name,start-time,interval,policy,run-count,next-run
/file print detail
```

`/export verbose` complements, **does not replace** the targeted prints. `/system default-configuration` is left out on purpose: its custom script may carry credentials, and `board-name` in `/system resource print` already tells whether the model ships the default firewall. On a device carrying a full routing table, never print `/ip route` or the connection table without `count-only` or a narrow `where`. Sensitive values are hidden by default on v7 (`show-sensitive` is the flag that reveals them); on v6 the default is the opposite and `hide-sensitive` must be given explicitly. Never use `show-sensitive` (v7) or omit `hide-sensitive` (v6) in any agent-assisted collection. There is no sensitive-review mode and no secret value may enter agent context. What only appears in `print`
is listed in `routeros-audit-ip-settings` and in `routeros-factory-defaults`.
