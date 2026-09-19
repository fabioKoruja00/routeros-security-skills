# Bulk collection

Read-only sequence to gather the baseline before judging any item:

```
/system identity print
/system resource print
/system package print
/system default-configuration print
/system routerboard print
/system routerboard settings print
/system device-mode print
/user print proplist=name,group,address,disabled,last-logged-in
/user group print detail
/user aaa print
/user ssh-keys print detail
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

`/export verbose` complements, **does not replace** the targeted prints. Sensitive values are hidden by default on current RouterOS releases; never use `show-sensitive` during normal AI-assisted collection. What only appears in `print`
is listed in `routeros-audit-ip-settings` and in `routeros-factory-defaults`.
