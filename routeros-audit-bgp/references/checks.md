# BGP and RPKI checks

Severity scale: CRITICAL / HIGH / MEDIUM / LOW. Every command is read-only. Method and output format: `routeros-audit-method`.

## 1. BGP — session

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Session without MD5 | `/routing bgp connection print count-only where tcp-md5-key=""` (v7) / `/routing bgp peer print count-only where tcp-md5-key=""` (v6); use explicit non-secret `proplist` for peer/session metadata | key empty on a session crossing a third party's network | HIGH |
| GTSM off | `/routing bgp peer print proplist=name,remote-address,remote-as,ttl-security,max-prefix-limit,disabled` (v6) / `/routing bgp connection print proplist=name,remote.address,remote.as,local.role,multihop,input.limit-process-routes-ipv4,input.limit-process-routes-ipv6,listen,disabled` (v7) | v6: `ttl-security=no` on a directly connected eBGP peer — a forged packet from afar reaches port 179. v7 has no `ttl-security` field: check that a directly connected peer is not `multihop=yes` | MEDIUM |
| No prefix ceiling | same `proplist` | `max-prefix-limit` (v6) / `input.limit-process-routes-ipv4`/`-ipv6` (v7) empty on an eBGP peer — a full-table leak exhausts RAM | HIGH |
| Peer accepting any ASN (v7) | `/routing bgp connection print proplist=name,remote.address,remote.as,local.role,multihop,input.limit-process-routes-ipv4,input.limit-process-routes-ipv6,listen,disabled` | `remote.as` empty with `listen` on: v7 discovers the ASN from the OPEN message and closes with whoever arrives | HIGH |
| Session on a physical address | same safe `proplist` | iBGP peer on a physical interface IP instead of loopback: a link drop kills the session | MEDIUM |
| Next-hop not adjusted on iBGP | explicit non-secret BGP `proplist` including the relevant nexthop-choice field | border without `force-self`: the iBGP peers receive an external next-hop, the route stays inactive or forces carrying the external network in the IGP | HIGH |
| Port 179 open | `/ip firewall filter print detail where chain=input` | `dst-port=179` without `src-address` restricted to the peers | HIGH |

## 2. BGP — filters, attributes and leaks

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| No output filter | safe BGP `proplist` + `/routing filter rule print` + the configured `output.network`/redistribution sources | an empty output filter is no outbound safety boundary. On RouterOS v7, if no output filter chain is set BGP accepts eligible output by default; verify `output.network`, redistribution, route selection and actual advertisements before declaring a leak | HIGH |
| No input filter | same | `input.filter` empty on a transit peer: accepts bogons, default and prefixes more specific than /24 | CRITICAL |
| Transit leak | `/routing filter rule print` | output filter letting a prefix learned from one transit through to another transit or to an IX | CRITICAL |
| `local-pref` accepted from outside | `/routing filter rule print` + `/ip route print detail` | attribute received from an external peer without normalisation in the input filter: **the neighbor starts deciding your AS's exit** | HIGH |
| `weight` as the only failover criterion | `/ip route print detail where bgp` | `weight` is local to the router and does not propagate — the policy does not replicate and the failover fails silently | MEDIUM |
| MED passed on | `/ip route print detail` | MED from one neighbor being announced to a third AS | MEDIUM |
| Origin `incomplete` announced | `/ip route print detail where bgp` | prefix with origin `incomplete` going out: that is redistribution entering BGP directly — an internal route leaking | HIGH |
| Private AS announced | `/routing bgp connection print proplist=name,remote.as,output.remove-private-as,output.redistribute,output.default-originate` (v7) / `/routing bgp peer print proplist=name,remote-as,remove-private-as,default-originate` (v6) | `remove-private-as=no` (v6) / `output.remove-private-as=no` (v7) on a session to the Internet | HIGH |
| Broad redistribution | same safe BGP `proplist` | `connected,static,ospf` without filter: publishes the whole IGP | HIGH |
| Unconditional default route | same safe BGP `proplist` | `default-originate=always` | MEDIUM |
| Community without scrubbing | `/routing filter rule print detail` | community received from a customer passed on — the customer triggers prepend or blackhole on your side | HIGH |
| Third-party blackhole accepted | same command | blackhole community accepted for a prefix that **does not belong** to the requester: a customer discards someone else's route | CRITICAL |
| Internal prefix without `no-export` | same command | internal network announced without the mark that pins it at the neighbor | HIGH |

**AS-path regex trap (v6 vs v7).** On v7 `_200_` matches ASN 200 in the middle of the path; on
v6 the same pattern matches **any ASN of at least 6 characters containing `200`**. The v6
equivalent is `".*_200_.*"`. A filter copied from one to the other matches another set — **with no
syntax error**.

**Filter syntax trap.** v6 uses field by field (`action=discard set-bgp-communities=no-export`);
v7 uses a script (`rule="if (bgp-communities equal 100:501) {reject;}"`). Configuration copied
between versions **is not applied and does not complain** — the policy simply stops existing.

**`discard` vs `reject` trap.** On v6, `discard` stops updating the route; `reject` keeps it in
memory and allows `refresh`. On v7 `discard` does not exist. A rejected route shows as
**inactive** — do not confuse it with a backup route.

## 3. BGP — reflection and confederation

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Reflection enabled on the client | `/routing bgp peer print proplist=name,remote-address,remote-as,route-reflect,disabled where route-reflect=yes` (v6) | `route-reflect=yes` on a peer that is not a reflector: crossed reflection and iBGP loop | HIGH |
| Inverted option on v7 | explicit non-secret `proplist` on `/routing bgp template` and `/routing bgp connection` | on v7 the field is **`no-client-to-client-reflection`** and reflection is automatic: whoever looks for the v6 name concludes "the RR is not active", and whoever ticks the box inverts the whole policy | HIGH |
| Incoherent cluster-id | explicit non-secret `proplist` including cluster-id on the relevant v7/v6 menu | redundant RRs with different cluster-ids where they should be equal: loop or loss of the anti-loop protection | MEDIUM |
| Improper confederated sub-AS | `/routing bgp instance print proplist=name,as,router-id,confederation,confederation-peers` (v6) | an AS in the `confederation-peers` list that should not be there: the eBGP exchange starts being treated as iBGP and attributes cross the boundary | HIGH |
| Confederated AS-path leaking | `/ip route print detail where bgp` | parentheses in the as-path seen by an external peer | MEDIUM |
| Expected aggregate that does not exist (v7) | `/routing filter rule print` | device migrated from v6 counting on `/routing bgp aggregate`: **the menu does not exist on v7** and every specific route leaks | HIGH |
| Aggregate inheriting attributes | `/routing bgp aggregate print proplist=prefix,instance,inherit-attributes,disabled` (v6) | `inherit-attributes=yes` pulling `no-export` from the specifics — the aggregate stops being announced | MEDIUM |

## 4. RPKI (v7 only)

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| RPKI absent at the border | `/routing rpki print` and `/routing rpki-session print` | device with a full table and no cache configured | HIGH |
| Cache configured without use | `/routing filter rule print` | cache active and no rule testing the result — validates and ignores | HIGH |
| Cache session down | `/routing rpki-session print` | session not `established`: validation stops and **the filter stops rejecting anything, with no alarm** | HIGH |
| `invalid` accepted | `/routing filter rule print` | no rule rejecting `rpki-status=invalid` | HIGH |
