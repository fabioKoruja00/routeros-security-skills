# QoS with a security effect checks

Severity scale: CRITICAL / HIGH / MEDIUM / LOW. Every command is read-only. Method and output format: `routeros-audit-method`.

## 1. QoS with a security effect

A badly built queue is not just slowness: it is the path by which the device becomes
unreachable during an attack or a peak, and by which one customer eats everybody else's bandwidth.

| Check | Read command | Characterises a failure | Sev. |
|---|---|---|---|
| Management without priority | `/queue tree print detail stats` and `/ip firewall mangle print detail` | management and routing traffic without a priority queue: a full link takes access down with it | HIGH |
| Guarantee above capacity | `/queue tree print proplist=name,parent,limit-at,max-limit,priority` | sum of the children's `limit-at` greater than the parent's `max-limit`: the guarantee is a lie and distribution becomes luck | HIGH |
| PCQ classifying backwards | `/queue type print proplist=name,kind,pcq-classifier,pcq-rate,pcq-limit,pcq-total-limit` | upload without `src-address` or download without `dst-address`: the whole network is treated as one client | MEDIUM |
| Queue that never matches | `/queue tree print detail stats` and `/queue simple print detail stats` | `bytes=0` on a production queue — wrong parent, wrong packet-mark, or fasttrack passing in front | MEDIUM |
| Dynamic queues without ceiling | `/queue simple print count-only` | thousands of dynamic simple queues on small hardware: CPU pegged and the device stops answering | MEDIUM |
| Bufferbloat | `/queue type print detail` and `/queue interface print stats` | `pfifo`/`bfifo` with a high `limit`: latency climbs under load and management goes with it | MEDIUM |
