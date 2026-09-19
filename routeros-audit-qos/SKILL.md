---
name: routeros-audit-qos
description: "Read-only audit of QoS on MikroTik RouterOS where a queue mistake becomes a security or availability problem: management and routing traffic without priority, guarantees above capacity, PCQ classifying backwards, queues that never match, unbounded dynamic queues on small hardware, bufferbloat. This skill should be used when reviewing queue trees and simple queues of a RouterOS device for their effect on reachability under load, without changing configuration."
---

# RouterOS security audit — QoS with a security effect

A badly built queue is not just slowness: it is the path by which the device becomes unreachable during an attack or a peak, and by which one customer eats everybody else's bandwidth.

## Rules

Read-only: `print`, `get`, `export`, `monitor` only — never `set`, `add`, `remove`, `enable`, `disable`, `reboot`. Connect with a `read`-group user and audit only the devices that were named. Secrets never enter the report (use `proplist` on areas that store credentials). Method, severity scale (CRITICAL / HIGH / MEDIUM / LOW — in doubt, the lower), output format and the collection order live in `routeros-audit-method`; factory values in `routeros-factory-defaults`. Read the RouterOS version first: v6 and v7 menus differ, and a command in the wrong menu returns empty.

## Checks

[references/checks.md](references/checks.md)

## Traps

- **Fasttrack passes in front of the queue.** A production queue with `bytes=0` is often that, not a wrong parent.
- **Sum of children `limit-at` above the parent `max-limit`** makes the guarantee a lie.
