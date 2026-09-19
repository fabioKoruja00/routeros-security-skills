# Procedure during an incident

Not a configuration check — how to look without making it worse.

| Situation | What to use | What NOT to use |
|---|---|---|
| Suspected flood | `/ip firewall connection print count-only`, then `/system resource print` | **Torch and `/tool profile` on a device already at 100% CPU**: both cost CPU and can take the device down for good |
| Finding the source | `/ip firewall connection print where protocol=... and dst-port=...` | active scanning from the device itself |
| Confirming state exhaustion | `/ip firewall connection tracking print` (compare usage and ceiling) | raising `max-entries` without treating the source — only postpones the exhaustion |
| Wireless | `/interface wireless registration-table print` | `scan` and `snooper` without `background=yes` — **they drop the radio's clients** |
