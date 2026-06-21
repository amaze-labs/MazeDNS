# Architecture

## Goal

A clustered, multi-site DNS system where one **master** holds configuration and
the web UI, and **agents** replicate it and keep serving if the master fails —
so a node or whole-site outage doesn't break resolution.

## Engine: Technitium DNS Server v15 + native clustering

Technitium's **clustering** is a single-master model that matches the
master/agent goal directly:

- **One primary** (the master): the only node where config changes are made;
  hosts the web console.
- **One or more secondaries** (the agents): replicate from the primary and keep
  answering independently.
- **Replicated automatically:** server settings, **DNSSEC private keys**, API
  tokens, **users/groups/permissions**, DNS apps + config, and Allowed/Blocked
  (blocklist) sections.
- **Per-node (not replicated):** cache, logs, and zones *unless* added to the
  **cluster catalog zone** (then they replicate everywhere as TSIG-secured
  secondary zones).
- **Failover:** secondaries hold the DNSSEC keys and can be **Promote-to-Primary**.

## Two tiers (we are authoritative *and* recursive, public-facing)

Running an open recursive resolver on a public authoritative server is a
DDoS-amplification risk, so the roles are split into two independent clusters:

|            | Authoritative tier            | Resolver tier                          |
|------------|-------------------------------|----------------------------------------|
| Purpose    | Host your public zones        | Recursive cache for your clients       |
| Recursion  | **OFF**                       | **ON**, restricted to internal CIDRs   |
| Exposure   | Internet :53 (your NS records)| Internal networks only                 |
| DNSSEC     | Online-signed on primary      | Validates upstream                     |
| Extras     | QPM rate-limiting             | blocklists, forwarders, split-horizon  |

### Diagram

```
                 WireGuard mesh — stable private IPs, encrypted replication
   Site A (k3s)                                          Site B (Docker)
 ┌──────────────────────────────┐   cluster sync   ┌──────────────────────────────┐
 │ AUTH primary ★ (StatefulSet)  │◀───────────────▶│ AUTH secondary                 │
 │  public zones, DNSSEC, rec OFF│   TSIG / AXFR    │  zones+keys replicated, rec OFF│
 ├──────────────────────────────┤   cluster sync   ├──────────────────────────────┤
 │ RESOLVER primary ★            │◀───────────────▶│ RESOLVER secondary             │
 │  recursion ON (internal only) │                  │  same config synced            │
 └──────────────────────────────┘                  └──────────────────────────────┘
        │ office A clients                                  │ office B clients
        ▼                                                   ▼
   Prometheus ← technitium-exporter (cluster mode) + blackbox dns_probe → Grafana / Alertmanager
   Key alert: SOA-serial drift primary↔secondary = replication broken
```

## Hard constraints (discovered, design-critical)

1. **No TLS-terminating reverse proxy in front of the cluster/web port.**
   Clustering authenticates node-to-node with **DANE-EE TLS**; a proxy presents a
   different cert and breaks validation. Use Technitium's own HTTPS (self-signed
   + DANE). For human SSO, use the built-in **OIDC** (v15).
2. **Static IPs per node.** In k3s → StatefulSet + fixed **MetalLB** LoadBalancer
   IP (or hostNetwork) + PVC; *not* an Ingress.
3. **Multi-site → WireGuard mesh.** Gives every node a stable private IP,
   encrypts replication over the WAN, and solves NAT in one move.
4. **Public authoritative HA = multiple NS records at diverse IPs/sites.**
   Anycast is an optional later optimization (needs your own AS + PI space).
5. **DNSSEC keys live on the primary**, sync to secondaries (promotable).
   Publish the **DS record at your registrar**; plan key rollover.

## Sources

- Clustering: <https://blog.technitium.com/2025/11/understanding-clustering-and-how-to.html>
- Catalog zones: <https://blog.technitium.com/2024/10/how-to-configure-catalog-zones-for.html>
- v15 release: <https://blog.technitium.com/2026/04/technitium-dns-server-v15-released.html>
- Docker image: <https://hub.docker.com/r/technitium/dns-server>
- API docs: <https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md>
- Prometheus exporter + Grafana dashboard 24555:
  <https://github.com/guycalledseven/technitium-dns-prometheus-exporter>
