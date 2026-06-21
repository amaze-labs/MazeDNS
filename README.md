# MazeDNS — Clustered DNS System

A production-oriented, multi-site **clustered DNS** built on
[Technitium DNS Server](https://technitium.com/dns/) v15, running on **Docker**
and **k3s**.

- **Master/agent model** via Technitium's native **clustering**: one *primary*
  owns config + the web UI; *secondaries* replicate it and keep serving if the
  primary fails (and can be promoted).
- **Two tiers**, because this deployment is both authoritative and recursive:
  - **Authoritative** (public-facing): hosts your zones, DNSSEC-signed,
    recursion OFF.
  - **Resolver** (internal): recursive caching for clients, recursion ON but
    restricted to internal networks.
- **Multi-site** over a WireGuard mesh; observability via Prometheus + Grafana.

See **[docs/architecture.md](docs/architecture.md)** for the full design and
**[docs/roadmap.md](docs/roadmap.md)** for the build phases.

## Quick start (Phase 1 — local proof of concept)

Spin up a 2-node cluster on your laptop and watch replication + failover:

```bash
cd compose/phase1-local-cluster
./scripts/up.sh
# then follow compose/phase1-local-cluster/README.md
```

## Repository layout

```
MazeDNS/
├── docs/
│   ├── architecture.md          # design: the two tiers, clustering, constraints
│   └── roadmap.md               # phased build plan (Phase 0–6)
└── compose/
    └── phase1-local-cluster/    # ← you are starting here
        ├── docker-compose.yml   # 2-node cluster (static IPs, HTTPS for DANE-EE)
        ├── .env.example
        ├── README.md            # step-by-step walkthrough
        └── scripts/             # up / verify / failover-test
```

(k8s manifests, the WireGuard mesh, and the monitoring stack arrive in later phases.)

## ⚠️ Security notes (read before going beyond local)

- **Never expose the web/API port (5380 / 53443) to the internet.** Keep it on a
  management network / VPN only. v15 supports OIDC SSO for admin auth.
- **Never run an open recursive resolver on a public authoritative server** —
  that's why the resolver and authoritative tiers are kept separate.
- Clustering authenticates node-to-node with **DANE-EE TLS**: do **not** put a
  TLS-terminating reverse proxy in front of the cluster/web port.
- Clustering requires **static IPs** per node.
