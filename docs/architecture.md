# Architecture

MazeDNS is a custom DNS filtering resolver (AdGuard / Pi-hole class) with advanced
DNS features, a React control panel, pluggable auth, and a path to multi-site
clustering. Built in Go; the only third-party piece in the hot path is the DNS
wire codec (`miekg/dns`).

## Components

```
                      ┌──────────────────────────────────────────────┐
   DNS clients ──53──▶ │  DNS ENGINE (data plane, Go + miekg/dns)      │
   (UDP/TCP, later     │   parse → identify client → FILTER → cache    │
    DoH/DoT/DoQ)       │   → upstream → DNSSEC-validate → cache → log  │
                      └───────────────┬──────────────────────────────┘
                                       │ reads rules/config, writes stats/logs
                      ┌───────────────▼──────────────────────────────┐
                      │  DATASTORE — SQLite (pure-Go)                  │
                      │  upstreams, blocklists, rules, rewrites,       │
                      │  clients/groups, users/sessions, query log     │
                      └───────────────▲──────────────────────────────┘
                                       │ CRUD / stats
                      ┌───────────────┴──────────────────────────────┐
   Admin (browser) ──▶ │  CONTROL PLANE — Go HTTP JSON API + /metrics  │
                      │   auth:  local argon2id   |   OIDC Authentik   │
                      └───────────────▲──────────────────────────────┘
                                       │ JSON over HTTPS
                      ┌───────────────┴──────────────────────────────┐
                      │  FRONTEND — React + Vite + TS SPA             │
                      │   dashboard · query log · config · auth        │
                      └──────────────────────────────────────────────┘
```

## Query pipeline (the heart)

1. **Receive** (UDP/TCP; later DoH/DoT/DoQ) and parse with `miekg/dns`.
2. **Identify client** (source IP → client/group → policy).
3. **Filter:** allowlist → blocklists (hosts / adblock-syntax / regex) →
   rewrites / local records. Blocked → synthesized response
   (NXDOMAIN / `0.0.0.0` / custom IP).
4. **Cache** lookup (TTL-aware, with negative caching). Hit → respond.
5. **Upstream:** forward via the configured strategy (fastest / parallel /
   per-domain split-horizon) over UDP/TCP/DoT/DoH.
6. **DNSSEC** validation (later phase).
7. **Cache store**, **respond**, **log** (async — feeds stats + query log).

## Data model (SQLite, replication-ready)

Pure-Go driver (`modernc.org/sqlite`) so the binary stays static and
cross-compiles cleanly with no cgo. Every mutable row carries `id`, `updated_at`,
and tombstones for deletes — so the **same schema replicates master→agent** later
without a redesign. Tables: `settings`, `upstreams`, `blocklists`, `rules`,
`rewrites`, `clients`, `groups`, `users`, `sessions`, `query_log`
(rotated/retained).

## Auth (pluggable)

- **Local:** users in SQLite, **argon2id** password hashes, session cookies
  (or JWT).
- **OIDC (Authentik):** authorization-code + PKCE; map Authentik groups → roles
  (RBAC: admin / read-only). Selected via config; both can be enabled at once.

## Clustering

MazeDNS separates the **control plane** from the **data plane** so dashboard,
API, and classifier load can never affect resolver latency. They ship as two
images (`mazedns-control-plane`, `mazedns-dns-agent`).

- **Control plane** = source of truth (its SQLite/Postgres). It serves the web UI,
  API, auth, classifier, list refresher, cluster coordination, and the
  cluster-wide dashboard. It **never answers DNS**.
- **DNS agents** = the data plane. Each agent serves DNS (UDP/TCP, optional
  DoT/DoH), replicates its effective filtering config from the control plane, and
  ships its query log + counters back for the dashboard. Agents keep resolving
  from their local copy even if the control plane is unreachable.

**Replication.** Each agent polls `GET /api/cluster/snapshot` on its interval,
authenticating with a per-node API key (Bearer). The snapshot carries the rules
and rewrites plus a short content **version hash** (`store.ConfigVersion`, an
order-independent hash of the replicated config); the agent applies a new snapshot
only when its own hash differs, so steady state is a cheap no-op. Query logs and
counters flow the other way via `POST /api/cluster/log`. None of this touches the
DNS hot path.

**Enrollment (token auto-join).** The control plane holds a shared **join token**
(`MAZEDNS_JOIN_TOKEN`). An agent boots with the control-plane URL, the join token,
and a node name, and self-registers at `POST /api/cluster/enroll`; the control
plane validates the token (constant-time), issues a per-node key, and the agent
persists that key locally (in its `app_meta`) for all later polls. If the control
plane sets `require_approval`, the node is created **pending** and cannot pull
config until an admin approves it in the Cluster tab. An agent that loses its key
(or whose key is revoked) re-enrolls automatically with the join token. A per-node
key can also be issued manually from the UI when no join token is used.

- Transport over a **WireGuard mesh**; deploy on Docker + k3s; HA via multiple
  agents (and later anycast). The row-versioned schema above is what makes this
  incremental rather than a rewrite.

## Observability

Structured logs + Prometheus `/metrics`: queries total, blocked total, cache-hit
ratio, upstream-latency histograms, per-client / per-type counters. Grafana
dashboards in a later phase.

## Security posture

- Admin API/UI bound to the management network / VPN, never public.
- Resolver serves recursion only to configured client CIDRs (no open resolver);
  per-client **rate limiting**.
- DNSSEC validation; OIDC secrets via env / secret store; argon2id for local creds.

## Stack rationale

- **Go + miekg/dns:** proven for high-throughput resolvers (AdGuard Home is Go),
  single static binary, trivial Docker/k3s. The library is used for wire format
  only — all resolver/filter/control logic is ours.
- **React/Vite/TS:** rich, interactive dashboards and query-log views.
- **SQLite (pure-Go):** zero-ops embedded store; row-versioned for clustering.
