# Architecture

MazeDNS is a custom DNS filtering resolver (AdGuard / Pi-hole class) with advanced
DNS features, a React control panel, pluggable auth, and multi-site clustering.
Built in Go; the only third-party piece in the hot path is the DNS
wire codec (`miekg/dns`).

## Components

```
                       ┌────────────────────────────────────────────────┐
   DNS clients ──53──▶ │  DNS AGENT (data plane, Go + miekg/dns)        │
   (UDP/TCP/DoT/DoH)   │  rate-limit → zones → rewrites → block →       │
                       │  cache → upstream → respond → log              │
                       └──────────────────┬─────────────────────────────┘
                                          │ pulls config, ships logs + counters
                       ┌──────────────────▼─────────────────────────────┐
   Admin (browser) ──▶ │  CONTROL PLANE — HTTP JSON API + /metrics      │
                       │  auth: local argon2id | OIDC · React SPA       │
                       └──────────────────┬─────────────────────────────┘
                                          │ CRUD / stats
                       ┌──────────────────▼─────────────────────────────┐
                       │  DATASTORE — SQLite (pure-Go) or Postgres      │
                       │  settings, rules, rewrites, forwarders,        │
                       │  lists, nodes, sites, users, query_log         │
                       └────────────────────────────────────────────────┘
```

## Query pipeline (the heart)

1. **Receive** (UDP/TCP, optional DoT/DoH) and parse with `miekg/dns`. DoQ is not
   implemented.
2. **Rate-limit** by source IP, when a per-client QPM is configured (off by
   default) → `REFUSED`.
3. **Authoritative zones** we own — answered locally, never forwarded.
4. **Rewrites / local records** — exact match, then `*.suffix` wildcard. A wildcard
   yields to a conditional forwarder whose suffix matches more specifically; an
   exact rewrite always wins.
5. **Block** — blocklists + deny rules (hosts / adblock syntax), unless the name is
   explicitly allowed or blocking is paused. Blocked → synthesized NXDOMAIN or
   `0.0.0.0`/`::`.
6. **Cache** lookup — TTL-aware, with serve-stale and refresh-ahead; signed and
   unsigned answers are cached under separate keys.
7. **Upstream** — split-horizon aware, over UDP/TCP/DoT/DoH. Concurrent misses for
   the same question are coalesced into one exchange.
8. **Cache store**, **respond** (DO/AD handling, UDP capped at 1232 bytes), **log**
   (async — feeds stats + query log).

DNSSEC is **transparent**, not validated locally: MazeDNS can force the DO bit
upstream and passes the AD flag through, leaving validation to the upstream.

## Data model

Pure-Go driver (`modernc.org/sqlite`) so the binary stays static and cross-compiles
cleanly with no cgo; the control plane can point at **PostgreSQL** instead
(`MAZEDNS_DB_DRIVER=postgres`). Replicated rows carry `updated_at` and tombstones for
deletes, and the snapshot is content-hashed (`store.ConfigVersion`) so an agent
applies it only when the config actually changed.

| Group | Tables |
|---|---|
| Policy (replicated) | `settings`, `rules`, `rewrites`, `forwarders`, `lists` |
| Cluster | `nodes`, `sites`, `enroll_keys`, `revoked_nodes` |
| Auth | `users`, `sessions` |
| Telemetry | `query_log` (rotated/retained), `query_rollup`, `client_rollup` |
| Classifier | `classifications`, `llm_usage`, `reputation_usage` |
| Housekeeping | `app_meta` (the agent's node id + key), `meta` |

There is no per-client *policy* model: a query's client is its source IP, used for
stats and rate limiting only — there are no `clients`/`groups` tables.

## Auth (pluggable)

- **Local:** users in SQLite, **argon2id** password hashes, server-side revocable
  session cookies (hashed at rest).
- **OIDC (Authentik):** authorization-code + PKCE; map Authentik groups → roles
  (RBAC: admin / read-only). Selected via config; both can be enabled at once.

## Clustering

MazeDNS separates the **control plane** from the **data plane** so dashboard,
API, and classifier load can never affect resolver latency. They ship as two
images (`mazedns-control-plane`, `mazedns-agent`).

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

**Enrollment (key-based auto-join).** Agents self-register with an **enrollment key**
— created in the UI (Cluster → Enrollment keys), each with an optional expiry and
max-uses and stored hashed (a deprecated `cluster.join_token` in config is imported
once as a never-expiring key). The env var `MAZEDNS_JOIN_TOKEN` carries the key. An
agent boots with the control-plane URL, an enrollment key, and a node name, and
self-registers at `POST /api/cluster/enroll`; the control plane validates the key by
SHA-256 hash lookup (checking expiry / use count / revocation), assigns the node an
immutable **UUID identity**, issues a per-node API key, and returns both. The agent
persists its node id + key locally (in its `app_meta`) for all later polls. If the
control plane sets `require_approval`, the node is created **pending** and cannot
pull config until an admin approves it in the Cluster tab. An agent that loses its
key (or whose key is revoked/rotated) re-enrolls automatically by presenting its
stored node id + current key, so it re-attaches to the SAME node. A fixed per-node
key can also be issued manually from the UI and supplied via `MAZEDNS_NODE_KEY`.

- Transport over a **WireGuard mesh**; deploy on Docker + k3s; HA via multiple
  agents (and later anycast). The row-versioned schema above is what makes this
  incremental rather than a rewrite.

## Observability

Structured logs + Prometheus `/metrics`: queries total, blocked total, cache-hit
ratio, upstream-latency histograms, per-client / per-type counters. Grafana
dashboards in a later phase.

## Security posture

- Admin API/UI bound to the management network / VPN, never public.
- **No resolver-side client ACL** — an agent answers anything that reaches its `:53`,
  so exposure is controlled at the network layer (private network / firewall).
  Per-client **rate limiting** exists but is disabled by default.
- DNSSEC left to the upstream (DO forced, AD passed through — no local validator).
- Runtime secrets (OIDC client secret, classifier keys, metrics passwords) live in
  the database and are write-only over the API; argon2id for local credentials.

## Stack rationale

- **Go + miekg/dns:** proven for high-throughput resolvers (AdGuard Home is Go),
  single static binary, trivial Docker/k3s. The library is used for wire format
  only — all resolver/filter/control logic is ours.
- **React/Vite/TS:** rich, interactive dashboards and query-log views.
- **SQLite (pure-Go):** zero-ops embedded store; row-versioned for clustering.
