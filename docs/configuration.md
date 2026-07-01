# Configuration

MazeDNS runs as **two components** that share one config format but use different
parts of it:

- **control-plane** — web UI, API, auth, classifier, cluster coordination. Never
  serves DNS.
- **dns-agent** — the resolver (data plane). Serves DNS, replicates its filtering
  rules from the control plane, exposes only `/healthz` + `/metrics`.

Every setting can be supplied two ways:

1. A **YAML file** passed with `--config` (see the ready-to-copy examples
   [`configs/control-plane.example.yaml`](../configs/control-plane.example.yaml)
   and [`configs/dns-agent.example.yaml`](../configs/dns-agent.example.yaml)).
2. An **environment variable** (`MAZEDNS_*`). Env always overrides the file — the
   preferred way to configure containers.

Two classes of settings behave differently:

- **Bootstrap settings** (listen/API address + ports, TLS, database, auth/OIDC,
  cluster) are read on **every start**.
- **Operational settings** (upstreams, forwarders, cache, rate limit, DNSSEC,
  `filter.block_response`) are only **seeded** from the file on first run; after
  that they live in the database and are edited from the UI. Editing them in the
  file later has no effect unless the database has no settings row yet.

This page is split into the three concerns from the two example files:
[control plane](#control-plane-settings), [DNS agent](#dns-agent-settings), and
[infrastructure integrations](#infrastructure-integrations).

---

## Control plane settings

Only the control-plane binary uses these. It has no DNS listener, so it has no
`listen`/`upstreams`/`cache`/`filter` sections (any it inherits are ignored).

### API / UI

| YAML | Env | Default | Notes |
|---|---|---|---|
| `api.address` | `MAZEDNS_API_ADDRESS` | `127.0.0.1` | Bind for UI + API + `/metrics` + `/healthz`. Keep it private; put a TLS reverse proxy in front for remote access. |
| `api.port` | — | `8080` | |

### Authentication

| YAML | Env | Default | Notes |
|---|---|---|---|
| `auth.enabled` | — | `true` | Require login for API + UI. |
| `auth.session_ttl` | — | `24h` | |
| `auth.admin.username` | `MAZEDNS_ADMIN_USERNAME` | `admin` | First-run bootstrap admin (created only if no users exist). |
| `auth.admin.password` | `MAZEDNS_ADMIN_PASSWORD` | *(random)* | Empty → a random password is generated and logged **once** at first start. |

**SSO via OIDC** (Authentik or any OIDC provider). Every field also has an env
override, which is the recommended way in containers:

| YAML | Env |
|---|---|
| `auth.oidc.enabled` | `MAZEDNS_OIDC_ENABLED` |
| `auth.oidc.issuer` | `MAZEDNS_OIDC_ISSUER` |
| `auth.oidc.client_id` | `MAZEDNS_OIDC_CLIENT_ID` |
| `auth.oidc.client_secret` | `MAZEDNS_OIDC_CLIENT_SECRET` |
| `auth.oidc.redirect_url` | `MAZEDNS_OIDC_REDIRECT_URL` |
| `auth.oidc.scopes` | `MAZEDNS_OIDC_SCOPES` |
| `auth.oidc.groups_claim` | `MAZEDNS_OIDC_GROUPS_CLAIM` |
| `auth.oidc.admin_group` | `MAZEDNS_OIDC_ADMIN_GROUP` |
| `auth.oidc.disable_password_login` | `MAZEDNS_OIDC_DISABLE_PASSWORD_LOGIN` |
| `auth.oidc.auto_login` | `MAZEDNS_OIDC_AUTO_LOGIN` |

The `redirect_url` must match the value registered at the provider **character for
character** — it is logged at startup so you can compare. Env values are trimmed of
surrounding quotes to avoid a common `env_file` mistake.

### Cluster (control-plane side)

| YAML | Env | Default | Notes |
|---|---|---|---|
| `cluster.enabled` | `MAZEDNS_CLUSTER_ENABLED` | `false` | Serve the cluster endpoints. |
| `cluster.join_token` | `MAZEDNS_JOIN_TOKEN` | *(empty)* | Shared secret agents present to self-enroll. Empty disables auto-join. |
| `cluster.require_approval` | `MAZEDNS_REQUIRE_APPROVAL` | `false` | Hold self-enrolled agents until an admin approves them in the Cluster tab. |

Pre-provisioning without a token: set `MAZEDNS_CLUSTER_BOOTSTRAP_NODES` to
`name1=key1,name2=key2` to seed node keys at startup (dev/automation).

### Classifier

Optional domain classification (static threat/reputation signals + an optional
LLM). Runs on the control plane only. These values **seed** the database on first
run; afterwards edit them live under **Settings → AI classification**. See
[`configs/control-plane.example.yaml`](../configs/control-plane.example.yaml) for
the full annotated block. Env overrides: `MAZEDNS_CLASSIFIER_ENABLED`,
`MAZEDNS_CLASSIFIER_ENDPOINT`, `MAZEDNS_CLASSIFIER_MODEL`, `MAZEDNS_CLASSIFIER_MODE`,
`MAZEDNS_CLASSIFIER_API_KEY`.

---

## DNS agent settings

Only the dns-agent binary uses these. Rules and rewrites are **replicated from the
control plane** and are not configured here; file blocklists are loaded locally by
each agent (they are not replicated).

### DNS listener

| YAML | Env | Default | Notes |
|---|---|---|---|
| `listen.address` | `MAZEDNS_LISTEN_ADDRESS` | `0.0.0.0` | |
| `listen.port` | — | `5300` | Map host `53 → 5300`, or grant `CAP_NET_BIND_SERVICE` to bind 53 directly. |

Encrypted endpoints for clients (self-signed cert if `tls.*` is empty):
`dot.enabled`/`dot.port` (853), `doh.enabled`/`doh.port`/`doh.path` (8443),
`tls.cert_file`/`tls.key_file`.

### Resolving (operational — seeded on first run)

`upstreams` (tried in order; plain `1.1.1.1:53`, `tls://…#servername`, or
`https://…/dns-query`), `forwarders` (split-horizon per suffix), `cache`
(`enabled`/`max_entries`/`min_ttl`/`max_ttl`), `rate_limit` (`enabled`/`qpm`),
`dnssec.enabled`, `filter.block_response` (`nxdomain`|`zeroip`), `zones`
(authoritative records). After first run these are edited in the UI, not the file.

### Health / metrics endpoint

| YAML | Env | Default | Notes |
|---|---|---|---|
| `api.address` | `MAZEDNS_API_ADDRESS` | `127.0.0.1` | The agent exposes only `/healthz` + `/metrics`, **unauthenticated**, so it binds loopback by default. To let Prometheus scrape it, set this to the agent's overlay/VPN IP (recommended) or `0.0.0.0`. |
| `api.port` | — | `8080` | |

### Cluster (agent side)

| YAML | Env | Default | Notes |
|---|---|---|---|
| `cluster.cp_url` | `MAZEDNS_CP_URL` | *(empty)* | Control-plane base URL, e.g. `https://dns.example.com`. Setting it auto-enables cluster mode. |
| `cluster.join_token` | `MAZEDNS_JOIN_TOKEN` | *(empty)* | Shared secret used to self-enroll; the control plane issues a per-node key in return. |
| `cluster.node_key` | `MAZEDNS_NODE_KEY` | *(empty)* | Per-node key — leave empty when using a join token. |
| `cluster.node_name` | `MAZEDNS_NODE_NAME` | *(hostname)* | Name to enroll under. |
| `cluster.master_ip` | `MAZEDNS_CP_IP` (or `MAZEDNS_MASTER_IP`) | *(empty)* | Pin the control-plane IP so the agent reaches it without DNS. TLS still verifies the URL host. |
| `cluster.advertise_addr` | `MAZEDNS_ADVERTISE_ADDR` | *(auto)* | The site-reachable address the agent reports to the control plane, used for display and generated client config. Set it when the auto-detected address (e.g. a docker-internal IP) would be wrong. |
| `cluster.interval` | — | `30s` | Snapshot poll interval. |

An agent with no `cp_url` runs **standalone**: it resolves and filters from its own
local config, with no control plane.

---

## Infrastructure integrations

Cross-cutting backends. `MAZEDNS_LOG_LEVEL` (`debug|info|warn|error`) applies to
both components.

### Database

Each component stores its state in a database. Two backends:

- **Embedded SQLite** (default) — one file, created on first run, no setup.
- **External PostgreSQL** — point the component at your own Postgres server.

| YAML | Env | Notes |
|---|---|---|
| `database.driver` | `MAZEDNS_DB_DRIVER` | `sqlite` (default) or `postgres`. |
| `database.path` | `MAZEDNS_DB_PATH` | SQLite file path. In containers this lives under `/data` — mount a volume there. |
| `database.dsn` | `MAZEDNS_DB_DSN` | Postgres DSN. Setting only the DSN implies the `postgres` driver. |

> **Each component needs its OWN database — never share one between the control
> plane and an agent.** An agent writes its *replicated* copy of the rules and its
> query-log buffer into its own tables; pointing it at the control plane's database
> would overwrite the source of truth. In practice: use PostgreSQL for the control
> plane (managed backups / HA / query it with your own tooling), and leave agents
> on their local SQLite.

**SQLite:** put the file on **fast local storage**. It runs in WAL mode with a
large page cache and memory-mapped reads (the dashboard's aggregate scans rely on
this). A networked filesystem (NFS/SMB) can corrupt WAL databases and is **not
supported**.

**PostgreSQL:** the schema is created automatically on first connect. The DSN
accepts the standard URL form
`postgres://user:pass@host:5432/mazedns?sslmode=disable` or libpq keyword form; use
`sslmode=require` for TLS. MazeDNS writes SQLite-dialect SQL internally and adapts
it to PostgreSQL at runtime (placeholders, aggregates, DDL), so the feature set is
identical on either backend.

> **Status:** the PostgreSQL backend is newer than SQLite — validate it against
> your server before relying on it in production. SQLite remains the tested default.

### Metrics — VictoriaMetrics (`metrics.victoria_metrics`)

Each component **pushes** its own Prometheus metrics to a VictoriaMetrics instance
(`/api/v1/import/prometheus`), labelled by `instance`, so a cluster aggregates in VM
without VM having to scrape every node. Fields: `enabled`, `url`, `interval` (15s),
`job` (`mazedns`), `instance` (empty → hostname), `username`/`password` (optional
basic auth). These are also editable live in the UI.

### Logs — VictoriaLogs (`metrics.victoria_logs`)

The **control plane** ships the cluster-wide query log (its own plus agents' shipped
entries) to VictoriaLogs (`/insert/jsonline`) for retention beyond the local window.
Fields: `enabled`, `url`, `interval` (15s), `username`/`password`.

### Client identity — NetBird / reverse DNS

The control plane can turn client IPs into peer/hostnames in the UI. Configured live
under **Settings** (NetBird API token + reverse-DNS resolvers), not via the config
file.

### Runtime tuning

`GOGC` (default raised to `200` internally for less GC jitter) and `GOMEMLIMIT` are
honored from the environment on both binaries.
