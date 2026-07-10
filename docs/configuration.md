# Configuration

MazeDNS is configured with **environment variables** (`MAZEDNS_*`) — the preferred
way for containers — or a **YAML file** baked into the image. Env always overrides
the file. This page is the single source of truth for every variable; other docs
link here rather than repeat the tables.

The **control plane** is configured through its web UI: a fresh install runs a
[first-boot setup wizard](install.md#first-boot-setup-wizard) (trust-on-first-use —
complete it before exposing the port), and everything after is edited under
**Settings**. The **DNS agent** keeps env-var configuration — that's the right fit
for a stateless resolver.

Two classes of settings behave differently:

- **Bootstrap settings** — read on **every start**, env/YAML only, because they're
  needed before the database or UI exist: the database (`MAZEDNS_DB_*`), the API
  bind (`MAZEDNS_API_ADDRESS`, `api.port`), and `MAZEDNS_LOG_LEVEL`.
- **Runtime settings** — everything else on the control plane (DNS defaults, SSO,
  session TTL, cluster policy, classifier, metrics/logs export). These are **seeded
  once** from env/YAML on first boot (so an existing deployment upgrades with no
  changes), then stored in the **database as the single source of truth** and edited
  live in the UI. After that first boot, the env/YAML runtime values are **ignored**
  (a startup log line says so). There is no dual source.

The first admin is created by the wizard, not an env var. To reset a lost admin,
use the break-glass CLI (not read on every boot):

```bash
control-plane reset-admin --username admin [--password …]
```

### Security & upgrade notes

- **Sessions are stored hashed.** On upgrade, existing sessions no longer resolve —
  everyone is logged out once and must sign in again. Expected, one-time.
- **Login is rate-limited** per source IP and per username (default 10 attempts /
  60s; `0` disables). Tune under **Settings → Access & SSO**; applied live.
- **Password policy:** at least 10 characters mixing letters with digits or symbols,
  enforced on every password path (setup, user create/reset, self-change,
  `reset-admin`).
- **Session cookies are `Secure`** when the request is HTTPS (`r.TLS` or
  `X-Forwarded-Proto: https`) — put the control plane behind TLS in production.
- **SSO accounts are keyed by the IdP `subject`**, not the username, so an OIDC user
  whose `preferred_username` matches an existing (e.g. local admin) account gets a
  separate, suffixed account instead of taking it over.
- **`/metrics`** can require a bearer token — see
  [Scraping /metrics](#scraping-metrics-prometheus).

The variable that applies to a component depends on which image it is:

- **Control plane** (`mazedns-control-plane`) — UI, API, auth, classifier, cluster
  coordination. No DNS listener.
- **DNS agent** (`mazedns-dns-agent`) — the resolver. Rules and rewrites are
  replicated from the control plane, not configured here.

---

## Environment variables

"Required" means the component won't start, or won't do its job, without it.

### Control plane

**Bootstrap** (read every start):

| Variable | Required | Default | Description |
|---|---|---|---|
| `MAZEDNS_API_ADDRESS` | In containers | `127.0.0.1` | HTTP bind address (set `0.0.0.0` in containers). |
| `MAZEDNS_DB_PATH` / `MAZEDNS_DB_DRIVER` / `MAZEDNS_DB_DSN` | No | sqlite `mazedns.db` | Datastore location (see [Shared](#shared-both-components)). |
| `MAZEDNS_LOG_LEVEL` | No | `info` | `debug`/`info`/`warn`/`error`. |

Clustering has no enable flag: the control plane **always** serves the cluster
endpoints. To let agents join, create an **enrollment key** in the UI (Cluster →
Enrollment keys) or via the admin API and pass it to each agent as
`MAZEDNS_JOIN_TOKEN`. The removed `MAZEDNS_CLUSTER_ENABLED` and
`MAZEDNS_CLUSTER_BOOTSTRAP_NODES` env vars are ignored (a startup warning is logged
if still set) — pre-provisioning nodes with fixed keys is no longer supported
because it put node secrets in the environment and bypassed enrollment keys, the
approval flow, and the server-assigned-UUID identity model.

To **pause replication** for a node (previously `cp_url` + `enabled: false`), either
unset `MAZEDNS_CP_URL`/`cp_url` so the agent runs standalone, or — to keep it
enrolled — put the node into **maintenance/drain** from the control-plane UI
(Cluster → the node), which stops it serving without de-enrolling it.

**Runtime** (seed-only — configured in the UI after first boot). The variables below
still work, but **only to seed the database on first boot**; afterwards they are
ignored and the values are edited under **Settings** (or the setup wizard):

| Seed variable | UI location | Notes |
|---|---|---|
| `MAZEDNS_ADMIN_USERNAME` / `MAZEDNS_ADMIN_PASSWORD` | *(removed)* | The first admin is created by the **setup wizard**; these env vars are no longer read. Recover with `control-plane reset-admin`. |
| `MAZEDNS_REQUIRE_APPROVAL` | Settings → Access → Cluster policy | Hold new agents pending approval. |
| `MAZEDNS_KEY_MAX_AGE` / `MAZEDNS_KEY_GRACE` | Settings → Access → Cluster policy | Per-node key rotation policy. |
| `MAZEDNS_ADVERTISE_ADDR` | Settings → Access → Cluster policy | Address handed to agents at enrollment. |
| `MAZEDNS_CLASSIFIER_*` | Settings → AI classification | Endpoint/model/mode/API key. |
| `MAZEDNS_OIDC_*` | Settings → Access & SSO | Issuer, client ID/secret, redirect URL, groups, flags. |

Runtime **secrets** (OIDC client secret, metrics passwords, classifier API keys)
are stored in the database and are **write-only over the API**: the UI shows them
masked and never receives the value; sending an empty field leaves the stored secret
unchanged. Settings changes are recorded in an **audit log** (who/when/which keys —
never the secret values), viewable at `GET /api/settings/audit`.

### DNS agent

| Variable | Required | Default | Description |
|---|---|---|---|
| `MAZEDNS_CP_URL` | For clustering | *(empty)* | Control-plane base URL, e.g. `https://cp.example.com:8080`. Setting it (with a credential) makes the agent join the cluster — there is no separate enable flag. (Deprecated alias: `MAZEDNS_MASTER_URL`.) With no URL the agent runs **standalone** — resolving and filtering from its own local config. |
| `MAZEDNS_CP_IP` | Conditional | *(auto)* | Pin the control plane's IP so the agent reaches it without DNS (TLS still verifies the URL host). Needed when the agent can't resolve the CP's FQDN — e.g. it's its network's only DNS. Left empty, the agent auto-learns and persists the address the CP advertises at enrollment. (Deprecated alias: `MAZEDNS_MASTER_IP`.) |
| `MAZEDNS_NODE_NAME` | No | *(hostname)* | **Initial** display label the agent enrolls under. A node's identity is an immutable UUID the control plane assigns at first enrollment and the agent stores locally (alongside its node key); this name is just an editable label. You can rename a node in the UI, and changing `MAZEDNS_NODE_NAME` after enrollment does **not** create a new node or change its identity. The UUID is never user-configurable. |
| `MAZEDNS_NODE_KEY` | No | *(auto-issued)* | Per-node API key. Leave empty when using an enrollment key — one is issued, persisted, and rotated automatically. **Retained** (not part of the removed bootstrap-nodes flow) for automation/recovery: supply a key minted for a specific node via the admin API (`POST /api/cluster/nodes/{id}/key`) to attach an agent without the enrollment round-trip. |
| `MAZEDNS_LISTEN_ADDRESS` | No | `0.0.0.0` | DNS bind address. |
| `MAZEDNS_LISTEN_PORT` | No | `53` | DNS listen port. The image binds `53` as non-root via a `CAP_NET_BIND_SERVICE` file capability. |
| `MAZEDNS_UDP_LISTENERS` | No | *(auto)* | Number of `SO_REUSEPORT` UDP sockets that share the port so the kernel spreads packets across cores. **Defaults to one per available CPU** (bounded at 8; scales with the container's CPU quota). Set to `1` to force a single socket, or to a specific number to pin it. Each socket reserves an 8 MiB read + 8 MiB write buffer, so more sockets means more memory. |

### Shared (both components)

| Variable | Required | Default | Description |
|---|---|---|---|
| `MAZEDNS_API_ADDRESS` | In containers | `127.0.0.1` | Bind address of the HTTP server. Control plane: UI + API + `/metrics` (optionally token-gated — see [Scraping /metrics](#scraping-metrics-prometheus)) + `/healthz`. Agent: `/healthz` + `/metrics` only (unauthenticated). Set to `0.0.0.0` so a mapped port is reachable; for an agent, prefer the node's private/overlay IP. |
| `MAZEDNS_JOIN_TOKEN` | For clustering | *(empty)* | The **enrollment key** an agent presents to self-enroll and receive a per-node key. Create/list/revoke enrollment keys in the UI (Cluster → Enrollment keys) with optional expiry and max-uses. On the **control plane** this variable is *deprecated*: if set it is auto-imported once as a never-expiring enrollment key so existing agents keep working — prefer managing keys in the UI. Enrollment keys only work at `/api/cluster/enroll`, never for serving DNS or shipping logs. |
| `MAZEDNS_KEY_MAX_AGE` | No | `720h` (30d) | Control plane: rotate a node's per-node key once it exceeds this age. The new key is handed to the agent on its next poll; the old key stays valid for `MAZEDNS_KEY_GRACE`. |
| `MAZEDNS_KEY_GRACE` | No | `15m` | Control plane: how long a rotated-out node key stays valid — the zero-downtime overlap window. |
| `MAZEDNS_ADVERTISE_ADDR` | No | *(auto)* | Site-reachable address a node advertises. On the control plane it's the CP address handed to agents (which pin it); on an agent it's the DNS address reported to the CP for display and generated client config. Set it when the auto-detected address (e.g. a docker-internal IP) would be wrong. |
| `MAZEDNS_DB_PATH` | No | `mazedns.db` | SQLite file path. In containers set it under the mounted volume, e.g. `/data/mazedns.db`. |
| `MAZEDNS_DB_DRIVER` | No | `sqlite` | `sqlite` or `postgres`. |
| `MAZEDNS_DB_DSN` | For Postgres | *(empty)* | PostgreSQL DSN, e.g. `postgres://user:pass@host:5432/mazedns?sslmode=disable`. Setting only the DSN implies the `postgres` driver. |
| `MAZEDNS_BLOCKLIST_FILES` | No | *(empty)* | Local blocklist file path(s), comma/space separated (absolute paths). Replaces `filter.blocklist_files`. Loaded locally per component (not replicated). |
| `MAZEDNS_LOG_LEVEL` | No | `info` | `debug`, `info`, `warn`, or `error`. |

> **Never share one database between the control plane and an agent.** Each writes
> its own tables; pointing an agent at the control plane's database would overwrite
> the source of truth. Use PostgreSQL for the control plane if you want managed
> backups/HA, and leave agents on their local SQLite.

The Go garbage-collector knobs `GOGC` (raised to `200` internally to cut GC jitter)
and `GOMEMLIMIT` are also honored on both images.

---

## YAML configuration reference

Every variable above maps to a field in the YAML file the image reads
(`/etc/mazedns/mazedns.yaml`). Full annotated examples ship in the repo:

- [`configs/control-plane.example.yaml`](../configs/control-plane.example.yaml)
- [`configs/dns-agent.example.yaml`](../configs/dns-agent.example.yaml)

You rarely need to touch the file for a container deployment — env vars cover the
bootstrap settings, and everything operational is edited in the UI. Mount your own
file at `/etc/mazedns/mazedns.yaml` only if you prefer file-based config.

### Bootstrap sections (read every start)

| Section | Keys | Notes |
|---|---|---|
| `listen` | `address` (`0.0.0.0`), `port` (`53`) | Agent DNS listener (agent only). |
| `api` | `enabled` (`true`), `address` (`127.0.0.1`), `port` (`8080`) | HTTP server. |
| `dot` / `doh` | `enabled` (`false`), `address`, `port` (`853`/`8443`), `doh.path` (`/dns-query`) | Encrypted DNS endpoints for clients (agent only). |
| `tls` | `cert_file`, `key_file` | Empty → a self-signed cert is generated on start. |
| `database` | `driver` (`sqlite`), `path` (`mazedns.db`), `dsn` | See the shared table and the note above. |
| `log` | `level` (`info`) | The `query_log` toggle is a runtime setting. |
| `cluster` | agent-side `cp_url`, `cp_ip`/`master_ip`, `node_name`, `node_key`, `interval` (`30s`) | Agent wiring. No enable flag — an agent joins when `cp_url` + a credential are set; the control plane always serves cluster endpoints. |

### Runtime sections — control plane (seeded once, then edited in the UI)

On the control plane these are seeded from the file on first boot only, then owned
by the database and edited under **Settings** (secrets are write-only):

| Section / setting | UI location |
|---|---|
| `auth.session_ttl`, login rate limit (attempts/window, default 10/60s), `auth.oidc.*` | Settings → Access & SSO |
| Metrics scrape token for `/metrics` (generate/clear) | Settings → Integrations |
| `cluster.require_approval`, `key_max_age` (`720h`), `key_grace` (`15m`), `advertise_addr`; `join_token` (deprecated → auto-imported as an enrollment key) | Settings → Access → Cluster policy |
| `classifier.*` | Settings → AI classification |
| `metrics.victoria_metrics.*`, `metrics.victoria_logs.*` | Settings → Integrations |
| `log.query_log` | Settings |

> `auth.admin.*` is no longer read — the first admin is created by the setup wizard.

### Runtime sections — DNS agent / resolver (seeded once, then edited in the UI)

The resolver settings below apply to whichever component runs a resolver. On the
control plane they configure only its headless resolver (it serves no DNS); agents
take rules/rewrites from the control plane via replication.

| Section | Keys |
|---|---|
| `upstreams` | Ordered list; plain `1.1.1.1:53`, `tls://1.1.1.1:853#cloudflare-dns.com`, or `https://dns.quad9.net/dns-query`. |
| `forwarders` | Split-horizon per suffix: `- { suffix: "corp.internal", upstreams: [...] }`. Seeds this node's local forwarders; cluster-wide scoped forwarders managed in the UI override a local entry with the same suffix. |
| `cache` | `enabled` (`true`), `max_entries` (`10000`), `min_ttl` (`10s`), `max_ttl` (`24h`). |
| `rate_limit` | `enabled` (`false`), `qpm` (`600`). |
| `dnssec` | `enabled` (`false`) — force the DO bit upstream and surface AD. |
| `filter` | `enabled` (`true`), `block_response` (`nxdomain` or `zeroip`), `blocklist_files`. |
| `zones` | Authoritative records served locally. |

---

## Infrastructure integrations

### Metrics — VictoriaMetrics (`metrics.victoria_metrics`)

Each component **pushes** its own Prometheus metrics to a VictoriaMetrics instance
(`/api/v1/import/prometheus`), labelled by `instance`, so a cluster aggregates in VM
without VM scraping every node. Fields: `enabled`, `url`, `interval` (`15s`), `job`
(`mazedns`), `instance` (empty → hostname), `username`/`password`. Also editable
live in the UI.

### Scraping `/metrics` (Prometheus)

`/metrics` is served by both components. On the **control plane** it is open by
default; you can require a bearer token under **Settings → Integrations → Metrics
scrape token**. Click *Generate* (the token is shown once and stored hashed), then
point Prometheus at it:

```yaml
scrape_configs:
  - job_name: mazedns-control-plane
    static_configs:
      - targets: ["control-plane:8080"]
    authorization:
      type: Bearer
      credentials: "<the-generated-token>"
```

With no token set, requests without an `Authorization` header still succeed
(unchanged behavior). *Clear* the token to reopen `/metrics`. While first-boot setup
is pending, `/metrics` is blocked entirely (only `/healthz` is public). The agent's
`/metrics` has no token and stays open — restrict it at the network layer.

### Logs — VictoriaLogs (`metrics.victoria_logs`)

The **control plane** ships the cluster-wide query log (its own plus agents' shipped
entries) to VictoriaLogs (`/insert/jsonline`) for retention beyond the local window.
Fields: `enabled`, `url`, `interval` (`15s`), `username`/`password`.

### PostgreSQL notes

The schema is created automatically on first connect. The DSN accepts the URL form
`postgres://user:pass@host:5432/mazedns?sslmode=disable` or libpq keyword form; use
`sslmode=require` for TLS. Put SQLite files on **fast local storage** (WAL mode,
memory-mapped reads) — a networked filesystem (NFS/SMB) can corrupt them and is not
supported.
