# Configuration

MazeDNS is configured with **environment variables** (`MAZEDNS_*`) — the preferred
way for containers — or a **YAML file** baked into the image. Env always overrides
the file. This page is the single source of truth for every variable; other docs
link here rather than repeat the tables.

Two classes of settings behave differently:

- **Bootstrap settings** (listen/API address + ports, TLS, database, auth/OIDC,
  cluster wiring) are read on **every start**.
- **Operational settings** (upstreams, forwarders, cache, rate limit, DNSSEC,
  `filter.block_response`) are only **seeded** on first run; after that they live in
  the database and are edited live from the **Settings** tab in the UI. Changing them
  in the file later has no effect once the database has a settings row.

The variable that applies to a component depends on which image it is:

- **Control plane** (`mazedns-control-plane`) — UI, API, auth, classifier, cluster
  coordination. No DNS listener.
- **DNS agent** (`mazedns-dns-agent`) — the resolver. Rules and rewrites are
  replicated from the control plane, not configured here.

---

## Environment variables

"Required" means the component won't start, or won't do its job, without it.

### Control plane

| Variable | Required | Default | Description |
|---|---|---|---|
| `MAZEDNS_ADMIN_USERNAME` | No | `admin` | First-run bootstrap admin username (created only if no users exist). |
| `MAZEDNS_ADMIN_PASSWORD` | Recommended | *(random)* | First-run admin password. If empty, a random one is generated and logged **once** at first start. |
| `MAZEDNS_CLUSTER_ENABLED` | For clustering | `false` | Serve the cluster endpoints so agents can enroll and replicate. Agents enable cluster mode implicitly by setting `MAZEDNS_CP_URL`. |
| `MAZEDNS_REQUIRE_APPROVAL` | No | `false` | Hold self-enrolled agents as *pending* until an admin approves them in the Cluster tab. |
| `MAZEDNS_CLUSTER_BOOTSTRAP_NODES` | No | *(empty)* | Pre-provision node keys without a token, as `name1=key1,name2=key2` (automation/dev). |
| `MAZEDNS_CLASSIFIER_ENABLED` | No | `false` | Enable optional LLM domain classification (seeds the DB; then edited under Settings → AI classification). |
| `MAZEDNS_CLASSIFIER_ENDPOINT` | No | `http://localhost:11434/v1` | OpenAI-compatible base URL of your local model (Ollama/llama.cpp/LM Studio). |
| `MAZEDNS_CLASSIFIER_MODEL` | No | `llama3.2` | Model name your local server serves. |
| `MAZEDNS_CLASSIFIER_MODE` | No | `suggest` | Initial enforcement mode: `off`, `suggest`, or `auto`. |
| `MAZEDNS_CLASSIFIER_API_KEY` | No | *(empty)* | API key for the model endpoint (usually empty for local models). |
| `MAZEDNS_OIDC_ISSUER` | For SSO | *(empty)* | OIDC issuer URL. **Setting it turns SSO on.** |
| `MAZEDNS_OIDC_CLIENT_ID` | For SSO | *(empty)* | OIDC client ID. |
| `MAZEDNS_OIDC_CLIENT_SECRET` | For SSO | *(empty)* | OIDC client secret. |
| `MAZEDNS_OIDC_REDIRECT_URL` | For SSO | *(empty)* | Callback URL; must match the provider registration **character-for-character** (it's logged at startup to compare). |
| `MAZEDNS_OIDC_SCOPES` | No | `openid profile email` | Scopes, comma/space separated. |
| `MAZEDNS_OIDC_GROUPS_CLAIM` | No | *(empty)* | Token claim holding the user's groups. |
| `MAZEDNS_OIDC_ADMIN_GROUP` | No | *(empty)* | Group whose members become admins. |
| `MAZEDNS_OIDC_ENABLED` | No | *(from issuer)* | `true`/`false` to force SSO on or off explicitly. |
| `MAZEDNS_OIDC_DISABLE_PASSWORD_LOGIN` | No | `false` | `true` = SSO only (hide/refuse local password login). |
| `MAZEDNS_OIDC_AUTO_LOGIN` | No | `false` | `true` = redirect straight to the SSO provider instead of showing the login form. |

OIDC env values are trimmed of surrounding quotes to avoid a common `env_file`
mistake.

### DNS agent

| Variable | Required | Default | Description |
|---|---|---|---|
| `MAZEDNS_CP_URL` | For clustering | *(empty)* | Control-plane base URL, e.g. `https://cp.example.com:8080`. Setting it auto-enables cluster mode. (Deprecated alias: `MAZEDNS_MASTER_URL`.) With no URL the agent runs **standalone** — resolving and filtering from its own local config. |
| `MAZEDNS_CP_IP` | Conditional | *(auto)* | Pin the control plane's IP so the agent reaches it without DNS (TLS still verifies the URL host). Needed when the agent can't resolve the CP's FQDN — e.g. it's its network's only DNS. Left empty, the agent auto-learns and persists the address the CP advertises at enrollment. (Deprecated alias: `MAZEDNS_MASTER_IP`.) |
| `MAZEDNS_NODE_NAME` | No | *(hostname)* | Name the agent enrolls under. |
| `MAZEDNS_NODE_KEY` | No | *(auto-issued)* | Per-node API key. Leave empty when using a join token — one is issued and persisted automatically. |
| `MAZEDNS_LISTEN_ADDRESS` | No | `0.0.0.0` | DNS bind address. |
| `MAZEDNS_LISTEN_PORT` | No | `53` | DNS listen port. The image binds `53` as non-root via a `CAP_NET_BIND_SERVICE` file capability. |
| `MAZEDNS_UDP_LISTENERS` | No | *(auto)* | Number of `SO_REUSEPORT` UDP sockets that share the port so the kernel spreads packets across cores. **Defaults to one per available CPU** (bounded at 8; scales with the container's CPU quota). Set to `1` to force a single socket, or to a specific number to pin it. Each socket reserves an 8 MiB read + 8 MiB write buffer, so more sockets means more memory. |

### Shared (both components)

| Variable | Required | Default | Description |
|---|---|---|---|
| `MAZEDNS_API_ADDRESS` | In containers | `127.0.0.1` | Bind address of the HTTP server. Control plane: UI + API + `/metrics` + `/healthz`. Agent: `/healthz` + `/metrics` only (unauthenticated). Set to `0.0.0.0` so a mapped port is reachable; for an agent, prefer the node's private/overlay IP. |
| `MAZEDNS_JOIN_TOKEN` | For clustering | *(empty)* | Shared enrollment secret. Control plane: accepts it. Agent: presents it to self-enroll and receive a per-node key. Empty disables auto-join. |
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
| `listen` | `address` (`0.0.0.0`), `port` (`53`) | Agent DNS listener. |
| `api` | `enabled` (`true`), `address` (`127.0.0.1`), `port` (`8080`) | HTTP server. |
| `dot` / `doh` | `enabled` (`false`), `address`, `port` (`853`/`8443`), `doh.path` (`/dns-query`) | Encrypted DNS endpoints for clients. |
| `tls` | `cert_file`, `key_file` | Empty → a self-signed cert is generated on start. |
| `auth` | `enabled` (`true`), `session_ttl` (`24h`), `admin.*`, `oidc.*` | Login and SSO. See the env table for OIDC. |
| `database` | `driver` (`sqlite`), `path` (`mazedns.db`), `dsn` | See the shared table and the note above. |
| `cluster` | `enabled`, `join_token`, `require_approval`, `cp_url`, `cp_ip`/`master_ip`, `node_name`, `node_key`, `interval` (`30s`), `advertise_addr` | Control plane ↔ agent wiring. |
| `metrics` | `victoria_metrics.*`, `victoria_logs.*` | Optional push export (below). |

### Operational sections (seeded once, then edited in the UI)

| Section | Keys |
|---|---|
| `upstreams` | Ordered list; plain `1.1.1.1:53`, `tls://1.1.1.1:853#cloudflare-dns.com`, or `https://dns.quad9.net/dns-query`. |
| `forwarders` | Split-horizon per suffix: `- { suffix: "corp.internal", upstreams: [...] }`. |
| `cache` | `enabled` (`true`), `max_entries` (`10000`), `min_ttl` (`10s`), `max_ttl` (`24h`). |
| `rate_limit` | `enabled` (`false`), `qpm` (`600`). |
| `dnssec` | `enabled` (`false`) — force the DO bit upstream and surface AD. |
| `filter` | `enabled` (`true`), `block_response` (`nxdomain` or `zeroip`), `blocklist_files`. |
| `zones` | Authoritative records served locally. |
| `classifier` | Optional LLM classification (control plane only) — see the env table. |

---

## Infrastructure integrations

### Metrics — VictoriaMetrics (`metrics.victoria_metrics`)

Each component **pushes** its own Prometheus metrics to a VictoriaMetrics instance
(`/api/v1/import/prometheus`), labelled by `instance`, so a cluster aggregates in VM
without VM scraping every node. Fields: `enabled`, `url`, `interval` (`15s`), `job`
(`mazedns`), `instance` (empty → hostname), `username`/`password`. Also editable
live in the UI.

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
