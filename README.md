# MazeDNS

A self-hosted, **fully custom DNS filtering resolver** — think AdGuard Home /
Pi-hole, but built from scratch in Go with advanced DNS features and designed for
multi-site **clustering**.

> Status: **early build.** The Go core resolver is the first milestone; API, web
> UI, auth, advanced protocols, and clustering follow — see
> [docs/roadmap.md](docs/roadmap.md).

## What it does (target)

- **Filtering resolver:** forward + cache + block (ads / trackers / malware) via
  managed block lists (file / paste / remote URL with scheduled auto-refresh,
  individually enable/disable, view & remove), allow/deny rules, custom local
  records & rewrites (incl. `*.wildcard`), and a one-click "pause blocking for N"
  control.
- **Advanced DNS:** DoH / DoT / DoQ (server + upstream), DNSSEC validation,
  conditional / split-horizon forwarding, authoritative zones, rate limiting.
- **Web UI:** React SPA — grouped KPI dashboard (traffic / protection /
  performance, per-client & per-type breakdowns, top domains) with a selectable
  time window (1h → 90d), live query log, and all configuration.
- **Auth:** pluggable — local users (SQLite) by default, or **OIDC SSO via
  Authentik**.
- **Clustering:** master holds config; agents replicate it; multisite HA on
  Docker + k3s. Built once the single-node core is solid.
- **Observability:** Prometheus metrics + Grafana.

## Stack

| Layer      | Choice                                                              |
|------------|--------------------------------------------------------------------|
| DNS engine | **Go** + [`miekg/dns`](https://github.com/miekg/dns) (wire codec only) |
| API        | Go HTTP (JSON REST) + Prometheus `/metrics`                        |
| Datastore  | **SQLite** (pure-Go driver, static-binary friendly)                |
| Frontend   | **React + Vite + TypeScript** SPA                                   |
| Auth       | Local (argon2id) **or** OIDC (Authentik)                            |
| Deploy     | Docker, then k3s                                                    |

Everything that makes MazeDNS unique — resolver logic, filtering, cache, API, UI,
auth, clustering — is custom. `miekg/dns` is used only for RFC-correct DNS packet
encoding/decoding, nothing more.

See [docs/architecture.md](docs/architecture.md) for the full design.

## Quick start

```bash
go run ./cmd/mazedns --config configs/mazedns.yaml

# DNS  (dev port 5300; macOS reserves 5353 for mDNS)
dig @127.0.0.1 -p 5300 example.com        # resolves
dig @127.0.0.1 -p 5300 doubleclick.net    # blocked (NXDOMAIN)

# Control plane  (http://127.0.0.1:8080)
curl -XPOST :8080/api/rules    -d '{"action":"deny","domain":"ads.example.com"}'
curl -XPOST :8080/api/rewrites -d '{"domain":"nas.lan","rrtype":"A","value":"10.0.0.5"}'
curl -XPOST :8080/api/rewrites -d '{"domain":"*.lab.lan","rrtype":"A","value":"10.0.0.9"}'  # wildcard: every subdomain
curl :8080/api/stats
curl ':8080/api/querylog?limit=20'
curl :8080/metrics              # Prometheus
```

### Web UI

The React dashboard (stats, query log, rules, rewrites, and settings) is served
by the binary when built with the frontend embedded:

```bash
npm --prefix web install && npm --prefix web run build
go run -tags embed_dist ./cmd/mazedns --config configs/mazedns.yaml
# → http://127.0.0.1:8080
```

Frontend dev with hot reload (UI on :5173, proxying /api to the Go server):

```bash
go run ./cmd/mazedns --config configs/mazedns.yaml   # API on :8080
npm --prefix web run dev                              # UI on :5173
```

### Auth

The API and UI require login by default (`auth.enabled: true`). On first run an
admin is created — configure it via `auth.admin` or `MAZEDNS_ADMIN_USERNAME` /
`MAZEDNS_ADMIN_PASSWORD`; if no password is given, a random one is generated and
logged once. Passwords are argon2id-hashed; sessions are server-side and
revocable. Roles: `admin` (full) and `readonly` (GET only).

For SSO, fill in `auth.oidc.*` (issuer, client_id, client_secret, redirect_url)
for your Authentik provider — a "Sign in with SSO" button then appears. In
containers you can configure the same fields entirely from the environment with
the `MAZEDNS_OIDC_*` variables (see the env table below); setting
`MAZEDNS_OIDC_ISSUER` is enough to turn SSO on.

### Settings

Operational settings — upstream resolvers, conditional forwarders, block
response, per-client rate limit, DNSSEC, and the response cache — are stored in
the database and managed from the **Settings** tab. Saving applies them live
(atomic hot-swap, no restart). The config file seeds these values on first run
only; after that the database is the source of truth.

Bootstrap settings stay in the config file / env because they're needed before
the DB or UI exists: listen and API addresses/ports, TLS, the first-run admin
credentials, and OIDC/SSO.

### Backup & restore

The Settings tab can **export** the full mutable config — settings, rules, and
rewrites — as a single versioned JSON bundle, and **import** it back. Import has
two modes: `merge` (upsert on top of what's there) and `replace` (clear rules
and rewrites first). A restore applies settings live, reloads the filtering
policy, and bumps the cluster config version so workers re-sync. The bundle
deliberately omits users/sessions, the query log, and per-node cluster keys.

```bash
curl -s http://127.0.0.1:8080/api/config/export -o mazedns-config.json
curl -s -X POST 'http://127.0.0.1:8080/api/config/import?mode=replace' \
  -H 'Content-Type: application/json' --data-binary @mazedns-config.json
```

## Build & deploy

Common tasks via the `Makefile` (`make help` lists them all):

```bash
make build-ui      # frontend + binary with embedded UI -> bin/mazedns
make run-ui        # master mode with the UI on :8080
make run-worker    # worker mode (resolver + /metrics, no UI/API)
make test vet      # Go tests + vet
make docker        # build the container image
make compose-dev   # docker compose up --build (master, UI on :8080)
```

### One image, two modes

The prebuilt multi-arch image (`linux/amd64` + `linux/arm64`) is published to
the GitHub Container Registry:

```bash
docker pull ghcr.io/ipmaze/mazedns:latest
```

A single container image runs either role, selected by `MAZEDNS_MODE`:

| Mode | Serves | Use |
|------|--------|-----|
| `master` (default) | DNS + control-plane API + **web UI** + `/metrics` | the node you manage |
| `worker` | DNS + `/healthz` + `/metrics` only | replica resolver nodes |

Workers replicate the master's rules/rewrites over an authenticated snapshot;
the **Cluster** tab generates the exact `docker run` / `docker compose` command
(with the node key) for each new worker.

### Container env overrides

Override the baked config without mounting a file:

| Env | Overrides |
|-----|-----------|
| `MAZEDNS_MODE` | `master` / `worker` |
| `MAZEDNS_API_ADDRESS` | UI/API bind address (use `0.0.0.0` in a container) |
| `MAZEDNS_LISTEN_ADDRESS` | DNS bind address |
| `MAZEDNS_DB_PATH` | SQLite path (e.g. `/data/mazedns.db`) |
| `MAZEDNS_ADMIN_USERNAME` / `MAZEDNS_ADMIN_PASSWORD` | first-run admin |
| `MAZEDNS_LOG_LEVEL` | `debug` / `info` / `warn` / `error` |
| `MAZEDNS_MASTER_URL` / `MAZEDNS_NODE_KEY` | worker: master URL + its node key |
| `MAZEDNS_MASTER_IP` | worker: pin the master's IP (skip DNS); TLS still uses the URL host |
| `MAZEDNS_CLUSTER_BOOTSTRAP_NODES` | master: pre-enroll nodes, `name=key,name=key` |
| `MAZEDNS_BLOCKLIST_FILES` | blocklist file path(s), comma/space separated (use absolute paths; replaces `filter.blocklist_files`) |
| `MAZEDNS_CLASSIFIER_ENABLED` | `true` to enable LLM domain classification (master only) |
| `MAZEDNS_CLASSIFIER_ENDPOINT` | local OpenAI-compatible base URL (e.g. `http://localhost:11434/v1`) |
| `MAZEDNS_CLASSIFIER_MODEL` / `MAZEDNS_CLASSIFIER_MODE` | model name; initial mode `off`/`suggest`/`auto` |
| `MAZEDNS_OIDC_ISSUER` | SSO issuer URL — setting it enables OIDC |
| `MAZEDNS_OIDC_CLIENT_ID` / `MAZEDNS_OIDC_CLIENT_SECRET` | SSO client credentials |
| `MAZEDNS_OIDC_REDIRECT_URL` | SSO callback URL |
| `MAZEDNS_OIDC_SCOPES` | scopes, comma/space separated (default `openid profile email`) |
| `MAZEDNS_OIDC_GROUPS_CLAIM` / `MAZEDNS_OIDC_ADMIN_GROUP` | map a provider group to admin |
| `MAZEDNS_OIDC_ENABLED` | `true` / `false` to force SSO on or off |
| `MAZEDNS_OIDC_DISABLE_PASSWORD_LOGIN` | `true` = SSO only (hide/refuse local password login) |
| `MAZEDNS_OIDC_AUTO_LOGIN` | `true` = redirect straight to SSO instead of showing the login form |

### Seeing real client IPs

The resolver reports each query's source IP as seen on the wire. When you publish
the DNS port through Docker's NAT (`-p 53:53`), the source is rewritten to the
Docker gateway — on Docker Desktop you'll see everything as `192.168.65.1`, so
per-client stats collapse to one client. To preserve real client IPs:

- **Linux:** run the resolver with `network_mode: host` (or a host-port without
  the userland proxy).
- **k3s:** give the DNS pod `hostNetwork: true`, or expose it via a Service with
  `externalTrafficPolicy: Local`.
- **Local dev on macOS/Windows:** run the binary natively (`make run-ui`) — Docker
  Desktop cannot pass the original client IP through its VM.

### Compose

- **Dev:** `docker compose up --build` (`docker-compose.yml`) — a full local
  cluster: master + UI on `:8080`, two workers (`worker-a`/`worker-b`,
  pre-enrolled via `MAZEDNS_CLUSTER_BOOTSTRAP_NODES`; resolvers on `:5311`/`:5312`,
  metrics on `:9091`/`:9092`), plus four **traffic-generator** clients that query
  the nodes over the compose network. Because that traffic is container-to-container
  it keeps each client's own IP, so the dashboard fills with real per-client
  metrics, query types, and blocked domains. Just the master? `docker compose up mazedns --build`.
- **Prod:** `MAZEDNS_ADMIN_PASSWORD=… docker compose -f docker-compose.prod.yml up -d`
  — pulls `ghcr.io/ipmaze/mazedns:latest` and runs a master + a worker.

### CI

`.github/workflows/build-containers.yml` builds a **multi-arch** image
(`linux/amd64` + `linux/arm64`) and pushes `ghcr.io/ipmaze/mazedns:latest` (plus
the version tag on `v*` releases) on push to `main`, tags, or manual dispatch.
`latest` is the only floating tag, so it's what GHCR shows on the package page;
the source commit is baked into the binary (`mazedns --version`).

### Clustering (master ↔ worker)

The master is the source of truth; each worker pulls its config (rules +
rewrites) over a snapshot authenticated by a **per-node API key**, and applies
it locally — no restart.

- **Master:** nothing to enable — the control plane is always on. Enroll workers
  in the UI's **Cluster** tab (or `POST /api/cluster/nodes`); each enrollment
  returns a one-time key (stored hashed). Revoke a node to cut it off. Until a
  node is enrolled, the snapshot endpoint rejects everyone (no valid keys exist).
- **Worker:** set `master_url` + `node_key` (+ `interval`). It polls the master,
  re-applies on each config-version change, and reports its address/version back
  (shown in the Cluster tab).

Env equivalents: `MAZEDNS_MASTER_URL` + `MAZEDNS_NODE_KEY` start a worker's sync
agent. `docker-compose.prod.yml` wires this up. For automation, the master can
pre-enroll nodes with fixed keys via `MAZEDNS_CLUSTER_BOOTSTRAP_NODES`
(`name=key,name=key`) — used by the dev `--profile cluster` stack so workers join
with no manual step. Use generated keys (not the dev placeholders) in production.

> Multisite networking (a WireGuard mesh so workers reach the master privately)
> and k3s manifests are left to the deploying operator.

## Security notes

- Never expose the admin API / UI to the internet — management network / VPN only.
- The resolver answers recursive queries only for configured client networks
  (no open resolver); per-client rate limiting is on by default.
