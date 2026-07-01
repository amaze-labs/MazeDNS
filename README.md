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
- **Clustering:** a **control plane** holds config + dashboard (no DNS); **DNS
  agents** replicate it and serve queries. Multisite HA on Docker + k3s.
- **Observability:** Prometheus metrics + Grafana.

## Stack

| Layer      | Choice                                                              |
|------------|--------------------------------------------------------------------|
| DNS engine | **Go** + [`miekg/dns`](https://github.com/miekg/dns) (wire codec only) |
| API        | Go HTTP (JSON REST) + Prometheus `/metrics`                        |
| Datastore  | **SQLite** (pure-Go, embedded — default) or external **PostgreSQL** |
| Frontend   | **React + Vite + TypeScript** SPA                                   |
| Auth       | Local (argon2id) **or** OIDC (Authentik)                            |
| Deploy     | Docker, then k3s                                                    |

Everything that makes MazeDNS unique — resolver logic, filtering, cache, API, UI,
auth, clustering — is custom. `miekg/dns` is used only for RFC-correct DNS packet
encoding/decoding, nothing more.

See [docs/architecture.md](docs/architecture.md) for the full design.

## Install

Grab the self-contained binaries for Linux/macOS/Windows from the rolling
[**`latest` release**](https://github.com/IPMaze/MazeDNS/releases/latest), or run the containers
(`ghcr.io/ipmaze/mazedns-control-plane:latest` and
`ghcr.io/ipmaze/mazedns-dns-agent:latest`). Full instructions — including how to
choose where the SQLite database lives — are in
[docs/install.md](docs/install.md).

MazeDNS runs as two components: a **control plane** (dashboard/API, no DNS) and
one or more **DNS agents** (resolvers that replicate config from the control
plane). This split keeps dashboard/classifier load off the resolver hot path.

## Quick start

```bash
# 1. Control plane — web UI + API on :8080, serves no DNS.
go run -tags embed_dist ./cmd/control-plane --config configs/mazedns.yaml

# 2. DNS agent — a resolver that self-enrolls with the control plane.
MAZEDNS_CP_URL=http://127.0.0.1:8080 MAZEDNS_JOIN_TOKEN=dev-token \
  go run ./cmd/dns-agent --config configs/mazedns.yaml
# (set cluster.join_token: dev-token in the config first, or run the agent
#  standalone with no MAZEDNS_CP_URL to resolve without a control plane)

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
by the **control-plane** binary when built with the frontend embedded:

```bash
npm --prefix web install && npm --prefix web run build
go run -tags embed_dist ./cmd/control-plane --config configs/mazedns.yaml
# → http://127.0.0.1:8080
```

Frontend dev with hot reload (UI on :5173, proxying /api to the Go server):

```bash
go run ./cmd/control-plane --config configs/mazedns.yaml   # API on :8080
npm --prefix web run dev                                   # UI on :5173
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
policy, and bumps the cluster config version so agents re-sync. The bundle
deliberately omits users/sessions, the query log, and per-node cluster keys.

```bash
curl -s http://127.0.0.1:8080/api/config/export -o mazedns-config.json
curl -s -X POST 'http://127.0.0.1:8080/api/config/import?mode=replace' \
  -H 'Content-Type: application/json' --data-binary @mazedns-config.json
```

## Build & deploy

Common tasks via the `Makefile` (`make help` lists them all):

```bash
make build-cp      # frontend + control-plane binary with embedded UI -> bin/control-plane
make build         # lean dns-agent binary -> bin/dns-agent
make run-cp        # run the control plane with the UI on :8080 (no DNS)
make run-agent     # run a dns-agent (resolver + /metrics, no UI/API)
make test vet      # Go tests + vet
make docker        # build both container images
make compose-dev   # docker compose up --build (control plane :8080 + 2 agents)
```

### Two images

Two prebuilt multi-arch images (`linux/amd64` + `linux/arm64`) are published to
the GitHub Container Registry:

```bash
docker pull ghcr.io/ipmaze/mazedns-control-plane:latest
docker pull ghcr.io/ipmaze/mazedns-dns-agent:latest
```

| Image | Serves | Use |
|-------|--------|-----|
| `mazedns-control-plane` | control-plane API + **web UI** + `/metrics` (**no DNS**) | the single host you manage |
| `mazedns-dns-agent` | DNS (UDP/TCP, opt. DoT/DoH) + `/healthz` + `/metrics` | every resolver node |

Agents replicate the control plane's rules/rewrites over an authenticated
snapshot and self-enroll with a shared **join token** — the **Cluster** tab shows
the exact `docker run` / `docker compose` command.

### Container env overrides

Override the baked config without mounting a file. Variables marked **CP** apply
to the control plane, **agent** to a dns-agent:

| Env | Overrides |
|-----|-----------|
| `MAZEDNS_API_ADDRESS` | UI/API (CP) or health/metrics (agent) bind address (use `0.0.0.0` in a container) |
| `MAZEDNS_LISTEN_ADDRESS` | agent: DNS bind address |
| `MAZEDNS_DB_PATH` | SQLite path (e.g. `/data/mazedns.db`) |
| `MAZEDNS_ADMIN_USERNAME` / `MAZEDNS_ADMIN_PASSWORD` | CP: first-run admin |
| `MAZEDNS_LOG_LEVEL` | `debug` / `info` / `warn` / `error` |
| `MAZEDNS_CLUSTER_ENABLED` | CP: serve cluster endpoints |
| `MAZEDNS_JOIN_TOKEN` | shared join token — CP: accept it; agent: present it to self-enroll |
| `MAZEDNS_REQUIRE_APPROVAL` | CP: hold self-enrolled agents until approved |
| `MAZEDNS_CP_URL` | agent: control-plane base URL (deprecated alias: `MAZEDNS_MASTER_URL`) |
| `MAZEDNS_NODE_NAME` | agent: name to enroll under (defaults to the hostname) |
| `MAZEDNS_NODE_KEY` | agent: per-node key (auto-issued via the join token) |
| `MAZEDNS_CP_IP` | agent: pin the control-plane IP (skip DNS); TLS still uses the URL host |
| `MAZEDNS_CLUSTER_BOOTSTRAP_NODES` | CP: pre-enroll nodes, `name=key,name=key` |
| `MAZEDNS_BLOCKLIST_FILES` | blocklist file path(s), comma/space separated (use absolute paths; replaces `filter.blocklist_files`) |
| `MAZEDNS_CLASSIFIER_ENABLED` | CP: `true` to enable LLM domain classification |
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
- **Local dev on macOS/Windows:** run the agent binary natively (`make run-agent`)
  — Docker Desktop cannot pass the original client IP through its VM.

### Host tuning (busy / container hosts)

On a host that fronts many containers, the kernel-default UDP socket buffer
(~208 KB) overflows under concurrent DNS bursts and silently drops packets —
seen as high DNS tail latency while CPU stays low (`netstat -su` shows a growing
`receive buffer errors`). MazeDNS requests an 8 MiB socket buffer, but the kernel
caps it at `net.core.rmem_max`/`wmem_max`, so raise those on the host:

```bash
sudo sysctl -w net.core.rmem_max=16777216
sudo sysctl -w net.core.rmem_default=4194304
sudo sysctl -w net.core.wmem_max=16777216
sudo sysctl -w net.core.netdev_max_backlog=4096
# persist:
printf 'net.core.rmem_max=16777216\nnet.core.rmem_default=4194304\nnet.core.wmem_max=16777216\nnet.core.netdev_max_backlog=4096\n' \
  | sudo tee /etc/sysctl.d/99-dns-udp.conf
```

See **[docs/troubleshooting.md](docs/troubleshooting.md)** for the full runbook
(UDP buffers, conntrack exhaustion, the Alpine/musl ~5 s race, DoT upstreams), and
`dev/dns-latency-debug.sh` for a read-only diagnostic that prints a verdict.

### Compose

- **Dev:** `docker compose up --build` (`docker-compose.yml`) — a full local
  cluster: a control plane + UI on `:8080` (no DNS), two agents (`agent-a`/`agent-b`
  that self-enroll via `MAZEDNS_JOIN_TOKEN`; resolvers on `:5311`/`:5312`, metrics
  on `:9091`/`:9092`), plus **traffic-generator** clients that query the agents over
  the compose network. Because that traffic is container-to-container it keeps each
  client's own IP, so the dashboard fills with real per-client metrics, query types,
  and blocked domains. Just the control plane? `docker compose up control-plane --build`.
- **Prod:** `MAZEDNS_ADMIN_PASSWORD=… MAZEDNS_JOIN_TOKEN=… docker compose -f docker-compose.prod.yml up -d`
  — pulls both images and runs a control plane + a dns-agent.

### CI

`.github/workflows/build-containers.yml` builds **multi-arch** images
(`linux/amd64` + `linux/arm64`) and pushes `ghcr.io/ipmaze/mazedns-control-plane`
and `ghcr.io/ipmaze/mazedns-dns-agent` (`:latest`, plus the version tag on `v*`
releases) on push to `main`, tags, or manual dispatch. The source commit is baked
into each binary (`--version`).

### Clustering (control plane ↔ agents)

The control plane is the source of truth; each agent pulls its config (rules +
rewrites) over a snapshot authenticated by a **per-node API key** and applies it
locally — no restart. The control plane never answers DNS, so its dashboard and
classifier load can't affect resolver latency.

- **Control plane:** set `cluster.join_token` (`MAZEDNS_JOIN_TOKEN`) and
  `MAZEDNS_CLUSTER_ENABLED=true`. Agents self-enroll with the token; set
  `require_approval` to hold them until you approve them in the **Cluster** tab.
  You can still issue a per-node key manually there when no join token is used.
- **Agent:** set `cp_url` + `join_token` (+ optional `node_name`, `interval`). On
  first boot it self-registers, persists the issued key locally, then polls the
  control plane and re-applies on each config-version change. If its key is revoked
  it re-enrolls automatically.

For automation, the control plane can also pre-enroll nodes with fixed keys via
`MAZEDNS_CLUSTER_BOOTSTRAP_NODES` (`name=key,name=key`). Use a strong join token
(not the dev placeholder) in production.

> Multisite networking (a WireGuard mesh so agents reach the control plane
> privately) and k3s manifests are left to the deploying operator.

## Security notes

- Never expose the admin API / UI to the internet — management network / VPN only.
- The resolver answers recursive queries only for configured client networks
  (no open resolver); per-client rate limiting is on by default.
