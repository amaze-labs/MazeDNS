# Installing & running MazeDNS

MazeDNS runs as **two self-contained components** so the dashboard can never slow
down DNS:

- **control-plane** — the web UI, API, auth, classifier, and cluster
  coordination. It holds the config and dashboard and **does not answer DNS**.
- **dns-agent** — a resolver node (the data plane). It serves DNS, replicates its
  filtering config from the control plane, and exposes only `/healthz` +
  `/metrics`.

Both are static binaries with no runtime dependencies (no Node, no C library, no
separate database server required). A single control plane coordinates any number
of agents; agents keep resolving even if the control plane is briefly down.

## Prebuilt binaries (latest)

Every build is published to the rolling **[`latest` release](https://github.com/IPMaze/MazeDNS/releases/latest)**
(mirroring the container `:latest` tag — no version numbers, just the newest
build). Filenames are stable, so the download URLs never change:

| OS | Arch | Asset |
|----|------|-------|
| Linux | x86-64 | `mazedns_linux_amd64.tar.gz` |
| Linux | ARM64 | `mazedns_linux_arm64.tar.gz` |
| macOS | Apple Silicon | `mazedns_darwin_arm64.tar.gz` |
| macOS | Intel | `mazedns_darwin_amd64.tar.gz` |
| Windows | x86-64 | `mazedns_windows_amd64.zip` |
| Windows | ARM64 | `mazedns_windows_arm64.zip` |

```bash
# Linux/macOS example (swap in your OS/arch):
curl -L -o mazedns.tar.gz \
  https://github.com/IPMaze/MazeDNS/releases/latest/download/mazedns_linux_amd64.tar.gz
tar xzf mazedns.tar.gz && cd mazedns_linux_amd64
./mazedns --config mazedns.yaml.example
```

Each archive contains **both** the `control-plane` and `dns-agent` binaries plus a
`mazedns.yaml.example` config. Run the control plane on your management host and a
dns-agent wherever you want to serve DNS. The build's commit and date are baked in
and printed at startup. Verify downloads against `mazedns_checksums.txt` (SHA-256).

> Maintainers: the binaries are produced by the **"Build latest binaries
> (manual)"** GitHub Action (`.github/workflows/release.yml`) — run it from the
> Actions tab to refresh the `latest` release. It cross-compiles all targets from
> one Linux runner (CGO off), so no per-OS runners are needed.

## Run from source

```bash
# Control plane (web UI on :8080, no DNS):
npm --prefix web install && npm --prefix web run build   # build the embedded UI
go run -tags embed_dist ./cmd/control-plane --config configs/mazedns.yaml

# DNS agent (resolver on :5300 in dev), in another terminal:
MAZEDNS_CP_URL=http://127.0.0.1:8080 MAZEDNS_JOIN_TOKEN=dev-token \
  go run ./cmd/dns-agent --config configs/mazedns.yaml
```

For control-plane API-only dev (UI served by Vite at `:5173`), omit
`-tags embed_dist` — see the README.

## Containers

Two images are published: `ghcr.io/ipmaze/mazedns-control-plane` and
`ghcr.io/ipmaze/mazedns-dns-agent`.

```bash
# 1. Control plane — dashboard/API only, never serves DNS.
docker run -d --name mazedns-control-plane \
  -p 8080:8080 -v cp-data:/data \
  -e MAZEDNS_ADMIN_PASSWORD=change-me \
  -e MAZEDNS_CLUSTER_ENABLED=true \
  -e MAZEDNS_JOIN_TOKEN=a-shared-secret \
  ghcr.io/ipmaze/mazedns-control-plane:latest

# 2. DNS agent — self-enrolls with the join token, then serves DNS.
docker run -d --name mazedns-agent \
  -p 53:5300/udp -p 53:5300/tcp -v agent-data:/data \
  -e MAZEDNS_CP_URL=http://<control-plane-host>:8080 \
  -e MAZEDNS_JOIN_TOKEN=a-shared-secret \
  -e MAZEDNS_NODE_NAME=agent-1 \
  ghcr.io/ipmaze/mazedns-dns-agent:latest
```

The agent appears in the control plane's **Cluster** tab automatically — no key to
copy. Set `MAZEDNS_REQUIRE_APPROVAL=true` on the control plane to hold new agents
until you approve them there. See [architecture.md](architecture.md#clustering) for
how enrollment and replication work.

## Data storage

MazeDNS stores its operational state (rules, rewrites, query log, classifier
verdicts, sessions, cluster nodes, …) in a database. Two backends are supported:

- **Embedded SQLite** (default) — a single file, created on first run, no setup.
- **External PostgreSQL** — point MazeDNS at your own Postgres server.

### Embedded SQLite (default)

| Setting | Where | Default |
|---|---|---|
| `database.path` | `mazedns.yaml` | `mazedns.db` |
| `MAZEDNS_DB_PATH` | environment variable (overrides the file) | — |

```yaml
# mazedns.yaml
database:
  driver: sqlite                       # default
  path: /var/lib/mazedns/mazedns.db
```

In the container the database lives under `/data` — mount a volume there to
persist it across restarts (the compose/`docker run` examples already do).

Put the file on **fast local storage**. SQLite is configured in WAL mode with a
large page cache and memory-mapped reads, which the dashboard's aggregate scans
rely on; a networked/remote filesystem (NFS, SMB) can corrupt WAL databases and
is not supported.

### External PostgreSQL

Set `driver: postgres` and provide a DSN. The schema is created automatically on
first connect.

```yaml
# mazedns.yaml
database:
  driver: postgres
  dsn: postgres://user:pass@db-host:5432/mazedns?sslmode=disable
```

```bash
MAZEDNS_DB_DRIVER=postgres \
MAZEDNS_DB_DSN='postgres://user:pass@db-host:5432/mazedns?sslmode=disable' \
  ./mazedns
```

(Setting only `MAZEDNS_DB_DSN` implies the `postgres` driver.) The DSN accepts
the standard `postgres://…` URL or libpq keyword form; use `sslmode=require` for
TLS. MazeDNS writes the SQLite dialect internally and adapts it to PostgreSQL at
runtime (placeholders, aggregates, DDL), so the same feature set works on either
backend.

> **Status:** the PostgreSQL backend is newer than the SQLite one — validate it
> against your server before relying on it in production. SQLite remains the
> tested default. Pick PostgreSQL when you want managed backups/HA or a shared
> database your own tooling can query directly.
