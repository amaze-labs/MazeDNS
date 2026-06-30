# Installing & running MazeDNS

MazeDNS ships as a **single self-contained binary** — the web UI is embedded and
the datastore driver is pure Go, so there are no runtime dependencies (no Node,
no C library, no separate database server required).

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

Each archive contains the `mazedns` binary plus a `mazedns.yaml.example` config.
The build's commit and date are baked in and printed at startup
(`"MazeDNS starting" version=latest+<sha> (<date>)`). Verify downloads against
`mazedns_checksums.txt` (SHA-256).

> Maintainers: the binaries are produced by the **"Build latest binaries
> (manual)"** GitHub Action (`.github/workflows/release.yml`) — run it from the
> Actions tab to refresh the `latest` release. It cross-compiles all targets from
> one Linux runner (CGO off), so no per-OS runners are needed.

## Run from source

```bash
npm --prefix web install && npm --prefix web run build   # build the embedded UI
go run -tags embed_dist ./cmd/mazedns --config configs/mazedns.yaml
# → DNS on :5300 (dev), control plane + UI on http://127.0.0.1:8080
```

Omit `-tags embed_dist` for API-only dev (the UI is then served by Vite at
`:5173` — see the README).

## Container

```bash
docker run -d --name mazedns \
  -p 53:5300/udp -p 53:5300/tcp -p 8080:8080 \
  -v mazedns-data:/data \
  ghcr.io/ipmaze/mazedns:latest
```

`MAZEDNS_MODE=worker` runs a resolver-only node (see the cluster docs).

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
