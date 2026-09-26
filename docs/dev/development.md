# Development

How to build MazeDNS from source and hack on it.

## Prerequisites

- **Go 1.26+** (see the `go` directive in [`go.mod`](../../go.mod); pinned at
  `1.26.4`). The build is pure-Go / `CGO_ENABLED=0` — no C toolchain needed.
- **Node 22** (for the web UI in `web/`), only if you build or work on the frontend.
- **Docker** with BuildKit, to build the container images.

## Repo layout

```
cmd/
  control-plane/   # control-plane binary: UI + API + auth + classifier + cluster
  dns-agent/       # dns-agent binary: resolver + config replication + /metrics
internal/
  resolver/        # DNS hot path: server, cache lookups, upstreams, hedging, serve-stale
  cache/           # TTL-aware sharded response cache
  filter/          # blocklist matching engine
  config/          # YAML + MAZEDNS_* env loading and validation
  store/           # SQLite/Postgres datastore (WAL, dialect adaptation)
  cluster/         # enrollment + snapshot replication (agent side)
  api/             # control-plane HTTP JSON API
  auth/            # local (argon2id) + OIDC sessions
  classifier/      # optional LLM domain classification
  metrics/ boot/ lists/ ...
web/               # React + Vite + TypeScript SPA (embedded into the CP binary)
configs/           # example YAML configs (baked into the images)
docs/              # documentation (operator docs at the top, this folder for devs)
```

## Make targets

`make help` lists them all:

| Target | What it does |
|---|---|
| `make run-agent` | Run a dns-agent locally on `:5300` (`MAZEDNS_LISTEN_PORT=5300`, so no root is needed to bind — the default port is `53`). |
| `make run-cp` | Build the frontend and run the control plane with the embedded UI on `:8080` (no DNS). |
| `make web` | `npm install` + `npm run build` the frontend into `web/dist`. |
| `make build` | Build the lean `dns-agent` binary (no UI) into `bin/`. |
| `make build-cp` | Build the frontend, then the `control-plane` binary with the UI embedded (`-tags embed_dist`). |
| `make test` | `go test ./...`. |
| `make vet` / `make fmt` / `make tidy` | `go vet`, `gofmt -s -w`, `go mod tidy`. |
| `make docker` | Build both container images (`--target control-plane` and `--target dns-agent`). |
| `make compose-dev` | Build + run the dev cluster: control plane on `:8080` + two agents + traffic generators. |
| `make compose-cp` | Build + run just the control plane. |
| `make compose-prod` | Run [`docker-compose.prod.yml`](../../docker-compose.prod.yml) (pulls the published images). |
| `make clean` | Remove `bin/` and `web/dist`. |

### Running a local cluster

```bash
make run-cp          # control plane + UI on http://127.0.0.1:8080
# in another shell — an agent that self-enrolls and serves DNS on :5300
MAZEDNS_CP_URL=http://127.0.0.1:8080 MAZEDNS_JOIN_TOKEN=dev-token make run-agent

dig @127.0.0.1 -p 5300 example.com        # resolves
dig @127.0.0.1 -p 5300 doubleclick.net    # blocked (once a blocklist/deny rule exists)
```

An agent with no `MAZEDNS_CP_URL` runs standalone (resolves + filters from its own
local config). The default DNS port is `53`; `make run-agent` binds `5300` so you
don't need root — override with `MAZEDNS_LISTEN_PORT`.

### Frontend dev with hot reload

```bash
make run-cp                       # API on :8080
npm --prefix web run dev          # UI on :5173, proxies /api to :8080
```

## The two-image Dockerfile

One multi-stage [`Dockerfile`](../../Dockerfile) produces both images, selected with
`--target`:

- `web` stage builds the React bundle (`node:22-alpine`).
- `build-cp` compiles the control-plane binary with the web bundle embedded
  (`-tags embed_dist`); `build-agent` compiles the lean agent (no web assets).
- The agent binary is given a `CAP_NET_BIND_SERVICE` file capability
  (`setcap` via `libcap`) so the non-root runtime user can bind port `53`. BuildKit
  preserves the capability xattr through `COPY --from` into the distroless image.
- Both runtimes are `gcr.io/distroless/static-debian12:nonroot` and run as
  `nonroot`. `configs/` is baked in at `/etc/mazedns`; state lives under `/data`.

```bash
docker build --target control-plane -t mazedns-control-plane .
docker build --target dns-agent     -t mazedns-agent .
# or: make docker
```

## Tests and benchmarks

```bash
go test ./...                 # unit tests
go test -race ./internal/cache/ ./internal/resolver/   # race detector on the hot path
```

Resolver hot-path benchmarks and how to read them are documented in
[latency-audit.md](latency-audit.md):

```bash
go test -bench . -benchmem ./internal/resolver/ ./internal/cache/ ./internal/filter/ ./internal/metrics/
```

## CI

`.github/workflows/build-containers.yml` is the release pipeline. On every push to
`main` (or manual dispatch) it:

1. computes the next version with `.github/scripts/next-version.sh`: starting from the
   latest semver tag (`N.N.N`, no `v` prefix) it applies every later non-merge commit
   in order — `type!:` bumps major, `feat:` bumps minor, anything else bumps patch. Write
   commit subjects as [Conventional Commits](https://www.conventionalcommits.org/): the
   version is derived from them;
2. publishes **both** `ghcr.io/amaze-labs/mazedns-control-plane` and
   `ghcr.io/amaze-labs/mazedns-agent` as `:<version>` and `:latest`, **multi-arch**
   (`linux/amd64` + `linux/arm64`). If anything that ends up in the binaries changed
   since the previous release (`cmd`, `internal`, `web`, `configs`, `go.mod`, `go.sum`,
   `Dockerfile`, `.dockerignore`), both images are rebuilt; otherwise (docs, CI) the
   previous release's manifests are retagged, which costs no build;
3. only after both images are published, pushes the git tag `<version>`. A tag
   therefore always means both images exist.

The version is baked into each binary via `-ldflags -X
github.com/IPMaze/MazeDNS/internal/version.Version` (the Go module path still uses
the original org). The two images are always rebuilt or retagged together so they
report the same version: the Cluster page flags an agent as outdated when its app
version differs from the control plane's.

The matrix axis `image` is the Dockerfile **target** (`control-plane`, `dns-agent`);
the published name comes from the separate `suffix` value, which is why the agent
image is `mazedns-agent` while its build target stays `dns-agent`.

`release.yml` is separate and manual: it builds the standalone binaries and
publishes them as the rolling `latest` GitHub Release.

`.github/workflows/release.yml` (manual only) publishes the standalone binaries to a
rolling `latest` GitHub Release.
