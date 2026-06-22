# MazeDNS

A self-hosted, **fully custom DNS filtering resolver** — think AdGuard Home /
Pi-hole, but built from scratch in Go with advanced DNS features and designed for
multi-site **clustering**.

> Status: **early build.** The Go core resolver is the first milestone; API, web
> UI, auth, advanced protocols, and clustering follow — see
> [docs/roadmap.md](docs/roadmap.md).

## What it does (target)

- **Filtering resolver:** forward + cache + block (ads / trackers / malware) via
  blocklists (hosts / AdGuard-syntax / regex), allow/deny rules, per-client
  policies, custom local records & rewrites.
- **Advanced DNS:** DoH / DoT / DoQ (server + upstream), DNSSEC validation,
  conditional / split-horizon forwarding, authoritative zones, rate limiting.
- **Web UI:** React SPA — live stats, query log, and all configuration.
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
curl :8080/api/stats
curl ':8080/api/querylog?limit=20'
curl :8080/metrics              # Prometheus
```

### Web UI

The React dashboard (stats, query log, rules, rewrites) is served by the binary
when built with the frontend embedded:

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
for your Authentik provider — a "Sign in with SSO" button then appears.

## Security notes

- Never expose the admin API / UI to the internet — management network / VPN only.
- The resolver answers recursive queries only for configured client networks
  (no open resolver); per-client rate limiting is on by default.
