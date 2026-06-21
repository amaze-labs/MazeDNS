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

> The code skeleton lands next. Once it does:
>
> ```bash
> go run ./cmd/mazedns --config configs/mazedns.yaml
> dig @127.0.0.1 -p 5300 example.com      # resolves
> dig @127.0.0.1 -p 5300 doubleclick.net  # blocked
> ```

## Security notes

- Never expose the admin API / UI to the internet — management network / VPN only.
- The resolver answers recursive queries only for configured client networks
  (no open resolver); per-client rate limiting is on by default.
