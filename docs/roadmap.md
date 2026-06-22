# Build roadmap

Custom Go DNS filtering resolver → advanced features → multi-site clustering.
Single-node first; the data model is designed so clustering is additive.

- [x] **Phase 1 — Core resolver (runnable).** Go engine: UDP/TCP listeners,
      forward to upstreams + TTL cache, blocklist filter (hosts format), YAML
      config, structured logs, stat counters, Dockerfile. *It resolves and it
      blocks* — verified end-to-end (blocked NXDOMAIN, subdomain block, forward,
      cache hit).
- [x] **Phase 2 — API + persistence.** JSON REST control plane, SQLite store
      (rules, rewrites, query log), live policy reload, Prometheus `/metrics`.
      Verified: an API-added deny rule and rewrite change resolution, and the
      query log persists to SQLite. (Upstreams/clients tables: a later pass.)
- [x] **Phase 3 — Web UI.** React + Vite + TS SPA: dashboard (live stats + query
      log) and rules/rewrites config screens, served by the Go binary via
      `go:embed` (build `-tags embed_dist`). Verified: the binary serves
      index.html, hashed assets, SPA fallback, and the API together.
- [x] **Phase 4 — Auth.** Local users (argon2id, server-side revocable sessions,
      first-run admin bootstrap) + OIDC via Authentik (config-gated), enforced by
      default; route guards + RBAC (admin mutates, read-only GETs); React login
      gate. Verified: 401 → login → authed access → admin mutation → logout.
      (OIDC needs your Authentik to test the live flow.)
- [ ] **Phase 5 — Advanced DNS.** DoH/DoT/DoQ server endpoints + encrypted
      upstreams, DNSSEC validation, conditional / split-horizon forwarding,
      authoritative zones, EDNS Client Subnet, rate limiting. ← current focus
- [ ] **Phase 6 — Clustering.** Master→agent config replication (row-versioned
      diffs), multisite over WireGuard, Docker + k3s manifests, HA.
- [ ] **Phase 7 — Observability + DR.** Grafana dashboards, alerting, config
      backups, upgrade / runbooks.

## Decisions locked

- Custom app; `miekg/dns` for wire format only.
- Go backend/engine; React + Vite + TypeScript SPA frontend.
- SQLite (pure-Go) datastore, row-versioned for replication.
- Pluggable auth: local SQLite (default) + OIDC Authentik.
- Clustering is a goal; build single-node first, design for it.
