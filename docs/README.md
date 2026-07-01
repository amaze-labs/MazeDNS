# MazeDNS documentation

MazeDNS runs as two containers: a **control plane** (web UI, API, config — no DNS)
and one or more **DNS agents** (the resolvers your clients query). Everything below
is written for deploying and operating those containers — no source builds required.

## For operators

- **[Install](install.md)** — deploy with Docker/Compose (fast deploy first) or
  Kubernetes.
- **[Configuration](configuration.md)** — the authoritative reference for every
  `MAZEDNS_*` environment variable and YAML setting, split by control plane / agent /
  shared.
- **[User guide](user-guide.md)** — the dashboard, blocklists and rules, rewrites
  and local records, running a cluster, authentication and SSO, and backup/restore.
- **[Troubleshooting](troubleshooting.md)** — symptom → fix, using `docker`,
  `kubectl`, and `dig` only.

## Concepts at a glance

- **Control plane** — holds the config and dashboard, coordinates the cluster,
  never answers DNS. Run one.
- **DNS agent** — serves DNS and replicates its filtering config from the control
  plane. Run one or more. Clients point here.
- **Enrollment** — agents self-register with a shared **join token** and receive a
  per-node key automatically; they then appear in the **Cluster** tab.
- **Bootstrap vs. operational settings** — addresses/ports, TLS, database, auth,
  and cluster wiring come from env/YAML on every start; upstreams, cache, rate
  limits, and block behavior are seeded once and then edited live in the UI.

## For developers

Building from source, repo layout, and internals live under **[docs/dev/](dev/README.md)**:

- **[Development](dev/development.md)** — prerequisites, repo layout, `make` targets,
  running locally, tests, benchmarks, and the two-image Dockerfile.
- **[Architecture](dev/architecture.md)** — components, query pipeline, data model,
  clustering protocol.
- **[Latency audit](dev/latency-audit.md)** — resolver hot-path performance work.
- **[Improvement plan](dev/improvement-plan.md)** and **[Roadmap](dev/roadmap.md)**.
