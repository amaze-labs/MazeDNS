# MazeDNS

A self-hosted **DNS filtering resolver** — like AdGuard Home / Pi-hole, but built
for **multi-site clustering**: one control plane holds your config and dashboard,
and any number of DNS agents replicate it and serve queries close to your clients.

- **Filtering resolver** — forward + cache + block ads/trackers/malware from
  managed blocklists, allow/deny rules, custom local records & rewrites (incl.
  `*.wildcard`), and a one-click "pause blocking for N minutes".
- **Advanced DNS** — DoH / DoT server + upstreams, DNSSEC-transparent forwarding,
  split-horizon/conditional forwarding, authoritative zones, per-client rate limits.
- **Web dashboard** — traffic / protection / performance KPIs with a selectable
  time window, per-client and per-type breakdowns, live query log, and all config.
- **Auth** — local users, or single sign-on via any **OIDC** provider (Authentik).
- **Clustering** — a control plane (no DNS) + DNS agents that self-enroll with an
  enrollment key and replicate config automatically. Multi-site HA on Docker/k8s.
- **Observability** — Prometheus `/metrics`, optional VictoriaMetrics/VictoriaLogs.

<!-- Add a dashboard screenshot here, e.g.: ![MazeDNS dashboard](docs/images/dashboard.png) -->

## How it runs

MazeDNS is two containers:

| Image | Serves | Run |
|-------|--------|-----|
| `ghcr.io/ipmaze/mazedns-control-plane` | web UI + API + `/metrics` (**no DNS**) | **one**, on the host you manage |
| `ghcr.io/ipmaze/mazedns-dns-agent` | DNS (UDP/TCP, opt. DoT/DoH) + `/healthz` + `/metrics` | **one or more**, wherever you serve DNS |

Clients point at the **agents**. Agents keep resolving from their local copy even
if the control plane is briefly down. This split keeps dashboard load off the
resolver hot path.

## Fast deploy (Docker Compose)

```bash
curl -O https://raw.githubusercontent.com/IPMaze/MazeDNS/main/docker-compose.prod.yml

# 1. Bring up the control plane, then open http://localhost:8080 and complete the
#    setup wizard (create your admin or configure SSO, then create an enrollment key).
#    There is no admin password env var, and no setup token — don't expose 8080
#    publicly until the wizard is done. (The placeholder just satisfies the agent
#    service's required var while the control plane starts.)
MAZEDNS_JOIN_TOKEN=placeholder docker compose -f docker-compose.prod.yml up -d control-plane

# 2. Start the agent with the enrollment key the wizard gave you:
MAZEDNS_JOIN_TOKEN='<enrollment-key>' docker compose -f docker-compose.prod.yml up -d
```

This runs a control plane (dashboard on `http://localhost:8080`) and one DNS agent
listening on `:53`. Log in with the admin account you created, then point a client
at the agent:

```bash
dig @<agent-host> example.com        # resolves
dig @<agent-host> doubleclick.net    # blocked
```

Full walkthrough — Docker, Kubernetes, `network_mode: host`, pinning the control
plane's IP — is in **[docs/install.md](docs/install.md)**.

## Documentation

Start at the **[documentation index](docs/README.md)**.

- **[Install](docs/install.md)** — Docker/Compose and Kubernetes.
- **[Configuration](docs/configuration.md)** — every `MAZEDNS_*` variable and YAML setting.
- **[User guide](docs/user-guide.md)** — dashboard, blocklists, rewrites, clustering, backup/restore, auth/SSO.
- **[Troubleshooting](docs/troubleshooting.md)** — symptom → fix.
- **[Developer docs](docs/dev/README.md)** — building from source and internals.

## Security notes

- Never expose the control-plane UI/API to the internet — keep it on a management
  network or VPN, behind a TLS reverse proxy.
- The agent's `/metrics` + `/healthz` endpoint is unauthenticated — bind it to a
  private address (it defaults to loopback).
- The resolver answers recursion only for its configured clients (no open
  resolver); per-client rate limiting is on by default.
