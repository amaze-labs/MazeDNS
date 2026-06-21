# Build roadmap

Living checklist — update as we go.

- [x] **Phase 0 — Repo + decisions.** Layout, git, architecture doc.
- [ ] **Phase 1 — Local PoC (Docker Compose).** 2-node cluster on your laptop:
      form cluster, sign a zone, replicate it, fail the primary, promote.
      → `compose/phase1-local-cluster/` (ready now)
- [ ] **Phase 2 — Harden the authoritative tier.** DNSSEC + DS at registrar,
      TSIG, QPM rate-limiting, recursion OFF, lock the web/API port, OIDC SSO.
- [ ] **Phase 3 — Resolver tier.** Second cluster: recursion ACLs, split-horizon
      internal zones, forwarders, blocklists.
- [ ] **Phase 4 — Multi-site networking.** WireGuard mesh, static overlay IPs,
      join nodes across sites.
- [ ] **Phase 5 — k3s.** StatefulSet + PVC + MetalLB fixed IPs (no ingress on the
      cluster channel); add the k3s-site nodes.
- [ ] **Phase 6 — Observability + DR.** Prometheus/Grafana/Alertmanager,
      Technitium exporter, blackbox DNS probes, SOA-drift alerts, config backups
      + a promote-to-primary runbook.

## Inputs needed for later phases

- Public domain(s) + registrar (for DS/NS records, DNSSEC).
- Site count; which sites are k3s vs Docker; static public IP per site?
- Overlay: self-managed WireGuard vs Tailscale/Netbird vs existing VPN.
- IdP for SSO (Keycloak / Authentik / Entra / Google) — or defer.
- Internal zone name(s) + client CIDRs for the resolver tier.
- Anycast ambitions (own AS + IP space?) — otherwise multi-NS is enough.
