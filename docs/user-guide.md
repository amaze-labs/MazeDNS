# User guide

Everything you do day-to-day happens in the **control-plane web UI** (default
`http://<control-plane-host>:8080`). The control plane holds all config; agents
replicate it automatically. You never edit files on an agent.

- [Dashboard](#dashboard)
- [Upstreams, cache, and DNS behavior](#upstreams-cache-and-dns-behavior)
- [Blocklists and allow/deny rules](#blocklists-and-allowdeny-rules)
- [Rewrites and local records](#rewrites-and-local-records)
- [Pause blocking](#pause-blocking)
- [Clustering operations](#clustering-operations)
- [Authentication and SSO](#authentication-and-sso)
- [Backup and restore](#backup-and-restore)
- [Seeing real client IPs](#seeing-real-client-ips)

---

## Dashboard

The dashboard groups KPIs into **traffic**, **protection**, and **performance**,
with a selectable time window (1 hour → 90 days), per-client and per-type
breakdowns, top domains, and a live query log. You can show/hide individual KPI
cards; the choice is remembered in your browser.

Use the **Requests** tab to inspect individual queries — filter by node, client, or
action, and sort by processing time (`ms`) to find slow lookups.

## Upstreams, cache, and DNS behavior

Operational DNS settings live under **Settings** and apply live across the cluster
(no restart):

- **Upstream resolvers** — tried in order, first to answer wins. Plain (`1.1.1.1:53`),
  DoT (`tls://1.1.1.1:853#cloudflare-dns.com`), or DoH
  (`https://dns.quad9.net/dns-query`). Quick-fill buttons are provided.
- **Conditional forwarders** — send a domain suffix to specific upstreams
  (split-horizon), e.g. `corp.internal` → your internal resolver. Cluster-wide
  forwarders are managed on the **Rewrites** tab, can be scoped to specific
  nodes or sites, and are pushed to the agents automatically; they override a
  node's own (YAML-seeded) forwarder for the same suffix.
- **Cache** — enable/size it and clamp TTLs (`min_ttl`/`max_ttl`).
- **Rate limit** — per-client queries per minute (`REFUSED` beyond).
- **DNSSEC** — force the DO bit upstream and surface the AD flag.
- **Block response** — `nxdomain` (default) or `zeroip` (`0.0.0.0` / `::`).

The config file only *seeds* these on first run; afterwards the database is the
source of truth and the file is ignored for them.

## Blocklists and allow/deny rules

Manage blocking from the UI:

- **Blocklists** — add lists from a file, pasted text, or a remote URL with
  scheduled auto-refresh. Enable/disable each independently, view entry counts, and
  remove them. Entries are tagged with their **list source** (not lumped into
  `custom`), so category stats stay meaningful.
- **Rules** — explicit **deny** (block a domain and its subdomains) or **allow**
  (exempt a domain from blocking). Allow wins over block.

A domain blocked by a list or a deny rule returns your configured block response.
Agents pick up changes automatically on their next sync.

File-based blocklists mounted into an agent (`MAZEDNS_BLOCKLIST_FILES`) are loaded
**locally** on that agent and are not replicated — mount them on every agent that
should use them.

## Rewrites and local records

Add local answers (LAN hosts, split-horizon overrides) under **Rewrites**:

- Exact records — `nas.lan → A 10.0.0.5`, plus `AAAA` and `CNAME`.
- Wildcards — `*.lab.lan → A 10.0.0.9` answers every subdomain.

The most specific match wins (an exact record beats a wildcard). This also
holds across rewrites and conditional forwarders: a forwarder whose suffix
matches the queried name more specifically than a wildcard rewrite takes the
query (e.g. with `*.lab.lan → 10.0.0.9` and a forwarder for `ha.lab.lan`,
names under `ha.lab.lan` are forwarded, every other `*.lab.lan` name is
rewritten). An exact rewrite always wins, as does a tie.

Rewrites can be **scoped**: to every node (default), to specific nodes, or to
one or more sites. The same domain may carry different values under different
scopes — the classic split-horizon setup where `nas.home` resolves to a
different address per site. When several entries match a node, the most
specific wins (node > site > all); creating two entries that would tie at the
same specificity is rejected. Entries scoped to a node or site that no longer
exists are kept but match nothing (flagged with ⚠ in the UI).

The **Conditional forwarders (cluster)** section on the same tab manages
suffix → upstream routing with identical scoping. Agents pick changes up on
their next config poll; the cluster page shows a per-node sync flag (⟳) until
each node has applied its own expected version.

## Pause blocking

A one-click control temporarily suspends blocking for N minutes across the cluster
— handy when a blocked domain breaks something and you're diagnosing it. Allow,
rewrite, cache, and forwarding are unaffected; blocking resumes automatically.

## Clustering operations

The control plane is the source of truth; each agent pulls rules + rewrites over an
authenticated snapshot and applies them live. The control plane never answers DNS,
so its dashboard/classifier load can't affect resolver latency.

- **Enrollment** — agents self-register with an **enrollment key** (created under
  Cluster → Enrollment keys, passed as `MAZEDNS_JOIN_TOKEN`) and appear in the
  **Cluster** tab automatically, no key to copy. Toggle **require approval**
  (setup wizard, or Settings → Access → Cluster policy) to hold new agents until you
  approve them there — `MAZEDNS_REQUIRE_APPROVAL` only seeds this on first boot.
- **Per-node keys** — issued automatically when an agent enrolls with a key, and
  rotated by the control plane. You can also issue one manually in the Cluster tab
  (used via `MAZEDNS_NODE_KEY`). An agent whose key was *rotated* re-attaches to the
  same node by itself; a *revoked* node is refused at re-enrollment until you
  un-revoke it (see [install.md](install.md#removing-an-agent-revoke-vs-remove-only)).
- **Node health** — the Cluster tab shows each node's address, status, and counters.
- **Maintenance/drain** — put a node into maintenance to answer `SERVFAIL` so clients
  fail over to another server while you work on it.
- **Removing agents** — *Remove & revoke* tombstones the node so the still-running
  agent can't rejoin; *Remove only* lets it re-enroll as a new node. Revoked agents
  are listed in a collapsible panel where you can *Un-revoke* (the agent may rejoin
  as a new node) or *Delete forever* (permanently remove the record — rejoining
  would still need a valid enrollment key).
- **Logs** — the **Logs** tab shows recent process logs from the control plane and
  every agent (admin only). Agents ship new lines with their config poll, so agent
  logs can lag by up to ~30s. Logs are kept in a bounded in-memory buffer — history
  is lost on restart; use VictoriaLogs export for durable, searchable query logs.

Create enrollment keys with an expiry and a maximum number of uses; the full secret
is shown once and then stored hashed. Multisite networking (e.g. a WireGuard mesh so
agents reach the control plane privately) is up to you; see
[install.md](install.md#reaching-the-control-plane-from-an-agent) for pinning the
control plane's IP when an agent can't resolve its FQDN.

## Authentication and SSO

The UI and API require login by default. On first run the control plane opens a
setup wizard where you create the first admin (or configure SSO) — there are no
`MAZEDNS_ADMIN_*` env vars. Lost the password? Reset it with the
`control-plane reset-admin` CLI. Passwords are argon2id-hashed and sessions are
server-side and revocable. Roles: **admin** (full) and **readonly** (GET only).

Configure single sign-on in the setup wizard or later under **Settings → Access &
SSO**: paste the issuer URL, client ID/secret, and the admin email or group. You can
map a provider group to admin, force SSO-only login, or auto-redirect to the
provider. The redirect URI must match your provider's registration exactly — the UI
shows the exact value to register, and it's logged at startup so you can compare.
(The `MAZEDNS_OIDC_*` variables still exist, but they only **seed** the database on
first boot and are ignored afterwards — see
[configuration.md](configuration.md#control-plane).)

## Backup and restore

The **Settings** tab can export the full mutable config — settings, rules, and
rewrites — as one versioned JSON bundle, and import it back. Import has two modes:
`merge` (upsert on top of what's there) and `replace` (clear rules and rewrites
first). A restore applies settings live, reloads the filtering policy, and bumps the
cluster config version so agents re-sync. The bundle omits users/sessions, the query
log, and per-node cluster keys.

From the command line against the control plane:

```bash
curl -s http://<control-plane-host>:8080/api/config/export -o mazedns-config.json
curl -s -X POST 'http://<control-plane-host>:8080/api/config/import?mode=replace' \
  -H 'Content-Type: application/json' --data-binary @mazedns-config.json
```

(Send your session cookie/credentials if auth is enabled.)

## Seeing real client IPs

The resolver reports each query's source IP as seen on the wire. When you publish
the DNS port through Docker's NAT (`-p 53:53`), the source is rewritten to the Docker
gateway, so per-client stats collapse to one client. To preserve real client IPs:

- **Docker (Linux):** run the agent with `network_mode: host` — see
  [install.md](install.md#real-client-ips-and-node-ips-host-networking).
- **Kubernetes:** give the DNS pod `hostNetwork: true`, or expose it via a Service
  with `externalTrafficPolicy: Local`.
- **Docker Desktop (macOS/Windows):** the VM can't pass the original client IP
  through NAT — expect a single collapsed client there.

For host-level DNS latency tuning (UDP buffers, conntrack), see
[troubleshooting.md](troubleshooting.md).
