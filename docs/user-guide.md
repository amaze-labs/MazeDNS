# User guide

Everything you do day-to-day happens in the **control-plane web UI** (default
`http://<control-plane-host>:8080`). The control plane holds all config; agents
replicate it automatically. You never edit files on an agent.

- [Dashboard](#dashboard)
- [Upstreams, cache, and DNS behavior](#upstreams-cache-and-dns-behavior)
- [Blocklists and allow/deny rules](#blocklists-and-allowdeny-rules)
- [Rewrites and local records](#rewrites-and-local-records)
- [Client names](#client-names)
- [Pause blocking](#pause-blocking)
- [Clustering operations](#clustering-operations)
- [Authentication and SSO](#authentication-and-sso)
- [API tokens](#api-tokens)
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

Switch the Requests tab to **Live** to watch queries as the agents answer them
(within about a second), newest first — e.g. while debugging a client or checking
that a new block rule takes effect. Filter by node or site, client (IP or resolved
name), domain, type, action, classification, and rcode; blocked and rewritten
queries are highlighted, and clicking a row opens the client's details. The
browser keeps the last 1000 rows, and the stream pauses while the tab is hidden.
Agents only send queries while someone is watching them, and only the ones that
match the filters. Live is best effort (a slow view drops rows); the stored query
log is unaffected.

## Upstreams, cache, and DNS behavior

Operational DNS settings live under **Settings** and apply live across the cluster
(no restart): every agent picks them up on its next config poll, and they override
the agent's own settings. Only the conditional forwarders listed there stay local to
the control plane (see below). An agent keeps its local settings until its first
successful sync, and keeps the last synced ones if the control plane is unreachable.
Agents older than the control plane ignore replicated settings until upgraded.

> **Upgrading:** before replicated settings, agents ignored this page and ran the
> settings seeded from their own config file. After upgrading, the control plane's
> settings replace them on every agent, so check this page (e.g. the upstreams)
> before rolling the upgrade out.

- **Upstream resolvers** — plain (`1.1.1.1:53`), DoT
  (`tls://1.1.1.1:853#cloudflare-dns.com`), or DoH (`https://dns.quad9.net/dns-query`).
  Quick-fill buttons are provided; use the ↑/↓ arrows on each row to set the order,
  which is saved exactly as shown. With the default **Ordered** strategy every query
  goes to the first resolver and the next one is tried only if it times out (the
  **per-resolver timeout**, default 1500 ms), fails, or answers `SERVFAIL`/`REFUSED`
  — never in parallel. **Hedged** instead races the remaining resolvers when the first
  hasn't answered within 30 ms, for lowest latency. Conditional forwarders with
  several upstreams follow the same strategy. See
  [Upstream strategy](configuration.md#upstream-strategy).
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
source of truth and the file is ignored for them. On an agent in a cluster, the
control plane's settings take precedence over both.

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

### Reverse lookups (PTR) from rewrites

Exact `A`/`AAAA` rewrites also answer reverse lookups for their address:
with `nas.example.lan → A 192.0.2.10`, `dig -x 192.0.2.10 @<agent>` returns
`nas.example.lan` (`2001:db8::10` works the same through `ip6.arpa`). There is
nothing to configure:

- **Scoping** — each agent derives PTR answers from the rewrites it serves, so
  they follow the forward record's scope: a site-scoped rewrite answers reverse
  lookups only on that site's nodes. Disabled and wildcard rewrites imply no PTR.
- **Several names, one address** — a single PTR is returned, the preferred name:
  shortest, then alphabetical (`fs.example.lan` over `nas.example.lan` over
  `storage.example.lan`). One record keeps every client and cache on the same
  answer, and it is the same name the Clients page shows.
- **Conditional forwarders win** — if a conditional forwarder covers the
  reverse name (e.g. `2.0.192.in-addr.arpa`, or all of `in-addr.arpa`, sent to
  the DHCP server that owns your PTRs), the query is forwarded there and no PTR
  is synthesized: an explicit routing choice beats an implied record. Remove or
  narrow the forwarder to let rewrites answer. Authoritative zones from the
  config file also take precedence.
- Addresses with no matching rewrite, and other query types on reverse names,
  are forwarded as before. Forward answers are unchanged, including the
  `NODATA` for the address family a rewritten name has no record for.

## Client names

Wherever a client IP is shown (Dashboard, Requests, Clients, domain drill-downs)
the UI labels it with a name, taking the first source that knows the IP:

1. **static** — a hostname you assigned on the client's detail view (Clients tab).
2. **netbird** — the NetBird peer name, when the NetBird integration is enabled.
3. **rewrite** — the name of an enabled, non-wildcard `A`/`AAAA` rewrite pointing
   at the IP. When several rewrites point at it, the shortest name (then
   alphabetical) is shown and the others appear in the tooltip (the badge reads
   `rewrite +N`). With scoped rewrites, the ones served by the node that handles
   the client win; if that node serves none for the IP, any enabled rewrite
   naming it is used. Rewrite changes rename clients immediately.
4. **reverse DNS** — a PTR lookup, for private addresses against the reverse-DNS
   resolver configured for the client's node, otherwise against the system
   resolver (cached for an hour, ten minutes when there is no PTR). Pointing that
   resolver at an agent also picks up the PTRs agents synthesize from rewrites
   (see above).

Rewrites come before reverse DNS because they are your own configuration and
cost no network query.

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
is shown once and then stored hashed. A revoked, expired or exhausted key can be
*Deleted* for good (audit-logged); an active key must be revoked first, and the
deprecated `join_token` can't be deleted while it is still in the config, since
every boot would import it again as an active key. Multisite networking (e.g. a WireGuard mesh so
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

## API tokens

Integrations, such as an IPAM that pushes its hosts as rewrites, call the API with
an **API token** instead of a user's password. Create one under **Settings →
Access & SSO → API tokens**: give it a name that says what it is for, a role
(**readonly** or **admin**) and an optional expiry. The token (`mzd_…`) is shown
**once**; only a hash is stored. Send it as a bearer header:

```bash
TOKEN=mzd_…   # paste the token shown at creation

# list rewrites (readonly or admin)
curl -H "Authorization: Bearer $TOKEN" https://dns.example.internal/api/rewrites

# add or update a rewrite (admin)
curl -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"domain":"nas.lan","rrtype":"A","value":"10.0.0.5"}' \
  https://dns.example.internal/api/rewrites
```

- **What a token can do:** whatever its role allows on DNS data: rewrites,
  forwarders, rules, lists, clients, resolver settings and the read-only views.
- **What it can never do, whatever its role:** manage users, API tokens, your
  own password, SSO / sessions / login settings, the metrics scrape token,
  credentials for integrations (NetBird, classifier and its connection test,
  metrics/log export),
  config backup and restore, or cluster nodes, sites and enrollment keys. Those
  answer **403** to a token and need a console sign-in.
- **SSO-only mode** has no effect on tokens: it only disables password login.
- **A token never outranks the admin who created it.** If that admin is
  demoted to readonly, their admin tokens act as readonly; if their account is
  deleted, their tokens stop working for good (re-creating an account with the
  same name doesn't revive them). Removing someone's access therefore also
  removes it from any token they kept a copy of. For a long-lived integration,
  create its token from an account that will stay.
- **Revoke** a token from the same list. It stops working on the next request.
  The list shows each token's role, last use (updated at most once a minute) and
  expiry, never its value.
- A request with an `Authorization: Bearer` header is judged on that header
  only: an invalid or revoked token gets **401**, even if the same client also
  sends a session cookie. Other schemes (e.g. `Basic`, added by a proxy in front of
  the console) are ignored.
- Creating and revoking tokens is recorded in the settings audit log, under the
  admin who did it. Changes to DNS data (rewrites, rules, …) have no change log
  yet, whoever makes them; where a token's action is recorded, it appears as
  `token:<name>`.

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
