# Scoped DNS rewrites & centrally managed conditional forwarders

**Date:** 2026-07-09
**Status:** Approved design, pending implementation plan

## Goal

Today every rewrite replicates to every dns-agent, and conditional forwarders
are hand-configured per node. This feature makes both **scopeable**: an entry
applies to *all nodes*, an explicit *list of nodes*, or one or more *sites*
(the existing node-group concept). Conditional forwarders additionally become
**centrally managed** on the control plane and are pushed to agents
automatically through the existing cluster snapshot — no more per-node editing.

The same domain may carry different rewrite values under different scopes
(split-horizon): `nas.home → 10.0.0.5` at site A and `nas.home → 192.168.1.5`
at site B.

## Non-goals

- No new grouping concept: groups are the existing sites (a node belongs to at
  most one site). No tags, no multi-membership.
- No per-node scoping of blocking rules — rules stay cluster-global.
- No removal of node-local forwarders; they remain as local overrides that
  central entries take precedence over (per suffix).

## Architecture: server-side scoping

Scope metadata lives **only on the control plane**. The snapshot endpoint
authenticates each agent by its node key, so the master filters entries **per
node at serve time**. Agents receive plain, scope-free entries and stay dumb:

- `ApplySnapshot` is unchanged for rewrites; agents contain zero scope logic.
- An old agent binary keeps answering correctly during rolling upgrades — it
  simply receives fewer rewrites and ignores the unknown `Forwarders` field.
- The version hash keeps its meaning ("hash of the content this node holds");
  the master computes it over the filtered set per node, and drift detection
  works unchanged.

The control plane never serves DNS, so no scope applies to itself.

## Data model (control plane only)

### `rewrites` — two new columns

| Column | Type | Meaning |
|---|---|---|
| `scope_type` | TEXT NOT NULL DEFAULT `'all'` | `'all'` \| `'nodes'` \| `'sites'` |
| `scope_values` | TEXT NOT NULL DEFAULT `'[]'` | JSON array of node names or site names, canonically sorted |

Uniqueness changes from `UNIQUE(domain, rrtype)` to
`UNIQUE(domain, rrtype, scope_type, scope_values)` — this is what permits
per-scope split-horizon values. SQLite cannot alter a constraint, so the
migration rebuilds the table (create new, copy, drop, rename); existing rows
become `scope_type='all'`.

### New `forwarders` table

```sql
CREATE TABLE IF NOT EXISTS forwarders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    suffix TEXT NOT NULL,
    upstreams TEXT NOT NULL,            -- JSON array
    scope_type TEXT NOT NULL DEFAULT 'all',
    scope_values TEXT NOT NULL DEFAULT '[]',
    enabled INTEGER NOT NULL DEFAULT 1,
    updated_at INTEGER NOT NULL,
    UNIQUE(suffix, scope_type, scope_values)
);
```

### Matching

An entry applies to a node when `scope_type='all'`; or `'nodes'` and the
node's name is in `scope_values`; or `'sites'` and the node's site is in
`scope_values`.

### Precedence

When several entries for the same `domain+rrtype` (or forwarder suffix) match
one node, the **most specific wins**: node-scoped > site-scoped > all. Ties
within the same specificity are **rejected at write time** (config tables are
tiny; the overlap check is cheap): for the same `domain+rrtype` / suffix, two
`'nodes'` entries may not have intersecting node lists, and two `'sites'`
entries may not have intersecting site lists. A second `'all'` entry is
already blocked by the UNIQUE constraint. Every node therefore resolves to
exactly one winner per `domain+rrtype` / suffix.

Because precedence yields a single winner, the filtered set served to an agent
still satisfies the agent's existing `UNIQUE(domain, rrtype)` constraint —
**agent schemas need no migration**.

## Replication & agent behavior

### Snapshot (per-node, computed at serve time)

- New store queries `ListRewritesForNode(node)` and
  `ListForwardersForNode(node)` apply matching + precedence and return plain
  entries: `store.Rewrite` exactly as today, and `ForwardGroup{suffix,
  upstreams}` for forwarders.
- `cluster.Snapshot` gains one field: `Forwarders []ForwardGroup`.
- `ConfigVersionForNode(node)` replaces the global hash in the snapshot path:
  the same content-hash formula over rules + the node's filtered rewrites +
  its filtered forwarders (new `F|suffix|upstreams` lines alongside the
  existing `R|`/`W|` lines). Disabled forwarders are excluded from both the
  served list and the hash — the served `ForwardGroup` carries no enabled
  flag, so hashing disabled entries would never converge. (Disabled rewrites
  keep replicating with their flag, exactly as today.)

### Agent

- On sync, the agent persists received forwarders as a JSON blob in its local
  DB (the existing `app_meta` pattern). Its `ConfigVersion()` adds the `F|`
  lines from that blob, so master and agent still compute identical hashes
  from their own local data.
- After applying a snapshot (and at boot), the agent builds **effective
  settings**: its local settings plus the central forwarders, merged so that
  **central wins** when the same normalized suffix appears in both; then it
  calls `ApplySettings`. The merge happens at apply time only — central
  entries are never baked into the agent's saved local settings, so deleting
  a central forwarder on the control plane cleanly restores local behavior on
  the next poll.

### Rolling-upgrade compatibility

- No central forwarders defined → old and new hash formulas are identical; a
  mixed cluster stays in sync.
- Central forwarders scoped to a node running an old agent → that node's hash
  never converges; it harmlessly re-applies the snapshot each poll and shows
  as drift on the cluster page — a visible prompt to upgrade that agent.

## API

- `POST /api/rewrites` accepts optional `scope_type` + `scope_values`
  (absent → `'all'`; config-bundle import and rule-import keep working
  unchanged). `GET /api/rewrites` returns them.
- New `PUT /api/rewrites/{id}` edits value/scope/enabled without
  delete-and-recreate.
- New admin-gated CRUD: `GET/POST/PUT/DELETE /api/forwarders` with
  `suffix, upstreams[], scope_type, scope_values, enabled`.
- The config bundle (`internal/api/config.go`) gains the forwarders list and
  the scope fields on rewrites.
- `GET /api/cluster/nodes` gains `expected_version` per node so the cluster
  page flags drift per node instead of against one global version.

## UI

- **Rewrites page**: the add-form and each row get a scope control — default
  "All nodes", or a multi-select of nodes and/or sites (chips, fed from
  `/api/cluster/nodes` and `/api/cluster/sites`). The table gains a Scope
  column with a badge ("all", "3 nodes", "site: office"). An entry whose
  scope references a since-deleted node/site gets a warning badge (it matches
  nothing but is preserved).
- Same page gains a **"Conditional forwarders (cluster)"** section with the
  same scope control.
- The node-local Settings page keeps its forwarders section, with a note that
  a centrally-pushed forwarder for the same suffix takes precedence.

## Validation & error handling

- Domains and suffixes normalized with `filter.Normalize`; forwarder
  upstreams validated with the same parsing the settings path uses.
- Write-time rejection of same-specificity overlaps (see Precedence).
- Scope values referencing unknown nodes/sites are allowed but flagged in the
  UI (deleting a site already just unassigns its nodes today — same spirit).

## Testing

- **Store**: scope filtering, precedence (node > site > all), write-time
  overlap rejection (intersecting node lists and intersecting site lists),
  per-node version hashes (two nodes in different sites get different hashes;
  identical content → identical hash).
- **API**: filtered snapshot — two enrolled nodes in different sites receive
  different rewrites/forwarders; forwarders CRUD; `expected_version` in the
  nodes listing.
- **Agent**: merge semantics (central wins per suffix), forwarders blob
  persists across restart, deleting a central entry restores local behavior.
- Resolver logic is untouched by this feature (it already supports rewrites
  and conditional forwarders); no resolver test changes expected beyond what
  settings-merge tests exercise.
