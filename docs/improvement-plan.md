# MazeDNS — Improvement Plan

Tracks the work for GitHub issues #2, #3, #4, #5, #7, #8. Each section lists the
root cause found in the code and the concrete tasks.

## Decisions taken
- **#8 default blocklist:** ship **no active default blocklist**; file-loaded
  entries are tagged with their **list source** (basename), not `custom`, so the
  user `custom` category stays clean.
- **#3 KPIs:** curated KPI set with **show/hide + localStorage persistence**.
- **#4 DNSSEC:** **latency fix only** — keep AD-passthrough semantics (validation
  stays upstream), no local validation.

---

## #7 — Graphs: colors don't match the legend
**Root cause:** node colors assigned by *array index* (`NODE_PALETTE[i % len]`)
independently in the latency lines, latency legend, the "Queries by node" donut,
and the node-focus dropdown — each ordered differently, so a node renders a
different color per component.

- [x] Deterministic `colorForNode(name)` shared everywhere; reserved color for `overall`.
- [x] Apply to latency lines + legend, by-node donut, node-focus swatches.

## #8 — Queries blocked as "custom" with no rules
**Root cause:** `configs/blocklist.hosts` loaded at startup with category
`"custom"` (`cmd/mazedns/main.go`), independent of UI rules.

- [x] Tag file blocklist entries with the list source, not `custom`.
- [x] Ship an empty/inactive default blocklist.
- [x] Verify empty rules + lists ⇒ zero blocked.
- [x] Remove the sample blocklist from the shipped image entirely: default
      `configs/mazedns.yaml` sets `blocklist_files: []`, the populated sample
      moved to `dev/blocklist.hosts` (dev compose + tests only), loaded via the
      new `MAZEDNS_BLOCKLIST_FILES` env override. (Subdomains of a blocked domain
      inherit the block, e.g. `doubleclick.net` ⇒ `securepubads.g.doubleclick.net`.)

## #5 — DNS latency audit
**Root cause:** new `dns.Client` per query (no socket reuse); DoT redials TLS per
query; upstreams tried sequentially burning the full timeout on a slow first.

- [x] Reuse clients / pool connections (UDP, DoT, DoH).
- [x] Race upstreams (first success wins) / fast failover.
- [x] Latency + TCP-fallback metrics for before/after measurement in production
      (`mazedns_upstream_duration_seconds`, `mazedns_upstream_tcp_fallback_total`).
      Hedge/failover behavior covered by unit tests; see `docs/latency-audit.md`.

## #4 — DNSSEC slowness
**Root cause:** forcing the DO bit enlarges responses → UDP truncation → TCP
fallback (extra round trip) per query.

- [x] Prefer TCP / larger EDNS buffer when DNSSEC is on; instrument fallback.
- [x] Reuse the connection-reuse work from #5.

## #2 — SSO config via env vars
**Root cause:** `config.Load` has env overrides for listen/api/db/log/cluster but
none for `Auth.OIDC` (or admin bootstrap).

- [x] `MAZEDNS_OIDC_*` + `MAZEDNS_ADMIN_USERNAME/PASSWORD` overrides.
- [x] Document in README + compose.

## #3 — Dashboard & UI overhaul
**Root cause:** Overview cards come from `api.stats()` (since-start, ignores
range + node focus); recent-queries has search only.

- [x] Every panel honors time range + node focus (drop since-start `stats()`).
- [x] Split traffic by selected window.
- [x] Curated KPIs with show/hide + persistence.
- [x] Recent queries: sortable columns + action/type/node filters.

### Follow-up: navigation reorganization
- [x] **Recent queries → dedicated "queries" tab** (`Queries.tsx`, "Requests"
      explorer) with its own window + node focus + action/type/search/sort.
- [x] **Merged Rules + Lists into one "filtering" tab** (`Filtering.tsx`) with
      Blocklists / Manual rules sub-tabs.
- [x] Shared filter UI (ranges, node-focus dropdown, node colors) extracted to
      `web/src/components/filters.tsx`; the query log honors the time window too
      (new `hours`/`SinceMs` on the query-log query).
