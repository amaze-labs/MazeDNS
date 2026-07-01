# DNS server performance audit

Audit of the resolver hot path (`internal/resolver`, `internal/cache`,
`internal/filter`) with the latency/efficiency work already applied and the
strategies still open, ordered by impact-per-effort.

## Per-query hot path (what runs on every query)

`Handle` (`resolver/resolver.go:318`) → `Resolve` (`:370`):

1. rate-limit check (if enabled)
2. `name = ToLower(TrimSuffix(q.Name,"."))` — 1 allocation (`:386`)
3. authoritative zone lookup (map)
4. rewrite lookup (map + wildcard walk)
5. **block match + allow match** — runs on **every** query, even cache hits
   (`:405`), because block state can change independently of cached answers
6. cache get (serve-stale aware)
7. on miss: force-DO (if DNSSEC), singleflight-coalesced forward with hedging,
   cache set
8. `finalize` (EDNS/DNSSEC hygiene) + UDP truncate to 1232
9. `record` — metrics + async query-log — runs **after** the reply is written
   (`:365`), so it is off the client's latency path

The cache-hit path (steps 1–6) is the highest-volume path and is where the
remaining wins concentrate.

## Already applied (verified in code)

- **Upstream connection reuse** — `plainUpstream` builds its clients once;
  `dotUpstream` keeps a warm TLS pool (`upstream.go`), kept alive by
  `MaintainUpstreams` (`resolver.go:259`).
- **Request hedging** — primary first, remaining upstreams launched in parallel
  after `hedgeDelay = 30ms`; first real answer wins, SERVFAIL/errors fail over
  immediately (`resolver.go:525`).
- **DNSSEC sizing** — force-DO advertises a ≥1232/4096 EDNS buffer and UDP replies
  are capped at the fragmentation-safe 1232 (TC only above that), avoiding a TCP
  round-trip on most signed answers (`resolver.go:351`, `ensureDO :709`).
- **Serve-stale (RFC 8767)** — a stale-but-in-grace hit is served instantly while
  one background goroutine refreshes it (`resolver.go:488`, `cache.go:28`).
- **Single-flight** — concurrent misses for the same question collapse into one
  upstream exchange (`resolver.go:438`).
- **Sharded cache** — 16 lock-striped shards, deep copy done *outside* the lock so
  concurrent hits don't serialize; sampled TTL-nearest eviction; negative caching
  from the SOA (`cache.go`).
- **Listener tuning** — opt-in SO_REUSEPORT multi-socket (`MAZEDNS_UDP_LISTENERS`),
  8 MiB socket buffers, EDNS-sized reads (`server.go`).
- **Non-blocking query log** — `QueryLogWriter.Write` drops on a full 4096 buffer
  instead of stalling the DNS goroutine (`store` writer).
- **GC tuning** — `GOGC` defaulted to 200 to cut tail-latency jitter (`boot.go`).

## Open strategies

### P1 — Drop the per-query lock in filter matching — DONE *(low effort, medium–high impact)*
Implemented: `filter.Engine.Seal()` freezes the map after `boot.BuildPolicy`
publishes it, and the lookup path reads lock-free once sealed. A parallel match
benchmark (`internal/filter/bench_test.go`) drops from ~70ns/op to ~8ns/op on 4
cores, 0 allocs; `-race` is clean. Original analysis:

`filter.Engine.Match` takes `mu.RLock()` on every call (`filter.go:89`), and
`Resolve` calls it **twice per query** (`Block.Match` + `Allow.IsBlocked`,
`resolver.go:405`). But an `Engine` is built once inside `boot.BuildPolicy` and
then published read-only through the atomic `pol` pointer — it is never mutated
after publication. The lock therefore only guards the (single-goroutine) build
phase yet costs two atomic read-modify-writes per query on a shared cache line
across every resolver goroutine. **Strategy:** seal the engine after build and read
the map lock-free (a `sealed` flag, or a dedicated immutable read path). Keep the
lock only on `Add`/`LoadHostsFile` during construction.

### P2 — Normalize the query name once — DONE (filter path) *(low effort, medium impact)*
Implemented for the block/allow match: `Resolve` calls `MatchNormalized`/
`IsBlockedNormalized` with the already-normalized name. The cache key still
lowercases independently (`cache.keyFor`) — left as a smaller follow-up. Original
analysis:

The name is lowercased up to three times per query: `Resolve` (`:386`),
`Engine.Match` internally (`filter.go:85`), and `cache.keyFor` (`cache.go:80`).
Each `ToLower` allocates when the name has any uppercase. **Strategy:** normalize
once and thread the normalized name into `Match`/`IsBlocked` and the cache key.

### P3 — Avoid the double copy on the miss path *(medium effort, medium impact)*
On a cache miss the forwarded message is copied by `cache.Set` (to store,
`cache.go:155`) and again by `Resolve` before returning (`resolver.go:458`).
**Strategy:** store once and return a single copy (mind single-flight sharing — the
stored copy must not be mutated by a coalesced caller).

### P4 — Cheaper cache hits *(high effort, high impact on cache-heavy loads)*
Every hit does `e.msg.Copy()` (a full RR deep copy, `cache.go:125`) plus a key
allocation — the single biggest per-hit cost. **Strategy:** store the packed wire
bytes alongside the message and rewrite TTLs on the wire (or serve from a
`sync.Pool` of messages), so a hit re-packs from bytes instead of deep-copying the
RR tree. Biggest potential win, biggest change — profile first.

### P5 — Trim per-query metric/log overhead *(low effort, low–medium impact)*
`Queries.WithLabelValues(action).Inc()` does a labelled map lookup every query
(`resolver.go:470`); the `QueryEvent` is allocated per query. **Strategy:**
pre-resolve the handful of action counters once at startup; optionally pool
`QueryEvent`. Off the client latency path, but reduces GC churn at high QPS.

### P6 — Make dropped query-log entries observable — DONE *(trivial)*
Implemented: `QueryLogWriter` counts drops and exposes
`mazedns_querylog_dropped_total` (registered by the dns-agent).

### P7 — Bounded UDP worker pool + buffer pooling *(medium–high effort, high-load only)*
`miekg/dns` spawns a goroutine per packet. Under extreme bursts this is scheduler/
GC pressure. **Strategy:** if profiling shows scheduler saturation, add a bounded
worker pool and a `sync.Pool` for read buffers/messages. SO_REUSEPORT multi-socket
already spreads ingestion; do this only if it proves necessary.

## Longer-term
- Per-upstream health scoring to pick the historically-fastest primary (beyond the
  fixed 30ms hedge).
- Cache prefetch for hot names ahead of expiry (serve-stale covers the first-miss
  case today).
- DoH3 (HTTP/3) upstreams.

## How to measure
- Add Go benchmarks for the two hot paths — cache hit and block/allow match — to
  quantify P1/P2/P4 before and after.
- Profile a loaded agent with `pprof` (CPU + alloc) driven by the `dev/traffic`
  generators or `dnsperf`.
- Watch `mazedns_upstream_tcp_fallback_total`, the cache-hit ratio, and (after P6)
  `mazedns_querylog_dropped_total`.
