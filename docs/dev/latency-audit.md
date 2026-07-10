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

- **Upstream connection reuse** — `dotUpstream` keeps a warm TLS pool, and
  `plainUpstream` (TCP mode) keeps a warm plain-TCP pool sharing the same
  `getPooledConn`/`putPooledConn` bounded-pool code (`upstream.go`); both are kept
  alive by `MaintainUpstreams` (`resolver.go:259`) via a `warmer` interface. UDP
  needs no pool — `dns.Client.Exchange` opens an unconnected local socket per call,
  no handshake, so dial-per-query is cheap there. (Previously `plainUpstream` had no
  pool at all: every plain TCP forward — e.g. a `tcp://` conditional-forwarding
  spec — paid a full TCP handshake per query. Fixed.)
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
- **Listener tuning** — SO_REUSEPORT multi-socket auto-scaled to available CPUs by
  default (override with `MAZEDNS_UDP_LISTENERS`), 8 MiB socket buffers, EDNS-sized
  reads (`server.go`).
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

### P2 — Normalize the query name once — DONE *(low effort, medium impact)*
Implemented for the block/allow match: `Resolve` calls `MatchNormalized`/
`IsBlockedNormalized` with the already-normalized name. The cache/forward keys
(`cache.keyFor`, `resolver.forwardKey`) previously re-lowercased via `strings.ToLower`
and built the key with a `strings.Builder` + two `strconv.FormatUint` calls, several
allocations each. Both now append into one pre-sized byte buffer with inline ASCII
lowercasing — a single allocation per key. This shaved one allocation off every cache
`Get`/`Set` and every forward (e.g. `BenchmarkCacheGetParallel` 7→6 allocs,
`BenchmarkResolveForward` 13→12 allocs), on the path of every query. Original
analysis:

The name is lowercased up to three times per query: `Resolve` (`:386`),
`Engine.Match` internally (`filter.go:85`), and `cache.keyFor` (`cache.go:80`).
Each `ToLower` allocates when the name has any uppercase. **Strategy:** normalize
once and thread the normalized name into `Match`/`IsBlocked` and the cache key.

### P3 — Avoid the double copy on the miss path — DONE *(medium effort, medium impact)*
Implemented: `cache.Set` now takes ownership of the message and stores it directly
instead of deep-copying it (`cache.go`). This is safe because the resolver only ever
caches a freshly-forwarded message that it copies (never mutates) before returning to
callers, and `cache.Get` still hands out an independent `Copy` — so a stored entry is
never mutated in place. `-race` is clean. `BenchmarkCacheSet` (a small A-record reply):
257ns/560B/14 allocs → **189ns/312B/9 allocs** per store (−26% time, −44% bytes). The
saving scales with response size (RRs no longer deep-copied twice per miss). Original
analysis:

On a cache miss the forwarded message was copied by `cache.Set` (to store) and again by
`Resolve` before returning. **Strategy:** store once and return a single copy (mind
single-flight sharing — the stored copy must not be mutated by a coalesced caller).

### P4 — Cheaper cache hits *(high effort, high impact on cache-heavy loads)* — investigated, deferred
Every hit does `e.msg.Copy()` (a full RR deep copy, `cache.go:152`) plus a key
allocation. Measured: `BenchmarkCacheGetParallel` is **6 allocs/op, 272 B/op**
(single-CPU) for a 1-RR answer — the key buffer, the `dns.Msg` struct, the RR
backing-array slice, and one allocation per copied RR.

The deep copy is load-bearing, not incidental: `cache.Get` hands out the copy
specifically so callers can mutate it in place — `adjustTTL` rewrites RR TTLs
in-place, and downstream `finalize`/`stripDNSSEC`/`Truncate` (`resolver.go`) all
mutate the message's Answer/Ns/Extra slices in place. Skip the copy and any of
those would corrupt the shared cache entry for every concurrent reader (a data
race, not just a logic bug).

The two ways to actually avoid the RR-level allocations both require bypassing
`dns.Msg` for the fast path entirely — caching packed wire bytes and patching the
TTL/ID fields directly in a byte copy, then writing those bytes straight to the
connection instead of building a `dns.Msg` and calling `WriteMsg`. That's a real
architectural change (a parallel raw-bytes path through `Handle`, correct only
when DNSSEC-stripping/EDNS-rewriting/truncation aren't needed) for a modest win
per hit. Pooling just the outer `*dns.Msg` (via `CopyTo`) saves only 1 of the 6
allocations, and doing so safely needs explicit pool-return plumbed through
`Handle`/the DoT/DoH handlers with no risk of a message being reused while still
referenced. Given the risk/reward, this is deliberately left open rather than
implemented — revisit if profiling a real deployment shows cache-hit GC pressure
actually dominates.

### P5 — Trim per-query metric/log overhead — DONE (counters) *(low effort, low–medium impact)*
Implemented: the fixed set of action counters is pre-resolved once in `metrics.New`
and `record` increments them through `Metrics.IncQuery` (a plain map read) instead of
`Queries.WithLabelValues(action)` (which re-hashes the label set under an internal
lock) on every query. `BenchmarkIncQuery` vs the old path (parallel, 0 allocs both):
118.7ns/op → **40.0ns/op** (~2.9× faster under contention). Off the client latency
path, but cuts CPU/lock traffic on the record path at high QPS. The per-query
`QueryEvent` is now pooled too (`queryEventPool` in `resolver.go`): escape analysis
confirmed it heap-escapes on every call because it's passed through the
user-supplied `OnQuery` func value, so `record` now gets one from a `sync.Pool`,
fills it, calls `OnQuery`, and returns it — `OnQuery` implementations must not
retain the pointer past the call (the dns-agent's callback already only copies
fields into a `store.QueryLogEntry`, so this was a non-breaking, contained change).
Original analysis:

`Queries.WithLabelValues(action).Inc()` did a labelled map lookup every query; the
`QueryEvent` is allocated per query. **Strategy:** pre-resolve the handful of action
counters once at startup; optionally pool `QueryEvent`.

### P6 — Make dropped query-log entries observable — DONE *(trivial)*
Implemented: `QueryLogWriter` counts drops and exposes
`mazedns_querylog_dropped_total` (registered by the dns-agent).

### P8 — Shard the rate limiter and singleflight locks — DONE *(low effort, high-QPS-only impact)*
Implemented: both `rateLimiter` (`ratelimit.go`) and `singleflight` (`singleflight.go`)
now use the same 16-way lock-striped sharding as the cache (`cache.shardFor`'s
FNV-1a hash pattern, duplicated per-package per the existing in-package convention),
instead of one global mutex + map each. Previously every query with rate limiting
enabled contended on a single lock regardless of how many distinct clients were
querying, and every cache-miss forward's dedup bookkeeping contended on a single
lock regardless of how many distinct names were in flight. Only matters at high QPS
with many distinct clients/names — `-race` clean, existing behavior (limits,
bounded cleanup sweep, coalescing) unchanged, just scoped to a shard.

### P7 — Bounded UDP worker pool + buffer pooling *(medium–high effort, high-load only)*
`miekg/dns` spawns a goroutine per packet. Under extreme bursts this is scheduler/
GC pressure. **Strategy:** if profiling shows scheduler saturation, add a bounded
worker pool and a `sync.Pool` for read buffers/messages. SO_REUSEPORT multi-socket
already spreads ingestion; do this only if it proves necessary.

### Refresh-ahead prefetch — DONE *(low effort, medium impact on hot names)*
Implemented: `cache.Get` now signals a background refresh not only for stale
(serve-stale) hits but also when a still-fresh entry enters the last tenth of its
original TTL (`refreshAheadDivisor`, `cache.go`). The resolver reuses the existing
`refreshStale` dedup so continuously-queried names are re-fetched just before expiry
and effectively never go stale — extending serve-stale's first-miss coverage to the
common "popular record queried every few seconds" case. The entry now carries its
original clamped TTL to compute the window. Behavior for cold/rarely-hit names is
unchanged.

## Longer-term
- Per-upstream health scoring to pick the historically-fastest primary (beyond the
  fixed 30ms hedge).
- DoH3 (HTTP/3) upstreams.

## How to measure
- Resolver hot-path benchmarks live in `internal/resolver/bench_test.go`
  (`BenchmarkResolveCacheHit`, `BenchmarkResolveBlocked`, `BenchmarkResolveForward`,
  using a stub upstream), the cache store path in `internal/cache` (`BenchmarkCacheSet`,
  `BenchmarkCacheGetParallel`), the sealed matcher in `internal/filter/bench_test.go`,
  and the metric-increment path in `internal/metrics/bench_test.go`. Run with
  `go test -bench . -benchmem ./internal/{resolver,cache,filter,metrics}`.
- Profile a loaded agent with `pprof` (CPU + alloc) driven by the `dev/traffic`
  generators or `dnsperf`.
- Watch `mazedns_upstream_tcp_fallback_total`, the cache-hit ratio, and (after P6)
  `mazedns_querylog_dropped_total`.
