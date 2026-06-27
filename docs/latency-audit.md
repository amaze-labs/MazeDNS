# DNS Latency Audit (issues #5, #4)

Audit of the forwarding path in `internal/resolver` and the fixes applied.

## Findings & fixes

### 1. New client per query / TLS handshake per query
**Before:** `plainUpstream.Exchange` allocated a fresh `dns.Client` on every
query, and DoT (`dotUpstream`) redialed a TLS connection for every query — a full
TLS handshake (1–2 RTT) on each lookup, which dominates DoT latency.

**After:**
- `plainUpstream` builds its UDP/TCP clients once and reuses them.
- `dotUpstream` keeps a small pool (`dotPoolSize = 4`) of established TLS
  connections (`ExchangeWithConn`), so warm queries skip the handshake entirely.
  A stale pooled connection transparently falls back to a fresh dial + one retry.

### 2. Sequential upstreams burned the full timeout on a slow primary
**Before:** `forward` tried upstreams strictly in order; a slow or dead first
upstream cost the entire per-query timeout (up to 5s) before the second was
tried.

**After:** request **hedging**. The primary is queried immediately; if it hasn't
answered within `hedgeDelay = 30ms`, the remaining upstreams are queried in
parallel and the first success wins. A primary that errors fails over instantly.
In the common case only one upstream is queried (no extra load); a degraded
primary no longer stalls the query.

### 3. DNSSEC responses truncated → TCP fallback (issue #4)
**Before:** forcing the DO bit enlarges responses (RRSIGs); the client's default
UDP receive buffer (512 bytes) truncated them, forcing a second round trip over
TCP for nearly every signed answer — the cause of "DNSSEC makes it slow".

**After:**
- Plain UDP clients read with `UDPSize = 4096`.
- `ensureDO` advertises a ≥4096 EDNS UDP buffer, so signed responses arrive in a
  single datagram.
- `mazedns_upstream_tcp_fallback_total` now counts the remaining truncation
  retries, so the fallback rate is observable.

Semantics unchanged: DNSSEC remains AD-passthrough (validation stays upstream);
this is purely a latency fix.

## Further opportunities (not yet done)
- Cache prefetch / serve-stale for hot names at TTL expiry.
- Per-upstream health scoring to pick the historically-fastest primary.
- HTTP/3 (DoH3) for DoH upstreams.
