import type { UpstreamStat } from './api'
import { fmtMs } from './components/tableKit'

// upstreamName shows an upstream as configured, without the default port.
// '' is a forward from an agent too old to report which upstream answered.
export const upstreamName = (u: string) => (u ? u.replace(/:53$/, '') : 'Not reported')

// upstreamRoute names an upstream together with the conditional forwarder
// that routed to it: "corp.internal → 10.0.0.2".
export const upstreamRoute = (forwarder: string, upstream: string) =>
  forwarder ? `${forwarder} → ${upstreamName(upstream)}` : upstreamName(upstream)

// upstreamQueriesURL opens the Queries page filtered to one upstream.
export const upstreamQueriesURL = (forwarder: string, upstream: string) =>
  `/queries?upstream=${encodeURIComponent(upstream)}${forwarder ? `&forwarder=${encodeURIComponent(forwarder)}` : ''}`

const share = (n: number, total: number) => (total ? Math.round((n / total) * 1000) / 10 : 0)

// upstreamHost is an upstream's server alone, for tight spots: no scheme,
// default port or DoT server name ("tls://1.1.1.1:853#one.one" → "1.1.1.1").
export const upstreamHost = (u: string) => {
  const m = /^(?:https:\/\/([^/]+)|(?:udp|tcp|tls):\/\/([^#]+))/.exec(u)
  const host = m ? m[1] || m[2] : u
  return host.replace(/#.*$/, '').replace(/:(53|853)$/, '')
}

// upstreamHint sums up where the default upstreams' forwards went, busiest
// first, for the Forwarded figure: "1.1.1.1 62% · 9.9.9.9 38%" — the same
// shares UpstreamBars shows for them. null when no default upstream reported
// one (no forwards yet, or only agents too old to say).
export function upstreamHint(rows: UpstreamStat[], shown = 2): string | null {
  const defaults = rows.filter((r) => r.forwarder === '' && r.count > 0)
  const total = defaults.reduce((n, r) => n + r.count, 0)
  const known = defaults.filter((r) => r.upstream)
  if (known.length === 0) return null
  const top = known.slice(0, shown).map((r) => `${upstreamHost(r.upstream)} ${Math.round((r.count / total) * 100)}%`)
  return top.join(' · ') + (known.length > shown ? ` +${known.length - shown}` : '')
}

// UpstreamBars breaks forwarded queries down by the upstream that answered:
// the default upstreams first, then one group per conditional forwarder, each
// with its share of all forwarded queries. Within a group every upstream has
// its share of the group and its mean latency; a row opens its queries.
export function UpstreamBars({ rows, color = 'var(--fwd)' }: { rows: UpstreamStat[]; color?: string }) {
  const total = rows.reduce((n, r) => n + r.count, 0)
  const groups = new Map<string, UpstreamStat[]>()
  for (const r of rows.filter((r) => r.count > 0)) {
    const g = groups.get(r.forwarder)
    if (g) g.push(r)
    else groups.set(r.forwarder, [r])
  }
  // Default upstreams first, then forwarders by volume.
  const ordered = [...groups.entries()]
    .map(([forwarder, ups]) => ({ forwarder, ups: ups.sort((a, b) => b.count - a.count), count: ups.reduce((n, r) => n + r.count, 0) }))
    .sort((a, b) => (a.forwarder === '' ? -1 : b.forwarder === '' ? 1 : b.count - a.count))
  const open = (r: UpstreamStat) => {
    window.history.pushState({}, '', upstreamQueriesURL(r.forwarder, r.upstream))
    window.dispatchEvent(new PopStateEvent('popstate'))
  }
  return (
    <div className="up-groups">
      {ordered.map((g) => {
        const max = g.ups[0]?.count ?? 0
        return (
          <section key={g.forwarder || '(default)'} className="up-group">
            {(ordered.length > 1 || g.forwarder) && (
              <h4>
                <span>{g.forwarder ? <>Forwarder <b className="mono">{g.forwarder}</b></> : 'Default upstreams'}</span>
                <span className="faint">{share(g.count, total)}% of forwarded</span>
              </h4>
            )}
            <ol className="cat-bars">
              {g.ups.map((r) => {
                const label = `${upstreamRoute(r.forwarder, r.upstream)}: ${r.count.toLocaleString()} queries (${share(r.count, g.count)}%), ${fmtMs(r.avg_latency_ms)} on average`
                const body = (
                  <>
                    <span className="nm mono">{upstreamName(r.upstream)}</span>
                    <span className="v">
                      {r.count.toLocaleString()} <span className="faint">{share(r.count, g.count)}%</span>
                      <span className="faint"> · {fmtMs(r.avg_latency_ms)}</span>
                    </span>
                    <span className="meter">
                      <i style={{ ['--k' as string]: r.upstream ? color : 'var(--faint)', width: `${max ? (r.count / max) * 100 : 0}%` }} />
                    </span>
                  </>
                )
                return (
                  <li key={r.upstream}>
                    {r.upstream ? (
                      <button type="button" className="cat-row" onClick={() => open(r)} title={`${label} — show them`}>
                        {body}
                      </button>
                    ) : (
                      // Older agents don't say which upstream answered: nothing to filter on.
                      <div className="cat-row static" title={`${label}. Agents older than this version don’t report the upstream.`}>
                        {body}
                      </div>
                    )}
                  </li>
                )
              })}
            </ol>
          </section>
        )
      })}
    </div>
  )
}
