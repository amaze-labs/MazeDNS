import type { ClassifierStatus, ReputationUsageDay } from '../api'

// Known free-tier daily limits, used as a fallback for the quota bar when the API
// itself doesn't report one (VirusTotal v3 returns no remaining-quota header;
// AbuseIPDB does, and that takes precedence).
const SERVICES: Record<string, { label: string; defaultLimit: number; note: string }> = {
  virustotal: { label: 'VirusTotal', defaultLimit: 500, note: 'free tier ≈ 500 lookups/day' },
  abuseipdb: { label: 'AbuseIPDB', defaultLimit: 1000, note: 'free tier = 1000 checks/day' },
}

const todayUTC = () => new Date().toISOString().slice(0, 10)

// barTone colours the quota bar/badge by how close to the limit (or if throttled).
const barTone = (pct: number, rateLimited: boolean) =>
  rateLimited || pct >= 90 ? 'blocked' : pct >= 70 ? 'warn' : 'allow'

function ServiceQuota({ serviceKey, rows }: { serviceKey: string; rows: ReputationUsageDay[] }) {
  const meta = SERVICES[serviceKey]
  const mine = rows.filter((r) => r.service === serviceKey)
  const today = mine.find((r) => r.day === todayUTC())
  const calls = today?.calls ?? 0
  const errors = today?.errors ?? 0
  const rateLimited = today?.rate_limited ?? 0
  // Prefer the API-reported quota (authoritative, accounts for other tools sharing
  // the key); fall back to today's own call count vs the free-tier default.
  const reported = today && today.remaining >= 0 && today.limit > 0
  const limit = reported ? today!.limit : meta.defaultLimit
  const used = reported ? Math.max(0, today!.limit - today!.remaining) : calls
  const remaining = Math.max(0, limit - used)
  const pct = limit > 0 ? Math.min(100, Math.round((used / limit) * 100)) : 0
  const tone = barTone(pct, rateLimited > 0)
  const maxCalls = mine.reduce((m, r) => Math.max(m, r.calls), 0)

  return (
    <div className="quota">
      <div className="quota-head">
        <strong>{meta.label}</strong>
        <span className="muted">{meta.note}</span>
        <span className={`badge ${tone === 'warn' ? 'info' : tone}`} style={{ marginLeft: 'auto' }}>
          {pct}% of daily limit
        </span>
      </div>
      <div className="quota-bar" title={`${used} of ${limit} used today`}>
        <span className={`fill ${tone}`} style={{ width: `${pct}%` }} />
      </div>
      <div className="quota-stats muted">
        <span>
          <strong>{used.toLocaleString()}</strong> / {limit.toLocaleString()} used
          {reported ? '' : ' (est.)'}
        </span>
        <span>
          <strong>{remaining.toLocaleString()}</strong> remaining
        </span>
        <span>{calls.toLocaleString()} calls today</span>
        {errors > 0 && <span className="warn-text">{errors.toLocaleString()} errors</span>}
        {rateLimited > 0 && <span className="badge blocked">⚠ rate-limited ×{rateLimited}</span>}
      </div>
      {maxCalls > 0 && (
        <div className="quota-history">
          {[...mine].reverse().map((r) => (
            <span key={r.day} className="qh-bar" title={`${r.day}: ${r.calls} calls`}>
              <i style={{ height: `${Math.max(4, (r.calls / maxCalls) * 100)}%` }} className={r.rate_limited > 0 ? 'rl' : ''} />
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

// ReputationUsage shows how close the VirusTotal / AbuseIPDB keys are to their
// daily quota — rendered only for services the user has enabled.
export default function ReputationUsage({ info }: { info: ClassifierStatus }) {
  const rows = info.reputation_usage ?? []
  const enabled = [
    info.settings.vt_enabled && 'virustotal',
    info.settings.abuseipdb_enabled && 'abuseipdb',
  ].filter(Boolean) as string[]
  if (enabled.length === 0) return null
  return (
    <div className="settings-card" style={{ marginBottom: 18 }}>
      <h3>Reputation API usage</h3>
      <p className="muted" style={{ textAlign: 'left' }}>
        Calls made to each reputation service today and how close the key is to its daily quota. The trusted-list /
        CDN fast-path means most domains never reach these lookups, conserving quota.
      </p>
      <div className="quota-grid">
        {enabled.map((k) => (
          <ServiceQuota key={k} serviceKey={k} rows={rows} />
        ))}
      </div>
    </div>
  )
}
