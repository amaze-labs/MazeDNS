import type { ClassifierStatus, ReputationUsageDay } from '../api'

// Known free-tier daily limits, used as a fallback for the quota bar when the API
// itself doesn't report one (VirusTotal v3 returns no remaining-quota header;
// AbuseIPDB does, and that takes precedence).
const SERVICES: Record<string, { label: string; defaultLimit: number; note: string }> = {
  virustotal: { label: 'VirusTotal', defaultLimit: 500, note: 'Free tier: about 500 lookups a day' },
  abuseipdb: { label: 'AbuseIPDB', defaultLimit: 1000, note: 'Free tier: 1,000 checks a day' },
  opentip: { label: 'Kaspersky OpenTIP', defaultLimit: 200, note: 'Free tier: about 200 lookups a day' },
}

const todayUTC = () => new Date().toISOString().slice(0, 10)

// tone colours the quota meter by how close to the limit it is (or if throttled).
const tone = (pct: number, rateLimited: boolean) => (rateLimited || pct >= 90 ? 'block' : pct >= 70 ? 'warn' : 'ok')

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
  const k = tone(pct, rateLimited > 0)

  return (
    <div className="quota">
      <div className="quota-head">
        <b>{meta.label}</b>
        <span className={`tag ${k === 'ok' ? '' : k}`}>{pct}% of today’s limit</span>
      </div>
      <div className="meter" title={`${used} of ${limit} used today`}>
        <i style={{ width: `${pct}%`, ['--k' as string]: `var(--${k})` }} />
      </div>
      <div className="quota-stats">
        <span>
          <b>{used.toLocaleString()}</b> of {limit.toLocaleString()} used{reported ? '' : ' (estimated)'}
        </span>
        <span>
          <b>{remaining.toLocaleString()}</b> left
        </span>
        <span>{calls.toLocaleString()} calls today</span>
        {errors > 0 && <span className="warn-text">{errors.toLocaleString()} errors</span>}
        {rateLimited > 0 && <span className="bad-text">Rate-limited {rateLimited.toLocaleString()}×</span>}
      </div>
      <small className="faint">{meta.note}</small>
    </div>
  )
}

// ReputationUsage shows how close the VirusTotal / AbuseIPDB / OpenTIP keys are
// to their daily quota — rendered only for services the user has enabled.
export default function ReputationUsage({ info }: { info: ClassifierStatus }) {
  const rows = info.reputation_usage ?? []
  const enabled = [
    info.settings.vt_enabled && 'virustotal',
    info.settings.abuseipdb_enabled && 'abuseipdb',
    info.settings.opentip_enabled && 'opentip',
  ].filter(Boolean) as string[]
  if (enabled.length === 0) return null
  return (
    <section className="card">
      <h2>Reputation lookups</h2>
      <p className="sub">
        Calls to each reputation service today and how close the key is to its daily quota. Trusted and CDN domains skip these
        lookups, which saves quota.
      </p>
      <div className="quota-grid">
        {enabled.map((k) => (
          <ServiceQuota key={k} serviceKey={k} rows={rows} />
        ))}
      </div>
    </section>
  )
}
