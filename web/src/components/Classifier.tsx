import { useEffect, useState } from 'react'
import { api, type Classification, type ClassifierStatus } from '../api'
import Spinner from './Spinner'

const MODES = [
  { id: 'off', label: 'Off', desc: 'Stop classifying.' },
  { id: 'suggest', label: 'Suggest & approve', desc: 'Record verdicts; you approve before they block.' },
  { id: 'auto', label: 'Auto-block', desc: 'Block-category verdicts take effect immediately.' },
]
const STATUS_TABS = ['suggested', 'auto', 'approved', 'rejected', 'clean']
const PAGE = 25
const BLOCK_CATS = ['ads', 'trackers', 'malware', 'phishing']
// Security categories are red; legitimate content categories are neutral/blue.
const catClass = (c: string) => (BLOCK_CATS.includes(c) ? 'blocked' : c === 'clean' || c === 'other' ? 'allow' : 'info')

// Classifier is the AI domain-classification console: pick the enforcement mode,
// review the model's verdicts, and approve/reject suggestions.
export default function Classifier() {
  const [info, setInfo] = useState<ClassifierStatus | null>(null)
  const [tab, setTab] = useState('suggested')
  const [page, setPage] = useState(0)
  const [rows, setRows] = useState<Classification[]>([])
  const [err, setErr] = useState('')

  // Trusted-list viewer
  const [showTrusted, setShowTrusted] = useState(false)
  const [trustedSearch, setTrustedSearch] = useState('')
  const [trustedRows, setTrustedRows] = useState<string[]>([])

  const loadInfo = () => api.classifier().then(setInfo).catch((e) => setErr(e.message))
  const loadRows = () => api.classifications(tab, PAGE, page * PAGE).then(setRows).catch((e) => setErr(e.message))

  useEffect(() => {
    loadInfo()
  }, [])
  useEffect(() => {
    if (!showTrusted) return
    const t = setTimeout(() => api.trustedList(trustedSearch, 200).then((r) => setTrustedRows(r.domains)).catch(() => {}), 300)
    return () => clearTimeout(t)
  }, [showTrusted, trustedSearch])
  useEffect(() => {
    setPage(0) // reset paging when switching tabs
  }, [tab])
  useEffect(() => {
    loadRows()
    const id = setInterval(loadRows, 5000)
    return () => clearInterval(id)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, page])

  const setMode = async (mode: string) => {
    try {
      await api.setClassifierMode(mode)
      setErr('')
      loadInfo()
    } catch (e: any) {
      setErr(e.message)
    }
  }
  const decide = async (domain: string, decision: 'approve' | 'reject' | 'dismiss') => {
    try {
      await api.decideClassification(domain, decision)
      loadRows()
      loadInfo()
    } catch (e: any) {
      setErr(e.message)
    }
  }

  const counts = info?.counts ?? {}
  const total = counts[tab] ?? 0
  const lastPage = Math.max(0, Math.ceil(total / PAGE) - 1)
  // Category breakdown, most-seen first.
  const catCounts = Object.entries(info?.category_counts ?? {}).sort((a, b) => b[1] - a[1])
  return (
    <div>
      <h2 style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        AI classification {!info && <Spinner />}
      </h2>
      <p className="muted" style={{ textAlign: 'left' }}>
        A local model ({info?.settings.model || '—'}) classifies newly-seen domains as ads/trackers/malware/phishing or
        clean, so blocking is driven by the model instead of hand-maintained lists. Configure the model in{' '}
        <strong>Settings</strong>.
        {(info?.trusted_count ?? 0) > 0 && (
          <>
            {' '}
            Trusted list: <strong>{info?.trusted_count.toLocaleString()}</strong> domains (flagged matches are never
            blocked).{' '}
            <button className="linkbtn" onClick={() => setShowTrusted((v) => !v)}>
              {showTrusted ? 'hide' : 'view'}
            </button>
          </>
        )}
        {(info?.threat_count ?? 0) > 0 && (
          <>
            {' '}
            Threat list: <strong>{info?.threat_count.toLocaleString()}</strong> known-malicious domains (corroborate
            verdicts).
          </>
        )}
      </p>
      {err && <div className="error">{err}</div>}

      {showTrusted && (
        <div className="settings-card" style={{ marginBottom: 18 }}>
          <h3>Trusted domains ({(info?.trusted_count ?? 0).toLocaleString()})</h3>
          <input
            className="search"
            placeholder="search trusted domains…"
            value={trustedSearch}
            onChange={(e) => setTrustedSearch(e.target.value)}
          />
          <div className="cat-chips" style={{ marginTop: 10 }}>
            {trustedRows.map((d) => (
              <span key={d} className="cat-chip badge allow">
                {d}
              </span>
            ))}
            {trustedRows.length === 0 && <span className="muted">No matches</span>}
          </div>
        </div>
      )}

      <div className="settings-card" style={{ marginBottom: 18 }}>
        <h3>Enforcement mode</h3>
        <div className="mode-row">
          {MODES.map((m) => (
            <button
              key={m.id}
              className={`btn ${info?.settings.mode === m.id ? 'primary' : ''}`}
              onClick={() => setMode(m.id)}
              title={m.desc}
            >
              {m.label}
            </button>
          ))}
        </div>
        <p className="muted" style={{ textAlign: 'left', marginTop: 8 }}>
          {MODES.find((m) => m.id === info?.settings.mode)?.desc}
        </p>
      </div>

      {catCounts.length > 0 && (
        <div className="settings-card" style={{ marginBottom: 18 }}>
          <h3>Traffic by category</h3>
          <p className="muted" style={{ textAlign: 'left' }}>
            What the model has seen across all classified domains — security categories plus legitimate content (social,
            streaming, …).
          </p>
          <div className="cat-chips">
            {catCounts.map(([cat, n]) => (
              <span key={cat} className={`cat-chip badge ${catClass(cat)}`}>
                {cat} <strong>{n.toLocaleString()}</strong>
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="subtabs">
        {STATUS_TABS.map((st) => (
          <button key={st} className={tab === st ? 'active' : ''} onClick={() => setTab(st)}>
            {st} {counts[st] ? `(${counts[st]})` : ''}
          </button>
        ))}
      </div>

      <table className="cls-table">
        <thead>
          <tr>
            <th>Domain</th>
            <th>Category</th>
            <th>Signals</th>
            <th>Confidence</th>
            <th>Reason</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {rows.map((c) => {
            const blocked = c.status === 'auto' || c.status === 'approved'
            return (
              <tr key={c.domain}>
                <td className="cls-domain">{c.domain}</td>
                <td>
                  <span className={`badge ${catClass(c.category)}`}>{c.category}</span>
                </td>
                <td>
                  <div className="cls-signals">
                    {c.threat && (
                      <span className="badge blocked" title="Listed on a threat-intelligence feed (abuse.ch URLhaus) — corroborated malicious.">
                        🛡 threat
                      </span>
                    )}
                    {c.trusted && (
                      <span className="badge allow" title="On the trusted (known-legitimate) list — not blocked.">
                        ✓ trusted
                      </span>
                    )}
                    {blocked && <span className="badge blocked">blocked</span>}
                    {c.status === 'rejected' && <span className="badge allow">allowed</span>}
                  </div>
                </td>
                <td className="cls-conf">{Math.round((c.confidence || 0) * 100)}%</td>
                <td className="muted cls-reason" title={c.reason}>
                  {c.reason}
                </td>
                <td>
                  <div className="cls-actions">
                    {/* Block: enforce, unless already blocked. */}
                    {!blocked && (
                      <button className="btn primary" onClick={() => decide(c.domain, 'approve')} title="Block this domain">
                        Block
                      </button>
                    )}
                    {/* Allow: never block (hide forever from suggestions). */}
                    {c.status !== 'rejected' && (
                      <button className="btn" onClick={() => decide(c.domain, 'reject')} title="Allow — never block (hide forever)">
                        Allow
                      </button>
                    )}
                    {/* Dismiss: hide once; the domain may be re-suggested later. */}
                    {c.status === 'suggested' && (
                      <button className="btn ghost" onClick={() => decide(c.domain, 'dismiss')} title="Dismiss this suggestion (may reappear later)">
                        Dismiss
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            )
          })}
          {rows.length === 0 && (
            <tr>
              <td colSpan={6} className="muted">
                Nothing here yet
              </td>
            </tr>
          )}
        </tbody>
      </table>

      {total > PAGE && (
        <div className="pager">
          <span className="muted">
            {total.toLocaleString()} item{total === 1 ? '' : 's'} · page {page + 1} of {lastPage + 1}
          </span>
          <div className="spacer" />
          <button className="btn" disabled={page <= 0} onClick={() => setPage((p) => Math.max(0, p - 1))}>
            ‹ Prev
          </button>
          <button className="btn" disabled={page >= lastPage} onClick={() => setPage((p) => Math.min(lastPage, p + 1))}>
            Next ›
          </button>
        </div>
      )}
    </div>
  )
}
