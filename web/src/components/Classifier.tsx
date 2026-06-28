import { useEffect, useState } from 'react'
import { api, type Classification, type ClassifierStatus } from '../api'
import Spinner from './Spinner'
import ClassifierHelp from './ClassifierHelp'
import DomainDetail from './DomainDetail'

const MODES = [
  { id: 'off', label: 'Off', desc: 'Stop classifying.' },
  { id: 'suggest', label: 'Suggest & approve', desc: 'Record verdicts; you approve before they block.' },
  { id: 'auto', label: 'Auto-block', desc: 'Block-category verdicts take effect immediately.' },
]
const STATUS_TABS = ['suggested', 'auto', 'approved', 'rejected', 'clean']
// Clearer intent than the raw status keys: approved = you blacklisted it,
// rejected = you whitelisted it.
const STATUS_LABELS: Record<string, string> = {
  suggested: 'Suggested',
  auto: 'Auto-blocked',
  approved: 'Blacklisted',
  rejected: 'Whitelisted',
  clean: 'Clean',
}
export const statusLabel = (s: string) => STATUS_LABELS[s] ?? s
const PAGE = 25
const BLOCK_CATS = ['ads', 'trackers', 'malware', 'phishing']
// Security categories are red; "other" is neutral/green; content categories blue.
const catClass = (c: string) => (BLOCK_CATS.includes(c) ? 'blocked' : c === 'other' ? 'allow' : 'info')

// Classifier is the AI domain-classification console: pick the enforcement mode,
// review the model's verdicts, and approve/reject suggestions.
export default function Classifier() {
  const [info, setInfo] = useState<ClassifierStatus | null>(null)
  const [tab, setTab] = useState('suggested')
  const [page, setPage] = useState(0)
  const [rows, setRows] = useState<Classification[]>([])
  const [err, setErr] = useState('')

  const [showHelp, setShowHelp] = useState(false)
  const [selected, setSelected] = useState<Classification | null>(null)
  // List viewer (trusted / threat)
  const [listView, setListView] = useState<'trusted' | 'threat' | null>(null)
  const [listSearch, setListSearch] = useState('')
  const [listRows, setListRows] = useState<string[]>([])

  const loadInfo = () => api.classifier().then(setInfo).catch((e) => setErr(e.message))
  const loadRows = () => api.classifications(tab, PAGE, page * PAGE).then(setRows).catch((e) => setErr(e.message))

  useEffect(() => {
    loadInfo()
  }, [])
  useEffect(() => {
    if (!listView) return
    const t = setTimeout(
      () => api.classifierList(listView, listSearch, 200).then((r) => setListRows(r.domains)).catch(() => {}),
      300,
    )
    return () => clearTimeout(t)
  }, [listView, listSearch])
  const openList = (l: 'trusted' | 'threat') => {
    setListSearch('')
    setListRows([])
    setListView((cur) => (cur === l ? null : l))
  }
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
  const clearAll = async () => {
    if (!window.confirm('Delete ALL AI classifications and start fresh? Domains will be re-evaluated as they are queried again.')) return
    try {
      await api.clearClassifications()
      setPage(0)
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
      {showHelp && <ClassifierHelp onClose={() => setShowHelp(false)} />}
      {selected && (
        <DomainDetail c={selected} onClose={() => setSelected(null)} onAction={decide} />
      )}
      <h2 style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        AI classification {!info && <Spinner />}
        <button className="btn" style={{ marginLeft: 'auto' }} onClick={() => setShowHelp(true)}>
          Learn more
        </button>
        <button className="btn ghost-danger" onClick={clearAll} title="Delete all classifications and start fresh">
          Clear all
        </button>
      </h2>
      <p className="muted" style={{ textAlign: 'left' }}>
        A local model ({info?.settings.model || '—'}) classifies newly-seen domains as ads/trackers/malware/phishing or
        legitimate content (social, streaming, …), so blocking is driven by the model instead of hand-maintained lists.
        Configure the model in <strong>Settings</strong>.
        {(info?.trusted_count ?? 0) > 0 && (
          <>
            {' '}
            Trusted list: <strong>{info?.trusted_count.toLocaleString()}</strong> domains (never blocked; includes CDN /
            cloud-edge providers).{' '}
            <button className="linkbtn" onClick={() => openList('trusted')}>
              {listView === 'trusted' ? 'hide' : 'view'}
            </button>
          </>
        )}
        {(info?.threat_count ?? 0) > 0 && (
          <>
            {' '}
            Threat list: <strong>{info?.threat_count.toLocaleString()}</strong> known-malicious domains (abuse.ch
            URLhaus).{' '}
            <button className="linkbtn" onClick={() => openList('threat')}>
              {listView === 'threat' ? 'hide' : 'view'}
            </button>
          </>
        )}
      </p>
      {err && <div className="error">{err}</div>}

      {listView && (
        <div className="settings-card" style={{ marginBottom: 18 }}>
          <h3>
            {listView === 'threat' ? 'Threat-intel domains — abuse.ch URLhaus' : 'Trusted domains'} (
            {((listView === 'threat' ? info?.threat_count : info?.trusted_count) ?? 0).toLocaleString()})
          </h3>
          <input
            className="search"
            placeholder={`search ${listView} domains…`}
            value={listSearch}
            onChange={(e) => setListSearch(e.target.value)}
          />
          <div className="cat-chips" style={{ marginTop: 10 }}>
            {listRows.map((d) => (
              <span key={d} className={`cat-chip badge ${listView === 'threat' ? 'blocked' : 'allow'}`}>
                {d}
              </span>
            ))}
            {listRows.length === 0 && <span className="muted">No matches</span>}
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

      {info && (info.llm_usage_totals?.calls ?? 0) > 0 && (
        <div className="settings-card" style={{ marginBottom: 18 }}>
          <h3>LLM usage</h3>
          {(() => {
            const t = info.llm_usage_totals
            const avg = t.calls ? Math.round(t.latency_ms_total / t.calls) : 0
            const tokens = t.prompt_tokens + t.completion_tokens
            const days = [...(info.llm_usage ?? [])].reverse() // oldest -> newest
            const maxCalls = days.reduce((m, d) => Math.max(m, d.calls), 0)
            return (
              <>
                <div className="usage-tiles">
                  <div className="usage-tile">
                    <span className="num">{t.calls.toLocaleString()}</span>
                    <span className="muted">model calls</span>
                  </div>
                  <div className="usage-tile">
                    <span className="num">{t.errors.toLocaleString()}</span>
                    <span className="muted">errors</span>
                  </div>
                  <div className="usage-tile">
                    <span className="num">{avg} ms</span>
                    <span className="muted">avg latency</span>
                  </div>
                  <div className="usage-tile">
                    <span className="num">{tokens ? tokens.toLocaleString() : '—'}</span>
                    <span className="muted">tokens {tokens ? `(${t.prompt_tokens.toLocaleString()}p / ${t.completion_tokens.toLocaleString()}c)` : 'n/a'}</span>
                  </div>
                </div>
                {days.length > 0 && (
                  <table className="table compact" style={{ marginTop: 12 }}>
                    <thead>
                      <tr>
                        <th>Day</th>
                        <th>Calls</th>
                        <th>Errors</th>
                        <th>Avg ms</th>
                        <th style={{ width: '40%' }}></th>
                      </tr>
                    </thead>
                    <tbody>
                      {days.map((d) => (
                        <tr key={d.day}>
                          <td className="muted">{d.day}</td>
                          <td>{d.calls.toLocaleString()}</td>
                          <td>{d.errors > 0 ? <span className="badge blocked">{d.errors}</span> : '—'}</td>
                          <td>{d.calls ? Math.round(d.latency_ms_total / d.calls) : 0}</td>
                          <td>
                            <div className="cbar">
                              <span style={{ width: `${maxCalls ? (d.calls / maxCalls) * 100 : 0}%` }} />
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </>
            )
          })()}
        </div>
      )}

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
            {statusLabel(st)} {counts[st] ? `(${counts[st]})` : ''}
          </button>
        ))}
      </div>

      <p className="muted" style={{ textAlign: 'left' }}>
        Click a row for full details + WHOIS.
      </p>
      <table className="cls-table">
        <thead>
          <tr>
            <th>Domain</th>
            <th>Category</th>
            <th>Legitimacy</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {rows.map((c) => {
            const blocked = c.status === 'auto' || c.status === 'approved'
            const stop = (fn: () => void) => (e: React.MouseEvent) => {
              e.stopPropagation()
              fn()
            }
            return (
              <tr key={c.domain} className="cls-row" onClick={() => setSelected(c)}>
                <td className="cls-domain">{c.domain}</td>
                <td>
                  <span className={`badge ${catClass(c.category)}`}>{c.category}</span>
                  {c.threat && <span className="badge blocked" title="On a threat-intel feed (abuse.ch)" style={{ marginLeft: 6 }}>🛡</span>}
                  {c.trusted && <span className="badge allow" title="On the trusted list" style={{ marginLeft: 6 }}>✓</span>}
                </td>
                <td className="cls-conf">
                  <span className={`badge ${typeof c.score === 'number' && c.score < 50 ? 'blocked' : c.score < 70 ? 'info' : 'allow'}`}>
                    {typeof c.score === 'number' ? c.score : 100}%
                  </span>
                </td>
                <td>
                  <div className="cls-actions">
                    {!blocked && (
                      <button className="btn primary" onClick={stop(() => decide(c.domain, 'approve'))} title="Block this domain">
                        Block
                      </button>
                    )}
                    {c.status !== 'rejected' && (
                      <button className="btn" onClick={stop(() => decide(c.domain, 'reject'))} title="Allow — never block">
                        Allow
                      </button>
                    )}
                    {c.status === 'suggested' && (
                      <button className="btn ghost" onClick={stop(() => decide(c.domain, 'dismiss'))} title="Dismiss (may reappear later)">
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
              <td colSpan={4} className="muted">
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
