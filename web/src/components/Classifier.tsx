import { useEffect, useState } from 'react'
import { api, type Classification, type ClassifierStatus } from '../api'
import Spinner from './Spinner'
import ClassifierHelp from './ClassifierHelp'
import DomainDetail from './DomainDetail'
import DecisionModal from './DecisionModal'
import ReputationUsage from './ReputationUsage'
import { pollWhileVisible } from '../poll'

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
  // Domain search — finds a domain within the current tab's list.
  const [search, setSearch] = useState('')
  const [searchQ, setSearchQ] = useState('')

  const [showHelp, setShowHelp] = useState(false)
  const [selected, setSelected] = useState<Classification | null>(null)
  // Pending allow/block awaiting the category + note review modal.
  const [pending, setPending] = useState<{ c: Classification; decision: 'approve' | 'reject' } | null>(null)
  // List viewer (trusted / threat)
  const [listView, setListView] = useState<'trusted' | 'threat' | null>(null)
  const [listSearch, setListSearch] = useState('')
  const [listRows, setListRows] = useState<string[]>([])

  const loadInfo = () => api.classifier().then(setInfo).catch((e) => setErr(e.message))
  // Search only applies to the Clean tab.
  const loadRows = () =>
    api
      .classifications(tab, PAGE, page * PAGE, searchQ)
      .then(setRows)
      .catch((e) => setErr(e.message))

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
    setSearch('') // and clear any search carried over from another tab
    setSearchQ('')
  }, [tab])
  // Debounce the search box; reset to the first page on a new query.
  useEffect(() => {
    const t = setTimeout(() => {
      setSearchQ(search.trim())
      setPage(0)
    }, 300)
    return () => clearTimeout(t)
  }, [search])
  useEffect(() => {
    loadRows()
    return pollWhileVisible(loadRows, 8000)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, page, searchQ])

  const setMode = async (mode: string) => {
    try {
      await api.setClassifierMode(mode)
      setErr('')
      loadInfo()
    } catch (e: any) {
      setErr(e.message)
    }
  }
  const decide = async (domain: string, decision: 'approve' | 'reject' | 'dismiss', category = '', note = '') => {
    try {
      await api.decideClassification(domain, decision, category, note)
      loadRows()
      loadInfo()
    } catch (e: any) {
      setErr(e.message)
    }
  }
  // Allow/Block go through the review modal (category + note); Dismiss is immediate.
  const requestDecision = (c: Classification, decision: 'approve' | 'reject' | 'dismiss') => {
    if (decision === 'dismiss') {
      decide(c.domain, 'dismiss')
      return
    }
    setPending({ c, decision })
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
  // When searching, the cached per-status count no longer reflects the filtered
  // result set, so drive paging off the returned page instead.
  const searchActive = searchQ !== ''
  const total = counts[tab] ?? 0
  const lastPage = searchActive
    ? rows.length === PAGE
      ? page + 1
      : page
    : Math.max(0, Math.ceil(total / PAGE) - 1)
  const showPager = searchActive ? page > 0 || rows.length === PAGE : total > PAGE
  // Category breakdown, most-seen first.
  const catCounts = Object.entries(info?.category_counts ?? {}).sort((a, b) => b[1] - a[1])
  // Which signals are live: static analysis is always on when classifying; the AI
  // model is an optional extra that only runs when an endpoint + model are set.
  const st = info?.settings
  const aiOn = !!(st?.endpoint?.trim() && st?.model?.trim())
  const trustedCount = info?.trusted_count ?? 0
  const threatCount = info?.threat_count ?? 0
  const feedCount = st?.threat_feeds?.length ?? 0
  return (
    <div>
      {showHelp && <ClassifierHelp onClose={() => setShowHelp(false)} />}
      {selected && (
        <DomainDetail c={selected} onClose={() => setSelected(null)} onAction={requestDecision} />
      )}
      {pending && (
        <DecisionModal
          domain={pending.c.domain}
          decision={pending.decision}
          currentCategory={pending.c.category}
          currentNote={pending.c.note}
          onClose={() => setPending(null)}
          onSubmit={async (category, note) => {
            await decide(pending.c.domain, pending.decision, category, note)
            setPending(null)
          }}
        />
      )}
      <h2 style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        Domain classification {!info && <Spinner />}
        <button className="btn" style={{ marginLeft: 'auto' }} onClick={() => setShowHelp(true)}>
          Learn more
        </button>
        <button className="btn ghost-danger" onClick={clearAll} title="Delete all classifications and start fresh">
          Clear all
        </button>
      </h2>
      <p className="muted" style={{ textAlign: 'left' }}>
        Each newly-seen domain is scored from <strong>100% legitimate</strong> downward by a set of signals. It's blocked
        only when a real threat indicator fires (a threat feed, a reputation service, or — if enabled — the AI model) and
        its legitimacy drops below 50%. No hand-maintained blocklists required.
      </p>

      {/* Engine status: spells out exactly which signals are live right now. */}
      <div className="settings-card cls-engine">
        <div className="cls-engine-head">
          <h3 style={{ margin: 0 }}>Active signals</h3>
          <span className={`badge ${aiOn ? 'info' : 'allow'}`}>
            {aiOn ? `Static analysis + AI (${st?.model})` : 'Static analysis only'}
          </span>
        </div>
        <div className="cat-chips" style={{ marginTop: 10 }}>
          <span className="cat-chip badge allow" title="Always on while classifying: domain age, risky TLDs, brand look-alikes, DGA/lexical patterns.">
            ✓ Static analysis · always on
          </span>
          {aiOn ? (
            <span className="cat-chip badge info" title="A local LLM adds one bounded signal and content categories.">
              🤖 AI model · {st?.model}
            </span>
          ) : (
            <span className="cat-chip badge" title="Set a model endpoint + model in Settings to enable the AI layer.">
              🤖 AI model · off
            </span>
          )}
          <button
            className={`cat-chip badge ${threatCount > 0 ? 'blocked' : ''}`}
            onClick={() => threatCount > 0 && openList('threat')}
            title="Domains on these feeds corroborate a malicious verdict."
          >
            🛡 Threat feeds · {threatCount > 0 ? `${threatCount.toLocaleString()} domains` : 'none'}
            {feedCount > 0 ? ` · ${feedCount} feed${feedCount === 1 ? '' : 's'}` : ''}
            {threatCount > 0 ? (listView === 'threat' ? ' ▴' : ' ▾') : ''}
          </button>
          <button
            className="cat-chip badge allow"
            onClick={() => trustedCount > 0 && openList('trusted')}
            title="Domains here (incl. CDN / cloud-edge providers) are never blocked."
          >
            ✓ Trusted list · {trustedCount.toLocaleString()} domains{trustedCount > 0 ? (listView === 'trusted' ? ' ▴' : ' ▾') : ''}
          </button>
          {st?.vt_enabled && <span className="cat-chip badge info" title="Per-domain reputation lookup.">VirusTotal</span>}
          {st?.abuseipdb_enabled && <span className="cat-chip badge info" title="Resolved-IP reputation lookup.">AbuseIPDB</span>}
          {st?.whois_enabled && <span className="cat-chip badge info" title="Domain age via RDAP — the single best phishing indicator.">WHOIS age</span>}
        </div>
        <p className="muted" style={{ textAlign: 'left', margin: '10px 0 0' }}>
          Tune signals in <strong>Settings → Domain classification</strong>.
        </p>
      </div>

      {err && <div className="error">{err}</div>}

      {listView && (
        <div className="settings-card" style={{ marginBottom: 18 }}>
          <h3>
            {listView === 'threat' ? 'Threat-intel domains' : 'Trusted domains'} (
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
            const tokens = t.prompt_tokens + t.completion_tokens
            const days = [...(info.llm_usage ?? [])].reverse() // oldest -> newest
            const maxCalls = days.reduce((m, d) => Math.max(m, d.calls), 0)
            // Average per active day (a day with at least one model call).
            const nDays = Math.max(1, days.length)
            const perDay = (n: number) => {
              const v = n / nDays
              return v >= 10 || v === 0 ? Math.round(v).toLocaleString() : v.toFixed(1)
            }
            return (
              <>
                <div className="usage-tiles">
                  <div className="usage-tile">
                    <span className="num">{perDay(t.calls)}</span>
                    <span className="muted">avg calls / day</span>
                  </div>
                  <div className="usage-tile">
                    <span className={`num${t.errors > 0 ? ' blocked' : ''}`}>{perDay(t.errors)}</span>
                    <span className="muted">avg errors / day</span>
                  </div>
                  <div className="usage-tile">
                    <span className="num">{tokens ? perDay(tokens) : '—'}</span>
                    <span className="muted">avg tokens / day</span>
                  </div>
                </div>
                {days.length > 0 && (
                  <table className="table compact" style={{ marginTop: 12 }}>
                    <thead>
                      <tr>
                        <th>Day</th>
                        <th>Calls</th>
                        <th>Errors</th>
                        <th>Tokens</th>
                        <th style={{ width: '40%' }}></th>
                      </tr>
                    </thead>
                    <tbody>
                      {days.map((d) => {
                        const dayTokens = d.prompt_tokens + d.completion_tokens
                        return (
                        <tr key={d.day}>
                          <td className="muted">{d.day}</td>
                          <td>{d.calls.toLocaleString()}</td>
                          <td>{d.errors > 0 ? <span className="badge blocked">{d.errors}</span> : '—'}</td>
                          <td title={dayTokens ? `${d.prompt_tokens.toLocaleString()} prompt / ${d.completion_tokens.toLocaleString()} completion` : ''}>
                            {dayTokens ? dayTokens.toLocaleString() : '—'}
                          </td>
                          <td>
                            <div className="cbar">
                              <span style={{ width: `${maxCalls ? (d.calls / maxCalls) * 100 : 0}%` }} />
                            </div>
                          </td>
                        </tr>
                        )
                      })}
                    </tbody>
                  </table>
                )}
              </>
            )
          })()}
        </div>
      )}

      {info && <ReputationUsage info={info} />}

      {catCounts.length > 0 && (
        <div className="settings-card" style={{ marginBottom: 18 }}>
          <h3>Traffic by category</h3>
          <p className="muted" style={{ textAlign: 'left' }}>
            Across all classified domains — security categories (blocked) plus, when the AI model is on, legitimate
            content types (social, streaming, …).
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

      <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap', margin: '4px 0 12px' }}>
        <p className="muted" style={{ textAlign: 'left', margin: 0 }}>
          Click a row for the full scorecard + WHOIS.{' '}
          <span className="badge allow">≥70 safe</span> <span className="badge info">50–69 watch</span>{' '}
          <span className="badge blocked">&lt;50 block candidate</span>
        </p>
        <input
          className="search"
          style={{ marginLeft: 'auto' }}
          placeholder="search domains…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>
      <div className="table-scroll">
      <table className="cls-table">
        <thead>
          <tr>
            <th>Domain</th>
            <th>Category</th>
            <th title="Legitimacy: every domain starts at 100% and each risk factor deducts. Below 50% it's a block candidate.">
              Legitimacy
            </th>
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
                      <button className="btn danger" onClick={stop(() => requestDecision(c, 'approve'))} title="Block this domain">
                        Block
                      </button>
                    )}
                    {/* Clean domains are already allowed, so an Allow button is redundant. */}
                    {c.status !== 'rejected' && tab !== 'clean' && (
                      <button className="btn" onClick={stop(() => requestDecision(c, 'reject'))} title="Allow — never block">
                        Allow
                      </button>
                    )}
                    {c.status === 'suggested' && (
                      <button className="btn ghost" onClick={stop(() => requestDecision(c, 'dismiss'))} title="Dismiss (may reappear later)">
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
      </div>

      {showPager && (
        <div className="pager">
          <span className="muted">
            {searchActive
              ? `page ${page + 1}`
              : `${total.toLocaleString()} item${total === 1 ? '' : 's'} · page ${page + 1} of ${lastPage + 1}`}
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
