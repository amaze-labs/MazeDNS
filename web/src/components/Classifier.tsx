import { useCallback, useEffect, useRef, useState } from 'react'
import { api, type Classification, type ClassifierStatus } from '../api'
import Spinner from './Spinner'
import ClassifierHelp from './ClassifierHelp'
import DomainDetail, { catTag, scoreTone, statusLabel } from './DomainDetail'
import DecisionModal, { type Decision } from './DecisionModal'
import ReputationUsage from './ReputationUsage'
import { pollWhileVisible } from '../poll'
import { PAGE_SIZE, TableStatusRow } from './tableKit'

const MODES = [
  { id: 'off', label: 'Off', desc: 'Domains are not scored. Earlier decisions stay in force.' },
  { id: 'suggest', label: 'Suggest', desc: 'Low scores wait in “To check” — nothing is blocked until you approve it.' },
  { id: 'auto', label: 'Auto-block', desc: 'Security verdicts block right away. Trusted domains are still spared.' },
]
const STATUS_TABS = ['suggested', 'auto', 'approved', 'rejected', 'clean']
const PAGE = PAGE_SIZE
const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1)

// Classifier is the review queue for scored domains: pick a status, open a row
// for its scorecard, block or allow it. Below the queue sit the engine settings
// that matter while reviewing (enforcement mode, live signals, usage). The page
// (Filtering) owns and polls the classifier status (`info`).
export default function Classifier({
  info,
  infoErr,
  reloadInfo,
  canEdit,
}: {
  info: ClassifierStatus | null
  infoErr: string
  reloadInfo: () => Promise<void> | void
  canEdit: boolean
}) {
  const [tab, setTab] = useState('suggested')
  const [page, setPage] = useState(0)
  const [rows, setRows] = useState<Classification[]>([])
  const [rowsLoaded, setRowsLoaded] = useState(false)
  // Load errors clear on the next successful poll; action errors stay until the
  // next action or until dismissed.
  const [rowsErr, setRowsErr] = useState('')
  const [actionErr, setActionErr] = useState('')
  const [search, setSearch] = useState('')
  const [searchQ, setSearchQ] = useState('')

  const [showHelp, setShowHelp] = useState(false)
  const [selected, setSelected] = useState<Classification | null>(null)
  const [pending, setPending] = useState<{ c: Classification; decision: Decision } | null>(null)
  const [busy, setBusy] = useState('')

  // Trusted / threat list viewer.
  const [listView, setListView] = useState<'trusted' | 'threat' | null>(null)
  const [listSearch, setListSearch] = useState('')
  const [listRows, setListRows] = useState<string[]>([])
  const [listLoaded, setListLoaded] = useState(false)
  const [listErr, setListErr] = useState('')

  // Only the newest request may write rows: switching status or page while an
  // older request is in flight must not let it land last and overwrite them.
  const seq = useRef(0)
  const loadRows = useCallback(() => {
    const mine = ++seq.current
    return api
      .classifications(tab, PAGE, page * PAGE, searchQ)
      .then((rs) => {
        if (mine !== seq.current) return
        setRows(rs)
        setRowsLoaded(true)
        setRowsErr('')
      })
      .catch((e) => {
        if (mine === seq.current) setRowsErr(e.message)
      })
  }, [tab, page, searchQ])

  useEffect(() => {
    loadRows()
    return pollWhileVisible(loadRows, 8000)
  }, [loadRows])

  const switchTab = (t: string) => {
    if (t === tab) return
    setTab(t)
    setPage(0)
    setSearch('')
    setSearchQ('')
    setRows([])
    setRowsLoaded(false)
  }
  // Debounce the search box; a new query starts at the first page.
  useEffect(() => {
    const q = search.trim()
    if (q === searchQ) return
    const t = setTimeout(() => {
      setSearchQ(q)
      setPage(0)
    }, 300)
    return () => clearTimeout(t)
  }, [search, searchQ])

  useEffect(() => {
    if (!listView) return
    let alive = true
    const t = setTimeout(
      () =>
        api
          .classifierList(listView, listSearch, 200)
          .then((r) => {
            if (!alive) return
            setListRows(r.domains)
            setListLoaded(true)
            setListErr('')
          })
          .catch((e) => alive && setListErr(e.message)),
      300,
    )
    return () => {
      alive = false
      clearTimeout(t)
    }
  }, [listView, listSearch])
  const openList = (l: 'trusted' | 'threat') => {
    setListSearch('')
    setListRows([])
    setListLoaded(false)
    setListErr('')
    setListView((cur) => (cur === l ? null : l))
  }

  const refreshAll = () => {
    loadRows()
    reloadInfo()
  }
  const setMode = async (mode: string) => {
    setBusy('mode')
    try {
      await api.setClassifierMode(mode)
      setActionErr('')
      await reloadInfo()
    } catch (e: any) {
      setActionErr(`Could not change the mode: ${e.message}`)
    } finally {
      setBusy('')
    }
  }
  // decide throws on failure so the decision form can show the error and keep
  // the typed note.
  const decide = useCallback(
    async (c: Classification, decision: Decision, category: string, note: string) => {
      await api.decideClassification(c.domain, decision, category, note)
      setActionErr('')
      refreshAll()
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [loadRows, reloadInfo],
  )
  const dismiss = useCallback(
    async (c: Classification) => {
      await api.decideClassification(c.domain, 'dismiss')
      setActionErr('')
      refreshAll()
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [loadRows, reloadInfo],
  )
  const dismissRow = async (c: Classification) => {
    setBusy(c.domain)
    try {
      await dismiss(c)
    } catch (e: any) {
      setActionErr(`Could not dismiss ${c.domain}: ${e.message}`)
    } finally {
      setBusy('')
    }
  }
  const clearAll = async () => {
    if (!window.confirm('Delete every classification and start fresh? Domains are scored again as they are queried.')) return
    setBusy('clear')
    try {
      await api.clearClassifications()
      setActionErr('')
      setPage(0)
      refreshAll()
    } catch (e: any) {
      setActionErr(`Could not clear the classifications: ${e.message}`)
    } finally {
      setBusy('')
    }
  }

  // Modal re-runs its focus effect whenever onClose changes, so these must be
  // stable — otherwise every poll would pull focus out of the note box.
  const closeDetail = useCallback(() => setSelected(null), [])
  const closePending = useCallback(() => setPending(null), [])
  const closeHelp = useCallback(() => setShowHelp(false), [])

  const counts = info?.counts ?? {}
  // While searching, the per-status count doesn't describe the filtered set, so
  // page off the returned rows instead.
  const searchActive = searchQ !== ''
  const total = counts[tab] ?? 0
  const lastPage = searchActive ? (rows.length === PAGE ? page + 1 : page) : Math.max(0, Math.ceil(total / PAGE) - 1)
  const showPager = searchActive ? page > 0 || rows.length === PAGE : total > PAGE
  // Decisions shrink a status; don't leave the pager past its end.
  useEffect(() => {
    if (!searchActive && info && page > lastPage) setPage(lastPage)
  }, [searchActive, info, page, lastPage])

  // Keep the open drawer in step with polled rows.
  const sel = selected ? (rows.find((r) => r.domain === selected.domain) ?? selected) : null

  const catCounts = Object.entries(info?.category_counts ?? {}).sort((a, b) => b[1] - a[1])
  const st = info?.settings
  // The model is on when one is set and reachable: Anthropic needs no endpoint,
  // OpenAI-compatible providers do.
  const aiOn = !!(st?.ai_enabled && st?.model?.trim() && (st?.provider === 'anthropic' || st?.endpoint?.trim()))
  const trustedCount = info?.trusted_count ?? 0
  const threatCount = info?.threat_count ?? 0
  const feedCount = st?.threat_feeds?.length ?? 0
  const err = actionErr
  const cols = canEdit ? 5 : 4

  return (
    <div className="review">
      {showHelp && <ClassifierHelp onClose={closeHelp} />}
      {sel && <DomainDetail c={sel} onClose={closeDetail} canEdit={canEdit} onDecide={decide} onDismiss={dismiss} />}
      {pending && (
        <DecisionModal
          domain={pending.c.domain}
          decision={pending.decision}
          currentCategory={pending.c.category}
          currentNote={pending.c.note}
          onClose={closePending}
          onSubmit={async (category, note) => {
            await decide(pending.c, pending.decision, category, note)
            setPending(null)
          }}
        />
      )}

      <p className="intro">
        New domains get a legitimacy score from threat feeds, WHOIS age, the shape of the name and, if enabled, a language model. Low
        scores land in “To check” for you to decide.{' '}
        <button className="linklike" onClick={() => setShowHelp(true)}>
          How scoring works
        </button>
      </p>

      {err && (
        <div className="error" role="alert">
          <span className="grow">{err}</span>
          <button className="btn sm quiet" onClick={() => setActionErr('')}>
            Dismiss
          </button>
        </div>
      )}
      {infoErr && <div className="error">Could not load the classifier status: {infoErr}</div>}
      {rowsErr && rowsLoaded && <div className="error">Could not refresh the list: {rowsErr}</div>}

      <div className="toolbar">
        <div className="seg status-seg" role="tablist" aria-label="Status">
          {STATUS_TABS.map((s) => (
            <button key={s} role="tab" aria-selected={tab === s} className={tab === s ? 'on' : ''} onClick={() => switchTab(s)}>
              {statusLabel(s)}
              {counts[s] ? <span className="cnt">{counts[s].toLocaleString()}</span> : null}
            </button>
          ))}
        </div>
        <span className="spacer" />
        <input
          type="search"
          className="search review-search"
          placeholder="Search domains"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          aria-label="Search domains"
        />
      </div>

      <section className="card flush">
        <div className="table-scroll">
          <table className="stackable review-table">
            <thead>
              <tr>
                <th>Domain</th>
                <th>Category</th>
                <th title="Every domain starts at 100 and each risk factor deducts. Below 50 it is a block candidate.">Legitimacy</th>
                <th className="hide-sm">Main reason</th>
                {canEdit && <th aria-label="Actions" />}
              </tr>
            </thead>
            <tbody>
              {rows.map((c) => {
                const score = typeof c.score === 'number' ? c.score : 100
                const blocked = c.status === 'auto' || c.status === 'approved'
                const stop = (fn: () => void) => (e: React.MouseEvent) => {
                  e.stopPropagation()
                  fn()
                }
                return (
                  <tr
                    key={c.domain}
                    className={`click${sel?.domain === c.domain ? ' sel' : ''}`}
                    onClick={() => setSelected(c)}
                    tabIndex={0}
                    onKeyDown={(e) => e.key === 'Enter' && setSelected(c)}
                  >
                    <td className="lead">
                      <span className="domain">{c.domain}</span>
                    </td>
                    <td className="cat-cell">
                      <span className={`tag ${catTag(c.category)}`}>{cap(c.category)}</span>
                      {c.threat && <span className="tag block">Threat feed</span>}
                      {c.trusted && <span className="tag ok">Trusted</span>}
                    </td>
                    <td className="lead-r">
                      <span className="score">
                        <b className={`${scoreTone(score)}-text`}>{score}</b>
                        <span className="meter hide-sm" aria-hidden="true">
                          <i style={{ width: `${score}%`, ['--k' as string]: `var(--${scoreTone(score)})` }} />
                        </span>
                      </span>
                    </td>
                    <td className="hide-sm muted">
                      <span className="reason" title={c.reason}>
                        {c.reason || '—'}
                      </span>
                    </td>
                    {canEdit && (
                      <td className="actions hide-sm">
                        {busy === c.domain ? (
                          <Spinner />
                        ) : (
                          <>
                            {!blocked && (
                              <button className="btn sm danger" onClick={stop(() => setPending({ c, decision: 'approve' }))}>
                                Block
                              </button>
                            )}
                            {/* Clean domains are already allowed. */}
                            {c.status !== 'rejected' && tab !== 'clean' && (
                              <button className="btn sm" onClick={stop(() => setPending({ c, decision: 'reject' }))}>
                                Allow
                              </button>
                            )}
                            {c.status === 'suggested' && (
                              <button className="btn sm quiet" onClick={stop(() => dismissRow(c))} title="Hide it for now; it may come back">
                                Dismiss
                              </button>
                            )}
                          </>
                        )}
                      </td>
                    )}
                  </tr>
                )
              })}
              <TableStatusRow loading={!rowsLoaded} error={rowsErr} empty={rows.length === 0} colSpan={cols}>
                {searchActive ? 'No domains match.' : tab === 'suggested' ? 'Nothing to check right now.' : 'Nothing here yet.'}
              </TableStatusRow>
            </tbody>
          </table>
        </div>
        {!rowsLoaded && rowsErr && <div className="error inset">Could not load the list: {rowsErr}</div>}
        {showPager && (
          <div className="pager">
            <span>
              {searchActive
                ? `Page ${page + 1}`
                : `${total.toLocaleString()} domain${total === 1 ? '' : 's'} · page ${page + 1} of ${lastPage + 1}`}
            </span>
            <span className="spacer" />
            <button className="btn sm" disabled={page <= 0} onClick={() => setPage((p) => Math.max(0, p - 1))}>
              Previous
            </button>
            <button className="btn sm" disabled={page >= lastPage} onClick={() => setPage((p) => Math.min(lastPage, p + 1))}>
              Next
            </button>
          </div>
        )}
      </section>
      <p className="legend-keys score-legend">
        <span style={{ ['--k' as string]: 'var(--ok)' }}>70 and up: looks legitimate</span>
        <span style={{ ['--k' as string]: 'var(--warn)' }}>50–69: worth watching</span>
        <span style={{ ['--k' as string]: 'var(--block)' }}>Below 50: block candidate</span>
      </p>

      <h2 className="section">Classifier</h2>
      <p className="section">
        How verdicts are enforced and which signals feed the score. Tune the signals in Settings → Classification.
      </p>

      <div className="cols even">
        <section className="card">
          <div className="card-head">
            <div className="grow">
              <h2>Enforcement</h2>
              <p className="sub">What happens to a domain that scores below 50 with a real threat signal.</p>
            </div>
            {!info && !infoErr && <Spinner />}
          </div>
          <div className="seg" role="group" aria-label="Enforcement mode">
            {MODES.map((m) => (
              <button
                key={m.id}
                className={st?.mode === m.id ? 'on' : ''}
                aria-pressed={st?.mode === m.id}
                onClick={() => setMode(m.id)}
                disabled={!canEdit || busy === 'mode'}
                title={m.desc}
              >
                {m.label}
              </button>
            ))}
          </div>
          <p className="hint">{MODES.find((m) => m.id === st?.mode)?.desc ?? ''}</p>
          {canEdit && (
            <div className="start-over">
              <div>
                <b>Start over</b>
                <small>Delete every verdict; domains are scored again as they are queried.</small>
              </div>
              <button className="btn sm danger" onClick={clearAll} disabled={busy === 'clear'}>
                {busy === 'clear' ? 'Clearing…' : 'Clear all'}
              </button>
            </div>
          )}
        </section>

        <section className="card flush">
          <div className="card-head">
            <div className="grow">
              <h2>Active signals</h2>
              <p className="sub">{aiOn ? `Static analysis plus the ${st?.model} model.` : 'Static analysis only — no language model.'}</p>
            </div>
          </div>
          <div className="rowlist signals">
            <Signal on title="Static analysis" detail="Always on: domain age, risky TLDs, look-alike and random-looking names." />
            <Signal
              on={aiOn}
              title="Language model"
              detail={aiOn ? `${st?.model} adds one bounded signal and content categories.` : 'Off. Set a provider and model in Settings to add it.'}
            />
            <Signal
              on={threatCount > 0}
              bad
              title="Threat feeds"
              detail={
                threatCount > 0
                  ? `${threatCount.toLocaleString()} domains from ${feedCount} feed${feedCount === 1 ? '' : 's'}.`
                  : 'No threat domains loaded.'
              }
              action={
                threatCount > 0 && (
                  <button className="btn sm quiet" aria-expanded={listView === 'threat'} onClick={() => openList('threat')}>
                    {listView === 'threat' ? 'Hide' : 'Browse'}
                  </button>
                )
              }
            />
            <Signal
              on={trustedCount > 0}
              title="Trusted list"
              detail={`${trustedCount.toLocaleString()} domains, including CDN and cloud providers, are never blocked.`}
              action={
                trustedCount > 0 && (
                  <button className="btn sm quiet" aria-expanded={listView === 'trusted'} onClick={() => openList('trusted')}>
                    {listView === 'trusted' ? 'Hide' : 'Browse'}
                  </button>
                )
              }
            />
            <Signal on={!!st?.whois_enabled} title="WHOIS age" detail="Domain age via RDAP — the strongest phishing hint." />
            {st?.vt_enabled && <Signal on title="VirusTotal" detail="Per-domain reputation lookup." />}
            {st?.abuseipdb_enabled && <Signal on title="AbuseIPDB" detail="Reputation of the resolved IPs." />}
            {st?.opentip_enabled && <Signal on title="Kaspersky OpenTIP" detail="Threat-zone lookup." />}
          </div>
        </section>
      </div>

      {listView && (
        <section className="card list-viewer">
          <div className="card-head">
            <div className="grow">
              <h2>
                {listView === 'threat' ? 'Threat feed domains' : 'Trusted domains'}{' '}
                <span className="muted">{(listView === 'threat' ? threatCount : trustedCount).toLocaleString()}</span>
              </h2>
              <p className="sub">Showing up to 200 — search to find a specific domain.</p>
            </div>
            <button className="btn sm quiet" onClick={() => setListView(null)}>
              Close
            </button>
          </div>
          <input
            type="search"
            className="search"
            placeholder={`Search ${listView === 'threat' ? 'threat' : 'trusted'} domains`}
            value={listSearch}
            onChange={(e) => setListSearch(e.target.value)}
          />
          <div className="domain-grid">
            {listErr ? (
              <span className="bad-text">{listErr}</span>
            ) : !listLoaded ? (
              <Spinner label="Loading…" />
            ) : listRows.length === 0 ? (
              <span className="muted">No matches.</span>
            ) : (
              listRows.map((d) => (
                <span key={d} className="domain">
                  {d}
                </span>
              ))
            )}
          </div>
        </section>
      )}

      {info && (info.llm_usage_totals?.calls ?? 0) > 0 && <LLMUsage info={info} />}
      {info && <ReputationUsage info={info} />}

      {catCounts.length > 0 && (
        <section className="card">
          <h2>Traffic by category</h2>
          <p className="sub">
            Across all classified domains: security categories, plus content types (social, streaming…) when the language model is on.
          </p>
          <div className="row">
            {catCounts.map(([cat, n]) => (
              <span key={cat} className={`tag ${catTag(cat)}`}>
                {cap(cat)} <b className="num">{n.toLocaleString()}</b>
              </span>
            ))}
          </div>
        </section>
      )}
    </div>
  )
}

function Signal({
  on,
  bad,
  title,
  detail,
  action,
}: {
  on: boolean
  bad?: boolean
  title: string
  detail: string
  action?: React.ReactNode
}) {
  return (
    <div className="rowitem signal">
      <span className={`dot${on ? (bad ? ' bad' : '') : ' off'}`} aria-label={on ? 'On' : 'Off'} />
      <div className="body">
        <div className="title">{title}</div>
        <div className="muted small">{detail}</div>
      </div>
      <div>{action || null}</div>
    </div>
  )
}

function LLMUsage({ info }: { info: ClassifierStatus }) {
  const t = info.llm_usage_totals
  const tokens = t.prompt_tokens + t.completion_tokens
  const days = [...(info.llm_usage ?? [])].reverse() // oldest → newest
  const maxCalls = days.reduce((m, d) => Math.max(m, d.calls), 0)
  // Average per active day (a day with at least one model call).
  const nDays = Math.max(1, days.length)
  const perDay = (n: number) => {
    const v = n / nDays
    return v >= 10 || v === 0 ? Math.round(v).toLocaleString() : v.toFixed(1)
  }
  return (
    <section className="card flush llm-usage">
      <div className="card-head">
        <div>
          <h2>Language model usage</h2>
          <p className="sub">Averages per day with at least one model call.</p>
        </div>
      </div>
      <div className="strip inset-strip">
        <div>
          <b>{perDay(t.calls)}</b>
          <span>calls a day</span>
        </div>
        <div>
          <b className={t.errors > 0 ? 'bad' : ''}>{perDay(t.errors)}</b>
          <span>errors a day</span>
        </div>
        <div>
          <b>{tokens ? perDay(tokens) : '—'}</b>
          <span>tokens a day</span>
        </div>
      </div>
      {days.length > 0 && (
        <div className="table-scroll">
          <table className="stackable">
            <thead>
              <tr>
                <th>Day</th>
                <th className="num">Calls</th>
                <th className="num">Errors</th>
                <th className="num hide-sm">Tokens</th>
                <th className="hide-sm" style={{ width: '35%' }} aria-label="Calls relative to the busiest day" />
              </tr>
            </thead>
            <tbody>
              {days.map((d) => {
                const dayTokens = d.prompt_tokens + d.completion_tokens
                return (
                  <tr key={d.day}>
                    <td className="lead">{d.day}</td>
                    <td className="num lead-r">{d.calls.toLocaleString()}</td>
                    <td className="num">{d.errors > 0 ? (
                        <span className="bad-text">
                          {d.errors.toLocaleString()}
                          <span className="show-sm"> errors</span>
                        </span>
                      ) : (
                        <span className="faint">—</span>
                      )}</td>
                    <td
                      className="num hide-sm"
                      title={dayTokens ? `${d.prompt_tokens.toLocaleString()} prompt / ${d.completion_tokens.toLocaleString()} completion` : ''}
                    >
                      {dayTokens ? dayTokens.toLocaleString() : '—'}
                    </td>
                    <td className="hide-sm">
                      <div className="meter">
                        <i style={{ width: `${maxCalls ? (d.calls / maxCalls) * 100 : 0}%`, ['--k' as string]: 'var(--fwd)' }} />
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}
