import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api, type QueryLogEntry, type Node, type CategoryCount, type Rule, type DomainClient, type ClientIdentity } from '../api'
import { NodeFilter, makeNodeColor, VALID_HOURS, siteGroups } from './filters'
import { pollWhileVisible } from '../poll'
import { useClientNames } from '../useClientNames'
import ClientLabel, { clientName } from './ClientLabel'
import ClientDetail, { resultOf } from './ClientDetail'
import Modal from './Modal'
import Spinner from './Spinner'
import { PAGE_SIZE, TableStatusRow, Th, fmtMs, fmtWhen, WindowPicker, SearchBox } from './tableKit'
import '../styles/queries.css'

const PAGE = PAGE_SIZE
// Result filter chips, in the order they are shown. The first four are always
// there; the rarer ones appear only when they occur (or are selected).
const ACTIONS = ['blocked', 'forward', 'cache', 'rewrite', 'authoritative', 'error', 'refused']
const MAIN_ACTIONS = ACTIONS.slice(0, 4)
const QTYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'PTR', 'SOA', 'SRV', 'HTTPS', 'SVCB', 'CAA', 'ANY']
const RCODES = ['NOERROR', 'NXDOMAIN', 'SERVFAIL', 'REFUSED']
// The full classification taxonomy (security + content), so the filter offers
// every category — not only the ones seen in the current window.
const BLOCK_CATS = ['ads', 'trackers', 'malware', 'phishing']
const CONTENT_CATS = [
  'social', 'streaming', 'shopping', 'news', 'gaming', 'productivity',
  'search', 'email', 'finance', 'technology', 'cdn', 'adult', 'other',
]
const ALL_CATS = [...BLOCK_CATS, ...CONTENT_CATS]
// Security categories are coral, "other" neutral, content categories blue.
const catTag = (c: string) => (BLOCK_CATS.includes(c) ? 'block' : c === 'other' ? '' : 'info')

// The query log stores names fully qualified ("example.com."): show them bare.
const bare = (name: string) => name.replace(/\.$/, '')
// A search that looks like (part of) an IP filters by client address.
const isIPish = (s: string) => /^[\d.]+$/.test(s) || s.includes(':')

const loadHours = (): number => {
  const v = Number(localStorage.getItem('mazedns.ql.hours'))
  return VALID_HOURS.includes(v) ? v : 24
}
const loadFocus = (): string[] => {
  try {
    const v = JSON.parse(localStorage.getItem('mazedns.ql.focus') || '[]')
    return Array.isArray(v) ? v : []
  } catch {
    return []
  }
}
const clientFromURL = () => new URLSearchParams(window.location.search).get('client') || ''

type Row = QueryLogEntry & { key: number | string }

// Queries is the query-log explorer: History pages through the stored log of the
// chosen window, Live streams queries as the agents answer them. Both share the
// same filters (search, result, type, category, agents) and open the same
// drawer when a row is clicked.
export default function Queries() {
  const [live, setLive] = useState(false)
  const [hours, setHoursRaw] = useState(loadHours)
  const [focus, setFocusRaw] = useState<string[]>(loadFocus)
  const [nodes, setNodes] = useState<Node[]>([])

  // Seed the search box from ?client= so the Clients page can deep-link here.
  const [input, setInput] = useState(clientFromURL)
  const [search, setSearch] = useState(clientFromURL)
  const [action, setActionRaw] = useState('')
  const [qtype, setQtypeRaw] = useState('')
  const [category, setCategoryRaw] = useState('')
  const [rcode, setRcode] = useState('') // live only: the history API has no rcode filter
  const [cats, setCats] = useState<CategoryCount[]>([])

  const [log, setLog] = useState<QueryLogEntry[]>([])
  const [total, setTotal] = useState(0)
  const [counts, setCounts] = useState<Record<string, number> | null>(null)
  const [page, setPage] = useState(0)
  const [sort, setSortCol] = useState('time')
  const [desc, setDesc] = useState(true)
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(true)

  const [paused, setPaused] = useState(false)
  const [selected, setSelected] = useState<Row | null>(null)
  const [selClient, setSelClient] = useState<string | null>(null)
  const [canEdit, setCanEdit] = useState(false)

  // Every filter change starts again from the first page.
  const setHours = (h: number) => {
    setHoursRaw(h)
    setPage(0)
  }
  const setFocus = (f: string[]) => {
    setFocusRaw(f)
    setPage(0)
  }
  const setAction = (a: string) => {
    setActionRaw(a)
    setPage(0)
  }
  const setQtype = (t: string) => {
    setQtypeRaw(t)
    setPage(0)
  }
  const setCategory = (c: string) => {
    setCategoryRaw(c)
    setPage(0)
  }

  useEffect(() => {
    localStorage.setItem('mazedns.ql.hours', String(hours))
  }, [hours])
  useEffect(() => {
    localStorage.setItem('mazedns.ql.focus', JSON.stringify(focus))
  }, [focus])

  // clusterNodes already includes the master, so don't prepend it again.
  const nodeNames = useMemo(() => [...new Set(nodes.map((n) => n.name))], [nodes])
  const nodeColor = useMemo(() => makeNodeColor(nodeNames), [nodeNames])

  useEffect(() => {
    api.clusterNodes().then(setNodes).catch(() => setNodes([]))
    // Rule actions in the drawer are for admins; when auth is off everyone is.
    api
      .authInfo()
      .then(async (inf) => (inf.auth_enabled ? (await api.me())?.role === 'admin' : true))
      .then(setCanEdit)
      .catch(() => setCanEdit(false))
  }, [])

  // A deep link (?client=) arriving while the page is already open.
  useEffect(() => {
    const onPop = () => {
      const c = clientFromURL()
      if (c) {
        setInput(c)
        setSearch(c)
        setLive(false)
        setPage(0)
      }
    }
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
  }, [])

  // Classification options also include categories seen in the window.
  useEffect(() => {
    api.categories(hours, focus).then(setCats).catch(() => setCats([]))
  }, [hours, focus])

  // Debounce the search box.
  useEffect(() => {
    const t = setTimeout(() => {
      setSearch(input.trim())
      setPage(0)
    }, 350)
    return () => clearTimeout(t)
  }, [input])

  // History: one page of the stored log, refreshed every 8s.
  useEffect(() => {
    if (live) return
    let alive = true
    setLoading(true)
    const fetchLog = () =>
      api
        .queryLog({ limit: PAGE, offset: page * PAGE, search, nodes: focus, action, qtype, category, sort, desc, hours })
        .then((r) => {
          if (!alive) return
          setLog(r.entries)
          setTotal(r.total)
          setErr('')
          setLoading(false)
          // The log moved on (retention, a narrower window): don't sit past the end.
          const last = Math.max(0, Math.ceil(r.total / PAGE) - 1)
          if (page > last) setPage(last)
        })
        .catch((e) => alive && setErr(e.message))
    fetchLog()
    const stop = pollWhileVisible(fetchLog, 8000)
    return () => {
      alive = false
      stop()
    }
  }, [live, page, search, focus, action, qtype, category, sort, desc, hours])

  // History: per-result counts for the chips, under the same filters (minus the
  // result itself). One count query per result; refreshed less often.
  useEffect(() => {
    if (live) return
    let alive = true
    const base = { limit: 1, search, nodes: focus, qtype, category, hours }
    const fetchCounts = () =>
      Promise.all([api.queryLog(base), ...ACTIONS.map((a) => api.queryLog({ ...base, action: a }))])
        .then(([all, ...per]) => {
          if (!alive) return
          const c: Record<string, number> = { '': all.total }
          ACTIONS.forEach((a, i) => (c[a] = per[i].total))
          setCounts(c)
        })
        .catch(() => alive && setCounts(null))
    setCounts(null)
    fetchCounts()
    const stop = pollWhileVisible(fetchCounts, 30000)
    return () => {
      alive = false
      stop()
    }
  }, [live, search, focus, qtype, category, hours])

  const stream = useLiveStream({ enabled: live, paused, focus, search, action, qtype, category, rcode })

  // Clicking a column header sorts by it; clicking the active column flips it.
  const sorter = {
    sortKey: sort,
    desc,
    sort: (col: string) => {
      if (sort === col) setDesc((d) => !d)
      else {
        setSortCol(col)
        setDesc(col === 'time' || col === 'ms')
      }
      setPage(0)
    },
  }

  // Live rows: the server filters by client IP; a name or domain search is
  // matched here against the domain and the resolved client names.
  const liveIps = useMemo(() => [...new Set(stream.rows.map((r) => r.client))].sort(), [stream.rows])
  const ips = live ? liveIps : log.map((e) => e.client)
  const names = useClientNames(ips)
  const q = search.toLowerCase()
  const liveShown: Row[] =
    q && !isIPish(search)
      ? stream.rows.filter((r) => r.name.toLowerCase().includes(q) || clientName(r.client, names).toLowerCase().includes(q))
      : stream.rows
  const rows: Row[] = live ? liveShown : log.map((e) => ({ ...e, key: e.id }))

  // Chip counts: the window's totals in History; what's on screen in Live.
  const chipCounts: Record<string, number> | null = live
    ? action
      ? { [action]: liveShown.length }
      : liveShown.reduce<Record<string, number>>((m, r) => ((m[r.action] = (m[r.action] ?? 0) + 1), m), { '': liveShown.length })
    : counts && !loading
    ? { ...counts, [action]: total } // the table's own count is the freshest
    : counts
  const chips = ['', ...MAIN_ACTIONS, ...ACTIONS.slice(4).filter((a) => a === action || (chipCounts?.[a] ?? 0) > 0)]

  const closeQuery = useCallback(() => setSelected(null), [])
  const closeClient = useCallback(() => setSelClient(null), [])
  const showClientQueries = useCallback((ip: string) => {
    setSelClient(null)
    setSelected(null)
    setLive(false)
    setInput(ip)
    setSearch(ip)
    setActionRaw('')
    setPage(0)
  }, [])
  const searchDomain = useCallback((domain: string) => {
    setSelected(null)
    setInput(domain)
    setSearch(domain)
    setActionRaw('')
    setPage(0)
  }, [])

  const lastPage = Math.max(0, Math.ceil(total / PAGE) - 1)
  const timeDesc = sort === 'time' && desc
  const catOptions = [...ALL_CATS, ...cats.map((c) => c.category).filter((c) => c && !ALL_CATS.includes(c))]

  return (
    <div className="pg-queries">
      {selected && (
        <QueryDrawer
          e={selected}
          names={names}
          nodes={nodes}
          canEdit={canEdit}
          onClose={closeQuery}
          onOpenClient={(ip) => {
            setSelected(null)
            setSelClient(ip)
          }}
          onSearchDomain={searchDomain}
        />
      )}
      {selClient && (
        <ClientDetail client={selClient} hours={hours} nodes={focus} names={names} onClose={closeClient} onShowQueries={showClientQueries} />
      )}

      <header className="page-head">
        <h1>Queries</h1>
        <div className="seg" role="group" aria-label="View">
          <button className={live ? '' : 'on'} aria-pressed={!live} onClick={() => setLive(false)}>
            History
          </button>
          <button className={live ? 'on' : ''} aria-pressed={live} onClick={() => setLive(true)}>
            Live
          </button>
        </div>
        {!live && loading && !err && <Spinner />}
        <span className="spacer" />
        {live ? (
          <div className="q-live">
            <span className={`dot ${stream.state === 'live' ? 'pulse' : stream.state === 'down' ? 'bad' : 'off'}`} />
            <span className="muted">{stream.label}</span>
            {stream.state === 'down' ? (
              <button className="btn sm" onClick={stream.reconnect}>
                Reconnect
              </button>
            ) : (
              <button className="btn sm" onClick={() => setPaused((p) => !p)}>
                {paused ? 'Resume' : 'Pause'}
              </button>
            )}
            <button className="btn sm quiet" onClick={stream.clear} disabled={stream.rows.length === 0}>
              Clear
            </button>
          </div>
        ) : (
          <WindowPicker hours={hours} onChange={setHours} />
        )}
        {nodeNames.length > 0 && <NodeFilter options={nodeNames} selected={focus} onChange={setFocus} color={nodeColor} sites={siteGroups(nodes)} />}
      </header>
      <p className="intro">
        {live
          ? `Queries appear within about a second of an agent answering them, newest first; the last ${LIVE_CAP.toLocaleString()} are kept. Click one to see why it was answered that way. Agents running an older version don't stream.`
          : 'Every query your agents answered. Click one to see why it was answered that way, and allow or block the domain from there.'}
      </p>
      {err && !live && <div className="error">{err}</div>}

      <div className="toolbar">
        <SearchBox value={input} onChange={setInput} placeholder={live ? 'Search domain or client' : 'Search domain or client IP'} />
        {chips.map((a) => {
          const n = chipCounts?.[a]
          return (
            <button key={a || 'all'} className={`chip${action === a ? ' on' : ''}`} aria-pressed={action === a} onClick={() => setAction(a)}>
              {a ? <span className="dot" style={{ ['--k' as string]: resultOf(a).color }} /> : null}
              {a ? resultOf(a).label : <b>All</b>}
              {n != null && <span className="num">{n.toLocaleString()}</span>}
            </button>
          )
        })}
        <span className="spacer" />
        <select className="q-filter" aria-label="Query type" value={qtype} onChange={(e) => setQtype(e.target.value)}>
          <option value="">Type: any</option>
          {QTYPES.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
        <select className="q-filter" aria-label="Category" value={category} onChange={(e) => setCategory(e.target.value)}>
          <option value="">Category: any</option>
          {catOptions.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        {live && (
          <select className="q-filter" aria-label="Response code" value={rcode} onChange={(e) => setRcode(e.target.value)}>
            <option value="">Response: any</option>
            {RCODES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        )}
      </div>

      <section className="card flush">
        <div className="table-scroll">
          <table className="stackable q-table">
            <thead>
              {live ? (
                <tr>
                  <th>Time</th>
                  <th>Domain</th>
                  <th>Type</th>
                  <th>Result</th>
                  <th>Client</th>
                  <th>Agent</th>
                  <th className="num">Latency</th>
                </tr>
              ) : (
                <tr>
                  <Th table={sorter} col="time">Time</Th>
                  <Th table={sorter} col="name">Domain</Th>
                  <Th table={sorter} col="qtype">Type</Th>
                  <Th table={sorter} col="action">Result</Th>
                  <Th table={sorter} col="client">Client</Th>
                  <Th table={sorter} col="node">Agent</Th>
                  <Th table={sorter} col="ms" className="num">Latency</Th>
                </tr>
              )}
            </thead>
            <tbody>
              {rows.map((e) => (
                <QueryRow key={e.key} e={e} names={names} selected={selected?.key === e.key} onClick={() => setSelected(e)} />
              ))}
              {live ? (
                <TableStatusRow loading={false} empty={rows.length === 0} colSpan={7}>
                  {stream.state === 'paused' ? 'The stream is paused.' : stream.rows.length > 0 ? 'No query on screen matches the search.' : 'Waiting for queries…'}
                </TableStatusRow>
              ) : (
                <TableStatusRow loading={loading} error={err} empty={rows.length === 0} colSpan={7}>
                  No queries match these filters in the last {hours < 1 ? `${hours * 60} minutes` : hours === 1 ? 'hour' : `${hours} hours`}.
                </TableStatusRow>
              )}
            </tbody>
          </table>
        </div>
        {live ? (
          rows.length > 0 && (
            <div className="pager">
              <span>
                {rows.length.toLocaleString()} {rows.length === 1 ? 'query' : 'queries'} on screen
                {stream.rows.length >= LIVE_CAP ? ` (the newest ${LIVE_CAP.toLocaleString()} are kept)` : ''}
              </span>
            </div>
          )
        ) : (
          total > 0 && (
            <div className="pager">
              <span>
                Showing {(page * PAGE + 1).toLocaleString()}–{Math.min(total, (page + 1) * PAGE).toLocaleString()} of {total.toLocaleString()}
              </span>
              <span className="spacer" />
              <button className="btn sm" disabled={page <= 0} onClick={() => setPage((p) => Math.max(0, p - 1))}>
                {timeDesc ? 'Newer' : 'Previous'}
              </button>
              <button className="btn sm" disabled={page >= lastPage} onClick={() => setPage((p) => Math.min(lastPage, p + 1))}>
                {timeDesc ? 'Older' : 'Next'}
              </button>
            </div>
          )
        )}
      </section>
    </div>
  )
}

// resultTag is the coloured tag of a query's result. A forwarded or cached answer
// that isn't NOERROR shows its response code instead (NXDOMAIN, SERVFAIL).
function ResultTag({ e }: { e: QueryLogEntry }) {
  const r = resultOf(e.action)
  const showRcode = (e.action === 'forward' || e.action === 'cache') && e.rcode && e.rcode !== 'NOERROR'
  return (
    <span className={`tag ${r.tag}`} title={showRcode ? `${r.label}, answered ${e.rcode}` : undefined}>
      {showRcode ? e.rcode : r.label}
    </span>
  )
}

function QueryRow({ e, names, selected, onClick }: { e: QueryLogEntry; names: Map<string, ClientIdentity>; selected: boolean; onClick: () => void }) {
  const when = fmtWhen(e.ts)
  const who = clientName(e.client, names)
  return (
    <tr
      className={`click${selected ? ' sel' : ''}`}
      onClick={onClick}
      tabIndex={0}
      onKeyDown={(k) => (k.key === 'Enter' || k.key === ' ') && (k.preventDefault(), onClick())}
    >
      <td className="when lead-r" title={when.full}>
        {when.time}
        {when.date && <small>{when.date}</small>}
      </td>
      <td className="lead">
        <span className="domain">{bare(e.name)}</span>
      </td>
      <td className="hide-sm">{e.qtype}</td>
      <td className="res">
        <ResultTag e={e} />
        <span className="show-sm"> · {who || <span className="mono">{e.client}</span>}</span>
      </td>
      <td className="hide-sm">
        <ClientLabel ip={e.client} names={names} showIp={false} />
      </td>
      <td className="hide-sm muted">{e.node || 'master'}</td>
      <td className="num hide-sm nowrap">{fmtMs(e.elapsed_ms)}</td>
    </tr>
  )
}

// ---- Live stream ----

const LIVE_CAP = 1000 // rows kept in the browser

type StreamState = 'live' | 'connecting' | 'reconnecting' | 'down' | 'paused'

// useLiveStream streams queries as the agents answer them (server-sent events
// from /api/querylog/stream), newest first. Filters are applied server-side, so
// the agents only send what the view shows; the stream stops while paused, while
// the tab is hidden, and when the view isn't Live.
function useLiveStream({
  enabled,
  paused,
  focus,
  search,
  action,
  qtype,
  category,
  rcode,
}: {
  enabled: boolean
  paused: boolean
  focus: string[]
  search: string
  action: string
  qtype: string
  category: string
  rcode: string
}) {
  const [hidden, setHidden] = useState(document.hidden)
  const [status, setStatus] = useState<'connecting' | 'live' | 'reconnecting' | 'closed'>('connecting')
  const [rows, setRows] = useState<Row[]>([])
  const [retry, setRetry] = useState(0)
  const pending = useRef<Row[]>([])
  const seq = useRef(0)
  const client = isIPish(search) ? search : ''
  const focusKey = focus.join(',')

  useEffect(() => {
    const onVis = () => setHidden(document.hidden)
    document.addEventListener('visibilitychange', onVis)
    return () => document.removeEventListener('visibilitychange', onVis)
  }, [])

  // New server-side filters: the rows on screen no longer match them.
  useEffect(() => setRows([]), [focusKey, client, action, qtype, category, rcode])

  useEffect(() => {
    if (!enabled || paused || hidden) return
    const p = new URLSearchParams()
    if (focusKey) p.set('nodes', focusKey)
    for (const [k, v] of [['client', client], ['action', action], ['qtype', qtype], ['category', category], ['rcode', rcode]]) {
      if (v) p.set(k, v)
    }
    setStatus('connecting')
    const es = new EventSource(`/api/querylog/stream?${p}`)
    es.onopen = () => setStatus('live')
    es.onerror = () => setStatus(es.readyState === EventSource.CLOSED ? 'closed' : 'reconnecting')
    es.onmessage = (ev) => {
      try {
        const e = JSON.parse(ev.data) as QueryLogEntry
        pending.current.push({ ...e, key: `l${++seq.current}` })
      } catch {
        // ignore a malformed event
      }
    }
    // Batch renders instead of one per query.
    const flush = setInterval(() => {
      if (pending.current.length === 0) return
      const batch = pending.current.reverse()
      pending.current = []
      setRows((r) => [...batch, ...r].slice(0, LIVE_CAP))
    }, 250)
    return () => {
      es.close()
      clearInterval(flush)
      pending.current = []
    }
  }, [enabled, paused, hidden, focusKey, client, action, qtype, category, rcode, retry])

  const state: StreamState = paused || hidden ? 'paused' : status === 'closed' ? 'down' : status
  const label = paused
    ? 'Paused'
    : hidden
    ? 'Paused while the tab is hidden'
    : status === 'live'
    ? 'Live'
    : status === 'closed'
    ? 'Disconnected'
    : status === 'reconnecting'
    ? 'Reconnecting…'
    : 'Connecting…'
  return {
    rows,
    state,
    label,
    clear: () => setRows([]),
    reconnect: () => setRetry((n) => n + 1),
  }
}

// ---- Query drawer ----

// explain says, in plain words, why a query got the answer it got. It only
// states what the log records: the log doesn't say which list or rule blocked a
// query, so neither does this.
function explain(e: QueryLogEntry, rule: Rule | undefined): { kind: string; title: string; text: string } {
  const answered = `Answered ${e.rcode || 'without a response code'} in ${fmtMs(e.elapsed_ms)}.`
  switch (e.action) {
    case 'blocked':
      return {
        kind: 'bad',
        title: 'Blocked',
        text:
          (rule?.action === 'deny'
            ? 'Your block rule for this domain matches it. '
            : `The domain matched one of your blocklists or block rules${e.category ? ` (category “${e.category}”)` : ''}; the query log doesn’t record which one. `) +
          answered,
      }
    case 'forward':
      return { kind: '', title: 'Forwarded upstream', text: `It wasn’t blocked, rewritten or cached, so the agent asked an upstream resolver. ${answered}` }
    case 'cache':
      return { kind: 'ok', title: 'Answered from cache', text: `The agent still had the answer from an earlier upstream lookup. ${answered}` }
    case 'rewrite':
      return { kind: 'warn', title: 'Rewritten', text: `A rewrite answers this name with your own records instead of asking upstream. ${answered}` }
    case 'authoritative':
      return { kind: 'ok', title: 'Answered from a local zone', text: `The agent is authoritative for this name and answered it itself. ${answered}` }
    case 'error':
      return { kind: 'bad', title: 'Lookup failed', text: `The upstream resolvers didn’t answer in time (or the query was malformed), so the agent replied ${e.rcode || 'with an error'}.` }
    case 'refused':
      return { kind: 'warn', title: 'Refused', text: 'The client went over the per-client rate limit, so the agent refused the query.' }
    default:
      return { kind: '', title: resultOf(e.action).label, text: answered }
  }
}

function QueryDrawer({
  e,
  names,
  nodes,
  canEdit,
  onClose,
  onOpenClient,
  onSearchDomain,
}: {
  e: QueryLogEntry
  names: Map<string, ClientIdentity>
  nodes: Node[]
  canEdit: boolean
  onClose: () => void
  onOpenClient: (ip: string) => void
  onSearchDomain: (domain: string) => void
}) {
  const domain = bare(e.name).toLowerCase()
  const [rules, setRules] = useState<Rule[] | null>(null)
  // null while loading; 'none' when the domain can't be looked up (no registered
  // domain, e.g. a PTR name) — the section is hidden then.
  const [askers, setAskers] = useState<{ domain: string; clients: DomainClient[] } | 'none' | null>(null)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')
  const [err, setErr] = useState('')

  const loadRules = () =>
    api
      .rules()
      .then(setRules)
      .catch(() => setRules([]))
  useEffect(() => {
    setRules(null)
    setAskers(null)
    setMsg('')
    setErr('')
    loadRules()
    let alive = true
    api
      .domainClients(domain)
      .then((r) => alive && setAskers(r))
      .catch(() => alive && setAskers('none'))
    return () => {
      alive = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [domain])

  const rule = rules?.find((r) => r.domain.toLowerCase() === domain)
  const why = explain(e, rule)
  const when = fmtWhen(e.ts)
  const node = nodes.find((n) => n.name === e.node)

  const addRule = async (act: 'allow' | 'deny') => {
    setBusy(true)
    setErr('')
    setMsg('')
    try {
      await api.addRule(act, domain, '')
      setMsg(act === 'allow' ? `Added an allow rule for ${domain}.` : `Added a block rule for ${domain}.`)
      await loadRules()
    } catch (x: any) {
      setErr(x.message)
    } finally {
      setBusy(false)
    }
  }
  const removeRule = async () => {
    if (!rule) return
    setBusy(true)
    setErr('')
    setMsg('')
    try {
      await api.deleteRule(rule.id)
      setMsg(`Removed your ${rule.action === 'allow' ? 'allow' : 'block'} rule for ${domain}.`)
      await loadRules()
    } catch (x: any) {
      setErr(x.message)
    } finally {
      setBusy(false)
    }
  }

  // The main action undoes the result: allow what was blocked, block the rest.
  const mainAct: 'allow' | 'deny' = e.action === 'blocked' ? 'allow' : 'deny'
  const footer = (
    <>
      {canEdit &&
        (rule ? (
          <button className="btn" disabled={busy} onClick={removeRule}>
            Remove your {rule.action === 'allow' ? 'allow' : 'block'} rule
          </button>
        ) : (
          <button className={`btn ${mainAct === 'allow' ? 'primary' : 'danger'}`} disabled={busy || rules === null} onClick={() => addRule(mainAct)}>
            {mainAct === 'allow' ? 'Allow this domain' : 'Block this domain'}
          </button>
        ))}
      <button className="btn" onClick={() => onOpenClient(e.client)}>
        Open client
      </button>
      <button className="btn quiet" onClick={() => onSearchDomain(domain)}>
        Queries for this domain
      </button>
    </>
  )

  return (
    <Modal
      title={<span className="domain q-title">{domain}</span>}
      eyebrow={`${e.qtype} query · ${when.date ? `${when.date}, ` : ''}${when.time}${e.node ? ` · ${e.node}` : ''}`}
      onClose={onClose}
      footer={footer}
    >
      <div className={`callout ${why.kind}`} style={{ margin: 0 }}>
        <ResultIcon kind={why.kind} />
        <div>
          <b>{why.title}</b>
          <p>{why.text}</p>
        </div>
      </div>
      {err && <div className="error" style={{ margin: 0 }}>{err}</div>}
      {msg && <div className="ok-msg" style={{ margin: 0 }}>{msg}</div>}

      <div>
        <h3>Request</h3>
        <dl className="kv">
          <dt>Client</dt>
          <dd>
            <ClientLabel ip={e.client} names={names} source />
          </dd>
          <dt>Type</dt>
          <dd>{e.qtype}</dd>
          <dt>Result</dt>
          <dd>
            <span className={`tag ${resultOf(e.action).tag}`}>{resultOf(e.action).label}</span>
          </dd>
          <dt>Response code</dt>
          <dd>{e.rcode || '—'}</dd>
          <dt>Latency</dt>
          <dd>{fmtMs(e.elapsed_ms)}</dd>
          <dt>Agent</dt>
          <dd>
            {e.node || 'master'}
            {node?.site ? <span className="muted"> ({node.site})</span> : null}
          </dd>
          <dt>Category</dt>
          <dd>{e.category ? <span className={`tag ${e.action === 'blocked' ? 'block' : catTag(e.category)}`}>{e.category}</span> : <span className="muted">Not classified</span>}</dd>
          <dt>Time</dt>
          <dd>{when.full}</dd>
          {rule && (
            <>
              <dt>Your rule</dt>
              <dd>
                <span className={`tag ${rule.action === 'allow' ? 'ok' : 'block'}`}>{rule.action === 'allow' ? 'Allow' : 'Block'}</span>{' '}
                <span className="domain">{rule.domain}</span>
                {!rule.enabled && <span className="muted"> (disabled)</span>}
              </dd>
            </>
          )}
        </dl>
      </div>

      {askers !== 'none' && (
      <div>
        <h3>Who asks for {askers?.domain ? <span className="domain">{askers.domain}</span> : 'this domain'}</h3>
        <p className="muted small" style={{ margin: '0 0 8px' }}>
          Clients that queried it or its subdomains, across the whole query log.
        </p>
        {askers === null ? (
          <Spinner label="Loading…" />
        ) : askers.clients.length === 0 ? (
          <p className="muted small" style={{ margin: 0 }}>
            No other queries recorded.
          </p>
        ) : (
          <ul className="q-askers">
            {askers.clients.slice(0, 6).map((c) => (
              <li key={c.client}>
                <button className="linklike" onClick={() => onOpenClient(c.client)}>
                  {c.name || names.get(c.client)?.name || c.client}
                </button>
                <span className="spacer" />
                <span className="num">{c.count.toLocaleString()}</span>
                {c.blocked > 0 && <span className="bad-text small num">{c.blocked.toLocaleString()} blocked</span>}
              </li>
            ))}
            {askers.clients.length > 6 && <li className="muted small">and {(askers.clients.length - 6).toLocaleString()} more</li>}
          </ul>
        )}
      </div>
      )}
    </Modal>
  )
}

function ResultIcon({ kind }: { kind: string }) {
  if (kind === 'bad')
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M12 3l8 3v6c0 4.5-3.4 8-8 9-4.6-1-8-4.5-8-9V6z" />
        <path d="M9.5 9.5l5 5M14.5 9.5l-5 5" />
      </svg>
    )
  if (kind === 'ok')
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <circle cx="12" cy="12" r="9" />
        <path d="M8 12.5l2.8 2.8L16 10" />
      </svg>
    )
  if (kind === 'warn')
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M4 7h11l-3-3M20 17H9l3 3" />
      </svg>
    )
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z" />
    </svg>
  )
}
