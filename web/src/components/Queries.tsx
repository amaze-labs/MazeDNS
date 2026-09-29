import { useEffect, useMemo, useRef, useState } from 'react'
import { api, type QueryLogEntry, type Node, type CategoryCount } from '../api'
import { NodeFilter, RangeNodeBar, makeNodeColor, VALID_HOURS, siteGroups } from './filters'
import { pollWhileVisible } from '../poll'
import { useClientNames } from '../useClientNames'
import ClientLabel from './ClientLabel'
import ClientDetail from './ClientDetail'
import Spinner from './Spinner'
import { PAGE_SIZE, TableStatusRow } from './tableKit'

const PAGE = PAGE_SIZE
const ACTIONS = ['forward', 'cache', 'blocked', 'rewrite', 'authoritative', 'error', 'refused']
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
// Security categories are red, "other" neutral-green, content categories blue.
const catClass = (c: string) => (BLOCK_CATS.includes(c) ? 'blocked' : c === 'other' ? 'allow' : 'info')

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

// Queries is the dedicated request-log explorer: full-window, focusable, with
// filtering and column sorting over the (cluster-wide) DNS query log.
export default function Queries() {
  const [hours, setHours] = useState(loadHours)
  const [focus, setFocus] = useState<string[]>(loadFocus)
  const [nodes, setNodes] = useState<Node[]>([])

  const [log, setLog] = useState<QueryLogEntry[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(0)
  // Seed the search box from ?client= so the Clients tab can deep-link here.
  const initialClient = new URLSearchParams(window.location.search).get('client') || ''
  const [input, setInput] = useState(initialClient)
  const [search, setSearch] = useState(initialClient)
  const [action, setAction] = useState('')
  const [qtype, setQtype] = useState('')
  const [category, setCategory] = useState('')
  const [cats, setCats] = useState<CategoryCount[]>([])
  const [sort, setSortCol] = useState('time')
  const [desc, setDesc] = useState(true)
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(true)
  const [live, setLive] = useState(false)

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
  }, [])

  // Classification options reflect the categories actually seen in the window.
  useEffect(() => {
    api.categories(hours, focus).then(setCats).catch(() => setCats([]))
  }, [hours, focus])

  // Debounce the search box.
  useEffect(() => {
    const t = setTimeout(() => {
      setSearch(input.trim())
      setPage(0)
    }, 400)
    return () => clearTimeout(t)
  }, [input])

  useEffect(() => {
    if (live) return
    let alive = true
    setLoading(true)
    const fetchLog = () =>
      api
        .queryLog({ limit: PAGE, offset: page * PAGE, search, nodes: focus, action, qtype, category, sort, desc, hours })
        .then((r) => {
          if (alive) {
            setLog(r.entries)
            setTotal(r.total)
            setErr('')
            setLoading(false)
          }
        })
        .catch((e) => alive && setErr(e.message))
    fetchLog()
    const stop = pollWhileVisible(fetchLog, 8000)
    return () => {
      alive = false
      stop()
    }
  }, [live, page, search, focus, action, qtype, category, sort, desc, hours])

  // Clicking a column header sorts by it; clicking the active column flips it.
  const setSort = (col: string) => {
    if (sort === col) {
      setDesc((d) => !d)
    } else {
      setSortCol(col)
      setDesc(col === 'time')
    }
    setPage(0)
  }
  const arrow = (col: string) => (sort === col ? (desc ? ' ↓' : ' ↑') : '')
  const lastPage = Math.max(0, Math.ceil(total / PAGE) - 1)
  const clientNames = useClientNames(log.map((e) => e.client))

  const head = (
    <>
      <h2 style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        Requests {loading && !live && <Spinner />}
      </h2>
      <div className="range-tabs" style={{ marginBottom: 12 }}>
        <span className="muted">View</span>
        <button className={live ? '' : 'active'} onClick={() => setLive(false)}>
          History
        </button>
        <button className={live ? 'active' : ''} onClick={() => setLive(true)}>
          Live
        </button>
      </div>
    </>
  )
  if (live) {
    return (
      <div>
        {head}
        <LiveQueries nodes={nodes} />
      </div>
    )
  }

  return (
    <div>
      {head}
      <p className="muted" style={{ textAlign: 'left' }}>
        Explore the cluster-wide DNS query log. Filter by window, node, action, type, and classification; click a column to sort.
      </p>
      {err && <div className="error">{err}</div>}

      <RangeNodeBar
        hours={hours}
        setHours={setHours}
        focus={focus}
        setFocus={(f) => { setFocus(f); setPage(0) }}
        nodeNames={nodeNames}
        color={nodeColor}
        sites={siteGroups(nodes)}
      />

      <div className="ql-filters" style={{ margin: '12px 0' }}>
        <select className="ql-select" value={action} onChange={(e) => { setAction(e.target.value); setPage(0) }}>
          <option value="">All actions</option>
          {ACTIONS.map((a) => (
            <option key={a} value={a}>
              {a}
            </option>
          ))}
        </select>
        <select className="ql-select" value={qtype} onChange={(e) => { setQtype(e.target.value); setPage(0) }}>
          <option value="">All types</option>
          {QTYPES.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
        <select className="ql-select" value={category} onChange={(e) => { setCategory(e.target.value); setPage(0) }}>
          <option value="">All classifications</option>
          {[...ALL_CATS, ...cats.map((c) => c.category).filter((c) => c && !ALL_CATS.includes(c))].map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        <input className="search" placeholder="search name or client…" value={input} onChange={(e) => setInput(e.target.value)} />
      </div>

      <div className="table-scroll">
      <table className="sortable nowrap">
        <thead>
          <tr>
            <th className="sortable" onClick={() => setSort('time')}>Time{arrow('time')}</th>
            <th className="sortable" onClick={() => setSort('node')}>Node{arrow('node')}</th>
            <th className="sortable" onClick={() => setSort('client')}>Client{arrow('client')}</th>
            <th className="sortable" onClick={() => setSort('name')}>Name{arrow('name')}</th>
            <th className="sortable" onClick={() => setSort('qtype')}>Type{arrow('qtype')}</th>
            <th className="sortable" onClick={() => setSort('action')}>Action{arrow('action')}</th>
            <th className="sortable" onClick={() => setSort('category')}>Classification{arrow('category')}</th>
            <th className="sortable" onClick={() => setSort('rcode')}>Rcode{arrow('rcode')}</th>
            <th className="sortable" onClick={() => setSort('ms')}>ms{arrow('ms')}</th>
          </tr>
        </thead>
        <tbody>
          {log.map((e) => (
            <tr key={e.id}>
              <td>{new Date(e.ts).toLocaleTimeString()}</td>
              <td>{e.node || 'master'}</td>
              <td><ClientLabel ip={e.client} names={clientNames} /></td>
              <td className="wrap">{e.name}</td>
              <td>{e.qtype}</td>
              <td>
                <span className={`badge ${e.action}`}>{e.action}</span>
              </td>
              <td>{e.category ? <span className={`badge ${catClass(e.category)}`}>{e.category}</span> : <span className="muted">—</span>}</td>
              <td>{e.rcode}</td>
              <td>{e.elapsed_ms.toFixed(2)}</td>
            </tr>
          ))}
          <TableStatusRow loading={loading} error={err} empty={log.length === 0} colSpan={9}>
            No matching queries
          </TableStatusRow>
        </tbody>
      </table>
      </div>
      <div className="pager">
        <span className="muted">
          {total.toLocaleString()} match{total === 1 ? '' : 'es'} · page {page + 1} of {lastPage + 1}
        </span>
        <div className="spacer" />
        <button className="btn" disabled={page <= 0} onClick={() => setPage((p) => Math.max(0, p - 1))}>
          ‹ Prev
        </button>
        <button className="btn" disabled={page >= lastPage} onClick={() => setPage((p) => Math.min(lastPage, p + 1))}>
          Next ›
        </button>
      </div>
    </div>
  )
}

const LIVE_CAP = 1000 // rows kept in the browser
// A client filter that looks like (part of) an IP is applied by the server;
// anything else is matched here against the resolved client names.
const isIPish = (s: string) => /^[\d.]+$/.test(s) || s.includes(':')

type LiveRow = QueryLogEntry & { key: number }

// LiveQueries streams queries as the agents answer them (server-sent events
// from /api/querylog/stream), newest first. Filters are applied server-side, so
// the agents only send what this view shows; the stream stops while paused or
// while the tab is hidden.
function LiveQueries({ nodes }: { nodes: Node[] }) {
  const [focus, setFocus] = useState<string[]>([])
  const [clientIn, setClientIn] = useState('')
  const [domainIn, setDomainIn] = useState('')
  const [client, setClient] = useState('')
  const [domain, setDomain] = useState('')
  const [action, setAction] = useState('')
  const [qtype, setQtype] = useState('')
  const [category, setCategory] = useState('')
  const [rcode, setRcode] = useState('')
  const [paused, setPaused] = useState(false)
  const [hidden, setHidden] = useState(document.hidden)
  const [status, setStatus] = useState<'connecting' | 'live' | 'reconnecting' | 'closed'>('connecting')
  const [rows, setRows] = useState<LiveRow[]>([])
  const [selected, setSelected] = useState<string | null>(null)
  const pending = useRef<LiveRow[]>([])
  const seq = useRef(0)

  const nodeNames = useMemo(() => [...new Set(nodes.map((n) => n.name))], [nodes])
  const nodeColor = useMemo(() => makeNodeColor(nodeNames), [nodeNames])

  useEffect(() => {
    const t = setTimeout(() => {
      setClient(clientIn.trim())
      setDomain(domainIn.trim())
    }, 300)
    return () => clearTimeout(t)
  }, [clientIn, domainIn])

  useEffect(() => {
    const onVis = () => setHidden(document.hidden)
    document.addEventListener('visibilitychange', onVis)
    return () => document.removeEventListener('visibilitychange', onVis)
  }, [])

  // New filters: the rows on screen no longer match them.
  useEffect(() => setRows([]), [focus, client, domain, action, qtype, category, rcode])

  useEffect(() => {
    if (paused || hidden) return
    const p = new URLSearchParams()
    if (focus.length) p.set('nodes', focus.join(','))
    if (client && isIPish(client)) p.set('client', client)
    for (const [k, v] of [['domain', domain], ['action', action], ['qtype', qtype], ['category', category], ['rcode', rcode]]) {
      if (v) p.set(k, v)
    }
    setStatus('connecting')
    const es = new EventSource(`/api/querylog/stream?${p}`)
    es.onopen = () => setStatus('live')
    es.onerror = () => setStatus(es.readyState === EventSource.CLOSED ? 'closed' : 'reconnecting')
    es.onmessage = (ev) => {
      try {
        pending.current.push({ ...JSON.parse(ev.data), key: ++seq.current })
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
  }, [paused, hidden, focus, client, domain, action, qtype, category, rcode])

  const ips = useMemo(() => [...new Set(rows.map((r) => r.client))].sort(), [rows])
  const clientNames = useClientNames(ips)
  const nameFilter = client && !isIPish(client) ? client.toLowerCase() : ''
  const shown = nameFilter
    ? rows.filter((r) => (clientNames.get(r.client)?.name ?? '').toLowerCase().includes(nameFilter))
    : rows

  const state = paused
    ? 'Paused'
    : hidden
    ? 'Paused while the tab is hidden'
    : status === 'live'
    ? 'Live'
    : status === 'closed'
    ? 'Stream closed — reload the page to reconnect'
    : status === 'reconnecting'
    ? 'Reconnecting…'
    : 'Connecting…'
  const select = (value: string, set: (v: string) => void, all: string, opts: string[]) => (
    <select className="ql-select" value={value} onChange={(e) => set(e.target.value)}>
      <option value="">{all}</option>
      {opts.map((o) => (
        <option key={o} value={o}>
          {o}
        </option>
      ))}
    </select>
  )

  return (
    <>
      {selected && (
        <ClientDetail client={selected} hours={1} nodes={focus} names={clientNames} onClose={() => setSelected(null)} />
      )}
      <p className="muted" style={{ textAlign: 'left' }}>
        Queries appear within about a second of an agent answering them, newest first (the last {LIVE_CAP} are kept).
        Blocked and rewritten queries are highlighted; click a row for the client's details. Agents running an older
        version don't stream.
      </p>
      <div className="range-tabs">
        <span className={`node-dot ${!paused && !hidden && status === 'live' ? 'on' : ''}`} />
        <span className="muted">{state}</span>
        <button onClick={() => setPaused((p) => !p)}>{paused ? 'Resume' : 'Pause'}</button>
        <button onClick={() => setRows([])} disabled={rows.length === 0}>
          Clear
        </button>
        {nodeNames.length > 0 && (
          <>
            <div className="spacer" />
            <span className="muted">Focus</span>
            <NodeFilter options={nodeNames} selected={focus} onChange={setFocus} color={nodeColor} sites={siteGroups(nodes)} />
          </>
        )}
      </div>
      <div className="ql-filters" style={{ margin: '12px 0' }}>
        {select(action, setAction, 'All actions', ACTIONS)}
        {select(qtype, setQtype, 'All types', QTYPES)}
        {select(category, setCategory, 'All classifications', ALL_CATS)}
        {select(rcode, setRcode, 'All rcodes', RCODES)}
        <input className="search" placeholder="client IP or name…" value={clientIn} onChange={(e) => setClientIn(e.target.value)} />
        <input className="search" placeholder="domain contains…" value={domainIn} onChange={(e) => setDomainIn(e.target.value)} />
      </div>
      <div className="table-scroll">
        <table className="nowrap">
          <thead>
            <tr>
              <th>Time</th>
              <th>Node</th>
              <th>Client</th>
              <th>Name</th>
              <th>Type</th>
              <th>Action</th>
              <th>Classification</th>
              <th>Rcode</th>
              <th>ms</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((e) => (
              <tr
                key={e.key}
                className={`cls-row ${e.action === 'blocked' ? 'live-blocked' : e.action === 'rewrite' ? 'live-rewrite' : ''}`}
                onClick={() => setSelected(e.client)}
              >
                <td>{new Date(e.ts).toLocaleTimeString()}</td>
                <td>{e.node}</td>
                <td><ClientLabel ip={e.client} names={clientNames} /></td>
                <td className="wrap">{e.name}</td>
                <td>{e.qtype}</td>
                <td>
                  <span className={`badge ${e.action}`}>{e.action}</span>
                </td>
                <td>{e.category ? <span className={`badge ${catClass(e.category)}`}>{e.category}</span> : <span className="muted">—</span>}</td>
                <td>{e.rcode}</td>
                <td>{e.elapsed_ms.toFixed(2)}</td>
              </tr>
            ))}
            <TableStatusRow loading={false} error="" empty={shown.length === 0} colSpan={9}>
              {paused || hidden ? 'Stream paused' : 'Waiting for queries…'}
            </TableStatusRow>
          </tbody>
        </table>
      </div>
    </>
  )
}
