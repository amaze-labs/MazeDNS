import { useEffect, useMemo, useState } from 'react'
import { api, type QueryLogEntry, type Node } from '../api'
import { RangeNodeBar, makeNodeColor } from './filters'
import { useClientNames } from '../useClientNames'
import ClientLabel from './ClientLabel'
import Spinner from './Spinner'

const PAGE = 50
const ACTIONS = ['forward', 'cache', 'blocked', 'rewrite', 'authoritative', 'error', 'refused']
const QTYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'PTR', 'SOA', 'SRV', 'HTTPS', 'SVCB', 'CAA', 'ANY']

const loadHours = (): number => {
  const v = Number(localStorage.getItem('mazedns.ql.hours'))
  return [1, 24, 168, 720, 2160].includes(v) ? v : 24
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
  const [input, setInput] = useState('')
  const [search, setSearch] = useState('')
  const [action, setAction] = useState('')
  const [qtype, setQtype] = useState('')
  const [sort, setSortCol] = useState('time')
  const [desc, setDesc] = useState(true)
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(true)

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

  // Debounce the search box.
  useEffect(() => {
    const t = setTimeout(() => {
      setSearch(input.trim())
      setPage(0)
    }, 400)
    return () => clearTimeout(t)
  }, [input])

  useEffect(() => {
    let alive = true
    setLoading(true)
    const fetchLog = () =>
      api
        .queryLog({ limit: PAGE, offset: page * PAGE, search, nodes: focus, action, qtype, sort, desc, hours })
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
    const id = setInterval(fetchLog, 5000)
    return () => {
      alive = false
      clearInterval(id)
    }
  }, [page, search, focus, action, qtype, sort, desc, hours])

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

  return (
    <div>
      <h2 style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        Requests {loading && <Spinner />}
      </h2>
      <p className="muted" style={{ textAlign: 'left' }}>
        Explore the cluster-wide DNS query log. Filter by window, node, action, and type; click a column to sort.
      </p>
      {err && <div className="error">{err}</div>}

      <RangeNodeBar hours={hours} setHours={setHours} focus={focus} setFocus={setFocus} nodeNames={[]} color={nodeColor} />

      <div className="ql-filters" style={{ margin: '12px 0' }}>
        <select
          className="ql-select"
          value={focus.length === 1 ? focus[0] : ''}
          onChange={(e) => { setFocus(e.target.value ? [e.target.value] : []); setPage(0) }}
        >
          <option value="">All nodes</option>
          {nodeNames.map((n) => (
            <option key={n} value={n}>
              {n}
            </option>
          ))}
        </select>
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
        <input className="search" placeholder="search name or client…" value={input} onChange={(e) => setInput(e.target.value)} />
      </div>

      <table className="sortable">
        <thead>
          <tr>
            <th className="sortable" onClick={() => setSort('time')}>Time{arrow('time')}</th>
            <th className="sortable" onClick={() => setSort('node')}>Node{arrow('node')}</th>
            <th className="sortable" onClick={() => setSort('client')}>Client{arrow('client')}</th>
            <th className="sortable" onClick={() => setSort('name')}>Name{arrow('name')}</th>
            <th className="sortable" onClick={() => setSort('qtype')}>Type{arrow('qtype')}</th>
            <th className="sortable" onClick={() => setSort('action')}>Action{arrow('action')}</th>
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
              <td>{e.name}</td>
              <td>{e.qtype}</td>
              <td>
                <span className={`badge ${e.action}`}>{e.action}</span>
              </td>
              <td>{e.rcode}</td>
              <td>{e.elapsed_ms.toFixed(2)}</td>
            </tr>
          ))}
          {log.length === 0 && (
            <tr>
              <td colSpan={8} className="muted">
                No matching queries
              </td>
            </tr>
          )}
        </tbody>
      </table>
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
