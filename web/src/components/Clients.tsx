import { useEffect, useMemo, useState } from 'react'
import { api, type ClientRow, type Node } from '../api'
import { RangeNodeBar, makeNodeColor, VALID_HOURS, siteGroups } from './filters'
import { pollWhileVisible } from '../poll'
import { useClientNames } from '../useClientNames'
import ClientLabel from './ClientLabel'
import ClientDetail from './ClientDetail'
import Spinner from './Spinner'
import { useTable, Th, Pager, timeAgo, type SortAccessors } from './tableKit'

const loadHours = (): number => {
  const v = Number(localStorage.getItem('mazedns.clients.hours'))
  return VALID_HOURS.includes(v) ? v : 24
}

// A client is "active" if it queried in the last 5 minutes.
const ACTIVE_MS = 5 * 60 * 1000

type Row = ClientRow & { pct: number }

const COLS: SortAccessors<Row> = {
  client: (r) => r.client,
  total: (r) => r.total,
  blocked: (r) => r.blocked,
  pct: (r) => r.pct,
  last_seen: (r) => r.last_seen,
}

// Clients lists every client seen in the window with its query volume, how much
// was blocked, and when it was last seen. Clicking a row opens a detail modal
// with per-client KPIs, charts, and the static-hostname editor.
export default function Clients() {
  const [hours, setHours] = useState(loadHours)
  const [focus, setFocus] = useState<string[]>([])
  const [nodes, setNodes] = useState<Node[]>([])
  const [rows, setRows] = useState<ClientRow[]>([])
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<string | null>(null)
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    localStorage.setItem('mazedns.clients.hours', String(hours))
  }, [hours])

  const nodeNames = useMemo(() => [...new Set(nodes.map((n) => n.name))], [nodes])
  const nodeColor = useMemo(() => makeNodeColor(nodeNames), [nodeNames])

  useEffect(() => {
    api.clusterNodes().then(setNodes).catch(() => setNodes([]))
  }, [])

  useEffect(() => {
    let alive = true
    setLoading(true)
    const fetchRows = () =>
      api
        .clientList(hours, focus)
        .then((r) => {
          if (alive) {
            setRows(r.clients)
            setErr('')
            setLoading(false)
          }
        })
        .catch((e) => alive && setErr(e.message))
    fetchRows()
    const stop = pollWhileVisible(fetchRows, 15000)
    return () => {
      alive = false
      stop()
    }
  }, [hours, focus])

  const clientNames = useClientNames(rows.map((r) => r.client))
  const maxTotal = rows.reduce((m, r) => Math.max(m, r.total), 0)

  // Window KPIs across all (unfiltered-by-search) clients.
  const totalQ = rows.reduce((s, r) => s + r.total, 0)
  const totalB = rows.reduce((s, r) => s + r.blocked, 0)
  const active = rows.filter((r) => r.last_seen && Date.now() - r.last_seen < ACTIVE_MS).length
  const named = rows.filter((r) => clientNames.get(r.client)?.name).length
  const blockedPct = totalQ ? Math.round((totalB / totalQ) * 100) : 0

  const filtered: Row[] = useMemo(() => {
    const q = search.trim().toLowerCase()
    const base = q
      ? rows.filter((r) => {
          const name = clientNames.get(r.client)?.name?.toLowerCase() ?? ''
          return r.client.toLowerCase().includes(q) || name.includes(q)
        })
      : rows
    return base.map((r) => ({ ...r, pct: r.total ? (r.blocked / r.total) * 100 : 0 }))
  }, [rows, search, clientNames])

  const table = useTable(filtered, COLS, 'total', true)

  return (
    <div>
      {selected && (
        <ClientDetail client={selected} hours={hours} nodes={focus} names={clientNames} onClose={() => setSelected(null)} />
      )}
      <h2 style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        Clients {loading && <Spinner />}
      </h2>
      <p className="muted" style={{ textAlign: 'left' }}>
        Per-client activity across the cluster. Click a client to inspect its KPIs and queries, or to assign a static
        hostname that shows everywhere.
      </p>
      {err && <div className="error">{err}</div>}

      <RangeNodeBar hours={hours} setHours={setHours} focus={focus} setFocus={setFocus} nodeNames={nodeNames} color={nodeColor} sites={siteGroups(nodes)} />

      <div className="cards" style={{ marginTop: 12 }}>
        <div className="card">
          <div className="card-value">{rows.length.toLocaleString()}</div>
          <div className="card-label">Clients seen</div>
        </div>
        <div className="card">
          <div className="card-value">{active.toLocaleString()}</div>
          <div className="card-label">Active now (5m)</div>
        </div>
        <div className="card">
          <div className="card-value">{named.toLocaleString()}</div>
          <div className="card-label">Named clients</div>
        </div>
        <div className="card">
          <div className="card-value">{totalQ.toLocaleString()}</div>
          <div className="card-label">Queries</div>
        </div>
        <div className={`card ${blockedPct >= 25 ? 'danger' : ''}`}>
          <div className="card-value">{blockedPct}%</div>
          <div className="card-label">Blocked ({totalB.toLocaleString()})</div>
        </div>
      </div>

      <div className="ql-filters" style={{ margin: '12px 0' }}>
        <input className="search" placeholder="search client or name…" value={search} onChange={(e) => setSearch(e.target.value)} />
      </div>

      <div className="table-scroll">
        <table className="sortable">
          <thead>
            <tr>
              <Th table={table} col="client">Client</Th>
              <Th table={table} col="total">Queries</Th>
              <Th table={table} col="blocked">Blocked</Th>
              <Th table={table} col="pct">Blocked %</Th>
              <Th table={table} col="last_seen">Last seen</Th>
              <th style={{ width: '30%' }}></th>
            </tr>
          </thead>
          <tbody>
            {table.rows.map((c) => {
              const activeNow = c.last_seen && Date.now() - c.last_seen < ACTIVE_MS
              return (
                <tr key={c.client} className="cls-row" onClick={() => setSelected(c.client)}>
                  <td><ClientLabel ip={c.client} names={clientNames} /></td>
                  <td>{c.total.toLocaleString()}</td>
                  <td>{c.blocked.toLocaleString()}</td>
                  <td>
                    <span className={`badge ${c.pct >= 25 ? 'blocked' : c.pct > 0 ? 'info' : 'allow'}`}>{c.pct.toFixed(0)}%</span>
                  </td>
                  <td className="muted" title={c.last_seen ? new Date(c.last_seen).toLocaleString() : ''}>
                    {activeNow && <span className="node-dot on" style={{ marginRight: 6 }} title="Active in the last 5 minutes" />}
                    {timeAgo(c.last_seen)}
                  </td>
                  <td>
                    <div className="cbar">
                      <span style={{ width: `${maxTotal ? (c.total / maxTotal) * 100 : 0}%` }} />
                    </div>
                  </td>
                </tr>
              )
            })}
            {table.rows.length === 0 && (
              <tr>
                <td colSpan={6} className="muted">
                  No client activity
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <Pager table={table} unit="clients" />
    </div>
  )
}
