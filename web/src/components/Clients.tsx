import { useEffect, useMemo, useState } from 'react'
import { api, type ClientRow, type Node } from '../api'
import { RangeNodeBar, makeNodeColor, VALID_HOURS, siteGroups } from './filters'
import { pollWhileVisible } from '../poll'
import { useClientNames } from '../useClientNames'
import ClientLabel from './ClientLabel'
import ClientDetail from './ClientDetail'
import Spinner from './Spinner'

const loadHours = (): number => {
  const v = Number(localStorage.getItem('mazedns.clients.hours'))
  return VALID_HOURS.includes(v) ? v : 24
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
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return rows
    return rows.filter((r) => {
      const name = clientNames.get(r.client)?.name?.toLowerCase() ?? ''
      return r.client.toLowerCase().includes(q) || name.includes(q)
    })
  }, [rows, search, clientNames])

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

      <div className="ql-filters" style={{ margin: '12px 0' }}>
        <input className="search" placeholder="search client or name…" value={search} onChange={(e) => setSearch(e.target.value)} />
      </div>

      <table className="sortable">
        <thead>
          <tr>
            <th>Client</th>
            <th>Queries</th>
            <th>Blocked</th>
            <th>Blocked %</th>
            <th>Last seen</th>
            <th style={{ width: '30%' }}></th>
          </tr>
        </thead>
        <tbody>
          {filtered.map((c) => {
            const pct = c.total ? (c.blocked / c.total) * 100 : 0
            return (
              <tr key={c.client} className="cls-row" onClick={() => setSelected(c.client)}>
                <td><ClientLabel ip={c.client} names={clientNames} /></td>
                <td>{c.total.toLocaleString()}</td>
                <td>{c.blocked.toLocaleString()}</td>
                <td>
                  <span className={`badge ${pct >= 25 ? 'blocked' : pct > 0 ? 'info' : 'allow'}`}>{pct.toFixed(0)}%</span>
                </td>
                <td className="muted">{c.last_seen ? new Date(c.last_seen).toLocaleString() : '—'}</td>
                <td>
                  <div className="cbar">
                    <span style={{ width: `${maxTotal ? (c.total / maxTotal) * 100 : 0}%` }} />
                  </div>
                </td>
              </tr>
            )
          })}
          {filtered.length === 0 && (
            <tr>
              <td colSpan={6} className="muted">
                No client activity
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
