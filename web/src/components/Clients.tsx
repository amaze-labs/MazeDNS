import { useCallback, useEffect, useMemo, useState } from 'react'
import { api, type ClientRow, type Node, type WindowTotals } from '../api'
import { NodeFilter, makeNodeColor, VALID_HOURS, siteGroups } from './filters'
import { pollWhileVisible } from '../poll'
import { useClientNames } from '../useClientNames'
import ClientLabel, { clientName } from './ClientLabel'
import ClientDetail, { ACTIVE_MS } from './ClientDetail'
import Spinner from './Spinner'
import { useTable, Th, Pager, TableStatusRow, timeAgo, windowLabel, WindowPicker, SearchBox, type SortAccessors } from './tableKit'
import '../styles/queries.css'

const loadHours = (): number => {
  const v = Number(localStorage.getItem('mazedns.clients.hours'))
  return VALID_HOURS.includes(v) ? v : 24
}

// The most clients /api/clients returns in one answer (busiest first). Past it
// the list, and the figures derived from it, cover the busiest clients only.
const LIST_MAX = 1000

type Row = ClientRow & { pct: number; name: string }

const COLS: SortAccessors<Row> = {
  client: (r) => r.name || r.client,
  total: (r) => r.total,
  blocked: (r) => r.blocked,
  pct: (r) => r.pct,
  last_seen: (r) => r.last_seen,
}

type View = 'all' | 'active' | 'unnamed'

// Clients lists every client seen in the window with its query volume, how much
// was blocked, and when it was last seen. Clicking a row opens the client drawer
// (figures, top domains, and the name editor).
export default function Clients() {
  const [hours, setHours] = useState(loadHours)
  const [focus, setFocus] = useState<string[]>([])
  const [nodes, setNodes] = useState<Node[]>([])
  const [rows, setRows] = useState<ClientRow[]>([])
  const [win, setWin] = useState<{ clients: number; totals: WindowTotals } | null>(null)
  const [search, setSearch] = useState('')
  const [view, setView] = useState<View>('all')
  const [selected, setSelected] = useState<string | null>(null)
  const [err, setErr] = useState('')
  // loading: the current window/focus has no answer yet; loaded: the first
  // answer ever arrived (the figures show "—" until then, not zeros).
  const [loading, setLoading] = useState(true)
  const [loaded, setLoaded] = useState(false)

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
    const fetchRows = () => {
      api
        .clientList(hours, focus, LIST_MAX)
        .then((r) => {
          if (!alive) return
          setRows(r.clients)
          setErr('')
          setLoading(false)
          setLoaded(true)
        })
        .catch((e) => alive && setErr(e.message))
      // Exact window figures (distinct clients, blocked share) come from the
      // window summary, so they stay right however many clients there are.
      api
        .insights(hours, focus)
        .then((i) => alive && setWin({ clients: i.unique_clients, totals: i.totals }))
        .catch(() => alive && setWin(null))
    }
    fetchRows()
    const stop = pollWhileVisible(fetchRows, 15000)
    return () => {
      alive = false
      stop()
    }
  }, [hours, focus])

  const names = useClientNames(rows.map((r) => r.client))
  const capped = rows.length >= LIST_MAX
  const now = Date.now()
  const isActive = (r: ClientRow) => r.last_seen > 0 && now - r.last_seen < ACTIVE_MS

  // Not memoised on `names`: the resolver map is mutated in place as names arrive.
  const all: Row[] = rows.map((r) => ({ ...r, pct: r.total ? (r.blocked / r.total) * 100 : 0, name: clientName(r.client, names) }))
  const activeN = all.filter(isActive).length
  const unnamedN = all.filter((r) => !r.name).length
  const namedN = all.length - unnamedN
  const q = search.trim().toLowerCase()
  const filtered = all.filter(
    (r) =>
      (view === 'all' || (view === 'active' ? isActive(r) : !r.name)) &&
      (!q || r.client.toLowerCase().includes(q) || r.name.toLowerCase().includes(q)),
  )
  const table = useTable(filtered, COLS, 'total', true)
  const changeSearch = (v: string) => {
    setSearch(v)
    table.setPage(0)
  }
  const changeView = (v: View) => {
    setView(v)
    table.setPage(0)
  }
  const maxTotal = all.reduce((m, r) => Math.max(m, r.total), 0)

  const seen = win?.clients ?? rows.length
  const t = win?.totals
  const blockedPct = t ? (t.total ? (t.blocked / t.total) * 100 : 0) : null
  const fig = (v: string) => (loaded ? v : '—')
  const plus = capped ? '+' : ''
  const closeDrawer = useCallback(() => setSelected(null), [])

  return (
    <div className="pg-clients">
      {selected && <ClientDetail client={selected} hours={hours} nodes={focus} names={names} onClose={closeDrawer} />}
      <header className="page-head">
        <h1>Clients</h1>
        {loading && !err && <Spinner />}
        <span className="spacer" />
        <WindowPicker hours={hours} onChange={setHours} />
        {nodeNames.length > 0 && <NodeFilter options={nodeNames} selected={focus} onChange={setFocus} color={nodeColor} sites={siteGroups(nodes)} />}
      </header>
      <p className="intro">
        Devices that asked your agents for names. Give a device a name once and it shows up everywhere: queries, charts and
        logs.
      </p>
      {err && <div className="error">{err}</div>}

      <div className="strip">
        <div>
          <b>{fig(seen.toLocaleString())}</b>
          <span>clients seen in the last {windowLabel(hours)}</span>
        </div>
        <div>
          <b>{fig(`${activeN.toLocaleString()}${plus}`)}</b>
          <span>active in the last 5 minutes</span>
        </div>
        <div>
          <b>{fig(`${namedN.toLocaleString()}${plus}`)}</b>
          <span>with a name{capped ? ` (of the busiest ${LIST_MAX.toLocaleString()})` : ''}</span>
        </div>
        <div>
          <b className={blockedPct != null && blockedPct >= 25 ? 'block' : ''}>
            {fig(blockedPct == null ? '—' : `${blockedPct.toFixed(1)}%`)}
          </b>
          <span>of their queries blocked</span>
        </div>
      </div>

      <div className="toolbar">
        <SearchBox value={search} onChange={changeSearch} placeholder="Search name or IP" maxWidth={360} />
        {(
          [
            ['all', 'All', all.length],
            ['active', 'Active now', activeN],
            ['unnamed', 'Unnamed', unnamedN],
          ] as [View, string, number][]
        ).map(([v, label, n]) => (
          <button key={v} className={`chip${view === v ? ' on' : ''}`} aria-pressed={view === v} onClick={() => changeView(v)}>
            {v === 'all' ? <b>{label}</b> : label}
            {loaded && <span className="num">{n.toLocaleString()}{plus}</span>}
          </button>
        ))}
      </div>
      {capped && (
        <p className="hint" style={{ margin: '-4px 0 12px' }}>
          Showing the {LIST_MAX.toLocaleString()} busiest clients of {seen.toLocaleString()}. Search and the counts above cover those only.
        </p>
      )}

      <section className="card flush">
        <div className="table-scroll">
          <table className="stackable c-table">
            <thead>
              <tr>
                <Th table={table} col="client">Client</Th>
                <Th table={table} col="total" className="num">Queries</Th>
                <Th table={table} col="pct" className="num">Blocked</Th>
                <th className="hide-sm">Volume and blocked share</th>
                <Th table={table} col="last_seen">Last seen</Th>
              </tr>
            </thead>
            <tbody>
              {table.rows.map((c) => {
                const on = isActive(c)
                return (
                  <tr
                    key={c.client}
                    className={`click${selected === c.client ? ' sel' : ''}`}
                    onClick={() => setSelected(c.client)}
                    tabIndex={0}
                    onKeyDown={(k) => (k.key === 'Enter' || k.key === ' ') && (k.preventDefault(), setSelected(c.client))}
                  >
                    <td className="lead">
                      {c.name ? (
                        <>
                          <span className="hide-sm">
                            <ClientLabel ip={c.client} names={names} source />
                          </span>
                          <span className="show-sm">
                            <ClientLabel ip={c.client} names={names} />
                          </span>
                        </>
                      ) : (
                        <>
                          <span className="mono">{c.client}</span> <span className="tag">unnamed</span>
                        </>
                      )}
                    </td>
                    <td className="num lead-r">{c.total.toLocaleString()}</td>
                    <td className="num c-blocked">
                      {c.blocked.toLocaleString()} <span className="muted">({c.pct.toFixed(0)}%)</span>
                    </td>
                    <td className="hide-sm">
                      <div className="c-vol" title={`${c.total.toLocaleString()} queries, ${c.blocked.toLocaleString()} blocked`}>
                        <div className="mini" style={{ minWidth: 0, width: `${maxTotal ? Math.max(4, (c.total / maxTotal) * 100) : 0}%` }}>
                          <i style={{ ['--k' as string]: 'var(--faint)', flex: c.total - c.blocked }} />
                          <i style={{ ['--k' as string]: 'var(--block)', flex: c.blocked }} />
                        </div>
                      </div>
                    </td>
                    <td className="nowrap c-seen" title={c.last_seen ? new Date(c.last_seen).toLocaleString() : ''}>
                      <span className={`dot ${on ? '' : 'off'}`} /> {on && now - c.last_seen < 60_000 ? 'now' : timeAgo(c.last_seen)}
                    </td>
                  </tr>
                )
              })}
              <TableStatusRow loading={loading} error={err} empty={table.rows.length === 0} colSpan={5}>
                {rows.length === 0 ? `No client activity in the last ${windowLabel(hours)}.` : 'No client matches.'}
              </TableStatusRow>
            </tbody>
          </table>
        </div>
        <Pager table={table} unit="clients" />
      </section>
    </div>
  )
}
