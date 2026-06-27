import { useEffect, useMemo, useState, type ReactNode } from 'react'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import {
  api,
  type Stats,
  type QueryLogEntry,
  type SeriesPoint,
  type CategoryCount,
  type Insights,
  type Node,
  type LatencyPoint,
} from '../api'

const catColors: Record<string, string> = {
  ads: '#4ea1ff',
  trackers: '#c48aff',
  malware: '#ff5d6c',
  phishing: '#ffb454',
  'not-found': '#56d4dd',
  custom: '#8a93a0',
}
const sourceColors: Record<string, string> = {
  Forwarded: '#4ea1ff',
  Cached: '#3ecf8e',
  Blocked: '#ff5d6c',
  Rewritten: '#c48aff',
}
const NODE_PALETTE = ['#4ea1ff', '#3ecf8e', '#c48aff', '#ffb454', '#ff5d6c', '#56d4dd', '#e070c0']
// "overall" is not a node — it gets a reserved neutral color, never a palette slot.
const OVERALL_COLOR = '#e6e9ee'
// colorAt maps any integer (including -1) to a stable palette color.
const colorAt = (i: number) => NODE_PALETTE[((i % NODE_PALETTE.length) + NODE_PALETTE.length) % NODE_PALETTE.length]
const ONLINE_WINDOW = 120
const tooltipStyle = { background: '#171c23', border: '1px solid #262d36', borderRadius: 8 }
const PAGE = 25

const RANGES = [
  { label: '1h', hours: 1 },
  { label: '24h', hours: 24 },
  { label: '7d', hours: 24 * 7 },
  { label: '30d', hours: 24 * 30 },
  { label: '90d', hours: 24 * 90 },
]

const fmt = (n?: number) => (n == null ? '—' : n.toLocaleString())

// Persist dashboard view prefs (time window + node focus) in the browser.
const loadHours = (): number => {
  const v = Number(localStorage.getItem('mazedns.hours'))
  return RANGES.some((r) => r.hours === v) ? v : 24
}
const loadFocus = (): string[] => {
  try {
    const v = JSON.parse(localStorage.getItem('mazedns.focusNodes') || '[]')
    return Array.isArray(v) ? v : []
  } catch {
    return []
  }
}
// KPI cards are user-curatable: which ones show and in what order, persisted
// in the browser. `available` cards that aren't hidden render in `kpiOrder`.
type KpiDef = { id: string; label: string; value?: string; accent?: string; sub?: string; available: boolean }
const DEFAULT_KPI_ORDER = [
  'total', 'blocked', 'cached', 'forwarded', 'malicious', 'clients', 'latency', 'errors', 'rewritten', 'qtypes', 'cache_size',
]
// Hidden by default so the dashboard starts clean; users can switch them on.
const DEFAULT_KPI_HIDDEN = ['rewritten', 'qtypes', 'cache_size']
const loadJSON = <T,>(key: string, fallback: T): T => {
  try {
    const v = JSON.parse(localStorage.getItem(key) || 'null')
    return Array.isArray(v) ? (v as T) : fallback
  } catch {
    return fallback
  }
}

// ACTIONS are the resolver's action values, for the recent-queries filter.
const ACTIONS = ['forward', 'cache', 'blocked', 'rewrite', 'authoritative', 'error', 'refused']

const bucketLabel = (ts: number, hours: number) => {
  const d = new Date(ts * 1000)
  return hours <= 48
    ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    : d.toLocaleDateString([], { month: 'short', day: 'numeric' })
}

// PieTooltip reads the slice's own color from the datum (fixes the legend/tooltip
// color mismatch in Recharts pies).
function PieTooltip({ active, payload }: any) {
  if (!active || !payload?.length) return null
  const p = payload[0]
  const d = p.payload || {}
  const color = d.fill || p.color || '#8a93a0'
  const name = d.name ?? d.category ?? d.node ?? p.name
  return (
    <div style={{ ...tooltipStyle, padding: '6px 10px', fontSize: 13 }}>
      <span style={{ color }}>● </span>
      {name}: {Number(p.value).toLocaleString()}
    </div>
  )
}

function Section({
  title,
  children,
  defaultOpen = true,
  right,
}: {
  title: string
  children: ReactNode
  defaultOpen?: boolean
  right?: ReactNode
}) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <section className="dash-section">
      <div className="dash-head">
        <button className="dash-toggle" onClick={() => setOpen(!open)}>
          <span className="caret">{open ? '▾' : '▸'}</span> {title}
        </button>
        <div className="spacer" />
        {right}
      </div>
      {open && <div className="dash-body">{children}</div>}
    </section>
  )
}

function Donut({ data, height = 180 }: { data: { name: string; value: number; fill: string }[]; height?: number }) {
  if (data.length === 0) return <p className="muted">No data yet</p>
  return (
    <>
      <ResponsiveContainer width="100%" height={height}>
        <PieChart>
          <Pie data={data} dataKey="value" nameKey="name" innerRadius={50} outerRadius={80} paddingAngle={2}>
            {data.map((d) => (
              <Cell key={d.name} fill={d.fill} />
            ))}
          </Pie>
          <Tooltip content={<PieTooltip />} />
        </PieChart>
      </ResponsiveContainer>
      <div className="legend">
        {data.map((d) => (
          <span key={d.name}>
            <i style={{ background: d.fill }} /> {d.name} ({d.value.toLocaleString()})
          </span>
        ))}
      </div>
    </>
  )
}

// NodeFilter is a multi-select dropdown to focus the dashboard on one or more
// nodes. Empty selection = all nodes.
function NodeFilter({
  options,
  selected,
  onChange,
  color,
}: {
  options: string[]
  selected: string[]
  onChange: (s: string[]) => void
  color: (name: string) => string
}) {
  const [open, setOpen] = useState(false)
  const allActive = selected.length === 0
  const label = allActive ? 'All nodes' : selected.length === 1 ? selected[0] : `${selected.length} nodes`
  const toggle = (n: string) =>
    onChange(selected.includes(n) ? selected.filter((x) => x !== n) : [...selected, n])
  return (
    <div className="nodefilter">
      <button className={`nf-trigger ${open ? 'open' : ''} ${allActive ? '' : 'active'}`} onClick={() => setOpen((o) => !o)}>
        <span className="nf-label">{label}</span>
        <span className="nf-caret">▾</span>
      </button>
      {open && (
        <>
          <div className="nodefilter-backdrop" onClick={() => setOpen(false)} />
          <div className="nodefilter-menu">
            <div className="nf-head">Focus on nodes</div>
            <button type="button" className={`nf-opt ${allActive ? 'sel' : ''}`} onClick={() => onChange([])}>
              <span className="nf-check">{allActive ? '✓' : ''}</span>
              <span className="nf-name">All nodes</span>
            </button>
            <div className="nf-divider" />
            {options.map((o) => {
              const sel = selected.includes(o)
              return (
                <button key={o} type="button" className={`nf-opt ${sel ? 'sel' : ''}`} onClick={() => toggle(o)}>
                  <span className="nf-check">{sel ? '✓' : ''}</span>
                  <span className="nf-swatch" style={{ background: color(o) }} />
                  <span className="nf-name">{o}</span>
                </button>
              )
            })}
          </div>
        </>
      )}
    </div>
  )
}

export default function Dashboard() {
  const [hours, setHours] = useState(loadHours)
  const [focus, setFocus] = useState<string[]>(loadFocus)
  const [stats, setStats] = useState<Stats | null>(null)
  const [series, setSeries] = useState<SeriesPoint[]>([])
  const [cats, setCats] = useState<CategoryCount[]>([])
  const [ins, setIns] = useState<Insights | null>(null)
  const [lat, setLat] = useState<{ nodes: string[]; points: LatencyPoint[] } | null>(null)
  const [nodes, setNodes] = useState<Node[]>([])
  const [err, setErr] = useState('')

  // KPI curation (which cards show, and in what order)
  const [kpiOrder, setKpiOrder] = useState<string[]>(() => loadJSON('mazedns.kpiOrder', DEFAULT_KPI_ORDER))
  const [kpiHidden, setKpiHidden] = useState<string[]>(() => loadJSON('mazedns.kpiHidden', DEFAULT_KPI_HIDDEN))
  const [customizing, setCustomizing] = useState(false)

  // query log (paginated, searchable, filterable, sortable)
  const [log, setLog] = useState<QueryLogEntry[]>([])
  const [qlTotal, setQlTotal] = useState(0)
  const [qlPage, setQlPage] = useState(0)
  const [qlInput, setQlInput] = useState('')
  const [qlSearch, setQlSearch] = useState('')
  const [qlAction, setQlAction] = useState('')
  const [qlType, setQlType] = useState('')
  const [qlSort, setQlSort] = useState('time')
  const [qlDesc, setQlDesc] = useState(true)

  const rangeLabel = RANGES.find((r) => r.hours === hours)?.label ?? `${hours}h`

  useEffect(() => {
    localStorage.setItem('mazedns.hours', String(hours))
  }, [hours])
  useEffect(() => {
    localStorage.setItem('mazedns.focusNodes', JSON.stringify(focus))
  }, [focus])
  useEffect(() => {
    localStorage.setItem('mazedns.kpiOrder', JSON.stringify(kpiOrder))
  }, [kpiOrder])
  useEffect(() => {
    localStorage.setItem('mazedns.kpiHidden', JSON.stringify(kpiHidden))
  }, [kpiHidden])

  useEffect(() => {
    let alive = true
    const tick = async () => {
      try {
        const [s, ts, c, i, l] = await Promise.all([
          api.stats(),
          api.timeseries(hours, focus),
          api.categories(hours, focus),
          api.insights(hours, focus),
          api.latency(hours, focus),
        ])
        if (!alive) return
        setStats(s)
        setSeries(ts.points)
        setCats(c)
        setIns(i)
        setLat(l)
        setErr('')
        const n = await api.clusterNodes().catch(() => [] as Node[])
        if (alive) setNodes(n)
      } catch (e: any) {
        if (alive) setErr(e.message)
      }
    }
    tick()
    const id = setInterval(tick, 5000)
    return () => {
      alive = false
      clearInterval(id)
    }
  }, [hours, focus])

  // Debounce the search box.
  useEffect(() => {
    const t = setTimeout(() => {
      setQlSearch(qlInput.trim())
      setQlPage(0)
    }, 400)
    return () => clearTimeout(t)
  }, [qlInput])

  useEffect(() => {
    let alive = true
    const fetchLog = () =>
      api
        .queryLog({
          limit: PAGE,
          offset: qlPage * PAGE,
          search: qlSearch,
          nodes: focus,
          action: qlAction,
          qtype: qlType,
          sort: qlSort,
          desc: qlDesc,
          hours,
        })
        .then((r) => {
          if (alive) {
            setLog(r.entries)
            setQlTotal(r.total)
          }
        })
        .catch(() => {})
    fetchLog()
    const id = setInterval(fetchLog, 5000)
    return () => {
      alive = false
      clearInterval(id)
    }
  }, [qlPage, qlSearch, focus, qlAction, qlType, qlSort, qlDesc, hours])

  const malicious = cats.find((c) => c.category === 'malware')?.count ?? 0
  const areaData = series.map((p) => ({
    time: bucketLabel(p.ts, hours),
    blocked: p.blocked,
    cached: p.cached,
    forwarded: p.forwarded,
  }))
  const round2 = (n: number) => Math.round(n * 100) / 100
  const latNodes = lat?.nodes ?? []

  // A node keeps the SAME color in every chart, legend, and the focus filter.
  // Color is keyed by the node's position in one canonical, sorted name list
  // (built from every place a node can appear), so it never depends on the order
  // a given panel happens to return its rows in.
  const nodeNames = useMemo(() => {
    const s = new Set<string>(['master'])
    nodes.forEach((n) => s.add(n.name))
    ;(lat?.nodes ?? []).forEach((n) => s.add(n))
    ;(ins?.by_node ?? []).forEach((n) => s.add(n.node))
    return [...s].sort()
  }, [nodes, lat, ins])
  const nodeColor = (name: string) => colorAt(nodeNames.indexOf(name))

  const latData = (lat?.points ?? []).map((p) => {
    const row: Record<string, number | string | null> = { time: bucketLabel(p.ts, hours), overall: round2(p.overall) }
    for (const n of latNodes) row[n] = p.by_node[n] != null ? round2(p.by_node[n]) : null
    return row
  })
  // Known categories keep their fixed color; file-sourced lists (e.g. "blocklist",
  // "stevenblack") fall back to a distinct palette color rather than all-gray.
  const catData = cats.map((c, i) => ({ name: c.category, value: c.count, fill: catColors[c.category] || colorAt(i) }))
  const totals = ins?.totals
  const sourceData = totals
    ? [
        { name: 'Forwarded', value: totals.forwarded },
        { name: 'Cached', value: totals.cached },
        { name: 'Blocked', value: totals.blocked },
        { name: 'Rewritten', value: totals.rewritten },
      ]
        .filter((d) => d.value > 0)
        .map((d) => ({ ...d, fill: sourceColors[d.name] }))
    : []
  const byNodeData = (ins?.by_node ?? [])
    .filter((n) => n.total > 0)
    .map((n) => ({ name: n.node, value: n.total, fill: nodeColor(n.node) }))
  const clientRows = ins?.clients ?? []
  const maxClient = clientRows.reduce((m, c) => Math.max(m, c.total), 0)

  const now = Date.now() / 1000
  const onlineNodes = nodes.filter((n) => n.last_seen && now - n.last_seen < ONLINE_WINDOW).length
  const clusterQ = nodes.reduce((sum, n) => sum + n.total, 0)
  const clusterB = nodes.reduce((sum, n) => sum + n.blocked, 0)
  const lastPage = Math.max(0, Math.ceil(qlTotal / PAGE) - 1)

  // KPI registry — every windowed card honors the time range + node focus (all
  // values derive from `totals`/`ins`, which are fetched with hours + focus).
  const tt = totals
  const wpct = (num?: number, den?: number) => (den && num != null ? `${Math.round((num / den) * 100)}% of total` : undefined)
  const kpiDefs: KpiDef[] = [
    { id: 'total', label: 'Total queries', value: fmt(tt?.total), available: true },
    { id: 'blocked', label: 'Blocked', value: fmt(tt?.blocked), accent: 'danger', sub: wpct(tt?.blocked, tt?.total), available: true },
    { id: 'cached', label: 'Cached', value: fmt(tt?.cached), sub: tt && tt.total ? `${Math.round((tt.cached / tt.total) * 100)}% hit rate` : undefined, available: true },
    { id: 'forwarded', label: 'Forwarded', value: fmt(tt?.forwarded), available: true },
    { id: 'malicious', label: `Malicious`, value: fmt(malicious), accent: malicious ? 'danger' : '', available: true },
    { id: 'clients', label: 'Unique clients', value: fmt(ins?.unique_clients), available: true },
    { id: 'latency', label: 'Avg latency', value: ins ? `${ins.avg_latency_ms.toFixed(1)} ms` : '—', available: true },
    { id: 'errors', label: 'Errors', value: fmt(tt?.errors), accent: tt?.errors ? 'danger' : '', available: true },
    { id: 'rewritten', label: 'Rewritten', value: fmt(tt?.rewritten), available: true },
    { id: 'qtypes', label: 'Query types', value: fmt(ins?.qtypes.length), available: true },
    { id: 'cache_size', label: 'Cache entries (live)', value: fmt(stats?.cache_size), available: true },
  ]
  const kpiById = new Map(kpiDefs.map((d) => [d.id, d]))
  // Saved order first, then any KPI ids not yet in the saved order (new ones).
  const orderedIds = [
    ...kpiOrder.filter((id) => kpiById.has(id)),
    ...kpiDefs.filter((d) => !kpiOrder.includes(d.id)).map((d) => d.id),
  ]
  const visibleKpis = orderedIds
    .map((id) => kpiById.get(id))
    .filter((d): d is KpiDef => !!d && d.available && !kpiHidden.includes(d.id))

  const moveKpi = (id: string, dir: -1 | 1) => {
    setKpiOrder(() => {
      const cur = orderedIds.slice()
      const i = cur.indexOf(id)
      const j = i + dir
      if (i < 0 || j < 0 || j >= cur.length) return cur
      ;[cur[i], cur[j]] = [cur[j], cur[i]]
      return cur
    })
  }
  const toggleKpi = (id: string) =>
    setKpiHidden((h) => (h.includes(id) ? h.filter((x) => x !== id) : [...h, id]))

  // Clicking a column header sorts by it; clicking the active column flips the
  // direction. Time defaults to newest-first, other columns to ascending.
  const setSort = (col: string) => {
    if (qlSort === col) {
      setQlDesc((d) => !d)
    } else {
      setQlSort(col)
      setQlDesc(col === 'time')
    }
    setQlPage(0)
  }
  const sortArrow = (col: string) => (qlSort === col ? (qlDesc ? ' ↓' : ' ↑') : '')

  return (
    <div>
      {err && <div className="error">{err}</div>}

      <div className="range-tabs">
        <span className="muted">Window</span>
        {RANGES.map((r) => (
          <button key={r.hours} className={hours === r.hours ? 'active' : ''} onClick={() => setHours(r.hours)}>
            {r.label}
          </button>
        ))}
        {nodes.length > 0 && (
          <>
            <div className="spacer" />
            <span className="muted">Focus</span>
            <NodeFilter options={['master', ...nodes.map((n) => n.name)]} selected={focus} onChange={setFocus} color={nodeColor} />
          </>
        )}
      </div>

      <Section
        title={`Overview (${rangeLabel})`}
        right={
          <button className={`btn ${customizing ? 'active' : ''}`} onClick={() => setCustomizing((c) => !c)}>
            ⚙ Customize
          </button>
        }
      >
        {customizing && (
          <div className="kpi-customize">
            <div className="muted">Show, hide, and reorder your KPI cards.</div>
            <ul>
              {orderedIds.map((id, i) => {
                const d = kpiById.get(id)
                if (!d) return null
                const shown = !kpiHidden.includes(id)
                return (
                  <li key={id}>
                    <label>
                      <input type="checkbox" checked={shown} onChange={() => toggleKpi(id)} /> {d.label}
                    </label>
                    <span className="spacer" />
                    <button className="btn" disabled={i === 0} onClick={() => moveKpi(id, -1)} title="Move up">
                      ▲
                    </button>
                    <button className="btn" disabled={i === orderedIds.length - 1} onClick={() => moveKpi(id, 1)} title="Move down">
                      ▼
                    </button>
                  </li>
                )
              })}
            </ul>
          </div>
        )}
        <div className="cards">
          {visibleKpis.map((d) => (
            <Card key={d.id} label={d.label} value={d.value} accent={d.accent} sub={d.sub} />
          ))}
          {visibleKpis.length === 0 && <p className="muted">All KPIs hidden — open Customize to show some.</p>}
        </div>
        {nodes.length > 0 && (
          <div className="kpi-section">
            <h3>Cluster health</h3>
            <div className="cards">
              <Card label="Worker nodes" value={fmt(nodes.length)} />
              <Card label="Online" value={fmt(onlineNodes)} accent={onlineNodes < nodes.length ? 'danger' : ''} />
              <Card label="Worker queries" value={fmt(clusterQ)} />
              <Card label="Worker blocked" value={fmt(clusterB)} accent="danger" />
            </div>
          </div>
        )}
      </Section>

      <Section title={`Traffic over time (${rangeLabel})`}>
        <div className="charts">
          <div className="panel">
            <h2>Queries</h2>
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={areaData} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="gForwarded" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#4ea1ff" stopOpacity={0.5} />
                    <stop offset="100%" stopColor="#4ea1ff" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gCached" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#3ecf8e" stopOpacity={0.5} />
                    <stop offset="100%" stopColor="#3ecf8e" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gBlocked" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#ff5d6c" stopOpacity={0.5} />
                    <stop offset="100%" stopColor="#ff5d6c" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#262d36" vertical={false} />
                <XAxis dataKey="time" stroke="#8a93a0" fontSize={11} tickLine={false} minTickGap={32} />
                <YAxis stroke="#8a93a0" fontSize={11} tickLine={false} width={40} allowDecimals={false} />
                <Tooltip contentStyle={tooltipStyle} />
                <Area type="monotone" dataKey="forwarded" stackId="1" stroke="#4ea1ff" fill="url(#gForwarded)" strokeWidth={2} />
                <Area type="monotone" dataKey="cached" stackId="1" stroke="#3ecf8e" fill="url(#gCached)" strokeWidth={2} />
                <Area type="monotone" dataKey="blocked" stackId="1" stroke="#ff5d6c" fill="url(#gBlocked)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
            <div className="legend">
              <span><i style={{ background: '#ff5d6c' }} /> blocked</span>
              <span><i style={{ background: '#3ecf8e' }} /> cached</span>
              <span><i style={{ background: '#4ea1ff' }} /> forwarded</span>
            </div>
          </div>
          <div className="panel">
            <h2>Avg latency (ms)</h2>
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={latData} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
                <CartesianGrid stroke="#262d36" vertical={false} />
                <XAxis dataKey="time" stroke="#8a93a0" fontSize={11} tickLine={false} minTickGap={32} />
                <YAxis stroke="#8a93a0" fontSize={11} tickLine={false} width={40} />
                <Tooltip contentStyle={tooltipStyle} />
                <Line type="monotone" dataKey="overall" name="overall" stroke={OVERALL_COLOR} strokeWidth={2.5} dot={false} connectNulls />
                {latNodes.map((n) => (
                  <Line
                    key={n}
                    type="monotone"
                    dataKey={n}
                    name={n}
                    stroke={nodeColor(n)}
                    strokeWidth={1.5}
                    dot={false}
                    connectNulls
                  />
                ))}
              </LineChart>
            </ResponsiveContainer>
            <div className="legend">
              <span><i style={{ background: OVERALL_COLOR }} /> overall</span>
              {latNodes.map((n) => (
                <span key={n}>
                  <i style={{ background: nodeColor(n) }} /> {n}
                </span>
              ))}
            </div>
          </div>
        </div>
      </Section>

      <Section title="Distribution">
        <div className="charts">
          <div className="panel">
            <h2>Queries by node</h2>
            <Donut data={byNodeData} />
          </div>
          <div className="panel">
            <h2>Answer source</h2>
            <Donut data={sourceData} />
          </div>
        </div>
        <div className="charts">
          <div className="panel">
            <h2>Query types ({rangeLabel})</h2>
            {(ins?.qtypes.length ?? 0) === 0 ? (
              <p className="muted">No queries yet</p>
            ) : (
              <ResponsiveContainer width="100%" height={Math.max(140, (ins?.qtypes.length ?? 0) * 28)}>
                <BarChart data={ins?.qtypes} layout="vertical" margin={{ top: 4, right: 16, left: 8, bottom: 0 }}>
                  <CartesianGrid stroke="#262d36" horizontal={false} />
                  <XAxis type="number" stroke="#8a93a0" fontSize={11} tickLine={false} allowDecimals={false} />
                  <YAxis type="category" dataKey="qtype" stroke="#8a93a0" fontSize={11} width={60} tickLine={false} />
                  <Tooltip contentStyle={tooltipStyle} cursor={{ fill: '#ffffff08' }} />
                  <Bar dataKey="count" fill="#4ea1ff" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
          <div className="panel">
            <h2>Blocked by category ({rangeLabel})</h2>
            <Donut data={catData} />
          </div>
        </div>
      </Section>

      <Section title={`Clients — cluster-wide (${rangeLabel})`}>
        <table className="mini">
          <thead>
            <tr>
              <th>Client</th>
              <th>Queries</th>
              <th>Blocked</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {clientRows.map((c) => (
              <tr key={c.client}>
                <td className="name">{c.client}</td>
                <td className="num">{c.total.toLocaleString()}</td>
                <td className="num">{c.blocked.toLocaleString()}</td>
                <td style={{ width: '40%' }}>
                  <div className="cbar">
                    <span style={{ width: `${maxClient ? (c.total / maxClient) * 100 : 0}%` }} />
                  </div>
                </td>
              </tr>
            ))}
            {clientRows.length === 0 && (
              <tr>
                <td colSpan={4} className="muted">
                  No client activity yet
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </Section>

      <Section title={`Top domains (${rangeLabel})`} defaultOpen={false}>
        <div className="charts">
          <DomainTable title="Top blocked" rows={ins?.top_blocked} />
          <DomainTable title="Most queried" rows={ins?.top_queried} />
        </div>
      </Section>

      <Section
        title="Recent queries"
        right={
          <div className="ql-filters">
            <select className="ql-select" value={qlAction} onChange={(e) => { setQlAction(e.target.value); setQlPage(0) }}>
              <option value="">All actions</option>
              {ACTIONS.map((a) => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </select>
            <select className="ql-select" value={qlType} onChange={(e) => { setQlType(e.target.value); setQlPage(0) }}>
              <option value="">All types</option>
              {(ins?.qtypes ?? []).map((t) => (
                <option key={t.qtype} value={t.qtype}>
                  {t.qtype}
                </option>
              ))}
            </select>
            <input
              className="search"
              placeholder="search name or client…"
              value={qlInput}
              onChange={(e) => setQlInput(e.target.value)}
            />
          </div>
        }
      >
        <table className="sortable">
          <thead>
            <tr>
              <th className="sortable" onClick={() => setSort('time')}>Time{sortArrow('time')}</th>
              <th className="sortable" onClick={() => setSort('node')}>Node{sortArrow('node')}</th>
              <th className="sortable" onClick={() => setSort('client')}>Client{sortArrow('client')}</th>
              <th className="sortable" onClick={() => setSort('name')}>Name{sortArrow('name')}</th>
              <th className="sortable" onClick={() => setSort('qtype')}>Type{sortArrow('qtype')}</th>
              <th className="sortable" onClick={() => setSort('action')}>Action{sortArrow('action')}</th>
              <th className="sortable" onClick={() => setSort('rcode')}>Rcode{sortArrow('rcode')}</th>
              <th className="sortable" onClick={() => setSort('ms')}>ms{sortArrow('ms')}</th>
            </tr>
          </thead>
          <tbody>
            {log.map((e) => (
              <tr key={e.id}>
                <td>{new Date(e.ts).toLocaleTimeString()}</td>
                <td>{e.node || 'master'}</td>
                <td>{e.client}</td>
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
            {qlTotal.toLocaleString()} match{qlTotal === 1 ? '' : 'es'} · page {qlPage + 1} of {lastPage + 1}
          </span>
          <div className="spacer" />
          <button className="btn" disabled={qlPage <= 0} onClick={() => setQlPage((p) => Math.max(0, p - 1))}>
            ‹ Prev
          </button>
          <button className="btn" disabled={qlPage >= lastPage} onClick={() => setQlPage((p) => Math.min(lastPage, p + 1))}>
            Next ›
          </button>
        </div>
      </Section>
    </div>
  )
}

function Card({ label, value, accent, sub }: { label: string; value?: string | number; accent?: string; sub?: string }) {
  return (
    <div className={`card ${accent || ''}`}>
      <div className="card-value">{value ?? '—'}</div>
      <div className="card-label">{label}</div>
      {sub && <div className="card-sub">{sub}</div>}
    </div>
  )
}

function DomainTable({ title, rows }: { title: string; rows?: { name: string; count: number }[] }) {
  return (
    <div className="panel">
      <h2>{title}</h2>
      <table className="mini">
        <tbody>
          {(rows ?? []).map((d) => (
            <tr key={d.name}>
              <td className="name">{d.name}</td>
              <td className="num">{d.count.toLocaleString()}</td>
            </tr>
          ))}
          {(rows?.length ?? 0) === 0 && (
            <tr>
              <td className="muted">Nothing yet</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
