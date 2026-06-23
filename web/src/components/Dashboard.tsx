import { useEffect, useState, type ReactNode } from 'react'
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
const pct = (num?: number, den?: number) => (den && num != null ? `${Math.round((num / den) * 100)}%` : '—')

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
function NodeFilter({ options, selected, onChange }: { options: string[]; selected: string[]; onChange: (s: string[]) => void }) {
  const [open, setOpen] = useState(false)
  const label = selected.length === 0 ? 'All nodes' : `${selected.length} node${selected.length > 1 ? 's' : ''}`
  const toggle = (n: string) =>
    onChange(selected.includes(n) ? selected.filter((x) => x !== n) : [...selected, n])
  return (
    <div className="nodefilter">
      <button className={`btn ${selected.length ? 'primary' : ''}`} onClick={() => setOpen((o) => !o)}>
        ▾ {label}
      </button>
      {open && (
        <>
          <div className="nodefilter-backdrop" onClick={() => setOpen(false)} />
          <div className="nodefilter-menu">
            <label>
              <input type="checkbox" checked={selected.length === 0} onChange={() => onChange([])} /> All nodes
            </label>
            {options.map((o) => (
              <label key={o}>
                <input type="checkbox" checked={selected.includes(o)} onChange={() => toggle(o)} /> {o}
              </label>
            ))}
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
  const [nodes, setNodes] = useState<Node[]>([])
  const [err, setErr] = useState('')

  // query log (paginated + searchable)
  const [log, setLog] = useState<QueryLogEntry[]>([])
  const [qlTotal, setQlTotal] = useState(0)
  const [qlPage, setQlPage] = useState(0)
  const [qlInput, setQlInput] = useState('')
  const [qlSearch, setQlSearch] = useState('')

  const rangeLabel = RANGES.find((r) => r.hours === hours)?.label ?? `${hours}h`

  useEffect(() => {
    localStorage.setItem('mazedns.hours', String(hours))
  }, [hours])
  useEffect(() => {
    localStorage.setItem('mazedns.focusNodes', JSON.stringify(focus))
  }, [focus])

  useEffect(() => {
    let alive = true
    const tick = async () => {
      try {
        const [s, ts, c, i] = await Promise.all([
          api.stats(),
          api.timeseries(hours, focus),
          api.categories(hours, focus),
          api.insights(hours, focus),
        ])
        if (!alive) return
        setStats(s)
        setSeries(ts.points)
        setCats(c)
        setIns(i)
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
        .queryLog({ limit: PAGE, offset: qlPage * PAGE, search: qlSearch, nodes: focus })
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
  }, [qlPage, qlSearch, focus])

  const malicious = cats.find((c) => c.category === 'malware')?.count ?? 0
  const areaData = series.map((p) => ({
    time: bucketLabel(p.ts, hours),
    blocked: p.blocked,
    cached: p.cached,
    forwarded: p.forwarded,
  }))
  const latData = series.map((p) => ({ time: bucketLabel(p.ts, hours), ms: Math.round(p.avg_latency_ms * 100) / 100 }))
  const catData = cats.map((c) => ({ name: c.category, value: c.count, fill: catColors[c.category] || '#8a93a0' }))
  const sourceData = stats
    ? [
        { name: 'Forwarded', value: stats.forwarded },
        { name: 'Cached', value: stats.cached },
        { name: 'Blocked', value: stats.blocked },
        { name: 'Rewritten', value: stats.rewritten },
      ]
        .filter((d) => d.value > 0)
        .map((d) => ({ ...d, fill: sourceColors[d.name] }))
    : []
  const byNodeData = (ins?.by_node ?? [])
    .filter((n) => n.total > 0)
    .map((n, i) => ({ name: n.node, value: n.total, fill: NODE_PALETTE[i % NODE_PALETTE.length] }))
  const clientRows = ins?.clients ?? []
  const maxClient = clientRows.reduce((m, c) => Math.max(m, c.total), 0)

  const now = Date.now() / 1000
  const onlineNodes = nodes.filter((n) => n.last_seen && now - n.last_seen < ONLINE_WINDOW).length
  const clusterQ = nodes.reduce((sum, n) => sum + n.total, 0)
  const clusterB = nodes.reduce((sum, n) => sum + n.blocked, 0)
  const lastPage = Math.max(0, Math.ceil(qlTotal / PAGE) - 1)

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
            <NodeFilter options={['master', ...nodes.map((n) => n.name)]} selected={focus} onChange={setFocus} />
          </>
        )}
      </div>

      <Section title="Overview">
        <div className="kpi-section">
          <h3>Traffic (since start)</h3>
          <div className="cards">
            <Card label="Total queries" value={fmt(stats?.total)} />
            <Card label="Forwarded" value={fmt(stats?.forwarded)} />
            <Card label="Cached" value={fmt(stats?.cached)} sub={`${pct(stats?.cached, stats?.total)} hit rate`} />
            <Card label="Errors" value={fmt(stats?.errors)} accent={stats?.errors ? 'danger' : ''} />
          </div>
        </div>
        <div className="kpi-section">
          <h3>Protection</h3>
          <div className="cards">
            <Card label="Blocked" value={fmt(stats?.blocked)} accent="danger" sub={`${pct(stats?.blocked, stats?.total)} of total`} />
            <Card label={`Malicious (${rangeLabel})`} value={fmt(malicious)} accent={malicious ? 'danger' : ''} />
            <Card label="Rewritten" value={fmt(stats?.rewritten)} />
            <Card label="Logged queries" value={fmt(stats?.log_count)} />
          </div>
        </div>
        <div className="kpi-section">
          <h3>Performance — cluster ({rangeLabel})</h3>
          <div className="cards">
            <Card label="Unique clients" value={fmt(ins?.unique_clients)} />
            <Card label="Avg latency" value={ins ? `${ins.avg_latency_ms.toFixed(1)} ms` : '—'} />
            <Card label="Cache entries" value={fmt(stats?.cache_size)} />
            <Card label="Query types" value={fmt(ins?.qtypes.length)} />
          </div>
        </div>
        {nodes.length > 0 && (
          <div className="kpi-section">
            <h3>Cluster</h3>
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
                <Line type="monotone" dataKey="ms" stroke="#ffb454" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
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
          <input
            className="search"
            placeholder="search name or client…"
            value={qlInput}
            onChange={(e) => setQlInput(e.target.value)}
          />
        }
      >
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Node</th>
              <th>Client</th>
              <th>Name</th>
              <th>Type</th>
              <th>Action</th>
              <th>Rcode</th>
              <th>ms</th>
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
