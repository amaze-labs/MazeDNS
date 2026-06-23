import { useEffect, useState, type ReactNode } from 'react'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
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
  custom: '#8a93a0',
}

const sourceColors: Record<string, string> = {
  Forwarded: '#4ea1ff',
  Cached: '#3ecf8e',
  Blocked: '#ff5d6c',
  Rewritten: '#c48aff',
}

const ONLINE_WINDOW = 120 // seconds
const qtypeColor = '#4ea1ff'
const tooltipStyle = { background: '#171c23', border: '1px solid #262d36', borderRadius: 8 }

const RANGES = [
  { label: '1h', hours: 1 },
  { label: '24h', hours: 24 },
  { label: '7d', hours: 24 * 7 },
  { label: '30d', hours: 24 * 30 },
  { label: '90d', hours: 24 * 90 },
]

const fmt = (n?: number) => (n == null ? '—' : n.toLocaleString())
const pct = (num?: number, den?: number) => (den && num != null ? `${Math.round((num / den) * 100)}%` : '—')

// For short ranges label buckets by time, for longer ones by date.
const bucketLabel = (ts: number, hours: number) => {
  const d = new Date(ts * 1000)
  return hours <= 48
    ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    : d.toLocaleDateString([], { month: 'short', day: 'numeric' })
}

export default function Dashboard() {
  const [hours, setHours] = useState(24)
  const [stats, setStats] = useState<Stats | null>(null)
  const [series, setSeries] = useState<SeriesPoint[]>([])
  const [cats, setCats] = useState<CategoryCount[]>([])
  const [ins, setIns] = useState<Insights | null>(null)
  const [log, setLog] = useState<QueryLogEntry[]>([])
  const [nodes, setNodes] = useState<Node[]>([])
  const [err, setErr] = useState('')

  const rangeLabel = RANGES.find((r) => r.hours === hours)?.label ?? `${hours}h`

  useEffect(() => {
    let alive = true
    const tick = async () => {
      try {
        const [s, ts, c, i, l] = await Promise.all([
          api.stats(),
          api.timeseries(hours),
          api.categories(hours),
          api.insights(hours),
          api.queryLog(50),
        ])
        if (alive) {
          setStats(s)
          setSeries(ts.points)
          setCats(c)
          setIns(i)
          setLog(l)
          setErr('')
        }
        // Cluster nodes are best-effort: a non-clustered master still returns [].
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
  }, [hours])

  const malicious = cats.find((c) => c.category === 'malware')?.count ?? 0
  const chartData = series.map((p) => ({
    time: bucketLabel(p.ts, hours),
    blocked: p.blocked,
    cached: p.cached,
    forwarded: p.forwarded,
  }))
  const clientBars = (ins?.clients ?? []).map((c) => ({ client: c.client, total: c.total, blocked: c.blocked }))
  const sourceData = stats
    ? [
        { name: 'Forwarded', value: stats.forwarded },
        { name: 'Cached', value: stats.cached },
        { name: 'Blocked', value: stats.blocked },
        { name: 'Rewritten', value: stats.rewritten },
      ].filter((d) => d.value > 0)
    : []

  const now = Date.now() / 1000
  const onlineNodes = nodes.filter((n) => n.last_seen && now - n.last_seen < ONLINE_WINDOW).length
  const clusterQ = nodes.reduce((sum, n) => sum + n.total, 0)
  const clusterB = nodes.reduce((sum, n) => sum + n.blocked, 0)

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
      </div>

      <KpiGroup label="Traffic (since start)">
        <Card label="Total queries" value={fmt(stats?.total)} />
        <Card label="Forwarded" value={fmt(stats?.forwarded)} />
        <Card label="Cached" value={fmt(stats?.cached)} sub={`${pct(stats?.cached, stats?.total)} hit rate`} />
        <Card label="Errors" value={fmt(stats?.errors)} accent={stats?.errors ? 'danger' : ''} />
      </KpiGroup>

      <KpiGroup label="Protection">
        <Card
          label="Blocked"
          value={fmt(stats?.blocked)}
          accent="danger"
          sub={`${pct(stats?.blocked, stats?.total)} of total`}
        />
        <Card label={`Malicious (${rangeLabel})`} value={fmt(malicious)} accent={malicious ? 'danger' : ''} />
        <Card label="Rewritten" value={fmt(stats?.rewritten)} />
        <Card label="Logged queries" value={fmt(stats?.log_count)} />
      </KpiGroup>

      <KpiGroup label={`Performance (${rangeLabel})`}>
        <Card label="Unique clients" value={fmt(ins?.unique_clients)} />
        <Card label="Avg latency" value={ins ? `${ins.avg_latency_ms.toFixed(1)} ms` : '—'} />
        <Card label="Cache entries" value={fmt(stats?.cache_size)} />
        <Card label="Query types" value={fmt(ins?.qtypes.length)} />
      </KpiGroup>

      {nodes.length > 0 && (
        <KpiGroup label="Cluster">
          <Card label="Worker nodes" value={fmt(nodes.length)} />
          <Card label="Online" value={fmt(onlineNodes)} accent={onlineNodes < nodes.length ? 'danger' : ''} />
          <Card label="Cluster queries" value={fmt(clusterQ)} />
          <Card label="Cluster blocked" value={fmt(clusterB)} accent="danger" />
        </KpiGroup>
      )}

      <div className="charts">
        <div className="panel">
          <h2>Queries ({rangeLabel})</h2>
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={chartData} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
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
          <h2>Blocked by category</h2>
          {cats.length === 0 ? (
            <p className="muted">No blocks yet</p>
          ) : (
            <>
              <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <Pie data={cats} dataKey="count" nameKey="category" innerRadius={50} outerRadius={80} paddingAngle={2}>
                    {cats.map((c) => (
                      <Cell key={c.category} fill={catColors[c.category] || '#8a93a0'} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={tooltipStyle} />
                </PieChart>
              </ResponsiveContainer>
              <div className="legend">
                {cats.map((c) => (
                  <span key={c.category}>
                    <i style={{ background: catColors[c.category] || '#8a93a0' }} /> {c.category} ({c.count})
                  </span>
                ))}
              </div>
            </>
          )}
        </div>
      </div>

      <div className="charts">
        <div className="panel">
          <h2>Top clients ({rangeLabel})</h2>
          {clientBars.length === 0 ? (
            <p className="muted">No traffic yet</p>
          ) : (
            <ResponsiveContainer width="100%" height={Math.max(140, clientBars.length * 28)}>
              <BarChart data={clientBars} layout="vertical" margin={{ top: 4, right: 16, left: 8, bottom: 0 }}>
                <CartesianGrid stroke="#262d36" horizontal={false} />
                <XAxis type="number" stroke="#8a93a0" fontSize={11} tickLine={false} allowDecimals={false} />
                <YAxis type="category" dataKey="client" stroke="#8a93a0" fontSize={11} width={120} tickLine={false} />
                <Tooltip contentStyle={tooltipStyle} cursor={{ fill: '#ffffff08' }} />
                <Bar dataKey="total" fill="#4ea1ff" radius={[0, 4, 4, 0]} />
                <Bar dataKey="blocked" fill="#ff5d6c" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="panel">
          <h2>Answer source</h2>
          {sourceData.length === 0 ? (
            <p className="muted">No queries yet</p>
          ) : (
            <>
              <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <Pie data={sourceData} dataKey="value" nameKey="name" innerRadius={50} outerRadius={80} paddingAngle={2}>
                    {sourceData.map((d) => (
                      <Cell key={d.name} fill={sourceColors[d.name]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={tooltipStyle} />
                </PieChart>
              </ResponsiveContainer>
              <div className="legend">
                {sourceData.map((d) => (
                  <span key={d.name}>
                    <i style={{ background: sourceColors[d.name] }} /> {d.name} ({d.value.toLocaleString()})
                  </span>
                ))}
              </div>
            </>
          )}
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
                <Bar dataKey="count" fill={qtypeColor} radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        {nodes.length > 0 && (
          <div className="panel">
            <h2>Cluster status</h2>
            <table className="mini">
              <tbody>
                {nodes.map((n) => (
                  <tr key={n.name}>
                    <td className="name">
                      <span className={`dot ${n.last_seen && now - n.last_seen < ONLINE_WINDOW ? 'on' : 'off'}`} />
                      {n.name}
                    </td>
                    <td className="num">{n.version ? <code>{n.version}</code> : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="charts">
        <DomainTable title={`Top blocked domains (${rangeLabel})`} rows={ins?.top_blocked} />
        <DomainTable title={`Most queried domains (${rangeLabel})`} rows={ins?.top_queried} />
      </div>

      <h2>Recent queries</h2>
      <table>
        <thead>
          <tr>
            <th>Time</th>
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
              <td>{e.client}</td>
              <td>{e.name}</td>
              <td>{e.qtype}</td>
              <td>
                <span className={`badge ${e.action}`}>{e.action}</span>
              </td>
              <td>{e.rcode}</td>
              <td>{e.elapsed_ms}</td>
            </tr>
          ))}
          {log.length === 0 && (
            <tr>
              <td colSpan={7} className="muted">
                No queries yet
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

function KpiGroup({ label, children }: { label: string; children: ReactNode }) {
  return (
    <section className="kpi-section">
      <h3>{label}</h3>
      <div className="cards">{children}</div>
    </section>
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
