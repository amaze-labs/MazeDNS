import { useEffect, useState } from 'react'
import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { api, type Stats, type QueryLogEntry, type SeriesPoint, type CategoryCount } from '../api'

const catColors: Record<string, string> = {
  ads: '#4ea1ff',
  trackers: '#c48aff',
  malware: '#ff5d6c',
  custom: '#8a93a0',
}

const tooltipStyle = { background: '#171c23', border: '1px solid #262d36', borderRadius: 8 }

export default function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null)
  const [series, setSeries] = useState<SeriesPoint[]>([])
  const [cats, setCats] = useState<CategoryCount[]>([])
  const [log, setLog] = useState<QueryLogEntry[]>([])
  const [err, setErr] = useState('')

  useEffect(() => {
    let alive = true
    const tick = async () => {
      try {
        const [s, ts, c, l] = await Promise.all([
          api.stats(),
          api.timeseries(24),
          api.categories(24),
          api.queryLog(50),
        ])
        if (alive) {
          setStats(s)
          setSeries(ts.points)
          setCats(c)
          setLog(l)
          setErr('')
        }
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
  }, [])

  const malicious = cats.find((c) => c.category === 'malware')?.count ?? 0
  const chartData = series.map((p) => ({
    time: new Date(p.ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    total: p.total,
    blocked: p.blocked,
  }))

  return (
    <div>
      {err && <div className="error">{err}</div>}
      <div className="cards">
        <Card label="Total" value={stats?.total} />
        <Card label="Blocked" value={stats?.blocked} accent="danger" />
        <Card label="Malicious" value={malicious} accent="danger" />
        <Card label="Rewritten" value={stats?.rewritten} />
        <Card label="Cache size" value={stats?.cache_size} />
        <Card label="Logged" value={stats?.log_count} />
      </div>

      <div className="charts">
        <div className="panel">
          <h2>Queries (24h)</h2>
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={chartData} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="gTotal" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#4ea1ff" stopOpacity={0.5} />
                  <stop offset="100%" stopColor="#4ea1ff" stopOpacity={0} />
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
              <Area type="monotone" dataKey="total" stroke="#4ea1ff" fill="url(#gTotal)" strokeWidth={2} />
              <Area type="monotone" dataKey="blocked" stroke="#ff5d6c" fill="url(#gBlocked)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
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

function Card({ label, value, accent }: { label: string; value?: number; accent?: string }) {
  return (
    <div className={`card ${accent || ''}`}>
      <div className="card-value">{value ?? '—'}</div>
      <div className="card-label">{label}</div>
    </div>
  )
}
