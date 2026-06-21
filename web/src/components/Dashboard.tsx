import { useEffect, useState } from 'react'
import { api, type Stats, type QueryLogEntry } from '../api'

export default function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null)
  const [log, setLog] = useState<QueryLogEntry[]>([])
  const [err, setErr] = useState('')

  useEffect(() => {
    let alive = true
    const tick = async () => {
      try {
        const [s, l] = await Promise.all([api.stats(), api.queryLog(50)])
        if (alive) {
          setStats(s)
          setLog(l)
          setErr('')
        }
      } catch (e: any) {
        if (alive) setErr(e.message)
      }
    }
    tick()
    const id = setInterval(tick, 3000)
    return () => {
      alive = false
      clearInterval(id)
    }
  }, [])

  return (
    <div>
      {err && <div className="error">{err}</div>}
      <div className="cards">
        <Card label="Total" value={stats?.total} />
        <Card label="Blocked" value={stats?.blocked} accent="danger" />
        <Card label="Rewritten" value={stats?.rewritten} />
        <Card label="Forwarded" value={stats?.forwarded} />
        <Card label="Cache size" value={stats?.cache_size} />
        <Card label="Logged" value={stats?.log_count} />
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
