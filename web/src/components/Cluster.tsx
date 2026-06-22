import { useEffect, useState } from 'react'
import { api, type Node } from '../api'

function ago(unixSec: number): string {
  const s = Math.max(0, Math.floor(Date.now() / 1000 - unixSec))
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  return `${Math.floor(s / 3600)}h ago`
}

export default function Cluster() {
  const [nodes, setNodes] = useState<Node[]>([])
  const [err, setErr] = useState('')

  useEffect(() => {
    let alive = true
    const tick = () =>
      api
        .clusterNodes()
        .then((n) => {
          if (alive) {
            setNodes(n)
            setErr('')
          }
        })
        .catch((e) => {
          if (alive) setErr(e.message)
        })
    tick()
    const id = setInterval(tick, 5000)
    return () => {
      alive = false
      clearInterval(id)
    }
  }, [])

  return (
    <div>
      <h2>Cluster nodes</h2>
      {err && <div className="error">{err}</div>}
      <table>
        <thead>
          <tr>
            <th>Node</th>
            <th>Address</th>
            <th>Config version</th>
            <th>Last seen</th>
          </tr>
        </thead>
        <tbody>
          {nodes.map((n) => (
            <tr key={n.name}>
              <td>{n.name}</td>
              <td>{n.address}</td>
              <td>{n.version}</td>
              <td>{ago(n.last_seen)}</td>
            </tr>
          ))}
          {nodes.length === 0 && (
            <tr>
              <td colSpan={4} className="muted">
                No worker nodes have reported in
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
