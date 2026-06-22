import { useEffect, useState, type FormEvent } from 'react'
import { api, type Node } from '../api'

const ONLINE_WINDOW = 120 // seconds

function ago(unixSec: number): string {
  if (!unixSec) return 'never'
  const s = Math.max(0, Math.floor(Date.now() / 1000 - unixSec))
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  return `${Math.floor(s / 3600)}h ago`
}

export default function Cluster() {
  const [nodes, setNodes] = useState<Node[]>([])
  const [name, setName] = useState('')
  const [newKey, setNewKey] = useState<{ name: string; key: string } | null>(null)
  const [err, setErr] = useState('')

  const load = () =>
    api
      .clusterNodes()
      .then((n) => {
        setNodes(n)
        setErr('')
      })
      .catch((e) => setErr(e.message))

  useEffect(() => {
    load()
    const id = setInterval(load, 5000)
    return () => clearInterval(id)
  }, [])

  const add = async (e: FormEvent) => {
    e.preventDefault()
    if (!name.trim()) return
    try {
      const r = await api.addNode(name.trim())
      setNewKey(r)
      setName('')
      setErr('')
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }

  const del = async (n: string) => {
    await api.deleteNode(n)
    if (newKey?.name === n) setNewKey(null)
    load()
  }

  const now = Date.now() / 1000
  const online = nodes.filter((n) => n.last_seen && now - n.last_seen < ONLINE_WINDOW).length
  const totalQ = nodes.reduce((sum, n) => sum + n.total, 0)
  const totalB = nodes.reduce((sum, n) => sum + n.blocked, 0)

  return (
    <div>
      <h2>Cluster metrics</h2>
      {err && <div className="error">{err}</div>}

      <div className="cards">
        <Card label="Nodes" value={nodes.length} />
        <Card label="Online" value={online} />
        <Card label="Cluster queries" value={totalQ} />
        <Card label="Cluster blocked" value={totalB} accent="danger" />
      </div>

      <form className="row" onSubmit={add}>
        <input placeholder="new node name (e.g. site-b)" value={name} onChange={(e) => setName(e.target.value)} />
        <button type="submit">Add node</button>
      </form>

      {newKey && (
        <div className="ok-msg">
          <strong>Node “{newKey.name}” enrolled.</strong> Copy its key now — it is stored hashed and won’t be shown again.
          Configure the worker with:
          <pre className="keybox">{`MAZEDNS_MODE=worker
MAZEDNS_MASTER_URL=http://<this-master>:8080
MAZEDNS_NODE_KEY=${newKey.key}`}</pre>
        </div>
      )}

      <table>
        <thead>
          <tr>
            <th>Node</th>
            <th>Key</th>
            <th>Address</th>
            <th>Queries</th>
            <th>Blocked</th>
            <th>Version</th>
            <th>Last seen</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {nodes.map((n) => (
            <tr key={n.name}>
              <td>{n.name}</td>
              <td>
                <code>{n.key_prefix}…</code>
              </td>
              <td>{n.address || '—'}</td>
              <td>{n.total}</td>
              <td>{n.blocked}</td>
              <td>{n.version}</td>
              <td>{ago(n.last_seen)}</td>
              <td>
                <button className="del" onClick={() => del(n.name)}>
                  ✕
                </button>
              </td>
            </tr>
          ))}
          {nodes.length === 0 && (
            <tr>
              <td colSpan={8} className="muted">
                No nodes enrolled — add one above
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

function Card({ label, value, accent }: { label: string; value: number; accent?: string }) {
  return (
    <div className={`card ${accent || ''}`}>
      <div className="card-value">{value}</div>
      <div className="card-label">{label}</div>
    </div>
  )
}
