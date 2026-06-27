import { useEffect, useState, type FormEvent } from 'react'
import { api, type Node } from '../api'

const ONLINE_WINDOW = 120 // seconds
const IMAGE = 'ghcr.io/ipmaze/mazedns:latest'

function ago(unixSec: number): string {
  if (!unixSec) return 'never'
  const s = Math.max(0, Math.floor(Date.now() / 1000 - unixSec))
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  return `${Math.floor(s / 3600)}h ago`
}

function CodeBlock({ label, text }: { label: string; text: string }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      /* clipboard unavailable */
    }
  }
  return (
    <div className="codeblock">
      <div className="codeblock-head">
        <span className="muted">{label}</span>
        <button className="btn ghost" onClick={copy}>
          {copied ? 'Copied ✓' : 'Copy'}
        </button>
      </div>
      <pre className="keybox">{text}</pre>
    </div>
  )
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
    if (!window.confirm(`Remove node “${n}”? Its key is revoked.`)) return
    await api.deleteNode(n)
    if (newKey?.name === n) setNewKey(null)
    load()
  }

  const renew = async (n: string) => {
    if (!window.confirm(`Rotate the key for “${n}”? The old key stops working immediately — update the worker's MAZEDNS_NODE_KEY.`)) return
    try {
      const r = await api.renewNodeKey(n)
      setNewKey(r)
      setErr('')
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }

  const now = Date.now() / 1000
  const isOnline = (n: Node) => n.is_master || (!!n.last_seen && now - n.last_seen < ONLINE_WINDOW)
  const online = nodes.filter(isOnline).length
  const totalQ = nodes.reduce((sum, n) => sum + n.total, 0)
  const totalB = nodes.reduce((sum, n) => sum + n.blocked, 0)

  const masterHost = window.location.hostname || '<master-host>'
  const masterURL = `http://${masterHost}:8080`
  const dockerRun = newKey
    ? `docker run -d --name mazedns-${newKey.name} --restart unless-stopped \\
  -e MAZEDNS_MODE=worker \\
  -e MAZEDNS_MASTER_URL=${masterURL} \\
  -e MAZEDNS_NODE_KEY=${newKey.key} \\
  -p 53:5300/udp -p 53:5300/tcp \\
  ${IMAGE}`
    : ''
  const dockerCompose = newKey
    ? `services:
  mazedns-${newKey.name}:
    image: ${IMAGE}
    restart: unless-stopped
    environment:
      MAZEDNS_MODE: worker
      MAZEDNS_MASTER_URL: "${masterURL}"
      MAZEDNS_NODE_KEY: "${newKey.key}"
    ports:
      - "53:5300/udp"
      - "53:5300/tcp"`
    : ''

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

      <h2>Add a worker node</h2>
      <p className="muted">
        Enroll a node to get a one-time key, then run the worker from the prebuilt image <code>{IMAGE}</code>.
      </p>
      <form className="row" onSubmit={add}>
        <input placeholder="new node name (e.g. site-b)" value={name} onChange={(e) => setName(e.target.value)} />
        <button type="submit" className="btn primary">
          Add node
        </button>
      </form>

      {newKey && (
        <div className="enroll">
          <div className="ok-msg">
            <strong>Key for node “{newKey.name}” — shown once</strong> (stored hashed). Run the worker with it, or update
            its <code>MAZEDNS_NODE_KEY</code> if you rotated. Adjust <code>{masterURL}</code> if the worker reaches the
            master at a different address.
          </div>
          <CodeBlock label="Option A — docker run" text={dockerRun} />
          <CodeBlock label="Option B — docker compose (add to your compose file)" text={dockerCompose} />
        </div>
      )}

      <h2>Nodes</h2>
      <table>
        <thead>
          <tr>
            <th>Status</th>
            <th>Node</th>
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
              <td>
                <span className={`node-dot ${isOnline(n) ? 'on' : 'off'}`} title={isOnline(n) ? 'online' : 'offline'} />
              </td>
              <td>
                {n.name} {n.is_master && <span className="badge">master</span>}
              </td>
              <td>{n.address || '—'}</td>
              <td>{n.total.toLocaleString()}</td>
              <td>{n.blocked.toLocaleString()}</td>
              <td>{n.version ? <code>{n.version}</code> : <span className="muted">pending</span>}</td>
              <td>{n.is_master ? 'now' : ago(n.last_seen)}</td>
              <td>
                {!n.is_master && (
                  <div className="ql-filters">
                    <button className="btn" onClick={() => renew(n.name)} title="Rotate this node's key">
                      Renew key
                    </button>
                    <button className="del" onClick={() => del(n.name)}>
                      ✕
                    </button>
                  </div>
                )}
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
      <div className="card-value">{value.toLocaleString()}</div>
      <div className="card-label">{label}</div>
    </div>
  )
}
